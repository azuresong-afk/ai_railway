package audit

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Файлы архива и выгрузки журнала (ADR-0008) — JSON Lines: строка
// заголовка, строки записей в той же форме, что хешируется, плюс хеш записи;
// в архиве последняя строка — подписанная контрольная точка. Хеш тела
// (заголовок и записи) входит в точку, поэтому файл проверяется без БД.
const (
	archiveFormat = "aisec-audit-archive"
	exportFormat  = "aisec-audit-export"
	// maxFileLine — предел строки файла: подробности записи не больше 16 КиБ.
	maxFileLine = 256 << 10
	// maxArchiveRecords — предел числа записей в проверяемом архиве.
	maxArchiveRecords = 1 << 40
)

// ErrArchiveInvalid — файл архива повреждён, подменён или не соответствует
// своей контрольной точке.
var ErrArchiveInvalid = errors.New("архив журнала аудита недействителен")

// fileHeader — первая строка файла.
type fileHeader struct {
	Format    string `json:"format"`
	V         int    `json:"v"`
	OrgID     string `json:"org_id"`
	HashAlg   string `json:"hash_alg"`
	PrevSeq   int64  `json:"prev_seq"`
	PrevHash  string `json:"prev_hash"`
	FromSeq   int64  `json:"from_seq"`
	ToSeq     int64  `json:"to_seq"`
	CreatedAt string `json:"created_at"`
	// Только у выгрузки: границы по времени, ГГГГ-ММ-ДД или пусто.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// fileRecord — запись в файле: каноническая форма и хеш.
type fileRecord struct {
	V       int             `json:"v"`
	Seq     int64           `json:"seq"`
	ID      string          `json:"id"`
	OrgID   string          `json:"org_id"`
	TS      string          `json:"ts"`
	Actor   canonicalActor  `json:"actor"`
	IP      string          `json:"ip"`
	Action  string          `json:"action"`
	Object  canonicalObject `json:"object"`
	Result  string          `json:"result"`
	Details json.RawMessage `json:"details"`
	Alg     string          `json:"alg"`
	Prev    string          `json:"prev"`
	Hash    string          `json:"hash"`
}

// fileTrailer — последняя строка архива.
type fileTrailer struct {
	Checkpoint checkpointPayload `json:"checkpoint"`
	SigAlg     string            `json:"sig_alg"`
	Signature  []byte            `json:"signature"`
	PublicKey  []byte            `json:"public_key"`
}

func toFileRecord(r *Record) fileRecord {
	ip := ""
	if r.SourceIP.IsValid() {
		ip = r.SourceIP.String()
	}
	return fileRecord{
		V: formatVersion, Seq: r.Seq, ID: r.ID, OrgID: r.OrgID, TS: r.TS.UTC().Format(tsLayout),
		Actor: canonicalActor{Type: string(r.Actor.Type), ID: r.Actor.ID, Name: r.Actor.Name},
		IP:    ip, Action: r.Action,
		Object: canonicalObject{Type: r.Object.Type, ID: r.Object.ID},
		Result: string(r.Result), Details: r.Details, Alg: r.HashAlg,
		Prev: hex.EncodeToString(r.PrevHash), Hash: hex.EncodeToString(r.Hash),
	}
}

// fromFileRecord восстанавливает запись. Ошибка разбора времени, адреса
// или хешей делает запись нечитаемой — проверка цепочки её отвергнет.
func fromFileRecord(f *fileRecord) Record {
	r := Record{
		Seq: f.Seq, ID: f.ID, OrgID: f.OrgID,
		Actor:  Actor{Type: ActorType(f.Actor.Type), ID: f.Actor.ID, Name: f.Actor.Name},
		Action: f.Action, Object: Object{Type: f.Object.Type, ID: f.Object.ID},
		Result: Result(f.Result), Details: f.Details, HashAlg: f.Alg,
	}
	var err error
	if f.V != formatVersion {
		r.unreadable = true
	}
	if r.TS, err = time.Parse(tsLayout, f.TS); err != nil {
		r.unreadable = true
	}
	if f.IP != "" {
		if r.SourceIP, err = netip.ParseAddr(f.IP); err != nil {
			r.unreadable = true
		}
	}
	if r.PrevHash, err = hex.DecodeString(f.Prev); err != nil {
		r.unreadable = true
	}
	if r.Hash, err = hex.DecodeString(f.Hash); err != nil {
		r.unreadable = true
	}
	return r
}

// fileWriter пишет строки файла и считает хеш тела.
type fileWriter struct {
	w   *bufio.Writer
	sum hash.Hash
}

func newFileWriter(w io.Writer, h crypto.Hasher) *fileWriter {
	return &fileWriter{w: bufio.NewWriter(w), sum: h.New()}
}

// line пишет объект строкой; hashed — строка входит в хеш тела.
func (fw *fileWriter) line(v any, hashed bool) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if hashed {
		fw.sum.Write(b) // запись в hash.Hash не возвращает ошибок
	}
	_, err = fw.w.Write(b)
	return err
}

func (fw *fileWriter) bodyHash() []byte { return fw.sum.Sum(nil) }

func (fw *fileWriter) flush() error { return fw.w.Flush() }

// strictUnmarshal разбирает одну строку: неизвестные поля и данные после
// объекта — ошибка.
func strictUnmarshal(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("данные после объекта")
	}
	return nil
}

// VerifyArchive проверяет файл архива без БД: заголовок, непрерывную цепочку
// записей от предыдущей точки, хеш тела, соответствие точки записям и
// подпись точки одним из ключей keys (после ротации ключа аудита — любым
// из открытых ключей каталога, ADR-0018, п. 5.3). Вход недоверенный (файл
// с внешнего носителя), разбор покрыт FuzzVerifyArchive.
func VerifyArchive(r io.Reader, h crypto.Hasher, keys ...crypto.Verifier) (*Checkpoint, error) {
	invalid := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrArchiveInvalid, fmt.Sprintf(format, a...))
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxFileLine)
	sum := h.New()
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return nil, invalid("заголовок: %v", err)
		}
		return nil, invalid("пустой файл")
	}
	var hdr fileHeader
	if err := strictUnmarshal(sc.Bytes(), &hdr); err != nil {
		return nil, invalid("заголовок: %v", err)
	}
	sum.Write(sc.Bytes())
	sum.Write([]byte{'\n'})
	if hdr.Format != archiveFormat || hdr.V != formatVersion || hdr.HashAlg != h.Name() {
		return nil, invalid("неизвестный формат, версия или алгоритм хеша")
	}
	prevHash, err := hex.DecodeString(hdr.PrevHash)
	if err != nil || len(prevHash) != len(genesis(h)) || hdr.PrevSeq < 0 || hdr.PrevSeq > math.MaxInt64-maxArchiveRecords {
		return nil, invalid("заголовок: предыдущая точка")
	}
	c := newChain(h, Anchor{Seq: hdr.PrevSeq, Hash: prevHash}, nil)
	// Последняя строка — точка; остальные — записи. Строка обрабатывается,
	// когда прочитана следующая.
	var pending []byte
	for sc.Scan() {
		if pending != nil {
			if err := addFileRecord(c, pending); err != nil {
				return nil, invalid("%v", err)
			}
			sum.Write(pending)
			sum.Write([]byte{'\n'})
			if c.checked > maxArchiveRecords {
				return nil, invalid("слишком много записей")
			}
		}
		pending = append(pending[:0:0], sc.Bytes()...)
	}
	if err := sc.Err(); err != nil {
		return nil, invalid("чтение: %v", err)
	}
	if pending == nil {
		return nil, invalid("нет контрольной точки")
	}
	var tr fileTrailer
	if err := strictUnmarshal(pending, &tr); err != nil {
		return nil, invalid("контрольная точка: %v", err)
	}
	cp, err := checkpointFromTrailer(&tr)
	if err != nil {
		return nil, invalid("контрольная точка: %v", err)
	}
	head := c.head()
	switch {
	case c.checked == 0:
		return nil, invalid("в архиве нет записей")
	case hdr.FromSeq != hdr.PrevSeq+1 || hdr.ToSeq != head.Seq:
		return nil, invalid("диапазон в заголовке не совпадает с записями")
	case cp.PrevSeq != hdr.PrevSeq || !crypto.Equal(cp.PrevHash, prevHash):
		return nil, invalid("точка не продолжает предыдущую из заголовка")
	case cp.Seq != head.Seq || !crypto.Equal(cp.Hash, head.Hash) || cp.Records != c.checked:
		return nil, invalid("точка не совпадает с последней записью архива")
	case cp.HashAlg != h.Name() || cp.OrgID != hdr.OrgID:
		return nil, invalid("точка: алгоритм или организация")
	case !crypto.Equal(cp.ArchiveHash, sum.Sum(nil)):
		return nil, invalid("хеш тела архива не совпадает с точкой")
	case !slices.ContainsFunc(keys, func(v crypto.Verifier) bool {
		return crypto.Equal(cp.PublicKey, v.PublicKey()) && cp.VerifySignature(v)
	}):
		return nil, invalid("подпись контрольной точки не проверяется")
	}
	return cp, nil
}

func addFileRecord(c *chain, line []byte) error {
	var f fileRecord
	if err := strictUnmarshal(line, &f); err != nil {
		return fmt.Errorf("запись после %d: %w", c.nextSeq-1, err)
	}
	r := fromFileRecord(&f)
	if b := c.add(&r); b != nil {
		return b
	}
	return nil
}

func checkpointFromTrailer(t *fileTrailer) (*Checkpoint, error) {
	p := &t.Checkpoint
	if p.V != formatVersion {
		return nil, errors.New("версия")
	}
	cp := &Checkpoint{
		ID: p.ID, OrgID: p.OrgID, Seq: p.Seq, HashAlg: p.HashAlg, PrevSeq: p.PrevSeq, Records: p.Records,
		ArchiveName: p.ArchiveName, SigAlg: t.SigAlg, Signature: t.Signature, PublicKey: t.PublicKey,
	}
	var err error
	if cp.Hash, err = hex.DecodeString(p.Hash); err != nil {
		return nil, errors.New("hash")
	}
	if cp.PrevHash, err = hex.DecodeString(p.PrevHash); err != nil {
		return nil, errors.New("prev_hash")
	}
	if cp.ArchiveHash, err = hex.DecodeString(p.ArchiveHash); err != nil {
		return nil, errors.New("archive_hash")
	}
	if cp.CreatedAt, err = time.Parse(tsLayout, p.CreatedAt); err != nil {
		return nil, errors.New("created_at")
	}
	// Подписанная форма должна воспроизводиться из разобранной точки: иначе
	// подпись проверялась бы не над тем, что записано в файле.
	if cp.payload() != *p {
		return nil, errors.New("неканоническая форма")
	}
	return cp, nil
}
