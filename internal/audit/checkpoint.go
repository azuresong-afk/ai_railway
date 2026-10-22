package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// ReasonCheckpoint — контрольная точка архивации подменена, удалена или не
// связана с предыдущей: начало хранимой цепочки нельзя подтвердить (DM-43).
const ReasonCheckpoint Reason = "checkpoint_invalid"

// ErrCheckpointInvalid — последовательность контрольных точек нарушена или
// подпись точки не проверяется.
var ErrCheckpointInvalid = errors.New("контрольная точка архивации журнала аудита недействительна")

// checkpointContext разделяет подписи: ключ аудита подписывает только
// контрольные точки, и подпись точки не подходит ни к чему другому.
const checkpointContext = "aisec-audit-checkpoint-v1\n"

// maxCheckpoints — предел числа точек при чтении (архивация — раз в
// месяцы, точек единицы и десятки).
const maxCheckpoints = 10000

// Checkpoint — подписанная контрольная точка архивации (РСБ.4, ADR-0008):
// последняя архивированная запись, предыдущая точка и хеш тела архива.
type Checkpoint struct {
	ID          string
	OrgID       string
	Seq         int64  // последняя архивированная запись
	Hash        []byte // её хеш
	HashAlg     string
	PrevSeq     int64  // предыдущая точка; у первой — 0
	PrevHash    []byte // у первой — нулевой хеш
	Records     int64  // Seq - PrevSeq
	ArchiveName string // имя файла архива
	ArchiveHash []byte // хеш заголовка и записей архива (без строки точки)
	CreatedAt   time.Time
	SigAlg      string
	Signature   []byte
	PublicKey   []byte // для сверки; проверка — ключом из каталога ключей
}

// Anchor — точка, от которой продолжается хранимая цепочка.
func (c *Checkpoint) Anchor() Anchor { return Anchor{Seq: c.Seq, Hash: c.Hash} }

// checkpointPayload — подписываемая часть точки; порядок полей фиксирован.
type checkpointPayload struct {
	V           int    `json:"v"`
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	Seq         int64  `json:"seq"`
	Hash        string `json:"hash"`
	HashAlg     string `json:"hash_alg"`
	PrevSeq     int64  `json:"prev_seq"`
	PrevHash    string `json:"prev_hash"`
	Records     int64  `json:"records"`
	ArchiveName string `json:"archive_name"`
	ArchiveHash string `json:"archive_hash"`
	CreatedAt   string `json:"created_at"`
}

func (c *Checkpoint) payload() checkpointPayload {
	return checkpointPayload{
		V: formatVersion, ID: c.ID, OrgID: c.OrgID, Seq: c.Seq, Hash: hex.EncodeToString(c.Hash), HashAlg: c.HashAlg,
		PrevSeq: c.PrevSeq, PrevHash: hex.EncodeToString(c.PrevHash), Records: c.Records,
		ArchiveName: c.ArchiveName, ArchiveHash: hex.EncodeToString(c.ArchiveHash),
		CreatedAt: c.CreatedAt.UTC().Format(tsLayout),
	}
}

// SignedBytes — то, что подписывается: контекст и каноническая форма точки.
func (c *Checkpoint) SignedBytes() ([]byte, error) {
	b, err := json.Marshal(c.payload())
	if err != nil {
		return nil, err
	}
	return append([]byte(checkpointContext), b...), nil
}

// Sign подписывает точку.
func (c *Checkpoint) Sign(s crypto.Signer) error {
	msg, err := c.SignedBytes()
	if err != nil {
		return err
	}
	sig, err := s.Sign(msg)
	if err != nil {
		return fmt.Errorf("подпись контрольной точки: %w", err)
	}
	c.SigAlg, c.Signature, c.PublicKey = s.Name(), sig, s.PublicKey()
	return nil
}

// VerifySignature проверяет подпись точки открытым ключом v.
func (c *Checkpoint) VerifySignature(v crypto.Verifier) bool {
	if c.SigAlg != v.Name() {
		return false
	}
	msg, err := c.SignedBytes()
	if err != nil {
		return false
	}
	return v.Verify(msg, c.Signature)
}

// VerifyCheckpoints проверяет последовательность точек, упорядоченную по
// номеру: первая начинается с {0, нулевой хеш}, каждая следующая продолжает
// предыдущую, число записей сходится, алгоритм — профиля, подпись и
// public_key — ключа по расписанию keys (ADR-0018, п. 5.2). keys = nil —
// подписи не проверяются (у компонента нет открытого ключа аудита), только
// связность. Возвращает начало хранимой цепочки.
func VerifyCheckpoints(h crypto.Hasher, keys CheckpointKeys, cps []Checkpoint) (Anchor, error) {
	prev := Anchor{Seq: 0, Hash: genesis(h)}
	for i := range cps {
		c := &cps[i]
		switch {
		case c.PrevSeq != prev.Seq || !crypto.Equal(c.PrevHash, prev.Hash):
			return Anchor{}, fmt.Errorf("%w: точка %d не продолжает предыдущую", ErrCheckpointInvalid, c.Seq)
		case c.Seq <= c.PrevSeq || c.Records != c.Seq-c.PrevSeq:
			return Anchor{}, fmt.Errorf("%w: точка %d: неверный диапазон", ErrCheckpointInvalid, c.Seq)
		case c.HashAlg != h.Name() || len(c.Hash) != len(prev.Hash):
			return Anchor{}, fmt.Errorf("%w: точка %d: чужой алгоритм хеша", ErrCheckpointInvalid, c.Seq)
		case keys != nil && !checkpointSigned(c, keys.CheckpointKey(c.Seq)):
			return Anchor{}, fmt.Errorf("%w: точка %d: подпись не проверяется ключом по расписанию", ErrCheckpointInvalid, c.Seq)
		}
		prev = c.Anchor()
	}
	return prev, nil
}

// checkpointSigned — точка подписана ключом v и называет его в public_key.
func checkpointSigned(c *Checkpoint, v crypto.Verifier) bool {
	return crypto.Equal(c.PublicKey, v.PublicKey()) && c.VerifySignature(v)
}

// querier — чтение из пула или из транзакции.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// loadCheckpoints читает все точки по возрастанию номера.
func loadCheckpoints(ctx context.Context, q querier) ([]Checkpoint, error) {
	rows, err := q.Query(ctx, `SELECT id::text, org_id::text, seq, hash, hash_alg, prev_seq, prev_hash, records,
		archive_name, archive_hash, created_at, sig_alg, signature, public_key
		FROM audit_checkpoints ORDER BY seq LIMIT $1`, maxCheckpoints+1)
	if err != nil {
		return nil, fmt.Errorf("журнал аудита: контрольные точки: %w", err)
	}
	defer rows.Close()
	var out []Checkpoint
	for rows.Next() {
		var c Checkpoint
		if err := rows.Scan(&c.ID, &c.OrgID, &c.Seq, &c.Hash, &c.HashAlg, &c.PrevSeq, &c.PrevHash, &c.Records,
			&c.ArchiveName, &c.ArchiveHash, &c.CreatedAt, &c.SigAlg, &c.Signature, &c.PublicKey); err != nil {
			return nil, fmt.Errorf("журнал аудита: контрольная точка: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("журнал аудита: контрольные точки: %w", err)
	}
	if len(out) > maxCheckpoints {
		return nil, fmt.Errorf("журнал аудита: контрольных точек больше %d", maxCheckpoints)
	}
	return out, nil
}

// PGCheckpoints — контрольные точки в audit_checkpoints (Checkpoints для
// WithCheckpoints).
type PGCheckpoints struct {
	db       DB
	provider crypto.Provider
	hasher   crypto.Hasher
	verifier crypto.Verifier
}

// NewPGCheckpoints читает точки из БД. v — открытый ключ-якорь аудита
// (audit-signing.pub): от него по сменам из audit_key_rotations строится
// расписание ключей; nil — проверяется только связность точек, подписи
// проверяет aisec-cli audit verify -keys.
func NewPGCheckpoints(db DB, p crypto.Provider, v crypto.Verifier) (*PGCheckpoints, error) {
	if db == nil || p == nil {
		return nil, errors.New("контрольные точки: нет БД или криптопрофиля")
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	return &PGCheckpoints{db: db, provider: p, hasher: h, verifier: v}, nil
}

// Latest проверяет всю последовательность точек и возвращает последнюю.
func (c *PGCheckpoints) Latest(ctx context.Context) (Anchor, bool, error) {
	return c.LatestIn(ctx, c.db)
}

// LatestIn — Latest в транзакции q (запись в пустой журнал, Н8 ревью 2.r1).
func (c *PGCheckpoints) LatestIn(ctx context.Context, q querier) (Anchor, bool, error) {
	ctx, cancel := withTimeout(ctx, batchTimeout)
	defer cancel()
	cps, err := loadCheckpoints(ctx, q)
	if err != nil {
		return Anchor{}, false, err
	}
	if len(cps) == 0 {
		return Anchor{}, false, nil
	}
	var keys CheckpointKeys
	if c.verifier != nil {
		ks, err := LoadKeySchedule(ctx, q, c.provider, c.verifier)
		if err != nil {
			return Anchor{}, false, err
		}
		keys = ks
	}
	a, err := VerifyCheckpoints(c.hasher, keys, cps)
	if err != nil {
		return Anchor{}, false, err
	}
	return a, true, nil
}

// Any сообщает, есть ли в журнале хотя бы одна контрольная точка: с ними
// сервер без открытого ключа аудита не запускается (замечание В5 ревью 2.r1).
func (c *PGCheckpoints) Any(ctx context.Context) (bool, error) {
	ctx, cancel := withTimeout(ctx, batchTimeout)
	defer cancel()
	var ok bool
	if err := c.db.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM audit_checkpoints)").Scan(&ok); err != nil {
		return false, fmt.Errorf("журнал аудита: контрольные точки: %w", err)
	}
	return ok, nil
}

// Exists сообщает, записана ли точка id: после ошибки фиксации архивации
// по ней решается, удалять ли файл архива. Сначала берётся та же
// блокировка, что у архивации: она держится до конца исходной транзакции,
// поэтому ответ не опередит фиксацию, которая ещё идёт на сервере.
func (c *PGCheckpoints) Exists(ctx context.Context, id string) (ok bool, err error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), archiveTimeout)
	defer cancel()
	tx, err := c.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = tx.Rollback(ctx) //nolint:gosec // G104: транзакция только читает, откат — уборка
	}()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", archiveLockID); err != nil {
		return false, err
	}
	err = tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM audit_checkpoints WHERE id = $1)", id).Scan(&ok)
	return ok, err
}
