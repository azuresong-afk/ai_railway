package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Ротация ключа подписи контрольных точек (ADR-0018, п. 5): смена ключа —
// строка audit_key_rotations с двумя подписями. Расписание ключей строится
// от файла-якоря audit-signing.pub по цепочке смен: точки с номером не
// больше checkpoint_seq смены проверяются прежним ключом, следующие —
// новым.

// keyRotationContext — домен подписи смены ключа: подпись смены не подходит
// ни к контрольной точке, ни к чему другому.
const keyRotationContext = "aisec-audit-key-rotation-v1\n"

// maxKeyRotations — предел числа смен при чтении.
const maxKeyRotations = 1000

// KeyRotation — смена ключа подписи контрольных точек.
type KeyRotation struct {
	OrgID     string
	Seq       int
	PrevKeyID string
	KeyID     string
	PublicKey []byte
	// CheckpointSeq — номер записи последней контрольной точки на момент
	// смены (0 — точек не было).
	CheckpointSeq int64
	RotatedAt     time.Time
	SigAlg        string
	// PrevSignature — подпись прежним ключом (передача доверия), Signature —
	// новым (владение ключом); подписываются одни и те же байты.
	PrevSignature []byte
	Signature     []byte
}

type keyRotationPayload struct {
	V             int    `json:"v"`
	OrgID         string `json:"org_id"`
	Seq           int    `json:"seq"`
	PrevKeyID     string `json:"prev_key_id"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
	CheckpointSeq int64  `json:"checkpoint_seq"`
	RotatedAt     string `json:"rotated_at"`
}

// SignedBytes — подписываемые байты смены.
func (r *KeyRotation) SignedBytes() ([]byte, error) {
	b, err := json.Marshal(keyRotationPayload{V: formatVersion, OrgID: r.OrgID, Seq: r.Seq, PrevKeyID: r.PrevKeyID,
		KeyID: r.KeyID, PublicKey: hex.EncodeToString(r.PublicKey), CheckpointSeq: r.CheckpointSeq,
		RotatedAt: r.RotatedAt.UTC().Format(tsLayout)})
	if err != nil {
		return nil, err
	}
	return append([]byte(keyRotationContext), b...), nil
}

// Файл смены ключа (3В3 ревью 3.r1): keys rotate-audit кладёт его рядом с
// открытым ключом, audit verify-archive строит по таким файлам расписание
// без БД. В файле — поля SignedBytes и обе подписи; доверие к нему — только
// по подписям от якоря (NewKeySchedule), не по месту в каталоге.
const (
	keyRotationFormat = "aisec-audit-key-rotation"
	// MaxKeyRotationFile — предел файла смены.
	MaxKeyRotationFile = 16 << 10
)

type keyRotationFile struct {
	Format string `json:"format"`
	keyRotationPayload
	SigAlg        string `json:"sig_alg"`
	PrevSignature string `json:"prev_signature"`
	Signature     string `json:"signature"`
}

// MarshalKeyRotation — файл смены ключа аудита.
func MarshalKeyRotation(r *KeyRotation) ([]byte, error) {
	b, err := json.Marshal(keyRotationFile{Format: keyRotationFormat, keyRotationPayload: keyRotationPayload{
		V: formatVersion, OrgID: r.OrgID, Seq: r.Seq, PrevKeyID: r.PrevKeyID, KeyID: r.KeyID,
		PublicKey: hex.EncodeToString(r.PublicKey), CheckpointSeq: r.CheckpointSeq, RotatedAt: r.RotatedAt.UTC().Format(tsLayout),
	}, SigAlg: r.SigAlg, PrevSignature: hex.EncodeToString(r.PrevSignature), Signature: hex.EncodeToString(r.Signature)})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseKeyRotation разбирает файл смены. Вход недоверенный (каталог ключей
// на носителе с архивами), разбор покрыт FuzzParseKeyRotation; подписи
// проверяет NewKeySchedule.
func ParseKeyRotation(data []byte) (KeyRotation, error) {
	bad := func(what string) (KeyRotation, error) {
		return KeyRotation{}, fmt.Errorf("%w: файл смены: %s", ErrKeyRotationInvalid, what)
	}
	if len(data) > MaxKeyRotationFile {
		return bad("слишком большой")
	}
	var f keyRotationFile
	if err := strictUnmarshal(bytes.TrimSuffix(data, []byte{'\n'}), &f); err != nil {
		return bad(err.Error())
	}
	if f.Format != keyRotationFormat || f.V != formatVersion {
		return bad("неизвестный формат или версия")
	}
	if f.Seq < 1 || f.Seq > maxKeyRotations || f.CheckpointSeq < 0 {
		return bad("номер смены или точки")
	}
	r := KeyRotation{OrgID: f.OrgID, Seq: f.Seq, PrevKeyID: f.PrevKeyID, KeyID: f.KeyID,
		CheckpointSeq: f.CheckpointSeq, SigAlg: f.SigAlg}
	var err error
	if r.PublicKey, err = hex.DecodeString(f.PublicKey); err != nil {
		return bad("public_key")
	}
	if r.PrevSignature, err = hex.DecodeString(f.PrevSignature); err != nil {
		return bad("prev_signature")
	}
	if r.Signature, err = hex.DecodeString(f.Signature); err != nil {
		return bad("signature")
	}
	if r.RotatedAt, err = time.Parse(tsLayout, f.RotatedAt); err != nil {
		return bad("rotated_at")
	}
	// Подписанная форма должна воспроизводиться из разобранной смены.
	if r.RotatedAt.UTC().Format(tsLayout) != f.RotatedAt || hex.EncodeToString(r.PublicKey) != f.PublicKey {
		return bad("неканоническая форма")
	}
	return r, nil
}

// KeyID — идентификатор ключа аудита: первые 8 байт хеша открытого ключа.
func KeyID(h crypto.Hasher, publicKey []byte) string { return hex.EncodeToString(h.Sum(publicKey)[:8]) }

// SignKeyRotation заполняет ключи и подписи смены: prev — действующий ключ
// по расписанию, next — новый.
func SignKeyRotation(h crypto.Hasher, prev, next crypto.Signer, r *KeyRotation) error {
	r.PrevKeyID, r.KeyID, r.PublicKey, r.SigAlg = KeyID(h, prev.PublicKey()), KeyID(h, next.PublicKey()), next.PublicKey(), next.Name()
	r.RotatedAt = r.RotatedAt.UTC().Truncate(time.Microsecond)
	msg, err := r.SignedBytes()
	if err != nil {
		return err
	}
	if r.PrevSignature, err = prev.Sign(msg); err != nil {
		return err
	}
	r.Signature, err = next.Sign(msg)
	return err
}

// CheckpointKeys — ключ проверки контрольной точки по её номеру.
type CheckpointKeys interface {
	CheckpointKey(seq int64) crypto.Verifier
}

type singleKey struct{ v crypto.Verifier }

func (k singleKey) CheckpointKey(int64) crypto.Verifier { return k.v }

// SingleKey — один ключ для всех точек; v = nil — подписи не проверяются.
func SingleKey(v crypto.Verifier) CheckpointKeys {
	if v == nil {
		return nil
	}
	return singleKey{v}
}

// KeySchedule — проверенное расписание ключей аудита.
type KeySchedule struct {
	keys []crypto.Verifier
	ids  []string
	// until[i] — последняя точка, подписанная keys[i]; у последнего ключа нет.
	until []int64
}

// ErrKeyRotationInvalid — смена ключа аудита подменена или не продолжает
// расписание.
var ErrKeyRotationInvalid = errors.New("смена ключа аудита недействительна")

// NewKeySchedule проверяет смены по порядку от якоря anchor: номера подряд с
// 1, прежний ключ — действующий по расписанию, обе подписи верны,
// checkpoint_seq не убывает.
func NewKeySchedule(p crypto.Provider, anchor crypto.Verifier, rots []KeyRotation) (*KeySchedule, error) {
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	s := &KeySchedule{keys: []crypto.Verifier{anchor}, ids: []string{KeyID(h, anchor.PublicKey())}}
	var last int64
	for i := range rots {
		r := &rots[i]
		cur := s.keys[len(s.keys)-1]
		msg, err := r.SignedBytes()
		if err != nil {
			return nil, err
		}
		switch {
		case r.Seq != i+1:
			return nil, fmt.Errorf("%w: смена %d не по порядку", ErrKeyRotationInvalid, r.Seq)
		case r.PrevKeyID != s.ids[len(s.ids)-1]:
			return nil, fmt.Errorf("%w: смена %d: прежний ключ не действующий", ErrKeyRotationInvalid, r.Seq)
		case r.CheckpointSeq < last:
			return nil, fmt.Errorf("%w: смена %d: номер точки убывает", ErrKeyRotationInvalid, r.Seq)
		case r.SigAlg != cur.Name() || !cur.Verify(msg, r.PrevSignature):
			return nil, fmt.Errorf("%w: смена %d: подпись прежним ключом не проверяется", ErrKeyRotationInvalid, r.Seq)
		case KeyID(h, r.PublicKey) != r.KeyID:
			return nil, fmt.Errorf("%w: смена %d: ID ключа не совпадает", ErrKeyRotationInvalid, r.Seq)
		}
		next, err := p.NewVerifier(r.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: смена %d: %v", ErrKeyRotationInvalid, r.Seq, err) //nolint:errorlint // причина — только текстом
		}
		if !next.Verify(msg, r.Signature) {
			return nil, fmt.Errorf("%w: смена %d: подпись новым ключом не проверяется", ErrKeyRotationInvalid, r.Seq)
		}
		s.until = append(s.until, r.CheckpointSeq)
		s.keys = append(s.keys, next)
		s.ids = append(s.ids, r.KeyID)
		last = r.CheckpointSeq
	}
	return s, nil
}

// CheckpointKey — ключ точки seq по расписанию.
func (s *KeySchedule) CheckpointKey(seq int64) crypto.Verifier {
	for i, until := range s.until {
		if seq <= until {
			return s.keys[i]
		}
	}
	return s.keys[len(s.keys)-1]
}

// Latest — действующий ключ: им подписываются новые точки.
func (s *KeySchedule) Latest() crypto.Verifier { return s.keys[len(s.keys)-1] }

// LatestID — ID действующего ключа.
func (s *KeySchedule) LatestID() string { return s.ids[len(s.ids)-1] }

// Rotations — число смен.
func (s *KeySchedule) Rotations() int { return len(s.until) }

// LoadKeyRotations читает смены ключа аудита по порядку.
func LoadKeyRotations(ctx context.Context, q querier) ([]KeyRotation, error) {
	rows, err := q.Query(ctx, `SELECT org_id::text, seq, prev_key_id, key_id, public_key, checkpoint_seq, rotated_at,
		sig_alg, prev_signature, signature FROM audit_key_rotations ORDER BY seq LIMIT $1`, maxKeyRotations+1)
	if err != nil {
		return nil, fmt.Errorf("журнал аудита: смены ключа: %w", err)
	}
	defer rows.Close()
	var out []KeyRotation
	for rows.Next() {
		var r KeyRotation
		if err := rows.Scan(&r.OrgID, &r.Seq, &r.PrevKeyID, &r.KeyID, &r.PublicKey, &r.CheckpointSeq, &r.RotatedAt,
			&r.SigAlg, &r.PrevSignature, &r.Signature); err != nil {
			return nil, fmt.Errorf("журнал аудита: смена ключа: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("журнал аудита: смены ключа: %w", err)
	}
	if len(out) > maxKeyRotations {
		return nil, fmt.Errorf("журнал аудита: смен ключа больше %d", maxKeyRotations)
	}
	return out, nil
}

// LoadKeySchedule читает смены и строит расписание от якоря.
func LoadKeySchedule(ctx context.Context, q querier, p crypto.Provider, anchor crypto.Verifier) (*KeySchedule, error) {
	rots, err := LoadKeyRotations(ctx, q)
	if err != nil {
		return nil, err
	}
	return NewKeySchedule(p, anchor, rots)
}

// InsertKeyRotation записывает смену в транзакции tx (aisec-cli keys
// rotate-audit под логином владельца схемы).
func InsertKeyRotation(ctx context.Context, tx pgx.Tx, r *KeyRotation) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_key_rotations (org_id, seq, prev_key_id, key_id, public_key, checkpoint_seq,
		rotated_at, sig_alg, prev_signature, signature) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		r.OrgID, r.Seq, r.PrevKeyID, r.KeyID, r.PublicKey, r.CheckpointSeq, r.RotatedAt, r.SigAlg, r.PrevSignature, r.Signature)
	if err != nil {
		return fmt.Errorf("журнал аудита: запись смены ключа: %w", err)
	}
	return nil
}

// LatestCheckpointSeq — номер записи последней контрольной точки (0 — нет).
func LatestCheckpointSeq(ctx context.Context, q pgx.Tx) (int64, error) {
	var seq int64
	if err := q.QueryRow(ctx, "SELECT COALESCE(max(seq), 0) FROM audit_checkpoints").Scan(&seq); err != nil {
		return 0, fmt.Errorf("журнал аудита: контрольные точки: %w", err)
	}
	return seq, nil
}

// ArchiveLockID — блокировка архивации: смена ключа берёт её, чтобы новая
// точка не легла между чтением номера последней точки и записью смены.
const ArchiveLockID = archiveLockID
