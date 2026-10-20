package audit

import (
	"fmt"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Reason — причина нарушения цепочки (DM-43).
type Reason string

const (
	// ReasonHashMismatch — содержимое записи изменено: хеш не сходится.
	ReasonHashMismatch Reason = "hash_mismatch"
	// ReasonPrevMismatch — запись не ссылается на предыдущую: подмена или
	// пересчёт записи перед ней.
	ReasonPrevMismatch Reason = "prev_mismatch"
	// ReasonGap — пропуск номера: удаление из середины.
	ReasonGap Reason = "gap"
	// ReasonHeadMissing — журнал начинается не с записи после контрольной
	// точки: удалено начало.
	ReasonHeadMissing Reason = "head_missing"
	// ReasonTailTruncated — записей меньше, чем при прошлой проверке.
	ReasonTailTruncated Reason = "tail_truncated"
	// ReasonRewritten — запись, проверенная в прошлый раз, теперь с другим
	// хешем: цепочка пересчитана заново.
	ReasonRewritten Reason = "rewritten"
	// ReasonAlgMismatch — запись захеширована не алгоритмом профиля.
	ReasonAlgMismatch Reason = "alg_mismatch"
	// ReasonInvalid — запись не приводится к канонической форме.
	ReasonInvalid Reason = "invalid_record"
)

// Anchor — точка, от которой проверяется цепочка: номер и хеш записи перед
// первой хранимой. Для журнала без архивации — {0, нули}; после архивации
// (задача 2.5) — подписанная контрольная точка.
type Anchor struct {
	Seq  int64
	Hash []byte
}

// Break — первое найденное нарушение цепочки.
type Break struct {
	Seq    int64  // номер записи, на которой обнаружено нарушение
	Reason Reason // что нарушено
}

func (b *Break) Error() string {
	return fmt.Sprintf("цепочка журнала аудита нарушена на записи %d: %s", b.Seq, b.Reason)
}

// chain проверяет записи по одной в порядке номеров.
type chain struct {
	hasher crypto.Hasher
	anchor Anchor
	// known — записи, проверенные раньше (из памяти процесса и из
	// audit_verifications): каждая должна найтись с тем же хешем.
	known   []Anchor
	hit     []bool
	nextSeq int64
	prev    []byte
	checked int64
}

func newChain(h crypto.Hasher, anchor Anchor, known []Anchor) *chain {
	var k []Anchor
	for _, a := range known {
		if a.Seq > anchor.Seq {
			k = append(k, a)
		}
	}
	return &chain{hasher: h, anchor: anchor, known: k, hit: make([]bool, len(k)), nextSeq: anchor.Seq + 1, prev: anchor.Hash}
}

// add проверяет очередную запись; nil — запись встроена в цепочку.
func (c *chain) add(r *Record) *Break {
	if r.Seq != c.nextSeq {
		reason := ReasonGap
		if c.checked == 0 && r.Seq > c.nextSeq {
			reason = ReasonHeadMissing
		}
		return &Break{Seq: r.Seq, Reason: reason}
	}
	if r.unreadable {
		return &Break{Seq: r.Seq, Reason: ReasonInvalid}
	}
	if r.HashAlg != c.hasher.Name() {
		return &Break{Seq: r.Seq, Reason: ReasonAlgMismatch}
	}
	// Хранимый текст подробностей должен совпадать с канонической формой:
	// иначе хеш посчитан не по тому, что лежит в БД.
	if !isCanonical(r.Details) {
		return &Break{Seq: r.Seq, Reason: ReasonInvalid}
	}
	if !crypto.Equal(r.PrevHash, c.prev) {
		return &Break{Seq: r.Seq, Reason: ReasonPrevMismatch}
	}
	h, err := r.ComputeHash(c.hasher)
	if err != nil {
		return &Break{Seq: r.Seq, Reason: ReasonInvalid}
	}
	if !crypto.Equal(h, r.Hash) {
		return &Break{Seq: r.Seq, Reason: ReasonHashMismatch}
	}
	for i, k := range c.known {
		if r.Seq == k.Seq {
			if !crypto.Equal(r.Hash, k.Hash) {
				return &Break{Seq: r.Seq, Reason: ReasonRewritten}
			}
			c.hit[i] = true
		}
	}
	c.prev = r.Hash
	c.nextSeq++
	c.checked++
	return nil
}

// finish проверяет, что журнал не короче, чем при прошлой проверке.
func (c *chain) finish() *Break {
	for i := range c.known {
		if !c.hit[i] {
			return &Break{Seq: c.nextSeq, Reason: ReasonTailTruncated}
		}
	}
	return nil
}

// head — последняя проверенная запись.
func (c *chain) head() Anchor { return Anchor{Seq: c.nextSeq - 1, Hash: c.prev} }

// VerifyRecords проверяет цепочку записей, упорядоченных по номеру, от
// точки anchor. known — записи, проверенные ранее (могут отсутствовать).
// Возвращает число проверенных записей и первое нарушение.
func VerifyRecords(h crypto.Hasher, anchor Anchor, known []Anchor, records []Record) (int64, *Break) {
	c := newChain(h, anchor, known)
	for i := range records {
		if b := c.add(&records[i]); b != nil {
			return c.checked, b
		}
	}
	return c.checked, c.finish()
}
