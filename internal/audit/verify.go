package audit

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/store"
)

const (
	// verifyBatch — записей за один запрос при проверке.
	verifyBatch = 1000
	// batchTimeout — предел на чтение одной пачки.
	batchTimeout = 30 * time.Second
	// DefaultVerifyInterval — период фоновой проверки цепочки (DM-43).
	DefaultVerifyInterval = time.Hour
	minVerifyInterval     = time.Minute
)

// Verification — итог проверки цепочки.
type Verification struct {
	At      time.Time
	Checked int64  // проверено записей
	Head    Anchor // последняя проверенная запись
	Break   *Break // nil — цепочка цела
}

// OK — цепочка цела.
func (v Verification) OK() bool { return v.Break == nil }

// Verifier проверяет цепочку журнала периодически и по команде (DM-43).
// Последняя проверенная запись хранится в памяти и в audit_verifications:
// по ней видно удаление хвоста и пересчёт цепочки после прошлой проверки.
type Verifier struct {
	log *Log
	// mu сериализует проверки и защищает known.
	mu    sync.Mutex
	known *Anchor
}

// NewVerifier создаёт проверку для журнала l.
func NewVerifier(l *Log) *Verifier { return &Verifier{log: l} }

// Verify проверяет всю хранимую цепочку, пишет итог в audit_verifications,
// в журнал аудита (audit.chain_verified или audit.chain_broken) и, при
// нарушении, в журнал технического состояния. Ошибка — проверку выполнить
// не удалось (например, БД недоступна); нарушение цепочки — не ошибка, а
// Verification.Break.
func (v *Verifier) Verify(ctx context.Context) (Verification, error) {
	return v.VerifyBy(ctx, Actor{Type: ActorSystem, ID: "audit-verifier", Name: "Проверка цепочки аудита"})
}

// VerifyBy — Verify по команде субъекта by (например, aisec-cli от имени
// пользователя ОС): он попадает в запись audit.chain_* как «кто» (РСБ.1).
// Сбой самой проверки пишется в журнал технического состояния.
func (v *Verifier) VerifyBy(ctx context.Context, by Actor) (Verification, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	res, err := v.verify(ctx, by)
	if err != nil {
		// Лучшее, что можно сделать: БД может быть недоступна и для этой записи.
		_ = v.log.Tech(ctx, TechEntry{ //nolint:gosec // G104: исходная ошибка важнее, её получает вызывающий
			Component: "audit", Kind: TechError, Level: LevelError, Class: ClassDB,
			Message: "проверка цепочки журнала аудита не выполнена",
		})
	}
	return res, err
}

func (v *Verifier) verify(ctx context.Context, by Actor) (Verification, error) {
	known, err := v.lastKnown(ctx)
	if err != nil {
		return Verification{}, err
	}
	anchor, err := v.log.anchor(ctx)
	if err != nil {
		return Verification{}, err
	}
	c := newChain(v.log.hasher, anchor, known)
	var brk *Break
	cursor := anchor.Seq
	for brk == nil {
		batch, err := v.readBatch(ctx, cursor)
		if err != nil {
			return Verification{}, err
		}
		for i := range batch {
			if brk = c.add(&batch[i]); brk != nil {
				break
			}
		}
		if brk != nil || len(batch) < verifyBatch {
			break
		}
		cursor = batch[len(batch)-1].Seq
	}
	if brk == nil {
		brk = c.finish()
	}
	res := Verification{At: v.log.now().UTC().Truncate(time.Microsecond), Checked: c.checked, Head: c.head(), Break: brk}
	if err := v.save(ctx, res, by); err != nil {
		return res, err
	}
	if res.OK() && res.Head.Seq > anchor.Seq {
		h := res.Head
		v.known = &h
	}
	return res, nil
}

// lastKnown — записи, проверенные успешно раньше: из памяти процесса и
// последняя из audit_verifications. Сверяются обе: строку в
// audit_verifications может добавить и нарушитель с ролью приложения.
func (v *Verifier) lastKnown(ctx context.Context) ([]Anchor, error) {
	ctx, cancel := withTimeout(ctx, batchTimeout)
	defer cancel()
	var out []Anchor
	if v.known != nil {
		out = append(out, *v.known)
	}
	var a Anchor
	err := v.log.db.QueryRow(ctx, `SELECT last_seq, last_hash FROM audit_verifications
		WHERE ok AND last_hash IS NOT NULL ORDER BY last_seq DESC LIMIT 1`).Scan(&a.Seq, &a.Hash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return nil, fmt.Errorf("журнал аудита: прошлые проверки: %w", err)
	default:
		out = append(out, a)
	}
	return out, nil
}

func (v *Verifier) readBatch(ctx context.Context, after int64) ([]Record, error) {
	ctx, cancel := withTimeout(ctx, batchTimeout)
	defer cancel()
	// ts — NULL, если в обход CHECK записано не конечное время: такая запись
	// — нарушение, а не сбой чтения.
	rows, err := v.log.db.Query(ctx, `SELECT seq, id::text, org_id::text,
		CASE WHEN isfinite(ts) THEN ts END, actor_type, actor_id, actor_name,
		host(source_ip), action, object_type, object_id, result, details::text, hash_alg, prev_hash, hash
		FROM audit_log WHERE seq > $1 ORDER BY seq LIMIT $2`, after, verifyBatch)
	if err != nil {
		return nil, fmt.Errorf("журнал аудита: чтение записей: %w", err)
	}
	defer rows.Close()
	out := make([]Record, 0, verifyBatch)
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("журнал аудита: чтение записей: %w", err)
	}
	return out, nil
}

func scanRecord(row pgx.Row) (Record, error) {
	var (
		r                 Record
		ts                *time.Time
		actorType, result string
		ip                *string
		details           string
	)
	if err := row.Scan(&r.Seq, &r.ID, &r.OrgID, &ts, &actorType, &r.Actor.ID, &r.Actor.Name,
		&ip, &r.Action, &r.Object.Type, &r.Object.ID, &result, &details, &r.HashAlg, &r.PrevHash, &r.Hash); err != nil {
		return Record{}, fmt.Errorf("журнал аудита: разбор записи: %w", err)
	}
	if ts == nil {
		r.unreadable = true
	} else {
		r.TS = ts.UTC()
	}
	r.Actor.Type = ActorType(actorType)
	r.Result = Result(result)
	r.Details = []byte(details)
	if ip != nil {
		a, err := netip.ParseAddr(*ip)
		if err != nil {
			r.unreadable = true
		}
		r.SourceIP = a
	}
	return r, nil
}

// save пишет итог проверки в audit_verifications и в журналы.
func (v *Verifier) save(ctx context.Context, res Verification, by Actor) error {
	ctx, cancel := withTimeout(ctx, writeTimeout)
	defer cancel()
	id, err := store.NewUUIDv7(res.At, v.log.random)
	if err != nil {
		return fmt.Errorf("журнал аудита: %w", err)
	}
	reason := "ok"
	var brokenSeq *int64
	action, result := "audit.chain_verified", ResultSuccess
	details := map[string]any{"checked": res.Checked, "last_seq": res.Head.Seq}
	if res.Break != nil {
		reason = string(res.Break.Reason)
		s := res.Break.Seq
		brokenSeq = &s
		action, result = "audit.chain_broken", ResultFailure
		details["broken_seq"] = s
		details["reason"] = reason
	}
	var lastHash []byte
	if res.OK() && res.Head.Seq > 0 {
		lastHash = res.Head.Hash
	}
	return v.log.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_verifications
			(id, ts, ok, checked, last_seq, last_hash, reason, broken_seq)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			string(id), res.At, res.OK(), res.Checked, res.Head.Seq, lastHash, reason, brokenSeq); err != nil {
			return fmt.Errorf("журнал аудита: запись итога проверки: %w", err)
		}
		if res.Break != nil {
			if err := v.log.techTx(ctx, tx, TechEntry{
				Component: "audit", Kind: TechError, Level: LevelCritical, Class: ClassIntegrity,
				Message: res.Break.Error(), Details: details,
			}); err != nil {
				return err
			}
		}
		_, err := v.log.recordTx(ctx, tx, Entry{
			Actor:  by,
			Action: action, Object: Object{Type: "audit_log"}, Result: result, Details: details,
		})
		return err
	})
}

// Run проверяет цепочку сразу и затем каждые interval, пока не отменён ctx.
// report получает каждый итог или ошибку (может быть nil).
func (v *Verifier) Run(ctx context.Context, interval time.Duration, report func(Verification, error)) error {
	if interval < minVerifyInterval {
		return fmt.Errorf("период проверки цепочки не меньше %s", minVerifyInterval)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		res, err := v.Verify(ctx)
		if report != nil {
			report(res, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
