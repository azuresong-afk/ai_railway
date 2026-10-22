package audit

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

const (
	// verifyBatch — записей за один запрос при проверке.
	verifyBatch = 1000
	// batchTimeout — предел на чтение одной пачки.
	batchTimeout = 30 * time.Second
	// DefaultVerifyInterval — период фоновой проверки цепочки (DM-43).
	DefaultVerifyInterval = time.Hour
	// MinVerifyInterval — наименьший период фоновой проверки.
	MinVerifyInterval = time.Minute
)

// headMACContext — контекст имитовставки головы цепочки.
const headMACContext = "aisec-audit-head-v1"

// HeadMACPurpose — назначение ключа имитовставки головы в keyring.Box.MAC.
const HeadMACPurpose = "audit-head"

// Verification — итог проверки цепочки.
type Verification struct {
	At      time.Time
	Checked int64  // проверено записей
	Head    Anchor // последняя проверенная запись
	Break   *Break // nil — цепочка цела
	// Cached — итог прежней проверки не старше VerifyCacheFor, новая не
	// выполнялась (только TryVerifyBy).
	Cached bool
}

// VerifyCacheFor — сколько итог проверки отвечает на команду из API без
// новой проверки (Н31 ревью 2.r3b): полный проход журнала (до 20 ГиБ) по
// каждой команде держал бы СУБД занятой. Немедленная проверка — aisec-cli
// audit verify.
const VerifyCacheFor = 10 * time.Minute

// OK — цепочка цела.
func (v Verification) OK() bool { return v.Break == nil }

// Verifier проверяет цепочку журнала периодически и по команде (DM-43).
// Последняя проверенная запись хранится в памяти и в audit_verifications:
// по ней видно удаление хвоста и пересчёт цепочки после прошлой проверки.
//
// С имитовставкой головы (WithHeadMAC) опорой из audit_verifications служат
// только строки с верной имитовставкой: переписать журнал, пересчитать
// цепочку и добавить «успешную» проверку новой головы нельзя без ключа вне
// БД (замечание В2 ревью 2.r1).
type Verifier struct {
	log *Log
	mac *HeadMAC
	// prev — имитовставки прежних версий ключа данных, ещё не удалённых
	// ротацией (ADR-0018, п. 3.4): их опоры тоже сверяются.
	prev []HeadMAC
	// src — источник версий ключа данных (keyring.Box): перед каждой
	// проверкой mac и prev берутся заново, поэтому после keys rotate-data
	// опора пишется действующей версией без перезапуска (3В2 ревью 3.r1).
	src MACSource
	// mu сериализует проверки и защищает known и last.
	mu    sync.Mutex
	known *Anchor
	// last — итог последней выполненной проверки этого процесса; failedAt —
	// когда проверка последний раз не завершилась (сбой, истёк срок).
	last     *Verification
	failedAt time.Time
}

// HeadMAC — имитовставка головы цепочки на ключе вне БД: KeyID — ID ключа
// данных, из которого выведен ключ (keyring.Box.MAC, назначение audit-head).
type HeadMAC struct {
	KeyID string
	MAC   crypto.MAC
}

// VerifierOption — настройка проверки цепочки.
type VerifierOption func(*Verifier)

// WithHeadMAC включает имитовставку головы цепочки в audit_verifications.
func WithHeadMAC(m HeadMAC) VerifierOption {
	return func(v *Verifier) {
		if m.MAC != nil && m.KeyID != "" {
			v.mac = &m
		}
	}
}

// WithPreviousHeadMACs — имитовставки прежних версий ключа данных: опоры,
// записанные до ротации, остаются опорами, пока версия не удалена.
func WithPreviousHeadMACs(ms ...HeadMAC) VerifierOption {
	return func(v *Verifier) {
		for _, m := range ms {
			if m.MAC != nil && m.KeyID != "" {
				v.prev = append(v.prev, m)
			}
		}
	}
}

// MACSource — версии ключа данных с выведением имитовставки
// (keyring.Box): KeyID — действующая версия, KeyIDs — все известные.
type MACSource interface {
	KeyID() string
	KeyIDs() []string
	MACFor(keyID, purpose string) (crypto.MAC, error)
}

// headMACs — имитовставка действующей версии и прежних версий src.
func headMACs(src MACSource) (*HeadMAC, []HeadMAC, error) {
	active := src.KeyID()
	var cur *HeadMAC
	var prev []HeadMAC
	for _, id := range src.KeyIDs() {
		m, err := src.MACFor(id, HeadMACPurpose)
		if err != nil {
			return nil, nil, fmt.Errorf("ключ имитовставки цепочки аудита: %w", err)
		}
		if id == active {
			cur = &HeadMAC{KeyID: id, MAC: m}
			continue
		}
		prev = append(prev, HeadMAC{KeyID: id, MAC: m})
	}
	if cur == nil {
		return nil, nil, fmt.Errorf("ключ имитовставки цепочки аудита: нет действующей версии %s", active)
	}
	return cur, prev, nil
}

// HeadMACOptions — имитовставка головы на действующей версии ключа данных и
// опоры прежних версий (ADR-0018, п. 3.4). Версии берутся из src перед
// каждой проверкой: смена действующей версии (keys rotate-data) видна
// без перезапуска (3В2 ревью 3.r1). Ошибка — ключ не выводится уже сейчас.
func HeadMACOptions(src MACSource) ([]VerifierOption, error) {
	cur, prev, err := headMACs(src)
	if err != nil {
		return nil, err
	}
	return []VerifierOption{WithHeadMAC(*cur), WithPreviousHeadMACs(prev...), func(v *Verifier) { v.src = src }}, nil
}

// refreshMACs перечитывает версии ключа данных из src (под v.mu).
func (v *Verifier) refreshMACs() error {
	if v.src == nil {
		return nil
	}
	cur, prev, err := headMACs(v.src)
	if err != nil {
		return err
	}
	v.mac, v.prev = cur, prev
	return nil
}

// NewVerifier создаёт проверку для журнала l.
func NewVerifier(l *Log, opts ...VerifierOption) *Verifier {
	v := &Verifier{log: l}
	for _, o := range opts {
		o(v)
	}
	return v
}

// headMessage — то, на что ставится имитовставка: контекст, номер и хеш головы.
func headMessage(a Anchor) []byte {
	msg := make([]byte, 0, len(headMACContext)+1+8+len(a.Hash))
	msg = append(msg, headMACContext...)
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint64(msg, uint64(a.Seq)) //nolint:gosec // G115: номер записи неотрицателен (CHECK last_seq >= 0)
	return append(msg, a.Hash...)
}

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
	return v.verifyLogged(ctx, by, netip.Addr{})
}

// ErrVerifyBusy — проверка цепочки уже выполняется (фоновая или по другой
// команде); новая не запускается.
var ErrVerifyBusy = errors.New("журнал аудита: проверка цепочки уже выполняется")

// ErrVerifyFailedRecently — проверка не завершилась менее VerifyCacheFor
// назад; новая по команде из API не запускается (самопроверка H4, С1: иначе
// проход, который не укладывается в срок, повторялся бы непрерывно).
var ErrVerifyFailedRecently = errors.New("журнал аудита: проверка цепочки недавно не завершилась")

// TryVerifyBy — VerifyBy по команде из API (задача 2.4a): с адресом
// субъекта (РСБ.1 «откуда») и без ожидания. Если проверка уже идёт —
// ErrVerifyBusy: ждать на блокировке нельзя, она не учитывает срок запроса.
// Если последняя проверка моложе VerifyCacheFor — её итог с Cached, без
// новой проверки и без записи в журнал.
func (v *Verifier) TryVerifyBy(ctx context.Context, by Actor, ip netip.Addr) (Verification, error) {
	if !v.mu.TryLock() {
		return Verification{}, ErrVerifyBusy
	}
	defer v.mu.Unlock()
	now := v.log.now()
	if l := v.last; l != nil && now.Sub(l.At) < VerifyCacheFor && !l.At.Before(v.failedAt) {
		res := *l
		res.Cached = true
		return res, nil
	}
	if !v.failedAt.IsZero() && now.Sub(v.failedAt) < VerifyCacheFor {
		return Verification{}, ErrVerifyFailedRecently
	}
	return v.verifyLogged(ctx, by, ip)
}

// verifyLogged — проверка под v.mu; сбой пишется в журнал технического состояния.
func (v *Verifier) verifyLogged(ctx context.Context, by Actor, ip netip.Addr) (Verification, error) {
	res, err := v.verify(ctx, by, ip)
	if err == nil {
		last := res
		v.last = &last
	} else {
		v.failedAt = v.log.now()
	}
	if err != nil {
		// Лучшее, что можно сделать: БД может быть недоступна и для этой записи.
		// Свой срок: сбой по истёкшему сроку проверки тоже должен оставить след.
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
		defer cancel()
		_ = v.log.Tech(tctx, TechEntry{ //nolint:gosec // G104: исходная ошибка важнее, её получает вызывающий
			Component: "audit", Kind: TechError, Level: LevelError, Class: ClassDB,
			Message: "проверка цепочки журнала аудита не выполнена",
		})
	}
	return res, err
}

func (v *Verifier) verify(ctx context.Context, by Actor, ip netip.Addr) (Verification, error) {
	if err := v.refreshMACs(); err != nil {
		return Verification{}, err
	}
	known, forged, err := v.lastKnown(ctx)
	if err != nil {
		return Verification{}, err
	}
	if forged != nil {
		res := Verification{At: v.log.now().UTC().Truncate(time.Microsecond), Break: forged}
		return res, v.save(ctx, res, by, ip)
	}
	anchor, err := v.log.anchor(ctx)
	if errors.Is(err, ErrCheckpointInvalid) {
		// Начало хранимой цепочки не подтверждается: это нарушение (DM-43),
		// а не сбой проверки.
		res := Verification{At: v.log.now().UTC().Truncate(time.Microsecond), Break: &Break{Seq: 0, Reason: ReasonCheckpoint}}
		return res, v.save(ctx, res, by, ip)
	}
	if err != nil {
		return Verification{}, err
	}
	c, brk, err := v.walk(ctx, anchor, known)
	if err != nil {
		return Verification{}, err
	}
	if brk != nil {
		// Архивация могла зафиксироваться между чтением точки и записей:
		// тогда начало журнала ушло в архив законно. Если точка сменилась,
		// цепочка проверяется заново от новой точки (один раз).
		next, err := v.log.anchor(ctx)
		if err != nil && !errors.Is(err, ErrCheckpointInvalid) {
			return Verification{}, err
		}
		if err == nil && next.Seq != anchor.Seq {
			anchor = next
			if c, brk, err = v.walk(ctx, anchor, known); err != nil {
				return Verification{}, err
			}
		}
	}
	if brk == nil && anchor.Seq > 0 && c.checked == 0 {
		// Последняя запись журнала не архивируется никогда: после точки
		// всегда есть записи. Их нет — удалён хвост (ADR-0008).
		brk = &Break{Seq: anchor.Seq + 1, Reason: ReasonTailTruncated}
	}
	res := Verification{At: v.log.now().UTC().Truncate(time.Microsecond), Checked: c.checked, Head: c.head(), Break: brk}
	if err := v.save(ctx, res, by, ip); err != nil {
		return res, err
	}
	if res.OK() && res.Head.Seq > anchor.Seq {
		h := res.Head
		v.known = &h
	}
	return res, nil
}

// walk проверяет записи после anchor.
func (v *Verifier) walk(ctx context.Context, anchor Anchor, known []Anchor) (*chain, *Break, error) {
	c := newChain(v.log.hasher, anchor, known)
	var brk *Break
	cursor := anchor.Seq
	for brk == nil {
		batch, err := v.readBatch(ctx, cursor)
		if err != nil {
			return nil, nil, err
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
	return c, brk, nil
}

// lastKnown — записи, проверенные успешно раньше: из памяти процесса и
// последняя из audit_verifications. Сверяются обе: строку в
// audit_verifications может добавить и нарушитель с ролью приложения.
// С имитовставкой головы из БД берётся последняя строка с имитовставкой
// действующего ключа данных; неверная имитовставка — нарушение
// ReasonAnchorForged.
func (v *Verifier) lastKnown(ctx context.Context) ([]Anchor, *Break, error) {
	ctx, cancel := withTimeout(ctx, batchTimeout)
	defer cancel()
	var out []Anchor
	if v.known != nil {
		out = append(out, *v.known)
	}
	if v.mac != nil {
		for _, m := range append([]HeadMAC{*v.mac}, v.prev...) {
			a, brk, err := v.macAnchor(ctx, m)
			if err != nil || brk != nil {
				return nil, brk, err
			}
			if a != nil {
				out = append(out, *a)
			}
		}
		return out, nil, nil
	}
	var a Anchor
	err := v.log.db.QueryRow(ctx, `SELECT last_seq, last_hash FROM audit_verifications
		WHERE ok AND last_hash IS NOT NULL ORDER BY last_seq DESC LIMIT 1`).Scan(&a.Seq, &a.Hash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return nil, nil, fmt.Errorf("журнал аудита: прошлые проверки: %w", err)
	default:
		out = append(out, a)
	}
	return out, nil, nil
}

// macAnchor — последняя проверка с имитовставкой ключа m. Строки без
// имитовставки (aisec-cli без каталога ключей, проверки до миграции 0015) и
// строки удалённых версий ключа данных опорой не служат.
func (v *Verifier) macAnchor(ctx context.Context, m HeadMAC) (*Anchor, *Break, error) {
	var a Anchor
	var tag []byte
	err := v.log.db.QueryRow(ctx, `SELECT last_seq, last_hash, head_mac FROM audit_verifications
		WHERE ok AND last_hash IS NOT NULL AND head_mac IS NOT NULL AND mac_key_id = $1::uuid
		ORDER BY last_seq DESC LIMIT 1`, m.KeyID).Scan(&a.Seq, &a.Hash, &tag)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil, nil
	case err != nil:
		return nil, nil, fmt.Errorf("журнал аудита: прошлые проверки: %w", err)
	case !m.MAC.Verify(headMessage(a), tag):
		return nil, &Break{Seq: a.Seq, Reason: ReasonAnchorForged}, nil
	}
	return &a, nil, nil
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

// save пишет итог проверки в audit_verifications и в журналы; ip — адрес
// субъекта by (нулевой — проверка без адреса: фоновая, aisec-cli).
func (v *Verifier) save(ctx context.Context, res Verification, by Actor, ip netip.Addr) error {
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
	var lastHash, headMAC []byte
	var macKeyID *string
	if res.OK() && res.Head.Seq > 0 {
		lastHash = res.Head.Hash
		if v.mac != nil {
			headMAC, macKeyID = v.mac.MAC.Sum(headMessage(res.Head)), &v.mac.KeyID
		}
	}
	return v.log.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_verifications
			(id, ts, ok, checked, last_seq, last_hash, reason, broken_seq, head_mac, mac_key_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::uuid)`,
			string(id), res.At, res.OK(), res.Checked, res.Head.Seq, lastHash, reason, brokenSeq, headMAC, macKeyID); err != nil {
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
			Actor: by, SourceIP: ip,
			Action: action, Object: Object{Type: "audit_log"}, Result: result, Details: details,
		})
		return err
	})
}

// Run проверяет цепочку сразу и затем каждые interval, пока не отменён ctx.
// report получает каждый итог или ошибку (может быть nil).
func (v *Verifier) Run(ctx context.Context, interval time.Duration, report func(Verification, error)) error {
	if interval < MinVerifyInterval {
		return fmt.Errorf("период проверки цепочки не меньше %s", MinVerifyInterval)
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
