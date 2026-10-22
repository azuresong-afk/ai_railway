package integrity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

const (
	// pgTimeout — предел на одно обращение к БД без своего срока у контекста.
	pgTimeout = 10 * time.Second
	// auditFailures — сколько путей с нарушением попадает в запись аудита
	// (лимит подробностей записи — 16 КиБ); полный список — в integrity_checks.
	auditFailures = 20
)

// DB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// PGStore сохраняет итоги проверок в integrity_checks и журнал аудита.
type PGStore struct {
	db     DB
	log    *audit.Log
	random aisecCrypto.Random
}

// NewPGStore создаёт хранилище итогов.
func NewPGStore(db DB, l *audit.Log, p aisecCrypto.Provider) (*PGStore, error) {
	if db == nil || l == nil || p == nil {
		return nil, errors.New("итоги контроля целостности: нет БД, журнала аудита или профиля")
	}
	r, err := p.Random()
	if err != nil {
		return nil, err
	}
	return &PGStore{db: db, log: l, random: r}, nil
}

func dbCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

// Baseline — самый поздний манифест успешных проверок установки после
// последнего принятого отката: с ним сравнивается новый итог (В20).
type Baseline struct {
	Version string
	Created time.Time
}

// baselineSQL — максимум по успешным проверкам всех компонентов установки
// (сервер, aisec-cli): у них один манифест, поэтому откат, увиденный
// сервером, принимает aisec-cli verify, даже если сам он этот выпуск с БД
// не проверял, а его обычная проверка видит тот же откат. Принятый откат
// (rollback_accepted) сбрасывает максимум для всех. Шлюзы — в gateways.
const baselineSQL = `SELECT manifest_version, manifest_created FROM integrity_checks
	WHERE org_id = $1 AND ok AND manifest_created IS NOT NULL
	AND ts >= COALESCE((SELECT max(ts) FROM integrity_checks WHERE org_id = $1 AND rollback_accepted), '-infinity')
	ORDER BY manifest_created DESC, ts DESC LIMIT 1`

// baseline читает Baseline установки; ok = false — успешных проверок нет.
func baseline(ctx context.Context, tx pgx.Tx) (Baseline, bool, error) {
	var b Baseline
	err := tx.QueryRow(ctx, baselineSQL, audit.DefaultOrgID).Scan(&b.Version, &b.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return Baseline{}, false, nil
	}
	if err != nil {
		return Baseline{}, false, fmt.Errorf("итоги контроля целостности: прежний манифест: %w", err)
	}
	return b, true, nil
}

// Record пишет итог и запись integrity.check одной транзакцией (РСБ.2), а
// нарушение — ещё и в журнал технического состояния с классом integrity.
// Успешная проверка манифестом, собранным раньше Baseline, записывается
// как ReasonManifestRollback (В20 ревью 2.r4, DM-42); итог с этой
// причиной возвращается вызывающему для реакции.
func (s *PGStore) Record(ctx context.Context, res Result, by audit.Actor, ip netip.Addr) (Result, error) {
	return s.record(ctx, res, by, ip, false)
}

// ErrNoRollback — -accept-rollback без отката: принимать нечего.
var ErrNoRollback = errors.New("откат не обнаружен: манифест не старше последней успешной проверки")

// AcceptRollback — намеренный откат на более старый выпуск (aisec-cli
// verify -accept-rollback): итог записывается успешным с отметкой
// rollback_accepted, после неё максимум считается заново для всех
// компонентов; запись integrity.rollback_accepted — с обеими версиями.
// Проверка с нарушением файлов не принимается; отката нет — ErrNoRollback.
func (s *PGStore) AcceptRollback(ctx context.Context, res Result, by audit.Actor) (Result, error) {
	if !res.OK() {
		return res, fmt.Errorf("откат не принимается: целостность нарушена (%s)", res.Reason)
	}
	return s.record(ctx, res, by, netip.Addr{}, true)
}

func (s *PGStore) record(ctx context.Context, res Result, by audit.Actor, ip netip.Addr, accept bool) (Result, error) {
	ctx, cancel := dbCtx(ctx)
	defer cancel()
	id, err := store.NewUUIDv7(res.At, s.random)
	if err != nil {
		return res, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return res, fmt.Errorf("итоги контроля целостности: %w", err)
	}
	defer func() {
		rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer rcancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после коммита безвреден
	}()
	var prev Baseline
	rollback := false
	if res.OK() && !res.ManifestCreated.IsZero() {
		b, found, err := baseline(ctx, tx)
		if err != nil {
			return res, err
		}
		if found && res.ManifestCreated.Before(b.Created) {
			prev, rollback = b, true
		}
	}
	switch {
	case accept && !rollback:
		return res, ErrNoRollback
	case rollback && !accept:
		res.Reason = ReasonManifestRollback
	}
	failures := res.Failures
	if failures == nil {
		failures = []Failure{}
	}
	fj, err := json.Marshal(failures)
	if err != nil {
		return res, err
	}
	var created *time.Time
	if !res.ManifestCreated.IsZero() {
		created = &res.ManifestCreated
	}
	if _, err := tx.Exec(ctx, `INSERT INTO integrity_checks (id, org_id, ts, component, trigger_kind, ok, reason,
		manifest_version, manifest_created, test_signed, checked, failures, omitted, actor_type, actor_id, rollback_accepted)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::json, $13, $14, $15, $16)`,
		string(id), audit.DefaultOrgID, res.At, res.Component, string(res.Trigger), res.OK(), string(res.Reason),
		res.ManifestVersion, created, res.TestSigned, res.Checked, string(fj), res.Omitted, string(by.Type), by.ID, accept); err != nil {
		return res, fmt.Errorf("итоги контроля целостности: вставка: %w", err)
	}
	details := auditDetails(res, string(id))
	if rollback {
		details["previous_version"], details["previous_created"] = prev.Version, prev.Created.UTC().Format(time.RFC3339)
	}
	if accept {
		if err := s.log.RecordTx(ctx, tx, audit.Entry{
			Actor: by, Action: "integrity.rollback_accepted",
			Object: audit.Object{Type: "component", ID: res.Component}, Result: audit.ResultSuccess, Details: details,
		}); err != nil {
			return res, err
		}
	}
	result := audit.ResultSuccess
	if !res.OK() {
		result = audit.ResultFailure
	}
	if err := s.log.RecordTx(ctx, tx, audit.Entry{
		Actor: by, SourceIP: ip, Action: "integrity.check",
		Object: audit.Object{Type: "component", ID: res.Component}, Result: result, Details: details,
	}); err != nil {
		return res, err
	}
	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("итоги контроля целостности: %w", err)
	}
	if res.OK() {
		return res, nil
	}
	return res, s.log.Tech(ctx, audit.TechEntry{
		Component: res.Component, Kind: audit.TechError, Level: audit.LevelCritical, Class: audit.ClassIntegrity,
		Message: "нарушена целостность компонента: " + string(res.Reason), Details: details,
	})
}

func auditDetails(res Result, checkID string) map[string]any {
	failures := res.Failures
	omitted := res.Omitted
	if len(failures) > auditFailures {
		omitted += len(failures) - auditFailures
		failures = failures[:auditFailures]
	}
	list := make([]any, 0, len(failures))
	for _, f := range failures {
		list = append(list, map[string]any{"path": f.Path, "problem": string(f.Problem)})
	}
	return map[string]any{
		"check_id": checkID, "trigger": string(res.Trigger), "reason": string(res.Reason),
		"manifest_version": res.ManifestVersion, "manifest_created": createdText(res.ManifestCreated), "test_signed": res.TestSigned, "checked": res.Checked,
		"failures": list, "omitted": omitted,
	}
}

// createdText — время манифеста для записи аудита; пусто — не прочитан.
func createdText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Latest — последняя проверка каждого компонента (экран «Состояние системы»).
func (s *PGStore) Latest(ctx context.Context) ([]Result, error) {
	ctx, cancel := dbCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT DISTINCT ON (component) component, trigger_kind, ts, reason,
		manifest_version, manifest_created, test_signed, checked, failures::text, omitted
		FROM integrity_checks WHERE org_id = $1 ORDER BY component, ts DESC, id DESC`, audit.DefaultOrgID)
	if err != nil {
		return nil, fmt.Errorf("итоги контроля целостности: чтение: %w", err)
	}
	defer rows.Close()
	var out []Result
	for rows.Next() {
		var (
			r        Result
			trig     string
			reason   string
			failures string
			created  *time.Time
		)
		if err := rows.Scan(&r.Component, &trig, &r.At, &reason, &r.ManifestVersion, &created, &r.TestSigned,
			&r.Checked, &failures, &r.Omitted); err != nil {
			return nil, fmt.Errorf("итоги контроля целостности: разбор: %w", err)
		}
		r.Trigger, r.Reason, r.At = Trigger(trig), Reason(reason), r.At.UTC()
		if created != nil {
			r.ManifestCreated = created.UTC()
		}
		if err := json.Unmarshal([]byte(failures), &r.Failures); err != nil {
			return nil, fmt.Errorf("итоги контроля целостности: разбор нарушений: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("итоги контроля целостности: чтение: %w", err)
	}
	return out, nil
}

// Service — контроль целостности для API сервера: последние итоги и
// проверка по команде.
type Service struct {
	Monitor *Monitor
	Store   *PGStore
}

// Latest — последние итоги по компонентам.
func (s Service) Latest(ctx context.Context) ([]Result, error) { return s.Store.Latest(ctx) }

// CheckBy — проверка сервера по команде пользователя.
func (s Service) CheckBy(ctx context.Context, by audit.Actor, ip netip.Addr) (Result, error) {
	return s.Monitor.CheckBy(ctx, by, ip)
}
