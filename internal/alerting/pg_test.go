package alerting_test

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/keyring/keyringtest"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются.
// Каждый тест — в своей схеме; сервер работает под ролью aisec_app.

const testGateway = "01900000-0000-7000-8000-0000000000a1"

type pgEnv struct {
	owner, app *pgxpool.Pool
	events     *events.PGStore
	alerts     *alerting.PGStore
	svc        *alerting.Service
	ids        *ids.Generator
	by         alerting.By
	log        *audit.Log
}

func pgCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func newPool(t *testing.T, dsn, schema, role string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 8
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	if role != "" {
		cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			_, err := c.Exec(ctx, "SELECT set_config('role', $1, false)", role)
			return err
		}
	}
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

type poolExec struct{ p *pgxpool.Pool }

func (e poolExec) InTx(ctx context.Context, fn func(store.Tx) error) error {
	tx, err := e.p.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() //nolint:gosec // G104: откат после фиксации безвреден
	if err := fn(poolTx{tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type poolTx struct{ tx pgx.Tx }

func (t poolTx) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := t.tx.Exec(ctx, sql, args...)
	return err
}

func (t poolTx) Applied(ctx context.Context) ([]store.Applied, error) {
	rows, err := t.tx.Query(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (store.Applied, error) {
		var a store.Applied
		err := r.Scan(&a.Version, &a.Name, &a.Checksum)
		return a, err
	})
}

func setupPG(t *testing.T) *pgEnv {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := pgCtx(t)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := aisecCrypto.RandomBytes(r, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "al_test_" + hex.EncodeToString(b)
	admin := newPool(t, dsn, "public", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE") //nolint:gosec // G104: уборка тестовой схемы
	})
	owner := newPool(t, dsn, schema, "")
	ms, err := store.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&store.Migrator{Exec: poolExec{owner}, Hasher: h, Migrations: ms}).Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO aisec_app"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO gateways (id, org_id, name, status, created_at, created_by)
		VALUES ($1, $2, 'gw-1', 'pending', now(), 'cli:test')`, testGateway, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	dir, _ := keyringtest.Install(t, ctx, owner, p, audit.DefaultOrgID)
	app := newPool(t, dsn, schema, "aisec_app")
	box, err := keyring.Load(ctx, app, p, dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	al, err := alerting.NewPGStore(app, l, r, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := events.NewPGStore(app, box, l, "", events.WithRandom(r), events.WithIngestHook(al))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ev.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	svc, err := alerting.New(alerting.Options{Store: al, Provider: p})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := svc.EnsureBuiltins(ctx); err != nil || n == 0 {
		t.Fatalf("встроенные правила: %d %v", n, err)
	}
	if n, err := svc.EnsureBuiltins(ctx); err != nil || n != 0 {
		t.Fatalf("повторно: %d %v", n, err)
	}
	by := alerting.By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000b1", Name: "admin"},
		UserID: "01900000-0000-7000-8000-0000000000b1", Confirm: func(context.Context) error { return nil }}
	return &pgEnv{owner: owner, app: app, events: ev, alerts: al, svc: svc, ids: ids.NewGenerator(r), by: by, log: l}
}

func (e *pgEnv) event(t *testing.T, app, model, action string, threats ...string) events.Event {
	t.Helper()
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	return events.Event{ID: u.String(), Time: u.Time(), Type: events.TypeGatewayRequest, App: app, Env: "prod",
		User: "a1b2c3", Provider: "mock", Model: model, PolicyMode: events.ModeEnforce, Storage: events.StorageMasked,
		Decision: &events.Decision{Action: action, Applied: []string{action}, Rule: "injection", Severity: "high"},
		Threats:  threats, Content: &events.Content{Request: "Синтетический промпт [masked]"}}
}

func (e *pgEnv) ingest(t *testing.T, evs ...events.Event) {
	t.Helper()
	if _, err := e.events.Insert(pgCtx(t), events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: evs}); err != nil {
		t.Fatal(err)
	}
}

func (e *pgEnv) ruleID(t *testing.T, key string) string {
	t.Helper()
	rules, err := e.svc.Rules(pgCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.BuiltinKey == key {
			return r.ID
		}
	}
	t.Fatalf("нет правила %s", key)
	return ""
}

func (e *pgEnv) list(t *testing.T, key string) []alerting.Alert {
	t.Helper()
	list, err := e.svc.Alerts(pgCtx(t), alerting.AlertQuery{RuleID: e.ruleID(t, key), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// Порог и новое в транзакции приёма на PostgreSQL: дедупликация, повтор
// пакета не удваивает, ссылки на события, жизненный цикл с аудитом,
// подавление после закрытия, права роли сервера.
func TestPGAlertsOnIngest(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	a1 := e.event(t, "crm-bot", "gigachat", "block", "DM-01")
	batch := []events.Event{a1, e.event(t, "crm-bot", "gigachat", "block", "DM-01"), e.event(t, "hr-bot", "yandexgpt", "allow")}
	e.ingest(t, batch...)
	e.ingest(t, batch...) // повтор пакета: дубли не доходят до движка
	inj := e.list(t, alerting.BuiltinInjectionBlocked)
	if len(inj) != 1 || inj[0].Count != 2 || inj[0].Values["app"] != "crm-bot" || inj[0].RuleName == "" || !inj[0].Open ||
		inj[0].FirstEventAt.IsZero() {
		t.Fatalf("порог: %+v", inj)
	}
	if m := e.list(t, alerting.BuiltinNewModel); len(m) != 2 {
		t.Fatalf("новые модели: %+v", m)
	}
	card, err := e.svc.Alert(ctx, inj[0].ID)
	// Внутри одной миллисекунды UUIDv7 не упорядочены: проверяется состав.
	if err != nil || len(card.Events) != 2 || (card.Events[0].ID != a1.ID && card.Events[1].ID != a1.ID) {
		t.Fatalf("карточка: %+v %v", card, err)
	}
	// Параллельные пакеты по одному ключу — одно открытое оповещение.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		ev := e.event(t, "par-bot", "gigachat", "block", "DM-01")
		wg.Go(func() {
			_, err := e.events.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{ev}})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var open, total int
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FILTER (WHERE open_key IS NOT NULL), max(count) FROM alerts
		WHERE group_values->>'app' = 'par-bot'`).Scan(&open, &total); err != nil || open != 1 || total != 8 {
		t.Fatalf("параллельный приём: открытых %d, срабатываний %d, %v", open, total, err)
	}
	// Закрытие с аудитом; в окне подавления — только счётчик.
	closed, err := e.svc.SetStatus(ctx, e.by, inj[0].ID, alerting.StatusClosed, "Проверено")
	if err != nil || closed.Status != alerting.StatusClosed || closed.Open {
		t.Fatalf("закрытие: %+v %v", closed, err)
	}
	var auditN int
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'alert.status_changed' AND object_id = $1`,
		inj[0].ID).Scan(&auditN); err != nil || auditN != 1 {
		t.Fatalf("аудит: %d %v", auditN, err)
	}
	e.ingest(t, e.event(t, "crm-bot", "gigachat", "block", "DM-01"))
	if got := e.list(t, alerting.BuiltinInjectionBlocked); len(got) != 2 {
		t.Fatalf("после закрытия: %+v", got)
	} else {
		for _, a := range got {
			if a.ID == inj[0].ID && a.Suppressed != 1 {
				t.Fatalf("подавление: %+v", a)
			}
		}
	}
	// Окно истекло — новое оповещение.
	if _, err := e.owner.Exec(ctx, `UPDATE alerts SET closed_at = closed_at - interval '2 hours' WHERE id = $1`, inj[0].ID); err != nil {
		t.Fatal(err)
	}
	e.ingest(t, e.event(t, "crm-bot", "gigachat", "block", "DM-01"))
	var crm int
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE group_values->>'app' = 'crm-bot'`).Scan(&crm); err != nil || crm != 2 {
		t.Fatalf("после окна: %d %v", crm, err)
	}
	// Роль сервера: оповещения не удаляются, правило безопасности не
	// отключается, содержимое не копируется.
	if _, err := e.app.Exec(ctx, `DELETE FROM alerts`); sqlState(err) != "42501" {
		t.Fatalf("удаление оповещений: %v", err)
	}
	if _, err := e.app.Exec(ctx, `UPDATE alert_rules SET enabled = false WHERE kind = 'security'`); sqlState(err) != "23514" {
		t.Fatalf("отключение правила безопасности: %v", err)
	}
	var leaked bool
	if err := e.owner.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM alerts WHERE details::text LIKE '%промпт%' OR title LIKE '%промпт%')`).
		Scan(&leaked); err != nil || leaked {
		t.Fatalf("содержимое в оповещениях: %v %v", leaked, err)
	}
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// Изменение получателей на PostgreSQL: запись аудита и оповещение правила
// безопасности в той же транзакции; страницы списка оповещений.
func TestPGRuleUpdateRaisesRecipientsAlert(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	r, err := e.svc.CreateRule(ctx, e.by, alerting.RuleInput{Kind: alerting.KindThreshold, Name: "Утечка ПДн",
		Condition: alerting.Condition{Filter: `threat = "DM-09"`}, GroupBy: []string{"app"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.UpdateRule(ctx, e.by, r.ID, alerting.RuleInput{Name: r.Name, Condition: r.Condition, GroupBy: r.GroupBy,
		Severity: r.Severity, Version: r.Version, Recipients: alerting.Recipients{Roles: []string{"analyst"}}})
	if err != nil || got.Version != 2 {
		t.Fatalf("изменение: %+v %v", got, err)
	}
	list := e.list(t, alerting.BuiltinRecipientsChanged)
	if len(list) != 1 || list[0].Kind != alerting.KindSecurity || list[0].FirstEventAt != (time.Time{}) {
		t.Fatalf("оповещение: %+v", list)
	}
	var n int
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'alert_rule.update' AND object_id = $1`, r.ID).
		Scan(&n); err != nil || n != 1 {
		t.Fatalf("аудит: %d %v", n, err)
	}
	if _, err := e.svc.UpdateRule(ctx, e.by, r.ID, alerting.RuleInput{Name: r.Name, Condition: r.Condition, Version: 1}); !errors.Is(err, alerting.ErrVersionConflict) {
		t.Fatalf("версия: %v", err)
	}
	// Страницы: от новых к старым без повторов.
	for i := range 5 {
		e.ingest(t, e.event(t, "app-"+string(rune('a'+i)), "m", "block", "DM-01"))
	}
	var seen []string
	q := alerting.AlertQuery{RuleID: e.ruleID(t, alerting.BuiltinInjectionBlocked), Limit: 2}
	for {
		page, err := e.svc.Alerts(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range page {
			seen = append(seen, a.ID)
		}
		if len(page) < q.Limit {
			break
		}
		last := page[len(page)-1]
		q.After = &alerting.Position{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	if len(seen) != 5 {
		t.Fatalf("страницы: %v", seen)
	}
	if _, err := e.svc.Alert(ctx, "01900000-0000-7000-8000-0000000fffff"); !errors.Is(err, alerting.ErrNotFound) {
		t.Fatalf("нет оповещения: %v", err)
	}
}
