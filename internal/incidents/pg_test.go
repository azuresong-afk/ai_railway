package incidents_test

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
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
	"github.com/azuresong-afk/ai_railway/internal/incidents"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/keyring/keyringtest"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются.
// Каждый тест — в своей схеме; сервер работает под ролью aisec_app.

type pgEnv struct {
	owner, app *pgxpool.Pool
	events     *events.PGStore
	alertsSvc  *alerting.Service
	store      *incidents.PGStore
	svc        *incidents.Service
	ids        *ids.Generator
	by         incidents.By
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
	schema := "inc_test_" + hex.EncodeToString(b)
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
	is, err := incidents.NewPGStore(app, l, al, r)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := events.NewPGStore(app, box, l, "", events.WithRandom(r), events.WithIngestHook(al.WithIncidents(is)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ev.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	asvc, err := alerting.New(alerting.Options{Store: al, Provider: p})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := asvc.EnsureBuiltins(ctx); err != nil {
		t.Fatal(err)
	}
	svc, err := incidents.New(incidents.Options{Store: is, Provider: p, Alerts: asvc})
	if err != nil {
		t.Fatal(err)
	}
	by := incidents.By{Actor: audit.Actor{Type: audit.ActorUser, ID: analystID, Name: "analyst"}, UserID: analystID}
	return &pgEnv{owner: owner, app: app, events: ev, alertsSvc: asvc, store: is, svc: svc, ids: ids.NewGenerator(r), by: by}
}

func (e *pgEnv) event(t *testing.T, app string, canary bool) events.Event {
	t.Helper()
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	ev := events.Event{ID: u.String(), Time: u.Time(), Type: events.TypeGatewayRequest, App: app, Env: "prod",
		User: "a1b2c3", Provider: "mock", Model: "mock-echo", PolicyMode: events.ModeEnforce, Storage: events.StorageMasked,
		Decision: &events.Decision{Action: "block", Applied: []string{"block"}, Rule: "injection", Severity: "high"},
		Threats:  []string{"DM-01"}, Content: &events.Content{Request: "Синтетический промпт [masked]"}}
	if canary {
		ev.Threats = []string{"DM-08"}
		ev.Decision.Rule, ev.Decision.Severity = "canary", "critical"
		ev.Findings = []events.Finding{{Detector: "canary", Version: "1.1.0", Category: "leak", Threat: "DM-08", Score: 1,
			Location: "choices[0].message.content"}}
	}
	return ev
}

func (e *pgEnv) ingest(t *testing.T, evs ...events.Event) {
	t.Helper()
	if _, err := e.events.Insert(pgCtx(t), events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: evs}); err != nil {
		t.Fatal(err)
	}
}

func (e *pgEnv) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(pgCtx(t), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// Инциденты на PostgreSQL: автоматический инцидент в транзакции приёма
// (канарейка, повтор — тот же), из оповещения (повтор — тот же), связь,
// закрытие вместе с оповещениями, повторное открытие, комментарии,
// инструкции, сквозные номера и аудит.
func TestPGIncidentsLifecycle(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	first := e.event(t, "crm-bot", true)
	e.ingest(t, first)
	e.ingest(t, e.event(t, "crm-bot", true), e.event(t, "crm-bot", false), e.event(t, "hr-bot", false))
	list, err := e.svc.List(ctx, incidents.Query{})
	if err != nil || len(list) != 1 {
		t.Fatalf("автоматические инциденты: %d %v", len(list), err)
	}
	auto := list[0]
	c, err := e.svc.Card(ctx, auto.ID)
	if err != nil {
		t.Fatal(err)
	}
	if auto.Number != 1 || auto.Category != incidents.CategorySystemPromptLeak || auto.Source != incidents.SourceAuto ||
		len(c.Related.Alerts) != 1 || len(c.Related.Events) != 2 || len(c.Related.Timeline) != 3 ||
		c.Related.Timeline[2].Kind != incidents.KindAlertTriggered || len(c.Incident.Stages) != 4 {
		t.Fatalf("карточка автоматического: %+v %+v", c.Incident, c.Related)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'incident.create'`); n != 1 {
		t.Fatalf("incident.create: %d", n)
	}

	// Из оповещения DM-01; повтор — тот же инцидент.
	ruleID := ""
	rules, err := e.alertsSvc.Rules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.BuiltinKey == alerting.BuiltinInjectionBlocked {
			ruleID = r.ID
		}
	}
	al, err := e.alertsSvc.Alerts(ctx, alerting.AlertQuery{RuleID: ruleID})
	if err != nil || len(al) != 2 {
		t.Fatalf("оповещения DM-01: %d %v", len(al), err)
	}
	inc, created, err := e.svc.Create(ctx, e.by, incidents.CreateInput{AlertID: al[0].ID})
	if err != nil || !created || inc.Number != 2 || inc.Category != incidents.CategoryPromptInjection {
		t.Fatalf("из оповещения: %+v %v %v", inc, created, err)
	}
	again, created, err := e.svc.Create(ctx, e.by, incidents.CreateInput{AlertID: al[0].ID})
	if err != nil || created || again.ID != inc.ID {
		t.Fatalf("повтор: %+v %v %v", again, created, err)
	}
	if _, created, err := e.svc.LinkAlert(ctx, e.by, inc.ID, incidents.LinkInput{AlertID: al[1].ID}); err != nil || !created {
		t.Fatalf("связь: %v %v", created, err)
	}
	if _, _, err := e.svc.LinkAlert(ctx, e.by, auto.ID, incidents.LinkInput{AlertID: al[1].ID}); !errors.Is(err, incidents.ErrLinked) {
		t.Fatalf("связь с другим: %v", err)
	}

	// Комментарий и правка.
	cm, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: "Источник — пользователь a1b2c3"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: "Исправлено", Replaces: cm.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: "Снова", Replaces: cm.ID}); !errors.Is(err, incidents.ErrSuperseded) {
		t.Fatalf("правка старой версии: %v", err)
	}
	if _, err := e.svc.CompleteStage(ctx, e.by, inc.ID, "intake", incidents.StageInput{Note: "Принято"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CompleteStage(ctx, e.by, inc.ID, "intake", incidents.StageInput{}); !errors.Is(err, incidents.ErrStageDone) {
		t.Fatalf("повторная отметка: %v", err)
	}

	// Автомат и закрытие вместе с оповещениями.
	for _, st := range []string{"in_progress", "contained"} {
		if _, err := e.svc.SetStatus(ctx, e.by, inc.ID, incidents.StatusInput{Status: st}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.SetStatus(ctx, e.by, inc.ID, incidents.StatusInput{Status: "in_progress"}); !errors.Is(err, incidents.ErrTransition) {
		t.Fatalf("назад: %v", err)
	}
	// Граница: 2000 символов с кавычками и трёхбайтовыми символами в хронологии.
	closed, err := e.svc.SetStatus(ctx, e.by, inc.ID, incidents.StatusInput{Status: "closed", Resolution: "resolved",
		Comment: strings.Repeat(`"—`, incidents.MaxResolutionComment/2)})
	if err != nil || closed.Version != 8 || closed.AssigneeID != analystID {
		t.Fatalf("закрытие: %+v %v", closed, err)
	}
	if n := e.count(t, `SELECT count(*) FROM alerts WHERE incident_id = $1 AND status = 'closed'`, inc.ID); n != 2 {
		t.Fatalf("закрыто оповещений: %d", n)
	}
	if _, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: "После"}); !errors.Is(err, incidents.ErrClosed) {
		t.Fatalf("комментарий к закрытому: %v", err)
	}
	re, created, err := e.svc.Create(ctx, e.by, incidents.CreateInput{ReopenOf: inc.ID})
	if err != nil || !created || re.Number != 3 || re.ReopenedFrom != inc.ID {
		t.Fatalf("повторное открытие: %+v %v %v", re, created, err)
	}
	if re2, created, err := e.svc.Create(ctx, e.by, incidents.CreateInput{ReopenOf: inc.ID}); err != nil || created || re2.ID != re.ID {
		t.Fatalf("повтор открытия: %v %v", created, err)
	}

	// Инструкции.
	cat := incidents.CategoryPromptInjection
	ins, err := e.svc.SetInstructions(ctx, e.by, cat, incidents.InstructionsInput{Body: "Своя инструкция", Version: 1})
	if err != nil || ins.Version != 2 {
		t.Fatalf("инструкция: %+v %v", ins, err)
	}
	if _, err := e.svc.SetInstructions(ctx, e.by, cat, incidents.InstructionsInput{Body: "Чужая", Version: 1}); !errors.Is(err, incidents.ErrVersionConflict) {
		t.Fatalf("конфликт: %v", err)
	}
	if c, err := e.svc.Card(ctx, re.ID); err != nil || c.Instruction.Body != "Своя инструкция" || len(c.Related.Events) != 2 {
		t.Fatalf("карточка нового: %+v %v", c, err)
	}
	if _, err := e.svc.Export(ctx, e.by, re.ID); err != nil {
		t.Fatal(err)
	}
	for action, want := range map[string]int{"incident.create": 3, "incident.alert_linked": 1, "incident.comment_added": 2,
		"incident.stage_completed": 1, "incident.status_changed": 3, "incident_category.update": 1, "data.export": 1,
		"alert.status_changed": 2} {
		if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = $1`, action); n != want {
			t.Errorf("%s: %d записей, ожидалось %d", action, n, want)
		}
	}
	// Фильтры списка на SQL.
	if l, err := e.svc.List(ctx, incidents.Query{Status: incidents.StatusOpen}); err != nil || len(l) != 2 {
		t.Fatalf("open: %d %v", len(l), err)
	}
	if l, err := e.svc.List(ctx, incidents.Query{Source: incidents.SourceReopen, Category: cat}); err != nil || len(l) != 1 {
		t.Fatalf("source+category: %d %v", len(l), err)
	}
	page, err := e.svc.List(ctx, incidents.Query{Limit: 2})
	if err != nil || len(page) != 2 {
		t.Fatal(err)
	}
	rest, err := e.svc.List(ctx, incidents.Query{After: &incidents.Position{CreatedAt: page[1].CreatedAt, ID: page[1].ID}})
	if err != nil || len(rest) != 1 || rest[0].ID == page[0].ID || rest[0].ID == page[1].ID {
		t.Fatalf("вторая страница: %+v %v", rest, err)
	}
}

// Права роли сервера и триггеры: хронология, комментарии, ссылки и версии
// инструкций не меняются и не удаляются; у инцидента меняются только
// изменяемые столбцы; закрытый инцидент и отмеченный этап не меняются.
func TestPGIncidentsAppendOnly(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.ingest(t, e.event(t, "crm-bot", true))
	list, err := e.svc.List(ctx, incidents.Query{})
	if err != nil || len(list) != 1 {
		t.Fatal(err)
	}
	inc := list[0]
	if _, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: "Текст"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CompleteStage(ctx, e.by, inc.ID, "triage", incidents.StageInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetInstructions(ctx, e.by, incidents.CategoryOther, incidents.InstructionsInput{Body: "x", Version: 1}); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`UPDATE incident_timeline SET kind = 'created'`, `DELETE FROM incident_timeline`,
		`UPDATE incident_comments SET body = 'подмена'`, `DELETE FROM incident_comments`,
		`UPDATE incident_events SET event_ts = now()`, `DELETE FROM incident_events`,
		`UPDATE incident_instructions SET body = 'подмена'`, `DELETE FROM incident_instructions`,
		`DELETE FROM incidents`, `UPDATE incidents SET title = 'подмена'`, `UPDATE incidents SET number = 100`,
		`UPDATE incidents SET category = 'other'`, `DELETE FROM incident_stages`, `UPDATE incident_stages SET key = 'x'`,
	} {
		if _, err := e.app.Exec(ctx, sql); sqlState(err) != "42501" {
			t.Errorf("%s: ожидался отказ в правах, %v", sql, err)
		}
	}
	if _, err := e.app.Exec(ctx, `UPDATE incident_stages SET note = 'подмена' WHERE key = 'triage'`); sqlState(err) != "23514" {
		t.Errorf("отмеченный этап изменён: %v", err)
	}
	if _, err := e.svc.SetStatus(ctx, e.by, inc.ID, incidents.StatusInput{Status: "closed", Resolution: "false_positive"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.app.Exec(ctx, `UPDATE incidents SET status = 'in_progress', resolution = NULL, closed_at = NULL, closed_by = NULL
		WHERE id = $1`, inc.ID); sqlState(err) != "23514" {
		t.Errorf("закрытый инцидент открыт заново в обход: %v", err)
	}
	// Закрытый инцидент не дополняется и прямым запросом.
	for _, sql := range []string{
		`INSERT INTO incident_comments (id, incident_id, at, author, author_name, body) VALUES (gen_random_uuid(), $1, now(), 'x', 'x', 'x')`,
		`INSERT INTO incident_timeline (id, incident_id, at, actor, kind, details) VALUES (gen_random_uuid(), $1, now(), 'x', 'comment_added', '{}')`,
		`INSERT INTO incident_events (incident_id, event_id, event_ts, added_at) VALUES ($1, gen_random_uuid(), now(), now())`,
		`UPDATE incident_stages SET done_at = now(), done_by = 'x' WHERE incident_id = $1 AND key = 'investigation'`,
	} {
		if _, err := e.app.Exec(ctx, sql, inc.ID); sqlState(err) != "23514" {
			t.Errorf("%s: закрытый инцидент дополнен: %v", sql, err)
		}
	}
	// Утечка после закрытия — сразу новый инцидент (окна подавления у DM-08 нет).
	e.ingest(t, e.event(t, "crm-bot", true))
	if n := e.count(t, `SELECT count(*) FROM incidents WHERE source = 'auto' AND status = 'new'`); n != 1 {
		t.Errorf("новых автоматических инцидентов после закрытия: %d", n)
	}
	// 3Н35 ревью 3.r2: связь оповещения с инцидентом и автомат статусов
	// защищены и от прямых запросов роли сервера.
	if _, err := e.app.Exec(ctx, `UPDATE alerts SET incident_id = NULL WHERE incident_id = $1`, inc.ID); sqlState(err) != "23514" {
		t.Errorf("оповещение отвязано от инцидента: %v", err)
	}
	e.ingest(t, e.event(t, "hr-bot", false))
	if _, err := e.app.Exec(ctx, `UPDATE alerts SET incident_id = $1 WHERE incident_id IS NULL`, inc.ID); sqlState(err) != "23514" {
		t.Errorf("оповещение связано с закрытым инцидентом: %v", err)
	}
	if _, err := e.app.Exec(ctx, `INSERT INTO incident_timeline (id, incident_id, at, actor, kind, details)
		VALUES (gen_random_uuid(), $1, now(), 'x', 'reopened', '{}')`, inc.ID); sqlState(err) != "23514" {
		t.Errorf("запись «открыт заново» без повторного открытия: %v", err)
	}
	open, err := e.svc.List(ctx, incidents.Query{Status: incidents.StatusOpen})
	if err != nil || len(open) != 1 {
		t.Fatalf("открытый инцидент: %d %v", len(open), err)
	}
	if _, err := e.svc.SetStatus(ctx, e.by, open[0].ID, incidents.StatusInput{Status: "in_progress"}); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`UPDATE incidents SET status = 'new' WHERE id = $1`,
		`UPDATE incidents SET reacted_at = reacted_at + interval '1 day' WHERE id = $1`,
		`UPDATE incidents SET status = 'closed', resolution = 'resolved', closed_at = now(), closed_by = 'x' WHERE id = $1`,
	} {
		if _, err := e.app.Exec(ctx, sql, open[0].ID); sqlState(err) != "23514" {
			t.Errorf("%s: %v", sql, err)
		}
	}
	// Внешний ключ оповещения на инцидент: связанное оповещение не
	// перепривязывается вовсе (3Н35).
	if _, err := e.app.Exec(ctx, `UPDATE alerts SET incident_id = $1 WHERE incident_id IS NOT NULL`, "01900000-0000-7000-8000-0000000fffff"); sqlState(err) != "23514" {
		t.Errorf("ссылка на другой инцидент: %v", err)
	}
	if _, err := e.app.Exec(ctx, `UPDATE alerts SET incident_id = $1 WHERE incident_id IS NULL`, "01900000-0000-7000-8000-0000000fffff"); sqlState(err) != "23503" {
		t.Errorf("ссылка на несуществующий инцидент: %v", err)
	}
}

// Параллельное создание из одного оповещения и параллельный приём
// канареек одного приложения дают один инцидент; номера без пропусков.
func TestPGIncidentsConcurrent(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.events.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(),
				Events: []events.Event{e.event(t, "crm-bot", true)}}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := e.count(t, `SELECT count(*) FROM incidents`); n != 1 {
		t.Fatalf("инцидентов после параллельного приёма: %d", n)
	}
	e.ingest(t, e.event(t, "hr-bot", false))
	al, err := e.alertsSvc.Alerts(ctx, alerting.AlertQuery{Severity: "high"})
	if err != nil || len(al) == 0 {
		t.Fatalf("оповещения: %v", err)
	}
	var target string
	for _, a := range al {
		if a.Values["app"] == "hr-bot" {
			target = a.ID
		}
	}
	ids := make(chan string, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inc, _, err := e.svc.Create(ctx, e.by, incidents.CreateInput{AlertID: target})
			if err != nil {
				t.Error(err)
				return
			}
			ids <- inc.ID
		}()
	}
	wg.Wait()
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
	}
	if len(seen) != 1 {
		t.Fatalf("инцидентов из одного оповещения: %d", len(seen))
	}
	if n := e.count(t, `SELECT count(*) FROM incidents WHERE number IN (1, 2)`); n != 2 {
		t.Fatalf("номера: %d", n)
	}
	// Закрытие и повторная связь того же оповещения параллельно — без
	// взаимоблокировки.
	var id string
	for id = range seen {
	}
	errs := make(chan error, 9)
	for i := range 9 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if i == 4 {
				_, err = e.svc.SetStatus(ctx, e.by, id, incidents.StatusInput{Status: "closed", Resolution: "risk_accepted"})
			} else {
				_, _, err = e.svc.LinkAlert(ctx, e.by, id, incidents.LinkInput{AlertID: target})
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("закрытие и связь: %v", err)
		}
	}
}

// 3В18 ревью 3.r2 на PostgreSQL: сверх предела автоматических записей приём
// событий хронологию не дополняет; на полной хронологии комментарий
// отклоняется, а закрытие проходит, и запись о нём попадает в карточку.
func TestPGIncidentCloseAtTimelineLimit(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.ingest(t, e.event(t, "crm-bot", true))
	list, err := e.svc.List(ctx, incidents.Query{})
	if err != nil || len(list) != 1 {
		t.Fatalf("инцидент: %d %v", len(list), err)
	}
	id := list[0].ID
	if _, err := e.owner.Exec(ctx, `INSERT INTO incident_timeline (id, incident_id, at, actor, kind, details)
		SELECT gen_random_uuid(), $1, now() - interval '1 hour' + make_interval(secs => g), 'system:aisec-server', 'alert_triggered', '{}'
		FROM generate_series(1, $2) AS g`, id, incidents.MaxTimeline-2); err != nil {
		t.Fatal(err)
	}
	e.ingest(t, e.event(t, "crm-bot", true))
	if n := e.count(t, `SELECT count(*) FROM incident_timeline WHERE incident_id = '`+id+`'`); n != incidents.MaxTimeline {
		t.Fatalf("записей после приёма у предела: %d", n)
	}
	if _, err := e.svc.AddComment(ctx, e.by, id, incidents.CommentInput{Body: "Сверх предела"}); !errors.Is(err, incidents.ErrLimit) {
		t.Fatalf("комментарий сверх предела: %v", err)
	}
	if _, err := e.svc.SetStatus(ctx, e.by, id, incidents.StatusInput{Status: "closed", Resolution: "resolved",
		Comment: "Канарейка сменена"}); err != nil {
		t.Fatalf("закрытие у предела: %v", err)
	}
	c, err := e.svc.Card(ctx, id)
	if err != nil || c.Related.Timeline[len(c.Related.Timeline)-1].Kind != incidents.KindStatusChanged {
		t.Fatalf("закрытие в карточке: %v", err)
	}
}

// 3Н37 ревью 3.r2: закрытый инцидент старше срока (по умолчанию 3 года)
// удаляется вместе с хронологией, комментариями, ссылками, этапами и
// оповещениями; незакрытый — никогда; открытый заново — после следующего;
// раньше срока роль сервера не удалит ничего даже прямым запросом;
// сокращение срока — с повторной проверкой и weakening в аудите.
func TestPGIncidentRetention(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.owner.Exec(ctx, `INSERT INTO install_settings (org_id, timezone, retention_mode, updated_at)
		VALUES ($1, 'Europe/Moscow', 'masked', now())`, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := incidents.New(incidents.Options{Store: e.store, Provider: p, Alerts: e.alertsSvc, Retention: e.store})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := svc.Retention(ctx); err != nil || incidents.DefaultRetentionDays != 1095 || got.RetentionDays != 1095 {
		t.Fatalf("срок по умолчанию: %+v %v", got, err)
	}
	// Автоматический инцидент DM-08 с оповещением и комментарием; ручной,
	// закрытый и открытый заново; незакрытый.
	e.ingest(t, e.event(t, "crm-bot", true))
	list, err := e.svc.List(ctx, incidents.Query{})
	if err != nil || len(list) != 1 {
		t.Fatalf("инциденты: %d %v", len(list), err)
	}
	auto := list[0]
	if _, err := e.svc.AddComment(ctx, e.by, auto.ID, incidents.CommentInput{Body: "Разобрано"}); err != nil {
		t.Fatal(err)
	}
	closeInc := func(id string) {
		t.Helper()
		if _, err := e.svc.SetStatus(ctx, e.by, id, incidents.StatusInput{Status: "closed", Resolution: "resolved"}); err != nil {
			t.Fatal(err)
		}
	}
	closeInc(auto.ID)
	first, _, err := e.svc.Create(ctx, e.by, incidents.CreateInput{Title: "Ручной", Severity: "low", Category: incidents.CategoryPromptInjection})
	if err != nil {
		t.Fatal(err)
	}
	closeInc(first.ID)
	again, _, err := e.svc.Create(ctx, e.by, incidents.CreateInput{ReopenOf: first.ID})
	if err != nil {
		t.Fatal(err)
	}
	closeInc(again.ID)
	open, _, err := e.svc.Create(ctx, e.by, incidents.CreateInput{Title: "Открытый", Severity: "low", Category: incidents.CategoryPromptInjection})
	if err != nil {
		t.Fatal(err)
	}
	alertID := ""
	if err := e.owner.QueryRow(ctx, `SELECT id::text FROM alerts WHERE incident_id = $1`, auto.ID).Scan(&alertID); err != nil {
		t.Fatal(err)
	}

	// Раньше срока роль сервера не удаляет ни записи инцидента, ни его оповещения.
	for _, q := range []string{
		`DELETE FROM incident_comments WHERE incident_id = $1`,
		`DELETE FROM incident_timeline WHERE incident_id = $1`,
		`DELETE FROM alert_history WHERE alert_id IN (SELECT id FROM alerts WHERE incident_id = $1)`,
	} {
		if _, err := e.app.Exec(ctx, q, auto.ID); sqlState(err) != "42501" {
			t.Fatalf("%s раньше срока: %v", q, err)
		}
	}
	if n, err := e.store.PurgeExpired(ctx, audit.DefaultOrgID); err != nil || n != 0 {
		t.Fatalf("очистка раньше срока: %d %v", n, err)
	}

	// Закрыты 1200 суток назад; незакрытый создан тогда же.
	if _, err := e.owner.Exec(ctx, `ALTER TABLE incidents DISABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `UPDATE incidents SET closed_at = now() - interval '1200 days' WHERE status = 'closed'`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `UPDATE incidents SET created_at = now() - interval '1300 days' WHERE id = $1`, open.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `ALTER TABLE incidents ENABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	// Первый проход: автоматический и открытый заново; прежний держит ссылка.
	if n, err := e.store.PurgeExpired(ctx, audit.DefaultOrgID); err != nil || n != 2 {
		t.Fatalf("первая пачка: %d %v", n, err)
	}
	if _, err := e.svc.Card(ctx, first.ID); err != nil {
		t.Fatalf("прежний удалён раньше следующего: %v", err)
	}
	if n, err := e.store.PurgeExpired(ctx, audit.DefaultOrgID); err != nil || n != 1 {
		t.Fatalf("вторая пачка: %d %v", n, err)
	}
	if n, err := e.store.PurgeExpired(ctx, audit.DefaultOrgID); err != nil || n != 0 {
		t.Fatalf("третья пачка: %d %v", n, err)
	}
	for _, id := range []string{auto.ID, first.ID, again.ID} {
		if _, err := e.svc.Card(ctx, id); !errors.Is(err, incidents.ErrNotFound) {
			t.Fatalf("инцидент %s не удалён: %v", id, err)
		}
	}
	if _, err := e.svc.Card(ctx, open.ID); err != nil {
		t.Fatalf("незакрытый удалён: %v", err)
	}
	for _, q := range []string{`SELECT count(*) FROM alerts WHERE id = $1`, `SELECT count(*) FROM alert_events WHERE alert_id = $1`,
		`SELECT count(*) FROM alert_history WHERE alert_id = $1`} {
		if n := e.count(t, q, alertID); n != 0 {
			t.Fatalf("%s: %d", q, n)
		}
	}
	gone := []string{auto.ID, first.ID, again.ID}
	for _, tbl := range []string{"incident_timeline", "incident_comments", "incident_events", "incident_stages"} {
		if n := e.count(t, `SELECT count(*) FROM `+tbl+` WHERE incident_id = ANY($1::uuid[])`, gone); n != 0 {
			t.Fatalf("%s: осталось %d", tbl, n)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM incident_stages WHERE incident_id = $1`, open.ID); n == 0 {
		t.Fatal("этапы незакрытого удалены")
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'incident.retention'`); n != 2 {
		t.Fatalf("incident.retention: %d", n)
	}

	// Сокращение срока — с повторной проверкой и weakening (DM-40).
	if _, err := svc.SetRetention(ctx, e.by, 400); !errors.Is(err, incidents.ErrConfirmRequired) {
		t.Fatalf("сокращение без проверки: %v", err)
	}
	by := e.by
	by.Confirm = func(context.Context) error { return nil }
	if _, err := svc.SetRetention(ctx, by, 400); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.Retention(ctx); err != nil || got.RetentionDays != 400 {
		t.Fatalf("срок: %+v %v", got, err)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'incident.settings_changed'
		AND (details::jsonb ->> 'weakening')::boolean`); n != 1 {
		t.Fatalf("аудит сокращения: %d", n)
	}
	// Ограничение столбца: меньше года не сохраняется даже напрямую.
	if _, err := e.app.Exec(ctx, `UPDATE install_settings SET incident_retention_days = 100`); sqlState(err) != "23514" {
		t.Fatalf("срок 100 суток: %v", err)
	}
}
