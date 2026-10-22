package notify_test

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/keyring/keyringtest"
	"github.com/azuresong-afk/ai_railway/internal/notify"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

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

// Каналы на PostgreSQL: секреты под ключом данных и не попадают в аудит;
// тестовая отправка и доставка пишут журнал; окончательный отказ поднимает
// оповещение DM-44; ротация ключа данных перешифровывает секреты каналов.
func TestPGNotifyChannels(t *testing.T) {
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := pgCtx(t)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := aisecCrypto.RandomBytes(rnd, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "nt_test_" + hex.EncodeToString(b)
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
	dir, _ := keyringtest.Install(t, ctx, owner, p, audit.DefaultOrgID)
	app := newPool(t, dsn, schema, "aisec_app")
	box, err := keyring.Load(ctx, app, p, dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	alStore, err := alerting.NewPGStore(app, log, rnd, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := alerting.New(alerting.Options{Store: alStore, Provider: p})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alerts.EnsureBuiltins(ctx); err != nil {
		t.Fatal(err)
	}
	log.SetRecordHook(alStore.OnAudit)

	// Локальный приёмник webhook.
	now := time.Now()
	ca, err := aisecCrypto.NewCA("AISec test CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	srvCfg, err := tp.ServerConfig(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	var status atomic.Int32
	status.Store(http.StatusOK)
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) //nolint:gosec // G104: тело запроса тестовому приёмнику не нужно
		hits.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	srv.TLS = srvCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	st, err := notify.NewPGStore(app, log, rnd, "")
	if err != nil {
		t.Fatal(err)
	}
	tr, err := notify.NewTransport(p, "test", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := notify.New(notify.Options{Store: st, Box: box, Provider: p, Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	by := notify.By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000b1", Name: "admin"},
		Confirm: func(context.Context) error { return nil }}
	url := srv.URL + "/hooks/synthetic-secret-token"
	signing := "0123456789abcdef0123456789abcdef-test-key"
	c, err := svc.CreateChannel(ctx, by, notify.ChannelInput{Name: "SOC", Type: notify.TypeWebhook,
		Settings: notify.Settings{CAPEM: string(ca.CertPEM())},
		Secrets:  notify.SecretsInput{URL: &url, SigningKey: &signing}})
	if err != nil {
		t.Fatal(err)
	}
	var rawSettings, rawSecret []byte
	var fields []string
	if err := owner.QueryRow(ctx, `SELECT settings::text, secret, secret_fields FROM notify_channels WHERE id = $1`, c.ID).
		Scan(&rawSettings, &rawSecret, &fields); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawSettings)+string(rawSecret), "synthetic-secret-token") || strings.Join(fields, ",") != "signing_key,url" {
		t.Fatalf("секрет в открытом виде: %s / %v", rawSettings, fields)
	}
	if _, err := svc.CreateChannel(ctx, by, notify.ChannelInput{Name: "SOC", Type: notify.TypeWebhook,
		Settings: notify.Settings{CAPEM: string(ca.CertPEM())},
		Secrets:  notify.SecretsInput{URL: &url, SigningKey: &signing}}); !errors.Is(err, notify.ErrNameTaken) {
		t.Fatalf("повтор названия: %v", err)
	}
	var leaked int
	if err := app.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE details::text LIKE '%synthetic-secret-token%'
		OR details::text LIKE '%0123456789abcdef%'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("секрет в аудите: %d %v", leaked, err)
	}

	// Тестовая отправка.
	d, err := svc.TestChannel(ctx, by, c.ID)
	if err != nil || d.Status != notify.StatusSent {
		t.Fatalf("тест: %+v %v", d, err)
	}

	// Доставка оповещения: постановка в очередь в транзакции и отправка.
	alertID := func(n string) string {
		var id string
		if err := owner.QueryRow(ctx, `INSERT INTO alerts (id, org_id, rule_id, kind, severity, title, status, dedup_key, open_key,
			group_values, count, suppressed, created_at, last_triggered_at, updated_at, details)
			SELECT $1::uuid, org_id, id, kind, severity, name, 'new', 'k' || $2, 'k' || $2, '{"gateway":"gw-1"}', 1, 0, now(), now(), now(), '{}'
			FROM alert_rules WHERE builtin_key = 'system.gateway_offline' RETURNING id::text`,
			"01900000-0000-7000-8000-00000000aa"+n, n).Scan(&id); err != nil {
			t.Fatal(err)
		}
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // G104: откат после фиксации безвреден
		if k, err := st.EnqueueAlertTx(ctx, tx, id, "high"); err != nil || k != 1 {
			t.Fatalf("в очередь: %d %v", k, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return id
	}
	alertID("01")
	if n, err := svc.DispatchOnce(ctx); err != nil || n != 1 {
		t.Fatalf("доставка: %d %v", n, err)
	}
	list, err := svc.Deliveries(ctx, c.ID, 10)
	if err != nil || len(list) != 2 || list[0].Status != notify.StatusSent || list[0].Kind != notify.KindAlert {
		t.Fatalf("журнал: %+v %v", list, err)
	}

	// Пять неудачных попыток — failed, notify.delivery_failed и оповещение DM-44.
	status.Store(http.StatusBadGateway)
	alertID("02")
	for i := range notify.MaxAttempts {
		if n, err := svc.DispatchOnce(ctx); err != nil || n != 1 {
			t.Fatalf("попытка %d: %d %v", i+1, n, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE alert_deliveries SET next_at = now() - interval '1 second' WHERE status = 'pending'`); err != nil {
			t.Fatal(err)
		}
	}
	list, _ = svc.Deliveries(ctx, c.ID, 1) //nolint:gosec // G104: проверяется результат
	if list[0].Status != notify.StatusFailed || list[0].Attempts != notify.MaxAttempts || list[0].Error != "http_502" {
		t.Fatalf("итог: %+v", list[0])
	}
	got, err := alerts.Alerts(ctx, alerting.AlertQuery{RuleID: builtinID(t, alerts, alerting.BuiltinNotifyFailed), Limit: 10})
	if err != nil || len(got) != 1 || got[0].Title != "Уведомление не доставлено — SOC" {
		t.Fatalf("DM-44: %+v %v", got, err)
	}

	// Роль сервера не удаляет доставки раньше срока.
	_, err = app.Exec(ctx, `DELETE FROM alert_deliveries WHERE channel_id = $1`, c.ID)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "42501" {
		t.Fatalf("удаление журнала: %v", err)
	}

	// Ротация ключа данных: секреты канала перешифрованы и читаются.
	ownerLog, err := audit.New(owner, p)
	if err != nil {
		t.Fatal(err)
	}
	actor := audit.Actor{Type: audit.ActorCLI, ID: "uid:0", Name: "root"}
	if _, err := keyring.RotateData(ctx, owner, ownerLog, p, dir, audit.DefaultOrgID, actor, time.Now()); err != nil {
		t.Fatal(err)
	}
	full, err := keyring.Load(ctx, owner, p, dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := keyring.Rewrap(ctx, owner, full, keyring.RewrapOptions{ContentPurpose: events.ContentKeyPurpose})
	if err != nil || n.Channels != 1 {
		t.Fatalf("перешифрование: %+v %v", n, err)
	}
	if res, err := keyring.DestroyRetired(ctx, owner, ownerLog, audit.DefaultOrgID, actor); err != nil || len(res.Destroyed) != 1 {
		t.Fatalf("вывод прежней версии: %+v %v", res, err)
	}
	if err := box.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	status.Store(http.StatusOK)
	if d, err := svc.TestChannel(ctx, by, c.ID); err != nil || d.Status != notify.StatusSent {
		t.Fatalf("после ротации: %+v %v", d, err)
	}
}

func builtinID(t *testing.T, s *alerting.Service, key string) string {
	t.Helper()
	rules, err := s.Rules(pgCtx(t))
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
