package compliance

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускаются.
// Каждый тест — в своей схеме; сервер работает под ролью aisec_app.

func pgTestCtx(t *testing.T) context.Context {
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
	cfg.MaxConns = 4
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

func setupPG(t *testing.T) (*pgxpool.Pool, *PGStore) {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := pgTestCtx(t)
	p := provider(t)
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := aisecCrypto.RandomBytes(r, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "compliance_test_" + hex.EncodeToString(b)
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
	app := newPool(t, dsn, schema, "aisec_app")
	l, err := audit.New(app, p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := NewPGStore(app, l)
	if err != nil {
		t.Fatal(err)
	}
	return owner, st
}

func TestPGComplianceMarksAndBase(t *testing.T) {
	owner, st := setupPG(t)
	ctx := pgTestCtx(t)
	base, err := ParseBase([]byte(miniBase(1, "2026-10-28")))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Store: st, Provider: provider(t), Facts: &fakeFacts{snap: goodSnapshot()}, Embedded: base,
		Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	count := func(sql string) int {
		var n int
		if err := owner.QueryRow(ctx, sql).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Ручная отметка: запись и запись аудита — одной транзакцией.
	if _, err := s.SetMark(ctx, testBy, "manual.one", MarkInput{Status: StatusMet, Comment: "проверено", Document: "Приказ № 1", ReviewBy: "2027-01-01"}); err != nil {
		t.Fatal(err)
	}
	if n := count("SELECT count(*) FROM compliance_marks"); n != 1 {
		t.Fatalf("отметок в БД: %d", n)
	}
	if n := count("SELECT count(*) FROM audit_log WHERE action = 'compliance.mark_set'"); n != 1 {
		t.Fatalf("записей аудита: %d", n)
	}
	o, err := s.Evaluate(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range o.Items {
		if it.ID == "manual.one" && it.Status == StatusMet && it.Mark != nil && it.Mark.ReviewBy == "2027-01-01" {
			found = true
		}
	}
	if !found {
		t.Fatalf("отметка не видна в оценке: %+v", o.Items)
	}
	// Повторная отметка заменяет прежнюю; снятие удаляет; повторное снятие — ErrNoMark.
	if _, err := s.SetMark(ctx, testBy, "manual.one", MarkInput{Status: StatusNotApplicable, Comment: "не применимо"}); err != nil {
		t.Fatal(err)
	}
	if n := count("SELECT count(*) FROM compliance_marks WHERE status = 'not_applicable'"); n != 1 {
		t.Fatalf("замена отметки: %d", n)
	}
	if _, err := s.ClearMark(ctx, testBy, "manual.one"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClearMark(ctx, testBy, "manual.one"); !errors.Is(err, ErrNoMark) {
		t.Fatalf("повторное снятие: %v", err)
	}
	if n := count("SELECT count(*) FROM compliance_marks"); n != 0 {
		t.Fatalf("отметок после снятия: %d", n)
	}
	// База: загрузка, отказ по версии, чтение новым сервисом с проверкой подписи.
	y2 := miniBase(2, "2026-10-28")
	if _, err := s.UploadBase(ctx, testBy, signBase(t, BaseKind, y2, nil)); err != nil {
		t.Fatal(err)
	}
	var be *BaseError
	if _, err := s.UploadBase(ctx, testBy, signBase(t, BaseKind, y2, nil)); !errors.As(err, &be) || be.Reason != "stale_version" {
		t.Fatalf("та же версия: %v", err)
	}
	if n := count("SELECT count(*) FROM audit_log WHERE action = 'compliance.base_rejected'"); n != 1 {
		t.Fatalf("аудит отказа: %d", n)
	}
	s2, err := New(Options{Store: st, Provider: provider(t), Facts: &fakeFacts{snap: goodSnapshot()}, Embedded: base,
		Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	v, err := s2.BaseView(ctx)
	if err != nil || v.Active.Version != 2 || v.Uploaded == nil || !v.Uploaded.Valid {
		t.Fatalf("база из БД: %+v %v", v, err)
	}
	// Хранилище не опускает версию даже при прямом вызове.
	err = st.SaveBase(ctx, audit.DefaultOrgID, StoredBase{Version: 1, Date: testNow, SubkeySerial: 1, Fingerprint: "fp", Requirements: 1, File: []byte("x"), UploadedAt: testNow, UploadedBy: "t"},
		audit.Entry{Actor: testBy.Actor, Action: "compliance.base_loaded", Object: audit.Object{Type: "compliance_base", ID: "x"}, Result: audit.ResultSuccess})
	if !errors.Is(err, ErrStaleBase) {
		t.Fatalf("понижение версии: %v", err)
	}
}
