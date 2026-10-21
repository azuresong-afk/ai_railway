package selftest

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тест на живой БД: AISEC_TEST_DATABASE_URL; без переменной пропускается
// (в CI нет PostgreSQL).
func TestRecordAuditPostgres(t *testing.T) {
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p := standard(t)
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := aisecCrypto.RandomBytes(r, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "selftest_test_" + hex.EncodeToString(b)
	admin, err := store.Open(ctx, dsn, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if err := admin.InTx(ctx, func(tx store.Tx) error { return tx.Exec(ctx, "CREATE SCHEMA "+schema) }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.InTx(context.Background(), func(tx store.Tx) error {
			return tx.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		}); err != nil {
			t.Error(err)
		}
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	db, err := store.Open(ctx, dsn+sep+"search_path="+schema, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ms, err := store.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&store.Migrator{Exec: db, Hasher: h, Migrations: ms}).Up(ctx); err != nil {
		t.Fatal(err)
	}
	log, err := audit.New(db.Pool(), p)
	if err != nil {
		t.Fatal(err)
	}

	silent := replace("pii.ru", func(context.Context, detect.Detector, detect.Text) ([]detect.Finding, error) { return nil, nil })
	res, err := Run(ctx, Config{Component: "gateway", Provider: p, Detectors: silent})
	if err != nil {
		t.Fatal(err)
	}
	if err := RecordAudit(ctx, log, res); err != nil {
		t.Fatal(err)
	}
	var result, details string
	if err := db.Pool().QueryRow(ctx, `SELECT result, details::text FROM audit_log WHERE action = 'selftest.result'`).Scan(&result, &details); err != nil {
		t.Fatal(err)
	}
	if result != string(audit.ResultFailure) || !strings.Contains(details, `"snils-01"`) || strings.Contains(details, "СНИЛС") {
		t.Fatalf("запись аудита: %s %s", result, details)
	}
	var techs int
	if err := db.Pool().QueryRow(ctx, `SELECT count(*) FROM tech_log WHERE component = 'gateway' AND level = 'critical'`).Scan(&techs); err != nil {
		t.Fatal(err)
	}
	if techs != 1 {
		t.Fatalf("записей журнала технического состояния: %d", techs)
	}
}
