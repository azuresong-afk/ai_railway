package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL (make dev, postgres на 127.0.0.1:5432).
// Без переменной пропускаются. Каждый тест работает в своей схеме.
func testDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := Open(ctx, dsn, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestOpenRejectsBadDSN(t *testing.T) {
	for _, dsn := range []string{"", "mysql://x", "not a url", "postgres://u:secret@h/%zz"} {
		if _, err := Open(context.Background(), dsn, 1); err == nil {
			t.Errorf("%q принято", dsn)
		}
	}
	if _, err := Open(context.Background(), "postgres://127.0.0.1:1/x", 0); err == nil {
		t.Error("0 соединений принято")
	}
}

func TestOpenErrorHidesPassword(t *testing.T) {
	_, err := Open(context.Background(), "postgres://aisec:sekret-pass@127.0.0.1:1/aisec", 1)
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if s := err.Error(); len(s) > 0 && contains(s, "sekret-pass") {
		t.Fatalf("пароль в ошибке: %s", s)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestMigrateOnRealDB(t *testing.T) {
	admin := testDB(t)
	ctx := context.Background()
	// Своя чистая схема: тест повторяется и не мешает тестам других пакетов
	// (internal/audit) в той же БД.
	const schema = "store_migrate_test"
	resetSchema := func(create bool) error {
		return admin.InTx(ctx, func(tx Tx) error {
			if err := tx.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil || !create {
				return err
			}
			return tx.Exec(ctx, "CREATE SCHEMA "+schema)
		})
	}
	if err := resetSchema(true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := resetSchema(false); err != nil {
			t.Error(err)
		}
	})
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	db, err := Open(ctx, dsn+sep+"search_path="+schema, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ms, err := LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	m := &Migrator{Exec: db, Hasher: hasher(t), Migrations: ms}
	if done, err := m.Up(ctx); err != nil || len(done) != len(ms) {
		t.Fatalf("Up = %v, %v", done, err)
	}
	if done, err := m.Up(ctx); err != nil || len(done) != 0 {
		t.Fatalf("повторный Up = %v, %v", done, err)
	}
}
