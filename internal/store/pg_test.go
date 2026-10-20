package store

import (
	"context"
	"os"
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
	db := testDB(t)
	ctx := context.Background()
	// Чистая схема: откатываем всё созданное, чтобы тест повторялся.
	err := db.InTx(ctx, func(tx Tx) error {
		return tx.Exec(ctx, "DROP TABLE IF EXISTS organizations, schema_migrations CASCADE")
	})
	if err != nil {
		t.Fatal(err)
	}
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
