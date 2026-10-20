package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// fakeDB — исполнитель в памяти: запоминает запросы, записи schema_migrations
// ведёт по INSERT, ошибку откатывает вместе с записями.
type fakeDB struct {
	applied []Applied
	sqls    []string
	failOn  string
}

func (f *fakeDB) InTx(_ context.Context, fn func(Tx) error) error {
	saved := append([]Applied(nil), f.applied...)
	if err := fn(f); err != nil {
		f.applied = saved
		return err
	}
	return nil
}

func (f *fakeDB) Exec(_ context.Context, sql string, args ...any) error {
	if f.failOn != "" && strings.Contains(sql, f.failOn) {
		return errors.New("сбой")
	}
	f.sqls = append(f.sqls, sql)
	if strings.HasPrefix(sql, "INSERT INTO schema_migrations") {
		f.applied = append(f.applied, Applied{Version: args[0].(int), Name: args[1].(string), Checksum: args[2].(string)})
	}
	return nil
}

func (f *fakeDB) Applied(context.Context) ([]Applied, error) { return f.applied, nil }

func hasher(t *testing.T) crypto.Hasher {
	t.Helper()
	p, err := crypto.New(crypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func testMigrations() []Migration {
	return []Migration{{1, "a", "CREATE TABLE a ()"}, {2, "b", "CREATE TABLE b ()"}}
}

func TestMigrateUpAndRepeat(t *testing.T) {
	db := &fakeDB{}
	m := &Migrator{Exec: db, Hasher: hasher(t), Migrations: testMigrations()}
	done, err := m.Up(context.Background())
	if err != nil || len(done) != 2 {
		t.Fatalf("Up = %v, %v", done, err)
	}
	done, err = m.Up(context.Background())
	if err != nil || len(done) != 0 {
		t.Fatalf("повторный Up = %v, %v", done, err)
	}
}

func TestMigrateRejectsChangedMigration(t *testing.T) {
	db := &fakeDB{}
	h := hasher(t)
	if _, err := (&Migrator{Exec: db, Hasher: h, Migrations: testMigrations()}).Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	changed := testMigrations()
	changed[0].SQL = "CREATE TABLE a (x int)"
	if _, err := (&Migrator{Exec: db, Hasher: h, Migrations: changed}).Up(context.Background()); err == nil {
		t.Fatal("изменённая миграция принята")
	}
}

func TestMigrateRejectsDatabaseNewerThanBuild(t *testing.T) {
	db := &fakeDB{}
	h := hasher(t)
	if _, err := (&Migrator{Exec: db, Hasher: h, Migrations: testMigrations()}).Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Migrator{Exec: db, Hasher: h, Migrations: testMigrations()[:1]}).Up(context.Background()); err == nil {
		t.Fatal("база новее программы принята")
	}
}

func TestMigrateRollsBackOnError(t *testing.T) {
	db := &fakeDB{failOn: "CREATE TABLE b"}
	_, err := (&Migrator{Exec: db, Hasher: hasher(t), Migrations: testMigrations()}).Up(context.Background())
	if err == nil || len(db.applied) != 0 {
		t.Fatalf("err = %v, записей = %d; ожидался откат", err, len(db.applied))
	}
}

func TestParseMigrationName(t *testing.T) {
	good := []string{"0001_init.sql", "0042_audit_log2.sql"}
	bad := []string{"1_init.sql", "0000_x.sql", "0001_.sql", "0001_Init.sql", "0001-init.sql", "0001_init.txt", "00a1_x.sql", "0001_" + strings.Repeat("x", 65) + ".sql", ""}
	for _, s := range good {
		if _, _, err := ParseMigrationName(s); err != nil {
			t.Errorf("%q отвергнуто: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, _, err := ParseMigrationName(s); err == nil {
			t.Errorf("%q принято", s)
		}
	}
}

func TestLoadMigrationsGaps(t *testing.T) {
	_, err := LoadMigrations(fstest.MapFS{"0001_a.sql": {Data: []byte("x")}, "0003_c.sql": {Data: []byte("x")}})
	if err == nil {
		t.Fatal("пропуск номера принят")
	}
	_, err = LoadMigrations(fstest.MapFS{"bad.sql": {Data: []byte("x")}})
	if err == nil {
		t.Fatal("неверное имя принято")
	}
}

func TestEmbeddedMigrationsLoad(t *testing.T) {
	ms, err := LoadMigrations(migrations.FS)
	if err != nil || len(ms) == 0 {
		t.Fatalf("встроенные миграции: %v, %d", err, len(ms))
	}
}

func FuzzParseMigrationName(f *testing.F) {
	f.Add("0001_init.sql")
	f.Add("")
	f.Add("../0001_x.sql")
	f.Fuzz(func(t *testing.T, s string) {
		v, name, err := ParseMigrationName(s)
		if err == nil && (v < 1 || name == "" || strings.ContainsAny(s, "/\\")) {
			t.Fatalf("принято %q: v=%d name=%q", s, v, name)
		}
	})
}
