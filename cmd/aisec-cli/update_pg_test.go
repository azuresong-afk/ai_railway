package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Откат обновления на живой PostgreSQL (задача 6.20, ADR-0036, раздел 4):
// копия pg_dump, миграции нового выпуска, восстановление одной транзакцией.
// Службы — подмена; «новый aisec-cli migrate» — тот же store.Migrator с
// миграциями нового выпуска.

// pgUpdateEnv — установка в своей схеме с настоящими миграциями и новым
// выпуском, у которого на одну миграцию больше (extraSQL).
func pgUpdateEnv(t *testing.T, schema, extraSQL string) (*updEnv, *installation) {
	t.Helper()
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	tools := pgTools{}
	for _, n := range []struct {
		dst  *string
		name string
	}{{&tools.PGDump, "pg_dump"}, {&tools.PGRestore, "pg_restore"}, {&tools.PSQL, "psql"}} {
		path, err := exec.LookPath(n.name)
		if err != nil {
			t.Skipf("нет %s", n.name)
		}
		*n.dst = path
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	in := newInstallation(t, admin, base, schema)
	in.exec(t, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO aisec_app")

	// Миграции нового выпуска: все текущие и ещё одна.
	cur, err := os.ReadDir("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	oldDir, newDir := t.TempDir(), t.TempDir()
	n := 0
	for _, f := range cur {
		if !strings.HasSuffix(f.Name(), ".sql") {
			continue
		}
		data, err := os.ReadFile(filepath.Join("../../migrations", f.Name())) //nolint:gosec // G304: каталог репозитория
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range []string{oldDir, newDir} {
			if err := os.WriteFile(filepath.Join(d, f.Name()), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		n++
	}
	if err := os.WriteFile(filepath.Join(newDir, fmt.Sprintf("%04d_update_probe.sql", n+1)), []byte(extraSQL), 0o600); err != nil {
		t.Fatal(err)
	}

	e := newUpdEnv(t)
	if err := os.RemoveAll(filepath.Join(e.root, "opt", "aisec")); err != nil {
		t.Fatal(err)
	}
	writeRelease(t, filepath.Join(e.root, "opt", "aisec"), mainSpec("1.0", updOld, oldDir))
	if err := os.RemoveAll(e.src); err != nil {
		t.Fatal(err)
	}
	writeRelease(t, e.src, mainSpec("2.0", updNew, newDir))
	oldRel, err := readManifestPair(e.u.p, filepath.Join(e.root, "opt", "aisec"))
	if err != nil {
		t.Fatal(err)
	}
	e.fromID = oldRel.ID
	db, err := openUpdateDB(context.Background(), e.u.p, in.dsn, base, []string{"PATH=" + os.Getenv("PATH")}, tools)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e.u.db = db
	e.db = nil
	ms, err := store.LoadMigrations(os.DirFS(newDir))
	if err != nil {
		t.Fatal(err)
	}
	h, err := e.u.p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	e.host.db = nil
	e.host.migrate = func(ctx context.Context) error {
		_, err := (&store.Migrator{Exec: in.db, Hasher: h, Migrations: ms}).Up(ctx)
		return err
	}
	return e, in
}

func probeExists(t *testing.T, in *installation) bool {
	t.Helper()
	var ok bool
	if err := in.db.Pool().QueryRow(context.Background(), "SELECT to_regclass('update_probe') IS NOT NULL").Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

func auditActions(t *testing.T, in *installation) string {
	t.Helper()
	rows, err := in.db.Pool().Query(context.Background(), "SELECT action FROM audit_log WHERE action LIKE 'update.%' ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return strings.Join(out, ",")
}

// Миграции применились, проверка здоровья не прошла: БД восстановлена из
// копии — таблицы новой миграции нет, число миграций прежнее, данные и права
// схемы на месте, в аудите начало и откат (запись об откате — после
// восстановления).
func TestUpdateRollbackRestoresDBOnRealDB(t *testing.T) {
	e, in := pgUpdateEnv(t, "cli_update_restore_6b1", "CREATE TABLE update_probe (id int);\nINSERT INTO update_probe VALUES (1);\n")
	ctx := context.Background()
	var before, auditBefore int
	if err := in.db.Pool().QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := in.db.Pool().QueryRow(ctx, "SELECT count(*) FROM audit_log").Scan(&auditBefore); err != nil || auditBefore == 0 {
		t.Fatalf("журнал аудита установки пуст: %v", err)
	}
	e.host.fail["verify"] = fmt.Errorf("целостность нарушена")
	var out bytes.Buffer
	e.u.out = &out
	if err := e.u.run("apply", e.src, false); err == nil || !strings.Contains(out.String(), "восстановление БД из копии") {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if probeExists(t, in) {
		t.Fatal("таблица новой миграции осталась после восстановления")
	}
	var after int
	if err := in.db.Pool().QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("миграций %d, до обновления %d", after, before)
	}
	var usage bool
	if err := in.db.Pool().QueryRow(ctx, "SELECT has_schema_privilege('aisec_app', current_schema(), 'USAGE')").Scan(&usage); err != nil || !usage {
		t.Fatalf("права схемы не восстановлены: %v", err)
	}
	if got := auditActions(t, in); got != "update.started,update.rollback" {
		t.Fatalf("аудит: %s", got)
	}
	var auditAfter int
	if err := in.db.Pool().QueryRow(ctx, "SELECT count(*) FROM audit_log").Scan(&auditAfter); err != nil || auditAfter != auditBefore+2 {
		t.Fatalf("журнал аудита: было %d, стало %d (%v)", auditBefore, auditAfter, err)
	}
	if got := e.link(t); got != "aisec-releases/"+e.fromID {
		t.Fatalf("ссылка: %s", got)
	}
	if !strings.Contains(out.String(), "БД восстановлена из копии") {
		t.Fatal(out.String())
	}
}

// Сбой миграции посреди транзакции: ни одной части новой миграции в БД,
// копия не восстанавливается (нечего), прежний выпуск работает.
func TestUpdateMigrationFailureKeepsDBOnRealDB(t *testing.T) {
	e, in := pgUpdateEnv(t, "cli_update_migfail_6b1", "CREATE TABLE update_probe (id int);\nSELECT 1/0;\n")
	var out bytes.Buffer
	e.u.out = &out
	if err := e.u.run("apply", e.src, false); err == nil {
		t.Fatal("обновление со сбойной миграцией прошло")
	}
	if probeExists(t, in) {
		t.Fatal("часть сбойной миграции осталась в БД")
	}
	if strings.Contains(out.String(), "восстановление БД") {
		t.Fatalf("копия восстанавливалась без применённых миграций:\n%s", out.String())
	}
	if got := auditActions(t, in); got != "update.started,update.rollback" {
		t.Fatalf("аудит: %s", got)
	}
}

// Успешное обновление на живой БД: копия снята, миграция применена, итог в
// аудите.
func TestUpdateApplyOnRealDB(t *testing.T) {
	e, in := pgUpdateEnv(t, "cli_update_ok_6b1", "CREATE TABLE update_probe (id int);\n")
	var out bytes.Buffer
	e.u.out = &out
	if err := e.u.run("apply", e.src, false); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !probeExists(t, in) {
		t.Fatal("миграция не применена")
	}
	if got := auditActions(t, in); got != "update.started,update.install" {
		t.Fatalf("аудит: %s", got)
	}
	entries, err := os.ReadDir(e.u.state.dir)
	if err != nil {
		t.Fatal(err)
	}
	dumps := 0
	for _, en := range entries {
		if updateIDRe.MatchString(en.Name()) {
			info, err := os.Stat(filepath.Join(e.u.state.dir, en.Name(), dumpFile))
			if err != nil || info.Mode().Perm() != 0o600 || info.Size() == 0 {
				t.Fatalf("копия БД: %v %v", info, err)
			}
			dumps++
		}
	}
	if dumps != 1 {
		t.Fatalf("копий БД: %d", dumps)
	}
}
