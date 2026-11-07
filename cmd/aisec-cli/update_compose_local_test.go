package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// localPG выполняет «docker compose exec postgres …» как обычные процессы
// на этой машине, а «docker compose run aisec-cli update-db …» — вызовом
// updateDBCmd: сценарии копии и восстановления проверяются на настоящем
// PostgreSQL без Docker.
type localPG struct{ dsn string }

func (l *localPG) Run(ctx context.Context, c dockerCall) (string, error) {
	a := c.Args
	if a[1] == "run" {
		var out bytes.Buffer
		err := updateDBCmd(a[7:], l.dsn, c.Stdin, &out)
		return out.String(), err
	}
	cmd := exec.CommandContext(ctx, a[4], a[5:]...) //nolint:gosec // G204: тест; сценарии — константы пакета
	cmd.Stdin = c.Stdin
	var out, eb bytes.Buffer
	cmd.Stdout = &out
	if c.Stdout != nil {
		cmd.Stdout = c.Stdout
	}
	cmd.Stderr = &eb
	if err := cmd.Run(); err != nil {
		return out.String(), &localErr{err, lastLine(eb.String())}
	}
	return strings.TrimSpace(out.String()), nil
}

type localErr struct {
	err error
	msg string
}

func (e *localErr) Error() string { return e.err.Error() + ": " + e.msg }

// Копия и восстановление БД установки compose сценариями из контейнера
// postgres на настоящем PostgreSQL. Нужны: роль aisec_owner с паролем из
// /run/secrets/db-owner-password, пустая база aisec и клиенты PostgreSQL в
// PATH — поэтому тест включается переменной AISEC_TEST_COMPOSE_LOCAL=1
// (ручная проверка 11, «сценарии БД без Docker»).
func TestComposeDBScriptsOnRealPostgres(t *testing.T) {
	if os.Getenv("AISEC_TEST_COMPOSE_LOCAL") != "1" {
		t.Skip("AISEC_TEST_COMPOSE_LOCAL=1 не задан")
	}
	pw, err := os.ReadFile("/run/secrets/db-owner-password")
	if err != nil {
		t.Skip("нет /run/secrets/db-owner-password")
	}
	dsn := "postgres://aisec_owner:" + strings.TrimSpace(string(pw)) + "@127.0.0.1:5432/aisec?sslmode=disable"
	ctx := context.Background()
	var o, eb bytes.Buffer
	if err := migrate(nil, dsn, &o, &eb); err != nil {
		t.Fatal(err, eb.String())
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx) //nolint:errcheck // тест
	c := &composeDB{sys: &composeSys{r: &localPG{dsn: dsn}}, p: standardProvider(t)}
	dump := filepath.Join(t.TempDir(), dumpFile)
	before, err := c.Applied(ctx)
	if err != nil || len(before) == 0 {
		t.Fatal(err, before)
	}
	if err := c.Dump(ctx, dump); err != nil {
		t.Fatal(err)
	}
	probe := func() bool {
		var ok bool
		if err := conn.QueryRow(ctx, "SELECT to_regclass('update_probe') IS NOT NULL").Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	// «Миграция нового выпуска»: таблица и запись о ней.
	if _, err := conn.Exec(ctx, "CREATE TABLE update_probe (id int); INSERT INTO schema_migrations(version, name, checksum) VALUES (9999, 'probe', 'x')"); err != nil {
		t.Fatal(err)
	}
	// Повреждённая копия: pg_restore не замечает обрезанных данных (код 0),
	// поэтому восстановление её отвергает по контрольной сумме.
	data, err := os.ReadFile(dump) //nolint:gosec // G304: копия теста
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dump, data[:len(data)*7/10], 0o600); err != nil { //nolint:gosec // G703: путь — в t.TempDir()
		t.Fatal(err)
	}
	if err := c.Restore(ctx, dump); err == nil || !strings.Contains(err.Error(), "контрольная сумма") || !probe() {
		t.Fatalf("обрезанная копия: %v, изменение осталось: %v", err, probe())
	}
	if err := os.WriteFile(dump, data, 0o600); err != nil { //nolint:gosec // G703: путь — в t.TempDir()
		t.Fatal(err)
	}
	if err := c.Restore(ctx, dump); err != nil {
		t.Fatal(err)
	}
	if probe() {
		t.Fatal("таблица новой миграции осталась после восстановления")
	}
	after, err := c.Applied(ctx)
	if err != nil || len(after) != len(before) {
		t.Fatalf("миграций %d, до обновления %d (%v)", len(after), len(before), err)
	}
	// Нет файлов заголовка и списка (контейнер postgres перезапускался между
	// записью файлов и восстановлением): сценарий обязан упасть, а не
	// зафиксировать пустую транзакцию и сообщить об успехе.
	if _, err := conn.Exec(ctx, "CREATE TABLE update_probe (id int)"); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dump) //nolint:gosec // G304: копия теста
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // тест
	if _, err := c.exec(ctx, dockerCall{Stdin: f}, "sh", "-c", restoreScript, "sh"); err == nil || !probe() {
		t.Fatalf("восстановление без заголовка и списка: ошибка %v, таблица осталась: %v", err, probe())
	}
}
