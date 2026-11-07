package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/store"
)

// aisec-cli update-db на живой PostgreSQL (задача 6.21, ADR-0036, раздел 7):
// список миграций и размер, заголовок восстановления, запись в журнал
// аудита — то, что обновление compose делает в одноразовом контейнере.
func TestUpdateDBCmdOnRealDB(t *testing.T) {
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	in := newInstallation(t, admin, base, "cli_update_db_6c1")

	var out bytes.Buffer
	if err := updateDBCmd([]string{"info"}, in.dsn, nil, &out); err != nil {
		t.Fatal(err)
	}
	var info dbInfo
	if err := lenientJSON(out.Bytes(), &info); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if info.Schema != "cli_update_db_6c1" || info.Size <= 0 || len(info.Applied) == 0 || info.Applied[0].Version != 1 || len(info.Applied[0].Checksum) != 64 {
		t.Fatalf("info: %+v", info)
	}

	out.Reset()
	if err := updateDBCmd([]string{"header"}, in.dsn, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `DROP SCHEMA "cli_update_db_6c1" CASCADE;`) || !strings.Contains(out.String(), "CREATE SCHEMA") {
		t.Fatalf("header: %s", out.String())
	}

	rec := `{"action":"update.started","result":"success","object_id":"2.0-0123456789ab","details":{"component":"aisec","update_id":"20261107T000000Z"}}`
	if err := updateDBCmd([]string{"audit"}, in.dsn, strings.NewReader(rec), &out); err != nil {
		t.Fatal(err)
	}
	if got := auditActions(t, in); got != "update.started" {
		t.Fatalf("аудит: %s", got)
	}

	for name, c := range map[string]struct {
		args  []string
		dsn   string
		stdin string
	}{
		"нет подкоманды":       {nil, in.dsn, ""},
		"неизвестная":          {[]string{"drop"}, in.dsn, ""},
		"нет строки":           {[]string{"info"}, "", ""},
		"чужой код аудита":     {[]string{"audit"}, in.dsn, `{"action":"user.delete","result":"success","object_id":"rejected"}`},
		"аудит не JSON":        {[]string{"audit"}, in.dsn, `не json`},
		"аудит больше предела": {[]string{"audit"}, in.dsn, strings.Repeat("x", maxUpdateAuditWire+1)},
	} {
		if err := updateDBCmd(c.args, c.dsn, strings.NewReader(c.stdin), &out); err == nil {
			t.Fatalf("%s: ошибка не возвращена", name)
		}
	}
	if got := auditActions(t, in); got != "update.started" {
		t.Fatalf("отвергнутые записи попали в аудит: %s", got)
	}
}
