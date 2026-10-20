package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/store"
)

func TestAuditErrors(t *testing.T) {
	var out, errb bytes.Buffer
	for name, args := range map[string][]string{
		"без подкоманды":  nil,
		"неизвестная":     {"purge"},
		"лишний аргумент": {"verify", "x"},
	} {
		if err := auditCmd(args, "postgres://u@127.0.0.1:1/x", &out, &errb); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if err := auditCmd([]string{"verify"}, "", &out, &errb); err == nil {
		t.Error("пустая строка подключения принята")
	}
	if err := auditCmd([]string{"verify"}, "postgres://u@127.0.0.1:1/x", &out, &errb); err == nil {
		t.Error("недоступная БД принята")
	}
	if code := run([]string{"audit"}, &out, &errb, time.Now()); code != 1 {
		t.Errorf("код %d", code)
	}
}

// Проверка по команде на живой БД (AISEC_TEST_DATABASE_URL): миграции,
// затем audit verify — цепочка цела, итог записан в журнал.
func TestAuditVerifyOnRealDB(t *testing.T) {
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	const schema = "cli_audit_test"
	reset := func(create bool) {
		t.Helper()
		if _, err := admin.Pool().Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
			t.Fatal(err)
		}
		if create {
			if _, err := admin.Pool().Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
				t.Fatal(err)
			}
		}
	}
	reset(true)
	defer reset(false)
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	sdsn := dsn + sep + "search_path=" + schema
	var out, errb bytes.Buffer
	if err := migrate(nil, sdsn, &out, &errb); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		out.Reset()
		if err := auditCmd([]string{"verify"}, sdsn, &out, &errb); err != nil {
			t.Fatalf("%v: %s", err, errb.String())
		}
		if !strings.Contains(out.String(), "Цепочка цела") {
			t.Fatalf("вывод: %s", out.String())
		}
	}
	// Вторая проверка видит запись о первой.
	if !strings.Contains(out.String(), "Проверено записей: 1") {
		t.Fatalf("вывод: %s", out.String())
	}
}
