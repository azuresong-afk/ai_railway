package main

import (
	"bytes"
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

func TestGatewayCmdErrors(t *testing.T) {
	var out, errb bytes.Buffer
	const dsn = "postgres://u@127.0.0.1:1/x"
	for name, args := range map[string][]string{
		"без подкоманды":     nil,
		"неизвестная":        {"delete"},
		"токен без имени":    {"token"},
		"токен, плохое имя":  {"token", "-name", "Шлюз"},
		"токен, лишнее":      {"token", "-name", "gw", "x"},
		"отзыв без имени":    {"revoke"},
		"отзыв, лишнее":      {"revoke", "-name", "gw", "x"},
		"список, лишнее":     {"list", "x"},
		"токен, плохой срок": {"token", "-name", "gw", "-ttl", "сутки"},
		"недоступная БД":     {"token", "-name", "gw"},
	} {
		if err := gatewayCmd(args, dsn, &out, &errb); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if err := gatewayCmd([]string{"list"}, "", &out, &errb); err == nil {
		t.Error("пустая строка подключения принята")
	}
	if code := run([]string{"gateway"}, &out, &errb, time.Now()); code != 1 {
		t.Errorf("код %d", code)
	}
}

// Команды на живой БД (AISEC_TEST_DATABASE_URL): токен, список, повторный
// токен, отзыв; токен печатается один раз в формате aisec_gwreg_.
func TestGatewayCmdOnRealDB(t *testing.T) {
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
	const schema = "cli_gateway_test"
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
	cmd := func(args ...string) (string, error) {
		out.Reset()
		errb.Reset()
		err := gatewayCmd(args, sdsn, &out, &errb)
		return out.String(), err
	}
	tokenRe := regexp.MustCompile(regexp.QuoteMeta(gwregistry.TokenPrefix) + `[A-Za-z0-9_-]{43}`)
	s, err := cmd("token", "-name", "gw-1", "-ttl", "1h")
	if err != nil || len(tokenRe.FindAllString(s, -1)) != 1 {
		t.Fatalf("token: %v\n%s", err, s)
	}
	if _, err := cmd("token", "-name", "gw-1"); err == nil || !strings.Contains(err.Error(), "-reregister") {
		t.Fatalf("повторное имя: %v", err)
	}
	if s, err = cmd("token", "-name", "gw-1", "-reregister"); err != nil || !tokenRe.MatchString(s) {
		t.Fatalf("reregister: %v %s", err, s)
	}
	if s, err = cmd("list"); err != nil || !strings.Contains(s, "gw-1") || !strings.Contains(s, "pending") {
		t.Fatalf("list: %v\n%s", err, s)
	}
	if _, err = cmd("revoke", "-name", "gw-1"); err != nil {
		t.Fatal(err)
	}
	if _, err = cmd("revoke", "-name", "gw-1"); err == nil {
		t.Fatal("повторный отзыв принят")
	}
	if _, err = cmd("revoke", "-name", "nope"); err == nil {
		t.Fatal("отзыв неизвестного принят")
	}
	if s, err = cmd("list"); err != nil || !strings.Contains(s, "revoked") {
		t.Fatalf("list после отзыва: %v\n%s", err, s)
	}
	var n int
	if err := admin.Pool().QueryRow(ctx, "SELECT count(*) FROM "+schema+".audit_log WHERE action LIKE 'gateway.%'").Scan(&n); err != nil || n != 3 {
		t.Fatalf("записей аудита о шлюзах: %d %v", n, err)
	}
}
