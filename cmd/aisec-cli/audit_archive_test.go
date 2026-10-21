package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

func TestAuditArchiveArgs(t *testing.T) {
	const dsn = "postgres://u@127.0.0.1:1/x"
	dir := keyDir(t)
	out := filepath.Join(t.TempDir(), "a.jsonl")
	var stdout, errb bytes.Buffer
	for name, args := range map[string][]string{
		"archive без -keys":        {"archive", "-out", out},
		"archive без -out":         {"archive", "-keys", dir},
		"archive лишний аргумент":  {"archive", "-keys", dir, "-out", out, "x"},
		"archive неверная дата":    {"archive", "-keys", dir, "-out", out, "-before", "21.10.2026"},
		"archive нет ключей":       {"archive", "-keys", dir, "-out", out},
		"export без -out":          {"export"},
		"export неверная дата":     {"export", "-out", out, "-from", "вчера"},
		"export лишний аргумент":   {"export", "-out", out, "x"},
		"export недоступная БД":    {"export", "-out", out},
		"verify-archive без -keys": {"verify-archive", out},
		"verify-archive без файла": {"verify-archive", "-keys", dir},
		"verify-archive нет ключа": {"verify-archive", "-keys", dir, out},
		"verify нет ключа":         {"verify", "-keys", dir},
	} {
		if err := auditCmd(args, dsn, &stdout, &errb); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if err := auditCmd([]string{"archive", "-keys", dir, "-out", out}, "", &stdout, &errb); err == nil {
		t.Error("archive без строки подключения принят")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("при ошибке создан файл: %v", err)
	}
}

// Архивация на живой БД (AISEC_TEST_DATABASE_URL): старые записи,
// init с ключом аудита, archive, проверка архива без БД и цепочки от
// контрольной точки, подмена файла (код 3), повторная архивация, выгрузка.
func TestAuditArchiveOnRealDB(t *testing.T) {
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
	const schema = "cli_archive_test"
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
	// USAGE на тестовую схему; в поставке схема — public.
	if _, err := admin.Pool().Exec(ctx, "GRANT USAGE ON SCHEMA "+schema+" TO aisec_audit_archiver"); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, sdsn, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := time.Now().AddDate(-2, 0, 0)
	oldLog, err := audit.New(db.Pool(), standardProvider(t), audit.WithClock(func() time.Time { return old }))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := oldLog.Record(ctx, audit.Entry{
			Actor: audit.Actor{Type: audit.ActorUser, ID: "u-1", Name: "admin"}, Action: "auth.login", Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}
	dir := keyDir(t)
	if err := initCmd([]string{"-dir", dir}, sdsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}

	file := filepath.Join(t.TempDir(), "audit-2024.jsonl")
	out.Reset()
	if err := auditCmd([]string{"archive", "-keys", dir, "-out", file}, sdsn, &out, &errb); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	if !strings.Contains(out.String(), "Архивировано записей: 3 (номера 1–3") {
		t.Fatalf("вывод: %s", out.String())
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("файл архива: %v %v", info, err)
	}
	out.Reset()
	if err := auditCmd([]string{"verify-archive", "-keys", dir, file}, "", &out, &errb); err != nil || !strings.Contains(out.String(), "Архив действителен: записи 1–3 (3)") {
		t.Fatalf("verify-archive: %v %s", err, out.String())
	}
	for _, args := range [][]string{{"verify", "-keys", dir}, {"verify"}} {
		out.Reset()
		if err := auditCmd(args, sdsn, &out, &errb); err != nil || !strings.Contains(out.String(), "Цепочка цела") {
			t.Fatalf("%v после архивации: %v %s", args, err, out.String())
		}
	}

	// Подменённый архив — код 3.
	data, err := os.ReadFile(file) //nolint:gosec // G304: файл во временном каталоге теста
	if err != nil {
		t.Fatal(err)
	}
	forged := filepath.Join(t.TempDir(), "forged.jsonl")
	if err := os.WriteFile(forged, bytes.Replace(data, []byte(`"name":"admin"`), []byte(`"name":"guest"`), 1), 0o600); err != nil { //nolint:gosec // G703: путь во временном каталоге теста
		t.Fatal(err)
	}
	if code := run([]string{"audit", "verify-archive", "-keys", dir, forged}, &out, &errb, time.Now()); code != 3 {
		t.Fatalf("подменённый архив: код %d", code)
	}

	// Повторно архивировать нечего, файл не остаётся; существующий файл не
	// перезаписывается.
	again := filepath.Join(t.TempDir(), "again.jsonl")
	out.Reset()
	if err := auditCmd([]string{"archive", "-keys", dir, "-out", again}, sdsn, &out, &errb); err != nil || !strings.Contains(out.String(), "Нет записей") {
		t.Fatalf("повторная архивация: %v %s", err, out.String())
	}
	if _, err := os.Stat(again); !os.IsNotExist(err) {
		t.Fatalf("пустой архив не удалён: %v", err)
	}
	if err := auditCmd([]string{"archive", "-keys", dir, "-out", file}, sdsn, &out, &errb); err == nil {
		t.Fatal("архив перезаписан")
	}

	// Выгрузка (РСБ.5).
	exp := filepath.Join(t.TempDir(), "export.jsonl")
	out.Reset()
	if err := auditCmd([]string{"export", "-out", exp, "-from", time.Now().AddDate(0, 0, -1).Format(time.DateOnly)}, sdsn, &out, &errb); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	if !strings.Contains(out.String(), "Выгружено записей:") {
		t.Fatalf("вывод: %s", out.String())
	}
	// В выводе команд нет закрытого ключа аудита.
	key, err := os.ReadFile(filepath.Join(dir, auditKeyFile)) //nolint:gosec // G304: файл во временном каталоге теста
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String()+errb.String(), strings.Split(string(key), "\n")[3]) {
		t.Fatal("ключ аудита в выводе")
	}
}
