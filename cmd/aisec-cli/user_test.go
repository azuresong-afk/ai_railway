package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

func TestUserCmdErrors(t *testing.T) {
	var out, errb bytes.Buffer
	const dsn = "postgres://u@127.0.0.1:1/x"
	for name, args := range map[string][]string{
		"без подкоманды":   nil,
		"неизвестная":      {"delete"},
		"без логина":       {"unlock"},
		"лишний аргумент":  {"reset-password", "-login", "admin", "x"},
		"неизвестный флаг": {"reset-mfa", "-user", "admin"},
		"недоступная БД":   {"unlock", "-login", "admin"},
	} {
		if err := userCmd(args, dsn, &out, &errb); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if err := userCmd([]string{"unlock", "-login", "admin"}, "", &out, &errb); err == nil {
		t.Error("пустая строка подключения принята")
	}
	if code := run([]string{"user"}, &out, &errb, time.Now()); code != 1 {
		t.Errorf("код %d", code)
	}
}

// В7 ревью 2.r2: единственного администратора безопасности разблокирует и
// восстанавливает aisec-cli; в записи аудита — пользователь ОС и логин СУБД
// (Н5 ревью 2.r1).
func TestUserCmdOnRealDB(t *testing.T) {
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
	const schema = "cli_user_test"
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
	addAdmin(ctx, t, sdsn)
	if _, err := admin.Pool().Exec(ctx, "UPDATE "+schema+".users SET failed_attempts = 5, locked_at = now() WHERE login = 'admin'"); err != nil {
		t.Fatal(err)
	}
	cmd := func(args ...string) (string, error) {
		out.Reset()
		errb.Reset()
		err := userCmd(args, sdsn, &out, &errb)
		return out.String(), err
	}
	if _, err := cmd("unlock", "-login", "admin"); err != nil {
		t.Fatal(err)
	}
	var locked bool
	if err := admin.Pool().QueryRow(ctx, "SELECT locked_at IS NOT NULL OR failed_attempts > 0 FROM "+schema+".users WHERE login = 'admin'").
		Scan(&locked); err != nil || locked {
		t.Fatalf("блокировка не снята: %v", err)
	}
	var actorType, raw string
	if err := admin.Pool().QueryRow(ctx, "SELECT actor_type, details::text FROM "+schema+".audit_log WHERE action = 'auth.unlocked'").
		Scan(&actorType, &raw); err != nil {
		t.Fatal(err)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		t.Fatal(err)
	}
	var dbUser string
	if err := admin.Pool().QueryRow(ctx, "SELECT session_user::text").Scan(&dbUser); err != nil {
		t.Fatal(err)
	}
	if actorType != string(audit.ActorCLI) || details["db_user"] != dbUser || details["was_locked"] != true {
		t.Fatalf("запись auth.unlocked: %s %v", actorType, details)
	}
	s, err := cmd("reset-password", "-login", "admin")
	if err != nil || !strings.Contains(s, "Временный пароль") {
		t.Fatalf("reset-password: %v\n%s", err, s)
	}
	var mustChange bool
	if err := admin.Pool().QueryRow(ctx, "SELECT must_change_password FROM "+schema+".users WHERE login = 'admin'").
		Scan(&mustChange); err != nil || !mustChange {
		t.Fatalf("временный пароль не выдан: %v", err)
	}
	if _, err := cmd("reset-mfa", "-login", "admin"); err == nil || !strings.Contains(err.Error(), "нет второго фактора") {
		t.Fatalf("reset-mfa без фактора: %v", err)
	}
	if _, err := cmd("unlock", "-login", "nobody"); err == nil || !strings.Contains(err.Error(), "нет") {
		t.Fatalf("неизвестный логин: %v", err)
	}
}

// addAdmin создаёт администратора безопасности admin. Пул из одного
// соединения: первая запись в пустой журнал читает контрольную точку в своей
// транзакции, второе соединение не нужно (Н8 ревью 2.r1).
func addAdmin(ctx context.Context, t *testing.T, dsn string) {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	pw, err := p.PasswordHasher()
	if err != nil {
		t.Fatal(err)
	}
	h, err := pw.Hash(ctx, []byte("Синтетический-пароль-2026"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	l, err := openAuditLog(db, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := auth.NewPGStore(db.Pool(), l)
	if err != nil {
		t.Fatal(err)
	}
	const id = "01900000-0000-7000-8000-00000000c001"
	now := time.Now().UTC()
	u := auth.User{ID: id, OrgID: audit.DefaultOrgID, Login: "admin", DisplayName: "Администратор", Role: auth.RoleSecurityAdmin,
		Status: auth.StatusActive, PasswordHash: h, PasswordChangedAt: now, CreatedAt: now, CreatedBy: "test"}
	rec := audit.Entry{Actor: cliActor(), Action: "user.create", Object: audit.Object{Type: "user", ID: id}, Result: audit.ResultSuccess}
	if err := st.CreateUser(ctx, u, rec); err != nil {
		t.Fatal(err)
	}
}
