package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

func TestRestoreFinishArgs(t *testing.T) {
	var out, errb bytes.Buffer
	const dsn = "postgres://u@127.0.0.1:1/x"
	for name, args := range map[string][]string{
		"лишний аргумент":  {"x"},
		"неизвестный флаг": {"-max-age", "1h"},
		"путь в имени":     {"-copy-dir", "/var/backups/aisec-1"},
		"«..» в имени":     {"-copy-dir", "a/../b"},
		"длинное имя":      {"-copy-dir", strings.Repeat("a", 129)},
		"пробел в имени":   {"-copy-dir", "aisec 1"},
		"недоступная БД":   {"-copy-dir", "aisec-20261022T101500Z"},
	} {
		if err := restoreFinish(args, dsn, &out, &errb, time.Now()); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if err := restoreFinish(nil, "", &out, &errb, time.Now()); err == nil || !strings.Contains(err.Error(), "AISEC_DATABASE_URL") {
		t.Errorf("пустая строка подключения: %v", err)
	}
	if !copyDirRe.MatchString(strings.Repeat("a", 128)) || !copyDirRe.MatchString("aisec-20261022T101500Z") {
		t.Error("допустимое имя каталога отвергнуто")
	}
	if code := run([]string{"restore-finish", "x"}, &out, &errb, time.Now()); code != 1 {
		t.Errorf("код %d", code)
	}
}

// В2 ревью B1 этапа 3 (РВ.2): после восстановления полной копии все
// сессии и токены API завершены одной транзакцией с записью
// system.restored; давность — по последней записи журнала аудита.
func TestRestoreFinishOnRealDB(t *testing.T) {
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
	const schema = "cli_restore_finish_test"
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
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := admin.Pool().Exec(ctx, "SET search_path = "+schema); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Pool().Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := admin.Pool().QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	addAdmin(ctx, t, sdsn)
	const (
		user  = "01900000-0000-7000-8000-00000000c001"
		user2 = "01900000-0000-7000-8000-00000000c002"
	)
	exec(`INSERT INTO users (id, org_id, login, display_name, role, status, password_hash, password_changed_at,
		must_change_password, created_at, created_by) SELECT $1, org_id, 'duty', 'Синтетический дежурный', 'auditor', 'active',
		password_hash, now(), false, now(), 'test' FROM users WHERE id = $2`, user2, user)
	// Сессии: две действующие у разных пользователей (активность — сейчас,
	// как у копии, снятой минуту назад) и одна завершённая до копии.
	for i, s := range []struct {
		user, revoked string
	}{{user, ""}, {user2, ""}, {user, "logout"}} {
		id := "01900000-0000-7000-8000-0000000d000" + string(rune('1'+i))
		if s.revoked == "" {
			exec(`INSERT INTO sessions (id, user_id, token_hash, csrf_hash, state, created_at, last_seen_at, expires_at, user_agent)
				VALUES ($1, $2, $3, $4, 'active', now(), now(), now() + interval '1 hour', 'test')`,
				id, s.user, bytes.Repeat([]byte{byte(i + 1)}, 32), bytes.Repeat([]byte{byte(i + 11)}, 32))
			continue
		}
		exec(`INSERT INTO sessions (id, user_id, token_hash, csrf_hash, state, created_at, last_seen_at, expires_at, user_agent,
			revoked_at, revoke_reason) VALUES ($1, $2, $3, $4, 'active', now() - interval '2 days', now() - interval '2 days',
			now() + interval '1 hour', 'test', now() - interval '2 days', $5)`,
			id, s.user, bytes.Repeat([]byte{byte(i + 1)}, 32), bytes.Repeat([]byte{byte(i + 11)}, 32), s.revoked)
	}
	exec(`INSERT INTO api_tokens (id, org_id, user_id, name, prefix, token_hash, hash_alg, permissions, expires_at, created_at)
		VALUES ('01900000-0000-7000-8000-0000000e0001', $1, $2, 'ci', 'aisec_pat_abcd1234', $3, 'SHA-256', '{events.read:all}',
		now() + interval '10 days', now())`, audit.DefaultOrgID, user2, bytes.Repeat([]byte{7}, 32))
	exec(`INSERT INTO api_tokens (id, org_id, user_id, name, prefix, token_hash, hash_alg, permissions, expires_at, created_at,
		revoked_at, revoked_by, revoke_reason) VALUES ('01900000-0000-7000-8000-0000000e0002', $1, $2, 'old', 'aisec_pat_zzzz9999',
		$3, 'SHA-256', '{events.read:all}', now() + interval '10 days', now() - interval '1 day', now() - interval '1 day', $2, 'owner')`,
		audit.DefaultOrgID, user, bytes.Repeat([]byte{8}, 32))

	// 3В21 ревью 3.r3: токены регистрации шлюзов (новый и -reregister,
	// который гасит прежний токен gw-1) и непогашенный токен первичной
	// настройки — в копии они действуют.
	for _, args := range [][]string{{"token", "-name", "gw-1"}, {"token", "-name", "gw-1", "-reregister"}, {"token", "-name", "gw-2"}} {
		if err := gatewayCmd(args, sdsn, &out, &errb); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	exec(`INSERT INTO setup_tokens (id, org_id, hash_alg, token_hash, created_at, expires_at)
		VALUES ('01900000-0000-7000-8000-0000000f0001', $1, 'SHA-256', $2, now(), now() + interval '1 day')`,
		audit.DefaultOrgID, bytes.Repeat([]byte{9}, 32))
	type gwToken struct {
		alg  string
		hash []byte
	}
	var live []gwToken
	rows, err := admin.Pool().Query(ctx, "SELECT hash_alg, token_hash FROM "+schema+".gateway_tokens WHERE used_at IS NULL")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var tk gwToken
		if err := rows.Scan(&tk.alg, &tk.hash); err != nil {
			t.Fatal(err)
		}
		live = append(live, tk)
	}
	rows.Close()
	if len(live) != 2 {
		t.Fatalf("действующих токенов регистрации до restore-finish: %d", len(live))
	}

	// Свежая копия: всё действующее завершено, завершённое не тронуто.
	out.Reset()
	errb.Reset()
	if err := restoreFinish([]string{"-copy-dir", "aisec-20261022T101500Z"}, sdsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("%v\n%s", err, errb.String())
	}
	if !strings.Contains(out.String(), "сессий консоли завершено 2, токенов API отозвано 1, токенов регистрации шлюзов погашено 2, "+
		"токенов первичной настройки погашено 1") || !strings.Contains(out.String(), "-reregister") || strings.Contains(errb.String(), "ВНИМАНИЕ") {
		t.Fatalf("вывод:\n%s\n%s", out.String(), errb.String())
	}
	// Регистрация по токену из копии отвергается тем же запросом, что у сервера.
	gdb, err := store.Open(ctx, sdsn, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer gdb.Close()
	gp, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	gl, err := openAuditLog(gdb, gp, nil)
	if err != nil {
		t.Fatal(err)
	}
	gst, err := gwregistry.NewPGStore(gdb.Pool(), gl)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range live {
		_, err := gst.Register(ctx, tk.alg, tk.hash, time.Now(), func(gwregistry.Gateway) (gwregistry.Issued, error) {
			t.Fatal("сертификат выпущен по погашенному токену")
			return gwregistry.Issued{}, nil
		}, func(gwregistry.Gateway) audit.Entry { return audit.Entry{} })
		if !errors.Is(err, gwregistry.ErrTokenInvalid) {
			t.Fatalf("регистрация по токену копии: %v", err)
		}
	}
	if n := count("SELECT count(*) FROM " + schema + ".setup_tokens WHERE used_at IS NULL"); n != 0 {
		t.Fatalf("непогашенных токенов первичной настройки: %d", n)
	}
	if n := count("SELECT count(*) FROM " + schema + ".sessions WHERE revoked_at IS NULL"); n != 0 {
		t.Fatalf("действующих сессий: %d", n)
	}
	if n := count("SELECT count(*) FROM " + schema + ".sessions WHERE revoke_reason = 'backup_restore'"); n != 2 {
		t.Fatalf("сессий с причиной backup_restore: %d", n)
	}
	if n := count("SELECT count(*) FROM " + schema + ".sessions WHERE revoke_reason = 'logout'"); n != 1 {
		t.Fatalf("завершённая до копии сессия изменена: %d", n)
	}
	if n := count("SELECT count(*) FROM " + schema + ".api_tokens WHERE revoke_reason = 'backup_restore' AND revoked_by IS NULL"); n != 1 {
		t.Fatalf("отозванных токенов: %d", n)
	}
	if n := count("SELECT count(*) FROM " + schema + ".api_tokens WHERE revoke_reason = 'owner'"); n != 1 {
		t.Fatalf("отозванный до копии токен изменён: %d", n)
	}
	type rec struct {
		actorType string
		details   map[string]any
	}
	records := func() []rec {
		t.Helper()
		rows, err := admin.Pool().Query(ctx, "SELECT actor_type, details::text FROM "+schema+".audit_log WHERE action = 'system.restored' ORDER BY seq")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var rs []rec
		for rows.Next() {
			var (
				r   rec
				raw string
			)
			if err := rows.Scan(&r.actorType, &raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(raw), &r.details); err != nil {
				t.Fatal(err)
			}
			rs = append(rs, r)
		}
		return rs
	}
	rs := records()
	if len(rs) != 1 || rs[0].actorType != string(audit.ActorCLI) || rs[0].details["revoked_sessions"] != float64(2) ||
		rs[0].details["revoked_api_tokens"] != float64(1) || rs[0].details["stale_copy"] != false ||
		rs[0].details["copy_dir"] != "aisec-20261022T101500Z" || rs[0].details["copy_age_hours"] != float64(0) ||
		rs[0].details["expired_gateway_tokens"] != float64(2) || rs[0].details["expired_setup_tokens"] != float64(1) {
		t.Fatalf("записи system.restored: %+v", rs)
	}

	// Повторный запуск через 8 суток: отзывать нечего, давность — по
	// последней записи копии, а не по прежней system.restored;
	// предупреждение, код возврата — успех.
	out.Reset()
	errb.Reset()
	if err := restoreFinish(nil, sdsn, &out, &errb, time.Now().Add(8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "завершено 0, токенов API отозвано 0") || !strings.Contains(errb.String(), "старше 7 суток") {
		t.Fatalf("вывод:\n%s\n%s", out.String(), errb.String())
	}
	rs = records()
	if len(rs) != 2 || rs[1].details["stale_copy"] != true || rs[1].details["copy_age_hours"].(float64) < 191 {
		t.Fatalf("повторная запись: %+v", rs)
	}
	if _, ok := rs[1].details["copy_dir"]; ok {
		t.Fatal("copy_dir без флага")
	}
}
