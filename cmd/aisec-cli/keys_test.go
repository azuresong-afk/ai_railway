package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

func TestKeysCmdErrors(t *testing.T) {
	var out, errb bytes.Buffer
	now := time.Now()
	for _, tc := range []struct {
		args []string
		dsn  string
		want string
	}{
		{nil, "postgres://x", "подкоманду"},
		{[]string{"status"}, "", "AISEC_DATABASE_URL"},
		{[]string{"rotate-data"}, "postgres://x", "-dir"},
		{[]string{"rotate-master"}, "postgres://x", "-dir"},
		{[]string{"rotate-data", "-dir", t.TempDir(), "-batch", "0"}, "postgres://x", "batch"},
		{[]string{"rotate-data", "-dir", t.TempDir(), "-settle", "2h"}, "postgres://x", "settle"},
		{[]string{"rotate-data", "-dir", "/нет/такого"}, "postgres://x", "каталог ключей"},
		{[]string{"rotate-master", "-dir", keyDir(t), "лишний"}, "postgres://x", "лишние"},
		{[]string{"wipe"}, "postgres://x", "неизвестная"},
	} {
		err := keysCmd(tc.args, tc.dsn, &out, &errb, now)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: ошибка %v, ожидалось «%s»", tc.args, err, tc.want)
		}
	}
	open := t.TempDir()
	if err := os.Chmod(open, 0o755); err != nil { //nolint:gosec // тест: каталог, открытый для группы, — проверка отказа
		t.Fatal(err)
	}
	if err := keysCmd([]string{"rotate-master", "-dir", open}, "postgres://x", &out, &errb, now); err == nil ||
		!strings.Contains(err.Error(), "0700") {
		t.Errorf("каталог 0755: %v", err)
	}
}

// keysInstallation — установка с секретами всех видов под ключом данных:
// TOTP (подключённый и в ожидании), учётные данные провайдера и
// содержимое событий full за двое суток.
func keysInstallation(t *testing.T, schema string) (*installation, *keysEnv, []string) {
	t.Helper()
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, base, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	in := newInstallation(t, admin, base, schema)
	populate(t, in)
	in.exec(t, "SELECT events_ensure_partitions(3, 1)")
	var ids []string
	now := time.Now().UTC()
	for i, ts := range []time.Time{now.Add(-48 * time.Hour), now.Add(-24 * time.Hour), now} {
		id := "0192a000-0000-7000-8000-00000000060" + string(rune('1'+i))
		keyID, alg, sealed, err := in.box.SealDerived(ctx, events.ContentKeyPurpose, ts, contentPlain(i), "event_content", "sealed", id)
		if err != nil {
			t.Fatal(err)
		}
		in.exec(t, `INSERT INTO event_content (event_id, ts, org_id, storage, key_id, key_day, alg, sealed)
			VALUES ($1, $2, $3, 'full', $4, ($2 AT TIME ZONE 'UTC')::date, $5, $6)`, id, ts, audit.DefaultOrgID, keyID, alg, sealed)
		ids = append(ids, id)
	}
	env, err := openKeysEnv(ctx, in.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	return in, env, ids
}

func contentPlain(i int) []byte {
	return []byte(`{"request":"синтетический запрос ` + string(rune('0'+i)) + `","response":"ответ"}`) //nolint:gosec // i — номер записи теста (0–9)
}

// checkSecrets — все секреты установки расшифровываются box и совпадают
// с исходными; ID ключа у каждой строки — want (пусто — любой).
func checkSecrets(t *testing.T, in *installation, box *keyring.Box, ids []string, want string) {
	t.Helper()
	ctx := context.Background()
	rows, err := in.db.Pool().Query(ctx, `SELECT user_id::text, data_key_id::text, secret FROM user_mfa`)
	if err != nil {
		t.Fatal(err)
	}
	type sec struct {
		id, key string
		data    []byte
	}
	var mfa []sec
	for rows.Next() {
		var s sec
		if err := rows.Scan(&s.id, &s.key, &s.data); err != nil {
			t.Fatal(err)
		}
		mfa = append(mfa, s)
	}
	rows.Close()
	if len(mfa) != 2 {
		t.Fatalf("строк TOTP %d", len(mfa))
	}
	for _, s := range mfa {
		plain, err := box.Open(s.key, s.data, "user_mfa", "secret", s.id)
		if err != nil || !bytes.Equal(plain, tTOTP) || (want != "" && s.key != want) {
			t.Fatalf("TOTP %s: ключ %s, %v", s.id, s.key, err)
		}
	}
	var key string
	var cred []byte
	if err := in.db.Pool().QueryRow(ctx, `SELECT credential_key_id::text, credential FROM providers WHERE id = $1`, tProvider).
		Scan(&key, &cred); err != nil {
		t.Fatal(err)
	}
	if plain, err := box.Open(key, cred, "providers", "credential", tProvider); err != nil || !bytes.Equal(plain, tCredential) ||
		(want != "" && key != want) {
		t.Fatalf("учётные данные провайдера: ключ %s, %v", key, err)
	}
	for i, id := range ids {
		var day time.Time
		var sealed []byte
		if err := in.db.Pool().QueryRow(ctx, `SELECT key_id::text, key_day, sealed FROM event_content WHERE event_id = $1`, id).
			Scan(&key, &day, &sealed); err != nil {
			t.Fatal(err)
		}
		plain, err := box.OpenDerived(key, events.ContentKeyPurpose, day, sealed, "event_content", "sealed", id)
		if err != nil || !bytes.Equal(plain, contentPlain(i)) || (want != "" && key != want) {
			t.Fatalf("содержимое %s: ключ %s, %v", id, key, err)
		}
	}
}

func TestKeysRotateDataOnRealDB(t *testing.T) {
	in, env, ids := keysInstallation(t, "cli_keys_data")
	ctx := context.Background()
	p := standardProvider(t)
	oldID := in.box.KeyID()
	// «Сервер», загрузивший ключ до ротации и ещё не резервировавший шифрований.
	server, err := keyring.Load(ctx, in.db.Pool(), p, in.keys, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	server2, err := keyring.Load(ctx, in.db.Pool(), p, in.keys, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}

	// Чужой каталог ключей: мастер-ключ не открывает ключ данных — отказ
	// без изменений.
	foreign := keyDir(t)
	other, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindMaster, p.Name(), bytes.Repeat([]byte{7}, aisecCrypto.AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, keyring.MasterKeyFile), other, 0o400); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = runRotateData(ctx, env, foreign, rotateDataOptions{Batch: 1}, cliActor(), time.Now(), &out); err == nil {
		t.Fatal("ротация с чужим мастер-ключом прошла")
	}
	if n := in.count(t, "SELECT count(*) FROM data_keys"); n != 1 {
		t.Fatalf("после отказа версий %d", n)
	}

	// Прерывание на середине: после второй пачки по одной строке.
	stop := errors.New("сбой посреди перешифрования")
	err = runRotateData(ctx, env, in.keys, rotateDataOptions{Batch: 1, afterBatch: func(c keyring.RewrapCounts) error {
		if c.Total() == 2 {
			return stop
		}
		return nil
	}}, cliActor(), time.Now(), &out)
	if !errors.Is(err, stop) || !strings.Contains(err.Error(), "-resume") {
		t.Fatalf("прерывание: %v", err)
	}
	if n := in.count(t, "SELECT count(*) FROM data_keys WHERE retired_at IS NOT NULL AND id = $1", oldID); n != 1 {
		t.Fatal("прежняя версия не выведена")
	}
	if n := in.count(t, "SELECT count(*) FROM user_mfa WHERE data_key_id = $1", oldID) +
		in.count(t, "SELECT count(*) FROM providers WHERE credential_key_id = $1", oldID) +
		in.count(t, "SELECT count(*) FROM event_content WHERE key_id = $1", oldID); n != 4 {
		t.Fatalf("после прерывания под прежней версией строк %d, ожидалось 4", n)
	}
	// В середине всё читается: строки обеих версий.
	mid, err := keyring.Load(ctx, in.db.Pool(), p, in.keys, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	checkSecrets(t, in, mid, ids, "")

	// Сервер без резерва шифрует уже новой версией: резерв прежней отклонён,
	// Box перечитывает версии. То же для производного ключа суток.
	newID, _, err := server.SealKey(ctx, []byte("x"), "providers", "credential", tProvider)
	if err != nil || newID == oldID || newID != mid.KeyID() {
		t.Fatalf("сервер после ротации: ключ %s, %v", newID, err)
	}
	kid, _, _, err := server2.SealDerived(ctx, events.ContentKeyPurpose, time.Now(), []byte("{}"), "event_content", "sealed", ids[0])
	if err != nil || kid != newID {
		t.Fatalf("содержимое после ротации: ключ %s, %v", kid, err)
	}
	// Сервер с остатком резерва шифрует прежней версией, пока опрос (Watch)
	// не заметит ротацию; после опроса — новой.
	if kid, _, err := in.box.SealKey(ctx, []byte("x"), "providers", "credential", tProvider); err != nil || kid != newID && kid != oldID {
		t.Fatalf("остаток резерва: %s, %v", kid, err)
	}
	if err := in.box.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if kid, _, err := in.box.SealKey(ctx, []byte("x"), "providers", "credential", tProvider); err != nil || kid != newID {
		t.Fatalf("после опроса: %s, %v", kid, err)
	}

	// Повторный запуск продолжает и удаляет прежнюю версию.
	out.Reset()
	if err := runRotateData(ctx, env, in.keys, rotateDataOptions{Resume: true, Batch: 2}, cliActor(), time.Now(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "удалена") {
		t.Fatalf("вывод: %s", out.String())
	}
	if n := in.count(t, "SELECT count(*) FROM data_keys"); n != 1 {
		t.Fatalf("версий после вывода %d", n)
	}
	if n := in.count(t, "SELECT count(*) FROM derived_key_usage WHERE data_key_id = $1", oldID); n != 0 {
		t.Fatal("счётчики прежней версии остались")
	}
	after, err := keyring.Load(ctx, in.db.Pool(), p, in.keys, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version() != 2 || after.KeyID() != newID {
		t.Fatalf("действующая версия %d %s", after.Version(), after.KeyID())
	}
	checkSecrets(t, in, after, ids, newID)
	// Сервер со старым Box читает и строки новой версии.
	checkSecrets(t, in, in.box, ids, newID)

	// Опора цепочки аудита новым ключом и записи аудита.
	if n := in.count(t, "SELECT count(*) FROM audit_verifications WHERE ok AND mac_key_id = $1", newID); n == 0 {
		t.Fatal("нет опоры цепочки на новом ключе")
	}
	for action, want := range map[string]int{"keys.data_rotated": 1, "keys.data_key_destroyed": 1} {
		if n := in.count(t, "SELECT count(*) FROM audit_log WHERE action = $1", action); n != want {
			t.Errorf("%s: записей %d", action, n)
		}
	}
	if n := in.count(t, "SELECT count(*) FROM audit_log WHERE action = 'keys.data_rewrapped'"); n < 2 {
		t.Errorf("keys.data_rewrapped: записей %d", n)
	}
	if n := in.count(t, "SELECT count(*) FROM audit_log WHERE details::text LIKE '%синтетический%'"); n != 0 {
		t.Fatal("содержимое попало в аудит")
	}

	// Состояние: одна действующая версия, строки под ней.
	out.Reset()
	if err := keysStatusCmd(nil, in.dsn, &out, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "версия 2") || strings.Contains(out.String(), "версия 1") {
		t.Fatalf("состояние: %s", out.String())
	}
}

func TestKeysRewrapGuardsOnRealDB(t *testing.T) {
	in, _, ids := keysInstallation(t, "cli_keys_guard")
	ctx := context.Background()
	old := in.box.KeyID()
	// Подменить секрет подключённого фактора или содержимое события без
	// перехода на новую версию нельзя никому, включая владельца.
	for _, q := range []string{
		"UPDATE user_mfa SET secret = secret || '\\x00'::bytea WHERE user_id = '" + tUser + "'",
		"UPDATE event_content SET sealed = sealed || '\\x00'::bytea WHERE event_id = '" + ids[0] + "'",
		"DELETE FROM event_content WHERE event_id = '" + ids[0] + "'",
		"UPDATE data_keys SET wrapped = wrapped || '\\x00'::bytea WHERE id = '" + old + "'",
		"UPDATE data_keys SET master_version = 2 WHERE id = '" + old + "'",
	} {
		if _, err := in.db.Pool().Exec(ctx, q); err == nil {
			t.Errorf("прошло: %s", q)
		}
	}
	// Переход на более старую версию тоже запрещён: новая версия, затем
	// попытка вернуть строку прежней.
	var out bytes.Buffer
	env, err := openKeysEnv(ctx, in.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	if err := runRotateData(ctx, env, in.keys, rotateDataOptions{Batch: 100}, cliActor(), time.Now(), &out); err != nil {
		t.Fatal(err)
	}
	if _, err := in.db.Pool().Exec(ctx, "INSERT INTO data_keys (id, org_id, version, profile, alg, wrapped, created_at, retired_at) "+
		"SELECT '0192a000-0000-7000-8000-0000000009a1', org_id, 1, profile, alg, wrapped, created_at, now() FROM data_keys LIMIT 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := in.db.Pool().Exec(ctx, "UPDATE user_mfa SET data_key_id = '0192a000-0000-7000-8000-0000000009a1' WHERE user_id = $1", tUser); err == nil {
		t.Error("переход подключённого фактора на старую версию прошёл")
	}
}

func TestKeysRotateMasterOnRealDB(t *testing.T) {
	in, env, ids := keysInstallation(t, "cli_keys_master")
	ctx := context.Background()
	p := standardProvider(t)
	before, err := os.ReadFile(filepath.Join(in.keys, keyring.MasterKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r, err := keyring.RotateMaster(ctx, env.db.Pool(), env.log, p, in.keys, audit.DefaultOrgID, cliActor(), now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Recovered || r.DataKeys != 1 || r.MasterVersion != 2 || r.Retired != "master.key.20261022T120000Z.retired" {
		t.Fatalf("итог: %+v", r)
	}
	retired, err := os.ReadFile(filepath.Join(in.keys, r.Retired))
	if err != nil || !bytes.Equal(retired, before) {
		t.Fatalf("прежний файл не сохранён: %v", err)
	}
	info, err := os.Stat(filepath.Join(in.keys, keyring.MasterKeyFile))
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("новый файл: %v %v", info, err)
	}
	box, err := keyring.Load(ctx, in.db.Pool(), p, in.keys, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	checkSecrets(t, in, box, ids, in.box.KeyID())
	// Прежний мастер-ключ больше не открывает ключ данных.
	oldDir := keyDir(t)
	if err := os.WriteFile(filepath.Join(oldDir, keyring.MasterKeyFile), before, 0o400); err != nil { //nolint:gosec // тест: путь во временном каталоге теста
		t.Fatal(err)
	}
	if _, err := keyring.Load(ctx, in.db.Pool(), p, oldDir, audit.DefaultOrgID); err == nil {
		t.Fatal("прежний мастер-ключ открыл ключ данных")
	}
	// И им нельзя повернуть мастер-ключ: ни один файл не подходит.
	if _, err := keyring.RotateMaster(ctx, env.db.Pool(), env.log, p, oldDir, audit.DefaultOrgID, cliActor(), now); err == nil {
		t.Fatal("ротация чужим мастер-ключом прошла")
	}

	// Сбой после фиксации, до переименования: master.key — прежний,
	// master.key.new — новый. Повторный запуск завершает переименование.
	cur, err := os.ReadFile(filepath.Join(in.keys, keyring.MasterKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(in.keys, keyring.MasterKeyFile), filepath.Join(in.keys, keyring.MasterKeyNextFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(in.keys, r.Retired), filepath.Join(in.keys, keyring.MasterKeyFile)); err != nil {
		t.Fatal(err)
	}
	r2, err := keyring.RotateMaster(ctx, env.db.Pool(), env.log, p, in.keys, audit.DefaultOrgID, cliActor(), now.Add(time.Minute))
	if err != nil || !r2.Recovered {
		t.Fatalf("восстановление: %+v %v", r2, err)
	}
	if got, _ := os.ReadFile(filepath.Join(in.keys, keyring.MasterKeyFile)); !bytes.Equal(got, cur) { //nolint:gosec // тест: ошибка чтения даёт пустой файл и провал сравнения
		t.Fatal("после восстановления master.key — не новый ключ")
	}

	// 3В1 ревью 3.r1: сбой между двумя переименованиями — master.key уже
	// стал .retired, master.key.new ещё не переименован. Повторный запуск
	// завершает второе переименование, ключ данных открывается новым ключом.
	if err := os.Rename(filepath.Join(in.keys, keyring.MasterKeyFile), filepath.Join(in.keys, keyring.MasterKeyNextFile)); err != nil {
		t.Fatal(err)
	}
	r3, err := keyring.RotateMaster(ctx, env.db.Pool(), env.log, p, in.keys, audit.DefaultOrgID, cliActor(), now.Add(90*time.Second))
	if err != nil || !r3.Recovered || r3.Retired != r2.Retired {
		t.Fatalf("восстановление после первого переименования: %+v %v", r3, err)
	}
	if got, _ := os.ReadFile(filepath.Join(in.keys, keyring.MasterKeyFile)); !bytes.Equal(got, cur) { //nolint:gosec // тест: ошибка чтения даёт пустой файл и провал сравнения
		t.Fatal("после восстановления master.key — не новый ключ")
	}
	if _, err := os.Stat(filepath.Join(in.keys, keyring.MasterKeyNextFile)); !os.IsNotExist(err) {
		t.Fatalf("master.key.new остался: %v", err)
	}
	if _, err := keyring.Load(ctx, in.db.Pool(), p, in.keys, audit.DefaultOrgID); err != nil {
		t.Fatalf("ключ данных после восстановления: %v", err)
	}

	// Сбой до фиксации: остался master.key.new, которым ничего не
	// зашифровано. Повторный запуск удаляет его и меняет ключ заново.
	stale, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindMaster, p.Name(), bytes.Repeat([]byte{9}, aisecCrypto.AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.keys, keyring.MasterKeyNextFile), stale, 0o400); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := keysRotateMasterCmd([]string{"-dir", in.keys}, in.dsn, &out, &out, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "несостоявшейся") || !strings.Contains(out.String(), "номер мастер-ключа — 3") {
		t.Fatalf("вывод: %s", out.String())
	}
	box, err = keyring.Load(ctx, in.db.Pool(), p, in.keys, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	checkSecrets(t, in, box, ids, "")
	if n := in.count(t, "SELECT count(*) FROM audit_log WHERE action = 'keys.master_rotated'"); n != 2 {
		t.Fatalf("keys.master_rotated: записей %d", n)
	}
	// 3Н5: каждое восстановление — запись аудита (два завершения, одно удаление .new).
	if n := in.count(t, "SELECT count(*) FROM audit_log WHERE action = 'keys.master_recovered'"); n != 3 {
		t.Fatalf("keys.master_recovered: записей %d", n)
	}
	// Ключ данных после ротации мастер-ключа поворачивается как обычно.
	if err := runRotateData(ctx, env, in.keys, rotateDataOptions{Batch: 100}, cliActor(), time.Now(), &out); err != nil {
		t.Fatal(err)
	}
	if n := in.count(t, "SELECT count(*) FROM data_keys WHERE master_version = 3"); n != 1 {
		t.Fatalf("новая версия ключа данных не под новым мастер-ключом: %d", n)
	}
}
