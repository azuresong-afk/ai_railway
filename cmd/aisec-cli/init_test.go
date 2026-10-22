package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// memInitStore — initStore в памяти.
type memInitStore struct {
	has     bool
	hasErr  error
	saveErr error
	// committed и existsErr — ответ DataKeyExists после ошибки Save.
	committed bool
	existsErr error
	saved     *initRecords
	actor     audit.Actor
	// recordErr и recorded — для init -add-audit-key.
	recordErr error
	recorded  []audit.Entry
}

func (m *memInitStore) DataKeyExists(context.Context, string) (bool, error) {
	return m.committed, m.existsErr
}

func (m *memInitStore) HasDataKey(context.Context, string) (bool, error) { return m.has, m.hasErr }

func (m *memInitStore) Record(_ context.Context, e audit.Entry) error {
	if m.recordErr != nil {
		return m.recordErr
	}
	m.recorded = append(m.recorded, e)
	return nil
}

func (m *memInitStore) Save(_ context.Context, r *initRecords, a audit.Actor) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saved, m.actor = r, a
	return nil
}

var setupTokenRe = regexp.MustCompile(`aisec_setup_[A-Za-z0-9_-]{43}`)

func keyDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// countFiles — число записей в каталоге ключей.
func countFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func standardProvider(t *testing.T) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInitCreatesKeys(t *testing.T) {
	dir := keyDir(t)
	p := standardProvider(t)
	st := &memInitStore{}
	var out bytes.Buffer
	if err := runInit(context.Background(), dir, p, st, cliActor(), now, &out); err != nil {
		t.Fatal(err)
	}
	if st.saved == nil {
		t.Fatal("в БД ничего не записано")
	}
	r := st.saved

	// Права файлов: закрытые — 0400, открытые — 0444.
	want := map[string]os.FileMode{
		masterKeyFile: 0o400, signingKeyFile: 0o400, caKeyFile: 0o400, auditKeyFile: 0o400,
		signingPubFile: 0o444, caCertFile: 0o444, auditPubFile: 0o444,
	}
	if len(want) != len(initFileNames) || countFiles(t, dir) != len(initFileNames) {
		t.Fatalf("файлов %d, ожидалось %d", countFiles(t, dir), len(initFileNames))
	}
	read := map[string][]byte{}
	for name, perm := range want {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != perm {
			t.Errorf("%s: права %04o, ожидалось %04o", name, info.Mode().Perm(), perm)
		}
		if read[name], err = os.ReadFile(filepath.Join(dir, name)); err != nil { //nolint:gosec // G304: файл во временном каталоге теста
			t.Fatal(err)
		}
	}

	// Ключ данных расшифровывается мастер-ключом только со своим AAD (Р4).
	profile, master, err := aisecCrypto.DecodeKeyPEM(read[masterKeyFile], aisecCrypto.KeyKindMaster)
	if err != nil || profile != aisecCrypto.ProfileStandard {
		t.Fatalf("мастер-ключ: %q %v", profile, err)
	}
	aead, err := p.NewAEAD(master)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := aisecCrypto.StorageAAD("data_keys", "wrapped", r.DataKeyID)
	if err != nil {
		t.Fatal(err)
	}
	dataKey, err := aead.Open(r.Wrapped, aad)
	if err != nil || len(dataKey) != aisecCrypto.AEADKeySize {
		t.Fatalf("ключ данных: %d байт, %v", len(dataKey), err)
	}
	other, err := aisecCrypto.StorageAAD("data_keys", "wrapped", r.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aead.Open(r.Wrapped, other); err == nil {
		t.Fatal("ключ данных расшифрован с AAD другой строки")
	}
	if r.Profile != "standard" || r.AEADAlg != "AES-256-GCM" || r.OrgID != audit.DefaultOrgID {
		t.Fatalf("запись ключа данных: %+v", r)
	}

	// Ключ подписи и открытый ключ — пара.
	_, seed, err := aisecCrypto.DecodeKeyPEM(read[signingKeyFile], aisecCrypto.KeyKindSigning)
	if err != nil {
		t.Fatal(err)
	}
	_, pub, err := aisecCrypto.DecodeKeyPEM(read[signingPubFile], aisecCrypto.KeyKindSigningPublic)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := p.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := p.NewVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign([]byte("пакет"))
	if err != nil || !verifier.Verify([]byte("пакет"), sig) {
		t.Fatalf("подпись не проверяется открытым ключом из файла: %v", err)
	}

	// Ключ аудита — отдельная пара, не совпадающая с ключом пакетов (ADR-0008).
	keyRoot, err := keyring.OpenKeyDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(keyRoot)
	auditSigner, err := keyring.ReadSigner(keyRoot, p, auditKeyFile, aisecCrypto.KeyKindAuditSigning)
	if err != nil {
		t.Fatal(err)
	}
	if aisecCrypto.Equal(auditSigner.PublicKey(), pub) {
		t.Fatal("ключ аудита совпадает с ключом подписи пакетов")
	}
	auditSeed := auditSigner.Seed()

	// УЦ загружается из файлов и выпускает сертификаты (задача 2.14).
	ca, err := aisecCrypto.LoadCA(read[caCertFile], read[caKeyFile])
	if err != nil {
		t.Fatal(err)
	}
	if !ca.NotAfter().Equal(r.CANotAfter) {
		t.Fatalf("срок УЦ: %v и %v", ca.NotAfter(), r.CANotAfter)
	}
	if _, _, err := ca.IssueServer([]string{"aisec-server"}, 24*time.Hour, now); err != nil {
		t.Fatal(err)
	}

	// Токен показан один раз, в БД — его хеш со сроком 24 ч.
	tokens := setupTokenRe.FindAllString(out.String(), -1)
	if len(tokens) != 1 {
		t.Fatalf("токенов в выводе: %d\n%s", len(tokens), out.String())
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	if !aisecCrypto.Equal(h.Sum([]byte(tokens[0])), r.TokenHash) || r.TokenHashAlg != "SHA-256" {
		t.Fatal("хеш токена в БД не соответствует показанному токену")
	}
	if r.TokenExpires.Sub(r.Created) != setupTokenTTL {
		t.Fatalf("срок токена: %v", r.TokenExpires.Sub(r.Created))
	}

	// Ни один секрет не попал в вывод.
	for name, secret := range map[string][]byte{"мастер-ключ": master, "ключ данных": dataKey, "ключ подписи": seed, "ключ аудита": auditSeed} {
		for _, enc := range []string{base64.StdEncoding.EncodeToString(secret), base64.RawURLEncoding.EncodeToString(secret)} {
			if strings.Contains(out.String(), enc) {
				t.Errorf("%s в выводе", name)
			}
		}
	}
	if strings.Contains(out.String(), "PRIVATE KEY") || strings.Contains(out.String(), "MASTER KEY") {
		t.Error("содержимое файла ключа в выводе")
	}

	// Запись аудита проходит фильтр секретов журнала и не содержит токен.
	e := initAuditEntry(r, st.actor)
	d, err := audit.CanonicalDetails(e.Details)
	if err != nil {
		t.Fatalf("подробности аудита: %v", err)
	}
	if strings.Contains(string(d), tokens[0]) || e.Action != "system.init" {
		t.Fatalf("запись аудита: %s %s", e.Action, d)
	}
	if ev, ok := audit.Lookup(e.Action); !ok || !ev.Mandatory {
		t.Fatal("system.init нет в перечне или оно отключаемое")
	}
}

func TestInitNeverOverwrites(t *testing.T) {
	p := standardProvider(t)
	for _, name := range initFileNames {
		dir := keyDir(t)
		existing := filepath.Join(dir, name)
		if err := os.WriteFile(existing, []byte("старый ключ"), 0o400); err != nil {
			t.Fatal(err)
		}
		st := &memInitStore{}
		var out bytes.Buffer
		if err := runInit(context.Background(), dir, p, st, cliActor(), now, &out); err == nil {
			t.Fatalf("%s: init поверх существующего файла", name)
		}
		got, err := os.ReadFile(existing) //nolint:gosec // G304: файл во временном каталоге теста
		if err != nil || string(got) != "старый ключ" {
			t.Fatalf("%s: существующий файл изменён", name)
		}
		if n := countFiles(t, dir); n != 1 || st.saved != nil {
			t.Fatalf("%s: созданы файлы или записи", name)
		}
	}
	// Висячая символическая ссылка тоже считается существующим файлом.
	dir := keyDir(t)
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(dir, masterKeyFile)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runInit(context.Background(), dir, p, &memInitStore{}, cliActor(), now, &out); err == nil {
		t.Fatal("init через символическую ссылку")
	}
}

func TestInitRefusesWhenDataKeyExists(t *testing.T) {
	p := standardProvider(t)
	for name, st := range map[string]*memInitStore{
		"ключ уже есть": {has: true},
		"ошибка БД":     {hasErr: errors.New("нет таблицы")},
	} {
		dir := keyDir(t)
		var out bytes.Buffer
		if err := runInit(context.Background(), dir, p, st, cliActor(), now, &out); err == nil {
			t.Fatalf("%s: принято", name)
		}
		if n := countFiles(t, dir); n != 0 {
			t.Fatalf("%s: созданы файлы", name)
		}
	}
}

func TestInitSaveFailureRemovesFiles(t *testing.T) {
	dir := keyDir(t)
	var out bytes.Buffer
	st := &memInitStore{saveErr: errors.New("транзакция не прошла")}
	if err := runInit(context.Background(), dir, standardProvider(t), st, cliActor(), now, &out); err == nil {
		t.Fatal("ошибка БД не возвращена")
	}
	if n := countFiles(t, dir); n != 0 {
		t.Fatalf("после сбоя остались файлы: %d", n)
	}
	if setupTokenRe.MatchString(out.String()) {
		t.Fatal("токен показан, хотя в БД не записан")
	}
}

// Ошибка пришла после фиксации: файлы остаются, токен показывается.
func TestInitCommitErrorButCommitted(t *testing.T) {
	dir := keyDir(t)
	var out bytes.Buffer
	st := &memInitStore{saveErr: errors.New("обрыв на COMMIT"), committed: true}
	if err := runInit(context.Background(), dir, standardProvider(t), st, cliActor(), now, &out); err != nil {
		t.Fatalf("зафиксированная транзакция считается сбоем: %v", err)
	}
	if n := countFiles(t, dir); n != len(initFileNames) || !setupTokenRe.MatchString(out.String()) {
		t.Fatalf("файлов %d, вывод: %s", n, out.String())
	}
}

// Исход фиксации неизвестен: файлы не удаляются — иначе ключ данных в БД
// навсегда остался бы без мастер-ключа.
func TestInitCommitOutcomeUnknownKeepsFiles(t *testing.T) {
	dir := keyDir(t)
	var out bytes.Buffer
	st := &memInitStore{saveErr: errors.New("обрыв на COMMIT"), existsErr: errors.New("БД недоступна")}
	err := runInit(context.Background(), dir, standardProvider(t), st, cliActor(), now, &out)
	if err == nil || !strings.Contains(err.Error(), "исход транзакции неизвестен") {
		t.Fatalf("ошибка: %v", err)
	}
	if n := countFiles(t, dir); n != len(initFileNames) {
		t.Fatalf("файлы удалены при неизвестном исходе: %d", n)
	}
	if setupTokenRe.MatchString(out.String()) || setupTokenRe.MatchString(err.Error()) {
		t.Fatal("токен показан при неизвестном исходе")
	}
}

// failWriter не принимает вывод: токен не дошёл до администратора.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("вывод закрыт") }

func TestInitTokenOutputFailure(t *testing.T) {
	dir := keyDir(t)
	err := runInit(context.Background(), dir, standardProvider(t), &memInitStore{}, cliActor(), now, failWriter{})
	if err == nil || !strings.Contains(err.Error(), "повторный выпуск токена") {
		t.Fatalf("ошибка вывода токена не возвращена: %v", err)
	}
}

func TestInitKeyDirChecks(t *testing.T) {
	p := standardProvider(t)
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o750); err != nil { //nolint:gosec // G302: проверяется отказ на каталоге, доступном группе
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{
		"доступен группе": open,
		"не каталог":      file,
		"нет каталога":    filepath.Join(t.TempDir(), "missing"),
	} {
		var out bytes.Buffer
		if err := runInit(context.Background(), dir, p, &memInitStore{}, cliActor(), now, &out); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// init -add-audit-key: только пара ключей аудита в каталоге установки.
func TestInitAddAuditKey(t *testing.T) {
	p := standardProvider(t)
	dir := keyDir(t)
	if err := runInit(context.Background(), dir, p, &memInitStore{}, cliActor(), now, io.Discard); err != nil {
		t.Fatal(err)
	}
	// Установка до ADR-0008: ключа аудита ещё нет.
	for _, name := range []string{auditKeyFile, auditPubFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	master, err := os.ReadFile(filepath.Join(dir, masterKeyFile)) //nolint:gosec // G304: файл во временном каталоге теста
	if err != nil {
		t.Fatal(err)
	}
	st := &memInitStore{has: true}
	var out bytes.Buffer
	if err := runAddAuditKey(context.Background(), dir, p, st, cliActor(), &out); err != nil {
		t.Fatal(err)
	}
	keyRoot, err := keyring.OpenKeyDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(keyRoot)
	if _, err := keyring.ReadSigner(keyRoot, p, auditKeyFile, aisecCrypto.KeyKindAuditSigning); err != nil {
		t.Fatal(err)
	}
	if len(st.recorded) != 1 || st.recorded[0].Action != "system.audit_key" || st.saved != nil {
		t.Fatalf("записи аудита: %+v", st.recorded)
	}
	if got, err := os.ReadFile(filepath.Join(dir, masterKeyFile)); err != nil || !bytes.Equal(got, master) { //nolint:gosec // G304: файл во временном каталоге теста
		t.Fatal("мастер-ключ изменён")
	}
	if n := countFiles(t, dir); n != len(initFileNames) {
		t.Fatalf("файлов %d", n)
	}
	if e, ok := audit.Lookup("system.audit_key"); !ok || !e.Mandatory {
		t.Fatal("system.audit_key нет в перечне или оно отключаемое")
	}
	// Повторно — отказ, существующий ключ не перезаписывается.
	if err := runAddAuditKey(context.Background(), dir, p, st, cliActor(), &out); err == nil {
		t.Fatal("ключ аудита перезаписан")
	}

	// Отказы: не каталог установки, установка не инициализирована, ошибка
	// записи аудита (файлы удаляются).
	empty := keyDir(t)
	if err := runAddAuditKey(context.Background(), empty, p, &memInitStore{has: true}, cliActor(), &out); err == nil || countFiles(t, empty) != 0 {
		t.Fatalf("без master.key: %v", err)
	}
	for name, st := range map[string]*memInitStore{
		"нет ключа данных": {},
		"ошибка БД":        {hasErr: errors.New("нет таблицы")},
		"ошибка аудита":    {has: true, recordErr: errors.New("журнал недоступен")},
	} {
		d := keyDir(t)
		if err := os.WriteFile(filepath.Join(d, masterKeyFile), master, 0o400); err != nil { //nolint:gosec // G703: путь во временном каталоге теста
			t.Fatal(err)
		}
		if err := runAddAuditKey(context.Background(), d, p, st, cliActor(), &out); err == nil {
			t.Errorf("%s: принято", name)
		}
		if n := countFiles(t, d); n != 1 {
			t.Errorf("%s: файлов %d", name, n)
		}
	}
}

func TestInitCmdErrors(t *testing.T) {
	dir := keyDir(t)
	const dsn = "postgres://u@127.0.0.1:1/x"
	var out, errb bytes.Buffer
	for name, c := range map[string]struct {
		args []string
		dsn  string
	}{
		"без -dir":            {nil, dsn},
		"лишний аргумент":     {[]string{"-dir", dir, "x"}, dsn},
		"без строки БД":       {[]string{"-dir", dir}, ""},
		"неизвестный профиль": {[]string{"-dir", dir, "-profile", "fips"}, dsn},
		"профиль gost":        {[]string{"-dir", dir, "-profile", "gost"}, dsn},
		"недоступная БД":      {[]string{"-dir", dir}, dsn},
	} {
		if err := initCmd(c.args, c.dsn, &out, &errb, now); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if n := countFiles(t, dir); n != 0 {
		t.Fatal("при ошибке созданы файлы")
	}
	if code := run([]string{"init"}, &out, &errb, now); code != 1 {
		t.Errorf("код %d", code)
	}
}

// init на живой БД (AISEC_TEST_DATABASE_URL): миграции, init, затем ключ
// данных, токен и запись аудита в БД, цепочка цела, повторный init отклонён.
func TestInitOnRealDB(t *testing.T) {
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
	const schema = "cli_init_test"
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
	dir := keyDir(t)
	out.Reset()
	if err := initCmd([]string{"-dir", dir}, sdsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	token := setupTokenRe.FindString(out.String())
	if token == "" {
		t.Fatalf("нет токена: %s", out.String())
	}

	db, err := store.Open(ctx, sdsn, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var keys, tokens, inits int
	if err := db.Pool().QueryRow(ctx, "SELECT count(*) FROM data_keys WHERE retired_at IS NULL").Scan(&keys); err != nil {
		t.Fatal(err)
	}
	h, err := standardProvider(t).Hasher()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Pool().QueryRow(ctx, "SELECT count(*) FROM setup_tokens WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()", h.Sum([]byte(token))).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool().QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action = 'system.init' AND actor_type = 'cli'").Scan(&inits); err != nil {
		t.Fatal(err)
	}
	if keys != 1 || tokens != 1 || inits != 1 {
		t.Fatalf("ключей %d, токенов %d, записей аудита %d", keys, tokens, inits)
	}
	out.Reset()
	if err := auditCmd([]string{"verify"}, sdsn, &out, &errb); err != nil || !strings.Contains(out.String(), "Цепочка цела") {
		t.Fatalf("цепочка после init: %v %s", err, out.String())
	}

	// Права роли сервера: ключ данных — только чтение, у токена меняется
	// только отметка о погашении. USAGE на тестовую схему выдаёт тест, в
	// поставке схема — public.
	if _, err := db.Pool().Exec(ctx, "GRANT USAGE ON SCHEMA "+schema+" TO aisec_app"); err != nil {
		t.Fatal(err)
	}
	for q, allowed := range map[string]bool{
		"SELECT count(*) FROM data_keys":                          true,
		"UPDATE setup_tokens SET used_at = now()":                 true,
		"UPDATE setup_tokens SET token_hash = '\\x00'":            false,
		"UPDATE data_keys SET retired_at = now()":                 false,
		"UPDATE data_keys SET sealed = sealed + 1000":             true,
		"UPDATE data_keys SET sealed = 2147483649":                false,
		"DELETE FROM data_keys":                                   false,
		"INSERT INTO data_keys SELECT * FROM data_keys LIMIT 0":   false,
		"SELECT count(*) FROM setup_tokens WHERE used_at IS NULL": true,
		"UPDATE data_keys SET sealed = 0":                         true, // счётчик уже 0: не уменьшение
	} {
		tx, err := db.Pool().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE aisec_app"); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, q)
		if (err == nil) != allowed {
			t.Errorf("%s под aisec_app: %v", q, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// Значения, которые права на столбцы не ловят: уменьшение счётчика и
	// повторное использование токена — отказ даже под владельцем схемы.
	for _, steps := range [][]string{
		{"UPDATE data_keys SET sealed = 10", "UPDATE data_keys SET sealed = 9"},
		{"UPDATE setup_tokens SET used_at = now()", "UPDATE setup_tokens SET used_at = NULL"},
		{"UPDATE setup_tokens SET used_at = now()", "UPDATE setup_tokens SET used_at = now() + interval '1 s'"},
		{"UPDATE data_keys SET retired_at = now()", "UPDATE data_keys SET retired_at = NULL"},
		{"UPDATE data_keys SET wrapped = '\\x00'"},
		{"UPDATE setup_tokens SET expires_at = expires_at + interval '1 day'"},
	} {
		tx, err := db.Pool().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var last error
		for _, q := range steps {
			if _, last = tx.Exec(ctx, q); last != nil {
				break
			}
		}
		if last == nil {
			t.Errorf("%v: принято", steps)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// Повторный init в чистый каталог отклоняется по ключу данных в БД.
	dir2 := keyDir(t)
	if err := initCmd([]string{"-dir", dir2}, sdsn, &out, &errb, now); err == nil {
		t.Fatal("повторный init принят")
	}
	if n := countFiles(t, dir2); n != 0 {
		t.Fatal("повторный init создал файлы")
	}

	// H-Р13 ревью 2.r5: повторный выпуск гасит прежний токен, новый действует,
	// запись аудита — в цепочке; после первичной настройки — отказ.
	out.Reset()
	if err := initCmd([]string{"-reissue-setup-token"}, sdsn, &out, &errb, time.Now()); err != nil {
		t.Fatalf("повторный выпуск: %v", err)
	}
	token2 := setupTokenRe.FindString(out.String())
	if token2 == "" || token2 == token || !strings.Contains(out.String(), "погашено: 1") {
		t.Fatalf("вывод повторного выпуска: %s", out.String())
	}
	var oldLive, newLive, reissued int
	if err := db.Pool().QueryRow(ctx, "SELECT count(*) FROM setup_tokens WHERE token_hash = $1 AND used_at IS NULL", h.Sum([]byte(token))).Scan(&oldLive); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool().QueryRow(ctx, "SELECT count(*) FROM setup_tokens WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()", h.Sum([]byte(token2))).Scan(&newLive); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'system.setup_token_reissued'
		AND actor_type = 'cli' AND (details->>'revoked_tokens')::int = 1`).Scan(&reissued); err != nil {
		t.Fatal(err)
	}
	if oldLive != 0 || newLive != 1 || reissued != 1 {
		t.Fatalf("прежний действует %d, новый %d, записей %d", oldLive, newLive, reissued)
	}
	if err := auditCmd([]string{"verify"}, sdsn, &out, &errb); err != nil {
		t.Fatalf("цепочка после повторного выпуска: %v", err)
	}
	if _, err := db.Pool().Exec(ctx, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash,
		password_changed_at, must_change_password, created_at, created_by) VALUES ('01900000-0000-7000-8000-00000000aa01', $1,
		'admin', 'Админ', 'security_admin', 'active', 'x', now(), false, now(), 'setup')`, audit.DefaultOrgID); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := initCmd([]string{"-reissue-setup-token"}, sdsn, &out, &errb, time.Now()); !errors.Is(err, errSetupDone) || setupTokenRe.MatchString(out.String()) {
		t.Fatalf("выпуск после первичной настройки: %v %s", err, out.String())
	}
	if err := db.Pool().QueryRow(ctx, "SELECT count(*) FROM setup_tokens WHERE used_at IS NULL").Scan(&newLive); err != nil || newLive != 1 {
		t.Fatalf("отказ изменил токены: %d %v", newLive, err)
	}
}

// memReissueStore — reissueStore в памяти.
type memReissueStore struct {
	err     error
	revoked int
	saved   *reissueRecord
	rec     audit.Entry
}

func (m *memReissueStore) Reissue(_ context.Context, r *reissueRecord, rec audit.Entry) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	m.saved, m.rec = r, rec
	return m.revoked, nil
}

// H-Р13 ревью 2.r5: токен показывается один раз, в БД и аудите — только хеш
// и ID записи; отказ хранилища и сбой вывода — ошибка.
func TestReissueSetupToken(t *testing.T) {
	p := standardProvider(t)
	now := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	st := &memReissueStore{revoked: 2}
	var out bytes.Buffer
	if err := runReissueSetupToken(context.Background(), p, st, cliActor(), now, &out); err != nil {
		t.Fatal(err)
	}
	token := setupTokenRe.FindString(out.String())
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || !strings.Contains(out.String(), "погашено: 2") || !strings.Contains(out.String(), "2026-10-23 10:00") {
		t.Fatalf("вывод: %s", out.String())
	}
	if !bytes.Equal(st.saved.TokenHash, h.Sum([]byte(token))) || st.saved.HashAlg != h.Name() || !st.saved.Expires.Equal(now.Add(setupTokenTTL)) {
		t.Fatalf("строка токена: %+v", st.saved)
	}
	if st.rec.Action != "system.setup_token_reissued" || st.rec.Object.ID != st.saved.TokenID ||
		strings.Contains(fmt.Sprint(st.rec.Details), token) {
		t.Fatalf("запись аудита: %+v", st.rec)
	}
	out.Reset()
	if err := runReissueSetupToken(context.Background(), p, &memReissueStore{err: errSetupDone}, cliActor(), now, &out); !errors.Is(err, errSetupDone) || out.Len() != 0 {
		t.Fatalf("после первичной настройки: %v %q", err, out.String())
	}
	if err := runReissueSetupToken(context.Background(), p, &memReissueStore{}, cliActor(), now, failWriter{}); err == nil {
		t.Fatal("сбой вывода токена не замечен")
	}
	for _, args := range [][]string{{"-reissue-setup-token", "-dir", "/tmp/x"}, {"-reissue-setup-token", "-add-audit-key"}} {
		if err := initCmd(args, "postgres://u@h/d", io.Discard, io.Discard, now); err == nil || !strings.Contains(err.Error(), "не сочетается") {
			t.Errorf("%v: %v", args, err)
		}
	}
	if err := initCmd([]string{"-reissue-setup-token"}, "", io.Discard, io.Discard, now); err == nil {
		t.Error("без AISEC_DATABASE_URL принято")
	}
}

// Н4 ревью 2.r1: копии закрытых ключей в памяти затираются после записи,
// открытые остаются как есть.
func TestWriteKeyFilesClearsPrivate(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }() //nolint:gosec // G104: каталог только читался и писался тестом
	files := []keyFile{
		{name: "private.key", data: []byte("секрет"), perm: 0o400},
		{name: "public.pub", data: []byte("открытый"), perm: 0o444},
	}
	if _, err := writeKeyFiles(root, files); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(files[0].data, make([]byte, len("секрет"))) {
		t.Fatalf("закрытый ключ не затёрт: %q", files[0].data)
	}
	if string(files[1].data) != "открытый" {
		t.Fatalf("открытый ключ изменён: %q", files[1].data)
	}
	got, err := root.ReadFile("private.key")
	if err != nil || string(got) != "секрет" {
		t.Fatalf("на диске: %q %v", got, err)
	}
}
