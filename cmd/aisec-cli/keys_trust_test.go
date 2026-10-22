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
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// trustInstallation — установка после init без секретов: для ротаций
// ключа подписи пакетов, корня УЦ и ключа аудита.
func trustInstallation(t *testing.T, schema string) *installation {
	t.Helper()
	base := os.Getenv("AISEC_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	admin, err := store.Open(context.Background(), base, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	return newInstallation(t, admin, base, schema)
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// loadChain — цепочка доверия из БД от якоря bundle-signing.pub.
func loadChain(t *testing.T, in *installation) *bundle.TrustChain {
	t.Helper()
	p := standardProvider(t)
	anchor, err := aisecCrypto.LoadVerifierFile(p, filepath.Join(in.keys, keyring.SigningPubFile), aisecCrypto.KeyKindSigningPublic)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := keyring.LoadTrust(context.Background(), in.db.Pool(), p, audit.DefaultOrgID, []aisecCrypto.Verifier{anchor})
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// ЗИ.1, ОЦЛ.3, ADR-0018, п. 4 и 6: rotate-signing и rotate-ca создают файлы
// рядом с якорями и заявления, которые проверяются цепочкой от
// bundle-signing.pub; следующая ротация подписывается новым ключом.
func TestKeysRotateTrustOnRealDB(t *testing.T) {
	in := trustInstallation(t, "cli_keys_trust")
	ctx := context.Background()
	p := standardProvider(t)
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	anchorPub, err := os.ReadFile(filepath.Join(in.keys, keyring.SigningPubFile))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	var out, errb bytes.Buffer
	if err := keysCmd([]string{"rotate-signing", "-dir", in.keys, "-overlap", "1h"}, in.dsn, &out, &errb, now); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	if !strings.Contains(out.String(), "заявление о доверии №1") || !strings.Contains(out.String(), "2026-10-22 13:00:00") {
		t.Fatalf("вывод: %s", out.String())
	}
	chain := loadChain(t, in)
	st := chain.Latest()
	if chain.Seq() != 1 || len(st.Keys) != 2 || len(st.Roots) != 1 || st.Roots[0].NotAfter != nil {
		t.Fatalf("заявление 1: %+v", st)
	}
	oldID, newID := st.Keys[0].ID, chain.ActiveKeyID()
	if st.Keys[0].NotAfter == nil || !st.Keys[0].NotAfter.Equal(now.Add(time.Hour)) || newID == oldID {
		t.Fatalf("ключи заявления 1: %+v", st.Keys)
	}
	keyName, pubName := keyring.SigningFiles(newID, oldID)
	if fileMode(t, filepath.Join(in.keys, keyName)) != 0o400 || fileMode(t, filepath.Join(in.keys, pubName)) != 0o444 {
		t.Fatal("права файлов нового ключа")
	}
	if got, _ := os.ReadFile(filepath.Join(in.keys, keyring.SigningPubFile)); !bytes.Equal(got, anchorPub) { //nolint:gosec // тест: ошибка чтения даёт пустой файл и провал сравнения
		t.Fatal("файл-якорь изменён")
	}
	// Корень УЦ из ca.crt вошёл в первое заявление.
	caPEM, err := os.ReadFile(filepath.Join(in.keys, keyring.CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	caDER, err := aisecCrypto.CertDER(caPEM)
	if err != nil || st.Roots[0].ID != bundle.RootID(h, caDER) {
		t.Fatalf("корень в заявлении: %v", err)
	}

	// Ротация корня без перекрытия (компрометация): прежний корень больше
	// не действует сразу.
	out.Reset()
	if err := keysCmd([]string{"rotate-ca", "-dir", in.keys, "-overlap", "0s"}, in.dsn, &out, &errb, now.Add(time.Minute)); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	chain = loadChain(t, in)
	st = chain.Latest()
	valid := chain.ValidRoots(now.Add(time.Minute))
	if chain.Seq() != 2 || len(st.Roots) != 2 || len(valid) != 1 || bytes.Equal(valid[0], caDER) {
		t.Fatalf("заявление 2: %d корней, действуют %d", len(st.Roots), len(valid))
	}
	active, ok := st.ActiveRoot()
	if !ok {
		t.Fatal("нет действующего корня")
	}
	rootID := active.ID
	crt, key := keyring.CAFiles(rootID, st.Roots[0].ID)
	if fileMode(t, filepath.Join(in.keys, crt)) != 0o444 || fileMode(t, filepath.Join(in.keys, key)) != 0o400 {
		t.Fatal("права файлов нового корня")
	}
	if st.SignedBy != newID {
		t.Fatalf("заявление 2 подписано %s, а не новым ключом %s", st.SignedBy, newID)
	}

	// После конца перекрытия прежний ключ выпадает из следующего заявления.
	out.Reset()
	if err := keysCmd([]string{"rotate-signing", "-dir", in.keys}, in.dsn, &out, &errb, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	chain = loadChain(t, in)
	st = chain.Latest()
	if chain.Seq() != 3 || len(st.Keys) != 2 || st.Keys[0].ID != newID || len(st.Roots) != 1 || st.Roots[0].ID != rootID {
		t.Fatalf("заявление 3: %+v", st)
	}
	out.Reset()
	if err := keysCmd([]string{"status", "-dir", in.keys}, in.dsn, &out, &errb, now); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	if !strings.Contains(out.String(), "ключ подписи пакетов "+chain.ActiveKeyID()) || !strings.Contains(out.String(), "корень УЦ "+rootID) {
		t.Fatalf("status: %s", out.String())
	}
	// 3В5 ревью 3.r1: срок каждого корня.
	if !strings.Contains(out.String(), "корень действует до ") || strings.Contains(out.String(), "не прочитан") {
		t.Fatalf("status без срока корня: %s", out.String())
	}
	if n := in.count(t, "SELECT count(*) FROM audit_log WHERE action IN ('keys.signing_rotated', 'keys.ca_rotated')"); n != 3 {
		t.Fatalf("записей аудита о ротации: %d", n)
	}

	// Без действующего закрытого ключа ротация отклоняется, и новых файлов
	// не остаётся.
	activeKey, _ := keyring.SigningFiles(chain.ActiveKeyID(), oldID)
	if err := os.Rename(filepath.Join(in.keys, activeKey), filepath.Join(t.TempDir(), "moved.key")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(in.keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := keysCmd([]string{"rotate-signing", "-dir", in.keys}, in.dsn, &out, &errb, now.Add(3*time.Hour)); err == nil ||
		!strings.Contains(err.Error(), "действующий ключ подписи") {
		t.Fatalf("ротация без действующего ключа: %v", err)
	}
	after, err := os.ReadDir(in.keys)
	if err != nil || len(after) != len(before) {
		t.Fatalf("файлы после отказа: %d → %d", len(before), len(after))
	}
	// Подменённое заявление в БД ломает цепочку: владелец схемы не может
	// его исправить (таблица только добавляется).
	if _, err := in.db.Pool().Exec(ctx, "UPDATE trust_statements SET statement = statement WHERE seq = 1"); err == nil {
		t.Fatal("заявление о доверии изменено")
	}
}

// ОЦЛ.3, ADR-0018, п. 5: rotate-audit — точки до смены проверяются прежним
// ключом, архивация после смены подписывает новым, verify-archive
// принимает архив по ключам каталога.
func TestKeysRotateAuditOnRealDB(t *testing.T) {
	in := trustInstallation(t, "cli_keys_audit")
	ctx := context.Background()
	p := standardProvider(t)
	schema := "cli_keys_audit"
	if err := in.db.Pool().QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	in.exec(t, "GRANT USAGE ON SCHEMA "+schema+" TO aisec_audit_archiver")
	anchor, err := loadAuditVerifier(p, in.keys)
	if err != nil {
		t.Fatal(err)
	}
	archDir := t.TempDir()
	// Архивация с часами в будущем: граница срока хранения позади всех
	// записей. Часы второй архивации дальше: запись первой тоже уходит.
	archive := func(at time.Time, s aisecCrypto.Signer, name string) (*audit.ArchiveResult, error) {
		t.Helper()
		cps, err := audit.NewPGCheckpoints(in.db.Pool(), p, anchor)
		if err != nil {
			t.Fatal(err)
		}
		l, err := audit.New(in.db.Pool(), p, audit.WithCheckpoints(cps), audit.WithClock(func() time.Time { return at }))
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(filepath.Join(archDir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: файл во временном каталоге теста
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }() //nolint:gosec // G104: файл тестового архива
		return l.Archive(ctx, audit.ArchiveOptions{Out: f, ArchiveName: name, Signer: s, Verifier: anchor, By: cliActor()})
	}
	plain, err := audit.New(in.db.Pool(), p)
	if err != nil {
		t.Fatal(err)
	}
	record := func(n int) {
		t.Helper()
		for range n {
			if err := plain.Record(ctx, audit.Entry{Actor: audit.Actor{Type: audit.ActorUser, ID: "u-1", Name: "admin"},
				Action: "auth.login", Result: audit.ResultSuccess}); err != nil {
				t.Fatal(err)
			}
		}
	}
	record(3)
	s1, _, err := loadAuditSigner(ctx, in.db, p, in.keys)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	res1, err := archive(now.AddDate(3, 0, 0), s1, "audit-1.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	if err := keysCmd([]string{"rotate-audit", "-dir", in.keys}, in.dsn, &out, &errb, now); err != nil {
		t.Fatalf("%v: %s", err, errb.String())
	}
	if !strings.Contains(out.String(), "смена №1") {
		t.Fatalf("вывод: %s", out.String())
	}
	record(2)
	s2, _, err := loadAuditSigner(ctx, in.db, p, in.keys)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s1.PublicKey(), s2.PublicKey()) {
		t.Fatal("после смены действует прежний ключ")
	}
	ks, err := audit.LoadKeySchedule(ctx, in.db.Pool(), p, anchor)
	if err != nil || ks.Rotations() != 1 || !bytes.Equal(ks.CheckpointKey(res1.Checkpoint.Seq).PublicKey(), s1.PublicKey()) {
		t.Fatalf("расписание: %v", err)
	}
	if _, err := archive(now.AddDate(6, 0, 0), s1, "audit-x.jsonl"); err == nil || !strings.Contains(err.Error(), "не действующий") {
		t.Fatalf("архивация прежним ключом после смены: %v", err)
	}
	res2, err := archive(now.AddDate(6, 0, 0), s2, "audit-2.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res2.Checkpoint.PublicKey, s2.PublicKey()) {
		t.Fatal("точка после смены подписана не новым ключом")
	}
	out.Reset()
	if err := auditCmd([]string{"verify", "-keys", in.keys}, in.dsn, &out, &errb); err != nil || !strings.Contains(out.String(), "Цепочка цела") {
		t.Fatalf("verify после смены: %v %s", err, out.String())
	}
	file2 := filepath.Join(archDir, "audit-2.jsonl")
	out.Reset()
	if err := auditCmd([]string{"verify-archive", "-keys", in.keys, file2}, "", &out, &errb); err != nil {
		t.Fatalf("verify-archive нового архива: %v", err)
	}
	// Каталог только с якорем не проверяет архив, подписанный новым ключом.
	onlyAnchor := keyDir(t)
	pub, err := os.ReadFile(filepath.Join(in.keys, keyring.AuditPubFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(onlyAnchor, keyring.AuditPubFile), pub, 0o444); err != nil { //nolint:gosec // G703: путь во временном каталоге теста
		t.Fatal(err)
	}
	if err := auditCmd([]string{"verify-archive", "-keys", onlyAnchor, file2}, "", &out, &errb); err == nil {
		t.Fatal("архив нового ключа проверен одним якорем")
	}
	// Архив до смены проверяется прежним ключом по расписанию.
	if err := auditCmd([]string{"verify-archive", "-keys", in.keys, filepath.Join(archDir, "audit-1.jsonl")}, "", &out, &errb); err != nil {
		t.Fatalf("verify-archive архива до смены: %v", err)
	}
	// 3В3 ревью 3.r1: открытый ключ смены без подписанного файла смены не
	// принимается — иначе подложенный ключ подписал бы любую точку.
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	newID := audit.KeyID(h, s2.PublicKey())
	_, newPub := keyring.AuditFiles(newID, audit.KeyID(h, anchor.PublicKey()))
	rotFile := keyring.AuditRotationFile(newID)
	if _, err := os.Stat(filepath.Join(in.keys, rotFile)); err != nil {
		t.Fatalf("rotate-audit не записал файл смены: %v", err)
	}
	newPubData, err := os.ReadFile(filepath.Join(in.keys, newPub)) //nolint:gosec // G304: файл во временном каталоге теста
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(onlyAnchor, newPub), newPubData, 0o444); err != nil { //nolint:gosec // G703: путь во временном каталоге теста
		t.Fatal(err)
	}
	if err := auditCmd([]string{"verify-archive", "-keys", onlyAnchor, file2}, "", &out, &errb); err == nil || !strings.Contains(err.Error(), rotFile) {
		t.Fatalf("ключ без файла смены: %v", err)
	}
	// Смену ключа нельзя переписать.
	if _, err := in.db.Pool().Exec(ctx, "DELETE FROM audit_key_rotations"); err == nil {
		t.Fatal("смена ключа аудита удалена")
	}
}
