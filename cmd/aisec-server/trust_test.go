package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Запуск сервера после rotate-signing и rotate-ca (ADR-0018, п. 4.3, 6.2):
// действующий ключ подписи и УЦ берутся по цепочке доверия из БД, клиентам
// доверяются все корни заявления, подменённый файл — отказ запуска.

func writeKeyFile(t *testing.T, dir, name string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, perm); err != nil { //nolint:gosec // G703: путь во временном каталоге теста
		t.Fatal(err)
	}
}

// trustSetup — схема с миграциями и каталог ключей с ключом подписи
// пакетов и УЦ, как после aisec-cli init.
func trustSetup(t *testing.T) (*store.DB, aisecCrypto.Provider, string) {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	const schema = "srv_trust_test"
	for _, q := range []string{"DROP SCHEMA IF EXISTS " + schema + " CASCADE", "CREATE SCHEMA " + schema} {
		if _, err := admin.Pool().Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = admin.Pool().Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE") //nolint:gosec // G104: уборка теста
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	db, err := store.Open(ctx, dsn+sep+"search_path="+schema, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	ms, err := store.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&store.Migrator{Exec: db, Hasher: h, Migrations: ms}).Up(ctx); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: каталог ключей теста
		t.Fatal(err)
	}
	s, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindSigning, p.Name(), s.Seed())
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindSigningPublic, p.Name(), s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := aisecCrypto.NewCA("AISec internal CA", 400*24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	writeKeyFile(t, dir, keyring.SigningKeyFile, keyPEM, 0o400)
	writeKeyFile(t, dir, keyring.SigningPubFile, pubPEM, 0o444)
	writeKeyFile(t, dir, keyring.CACertFile, ca.CertPEM(), 0o444)
	writeKeyFile(t, dir, keyring.CAKeyFile, caKey, 0o400)
	return db, p, dir
}

func TestServerTrustAfterRotation(t *testing.T) {
	db, p, dir := trustSetup(t)
	ctx := context.Background()
	cfg := &serverConfig{KeysDir: dir, CACert: filepath.Join(dir, keyring.CACertFile), CAKey: filepath.Join(dir, keyring.CAKeyFile)}
	tr, err := loadServerTrust(ctx, p, db, dir)
	if err != nil || tr == nil || tr.chain.Seq() != 0 {
		t.Fatalf("до ротаций: %v", err)
	}
	s0, err := loadBundleSigner(p, dir, tr)
	if err != nil || tr.chain.ActiveKeyID() != tr.anchorID {
		t.Fatalf("ключ до ротаций: %v", err)
	}
	ca0, err := loadServerCA(cfg, p, tr)
	if err != nil || ca0.roots.Active != "" {
		t.Fatalf("УЦ до ротаций: %v", err)
	}

	rec, err := audit.New(db.Pool(), p)
	if err != nil {
		t.Fatal(err)
	}
	actor := audit.Actor{Type: audit.ActorCLI, ID: "uid:0", Name: "root"}
	now := time.Now()
	rs, err := keyring.RotateSigning(ctx, db.Pool(), rec, p, dir, audit.DefaultOrgID, actor, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := keyring.RotateCA(ctx, db.Pool(), rec, p, dir, audit.DefaultOrgID, actor, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tr, err = loadServerTrust(ctx, p, db, dir)
	if err != nil || tr.chain.Seq() != 2 || tr.chain.ActiveKeyID() != rs.NewID {
		t.Fatalf("после ротаций: %v", err)
	}
	s1, err := loadBundleSigner(p, dir, tr)
	if err != nil || bytes.Equal(s1.PublicKey(), s0.PublicKey()) {
		t.Fatalf("ключ подписи после ротации: %v", err)
	}
	ca1, err := loadServerCA(cfg, p, tr)
	if err != nil {
		t.Fatal(err)
	}
	if ca1.roots.Active != rc.NewID || ca1.anchorRoot != rc.OldID || len(ca1.roots.NotAfter) != 2 ||
		ca1.roots.NotAfter[rc.OldID].IsZero() || !ca1.roots.NotAfter[rc.NewID].IsZero() {
		t.Fatalf("корни: %+v", ca1.roots)
	}
	if bytes.Equal(ca1.ca.CertDER(), ca0.ca.CertDER()) || bytes.Count(ca1.clientCAs, []byte("BEGIN CERTIFICATE")) != 2 {
		t.Fatal("УЦ после ротации: выпускает прежний корень или клиентам доверен один корень")
	}
	keys, err := bundleKeys(p, dir, rs.NewID, tr)
	if err != nil || !slices.Contains(keys.Known, rs.OldID) || !slices.Contains(keys.Known, rs.NewID) {
		t.Fatalf("ключи для сверки heartbeat: %+v %v", keys, err)
	}
	var watched []string
	for _, w := range tr.watch(cfg) {
		watched = append(watched, filepath.Base(w.Path))
	}
	_, newPub := keyring.SigningFiles(rs.NewID, rs.OldID)
	newCrt, _ := keyring.CAFiles(rc.NewID, rc.OldID)
	if !slices.Contains(watched, newPub) || !slices.Contains(watched, newCrt) || !slices.Contains(watched, keyring.SigningPubFile) {
		t.Fatalf("под контролем целостности: %v", watched)
	}

	// Подмена файлов нового ключа или корня — отказ запуска.
	newKey, _ := keyring.SigningFiles(rs.NewID, rs.OldID)
	other, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindSigning, p.Name(), other.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, newKey)); err != nil {
		t.Fatal(err)
	}
	writeKeyFile(t, dir, newKey, otherPEM, 0o400)
	if _, err := loadBundleSigner(p, dir, tr); err == nil {
		t.Fatal("подменённый ключ подписи принят")
	}
	stranger, err := aisecCrypto.NewCA("AISec internal CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	strangerKey, err := stranger.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, newCAKey := keyring.CAFiles(rc.NewID, rc.OldID)
	for _, n := range []string{newCrt, newCAKey} {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	writeKeyFile(t, dir, newCrt, stranger.CertPEM(), 0o444)
	writeKeyFile(t, dir, newCAKey, strangerKey, 0o400)
	if _, err := loadServerCA(cfg, p, tr); err == nil {
		t.Fatal("подменённый корень УЦ принят")
	}
	// Подменённое заявление в БД (владелец схемы обошёл триггер) — отказ
	// запуска: цепочка не проверяется от якоря.
	if _, err := db.Pool().Exec(ctx, "ALTER TABLE trust_statements DISABLE TRIGGER trust_statements_no_update"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool().Exec(ctx, "UPDATE trust_statements SET statement = (SELECT statement FROM trust_statements WHERE seq = 1) WHERE seq = 2"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadServerTrust(ctx, p, db, dir); err == nil {
		t.Fatal("подменённое заявление в БД принято")
	}
}
