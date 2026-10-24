package main

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
)

// В19 ревью 2.r4: у шлюза с сервером под контролем целостности корни
// доверия — -server-ca, -bundle-pub и -user-hmac-key; подмена ключа
// проверки пакетов после запуска — нарушение (changed). Эталон — хеш
// прочитанных байтов (Н37).
func TestTrustFilesWatched(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ca := write("ca.crt", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	pub := write("bundle-signing.pub", "-----BEGIN AISEC SIGNING PUBLIC KEY-----\nAAAA\n-----END AISEC SIGNING PUBLIC KEY-----\n")
	hmac := write("user-hmac.key", "синтетический ключ псевдонимов")
	srv, err := url.Parse("https://aisec.example:8444")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Gateway{Server: srv, ServerCAFile: ca, BundlePubFiles: []string{pub}, UserHMACKeyFile: hmac}
	tf, err := readTrustFiles(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, w := range tf.watch {
		if w.Data == nil {
			t.Errorf("%s: эталон не из прочитанных байтов", w.Path)
		}
		paths = append(paths, w.Path)
	}
	if !slices.Equal(paths, []string{ca, pub, hmac}) || len(tf.bundlePubs) != 1 || tf.serverCA == nil || tf.userHMACKey == nil {
		t.Fatalf("%v", paths)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	c, err := integrity.NewChecker(integrity.Config{Component: "gateway", Provider: p,
		ManifestPath: filepath.Join(dir, integrity.ManifestFile), Watch: tf.watch})
	if err != nil {
		t.Fatal(err)
	}
	// Нарушитель подменяет корень доверия пакетов своим ключом.
	write("bundle-signing.pub", "-----BEGIN AISEC SIGNING PUBLIC KEY-----\nBBBB\n-----END AISEC SIGNING PUBLIC KEY-----\n")
	res, err := c.Check(context.Background(), integrity.TriggerPeriodic)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Failures, integrity.Failure{Path: pub, Problem: integrity.ProblemChanged}) {
		t.Fatalf("подмена -bundle-pub не обнаружена: %+v", res)
	}
	// Без сервера — только ключ псевдонимов из файла конфигурации.
	file := &config.GatewayFile{}
	file.Gateway.UserHMACKeyFile = hmac
	tf, err = readTrustFiles(&config.Gateway{}, file)
	if err != nil || len(tf.watch) != 1 || tf.watch[0].Path != hmac {
		t.Fatalf("%+v %v", tf.watch, err)
	}
}

// 3В9 ревью 3.r1, DM-42: -bundle-pub перенесён на ключ заявления №1
// (компрометация первого ключа подписи). При запуске заявления до якоря из
// trust.json пропускаются, цепочка восстанавливается с первого подписанного
// якорем; подложенное прежним ключом заявление доверия не даёт.
func TestLoadTrustChainReanchor(t *testing.T) {
	first, second, third := bundletest.New(t), bundletest.New(t), bundletest.New(t)
	p := first.Provider
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	key := func(s aisecCrypto.Signer, notAfter *time.Time) bundle.TrustKey {
		return bundle.TrustKey{PublicKey: s.PublicKey(), NotAfter: notAfter}
	}
	stmt1, err := bundle.SignTrust(p, first.Signer, bundle.TrustDraft{Seq: 1, IssuedAt: now,
		Keys: []bundle.TrustKey{key(first.Signer, &now), key(second.Signer, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	stmt2, err := bundle.SignTrust(p, second.Signer, bundle.TrustDraft{Seq: 2, IssuedAt: now,
		Keys: []bundle.TrustKey{key(second.Signer, &now), key(third.Signer, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := gateway.OpenBundleState(dir, rnd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }() //nolint:gosec // G104: тест
	if err := st.SaveTrust([][]byte{stmt1, stmt2}); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	chain, err := loadTrustChain(p, []aisecCrypto.Verifier{second.Verifier(t)}, st, logger)
	if err != nil {
		t.Fatal(err)
	}
	if chain.Seq() != 2 || chain.ActiveKeyID() != third.Sealer.KeyID() {
		t.Fatalf("номер %d, ключ %s", chain.Seq(), chain.ActiveKeyID())
	}
	// Якорь на первом ключе: та же цепочка, как раньше.
	chain, err = loadTrustChain(p, []aisecCrypto.Verifier{first.Verifier(t)}, st, logger)
	if err != nil || chain.Seq() != 2 {
		t.Fatalf("исходный якорь: %v, номер %d", err, chain.Seq())
	}
	// Подложенное первым (скомпрометированным) ключом заявление №1 с ключом
	// нарушителя при якоре на втором ключе пропускается.
	evil := bundletest.New(t)
	forged, err := bundle.SignTrust(p, first.Signer, bundle.TrustDraft{Seq: 1, IssuedAt: now,
		Keys: []bundle.TrustKey{key(first.Signer, &now), key(evil.Signer, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveTrust([][]byte{forged}); err != nil {
		t.Fatal(err)
	}
	chain, err = loadTrustChain(p, []aisecCrypto.Verifier{second.Verifier(t)}, st, logger)
	if err != nil || chain.Latest() != nil || chain.ActiveKeyID() != second.Sealer.KeyID() {
		t.Fatalf("подложенное заявление: %v, ключ %s", err, chain.ActiveKeyID())
	}
}
