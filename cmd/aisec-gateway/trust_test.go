package main

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
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
