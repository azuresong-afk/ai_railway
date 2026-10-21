package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/api"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

type nopAudit struct{}

func (nopAudit) Record(context.Context, audit.Entry) error { return nil }

func TestLoadRegConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	ok := []string{"-console", "https://srv:8444", "-console-ca", "ca.crt", "-out-dir", "/etc/aisec/gw"}
	cfg, err := loadRegConfig(ok, env(map[string]string{tokenEnv: "aisec_gwreg_x"}), io.Discard) //nolint:gosec // G101: не токен, а произвольная строка теста разбора флагов
	if err != nil || cfg.Token != "aisec_gwreg_x" || cfg.OutDir != "/etc/aisec/gw" {
		t.Fatalf("%+v %v", cfg, err)
	}
	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
	}{
		"нет токена":       {ok, nil},
		"нет консоли":      {ok[2:], map[string]string{tokenEnv: "t"}},
		"http":             {[]string{"-console", "http://srv", "-console-ca", "c", "-out-dir", "d"}, map[string]string{tokenEnv: "t"}},
		"лишний аргумент":  {append(append([]string{}, ok...), "x"), map[string]string{tokenEnv: "t"}},
		"токен аргументом": {append(append([]string{}, ok...), "-token", "t"), map[string]string{tokenEnv: "t"}},
	} {
		if _, err := loadRegConfig(tc.args, env(tc.env), io.Discard); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// Регистрация против настоящего обработчика консоли: файлы с нужными
// правами, повторный запуск ничего не перезаписывает и токен не тратит.
func TestRunRegister(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca, err := aisecCrypto.NewCA("AISec test CA", 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := gwregistry.New(gwregistry.Options{Store: gwregistry.NewMemory(), Provider: p, CA: ca, Audit: nopAudit{}, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	handler, _, err := api.New(api.Options{Logger: quiet, Hasher: h, Gateways: svc})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	if srv.TLS, err = tp.ServerConfig(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	srv.StartTLS()
	defer srv.Close()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "console-ca.crt")
	if err := os.WriteFile(caFile, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "gw")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	tok, _, err := svc.IssueToken(context.Background(), gwregistry.TokenInput{Name: "gw-1", Actor: audit.Actor{Type: audit.ActorCLI, ID: "uid:0"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &regConfig{Console: srv.URL, ConsoleCA: caFile, OutDir: out, Token: tok}
	var stdout bytes.Buffer
	if err := runRegister(context.Background(), cfg, &stdout); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), tok) || !strings.Contains(stdout.String(), "gw-1") {
		t.Fatalf("вывод: %s", stdout.String())
	}
	for name, perm := range map[string]os.FileMode{regKeyFile: 0o600, regCertFile: 0o644, regCAFile: 0o644} {
		info, err := os.Stat(filepath.Join(out, name))
		if err != nil || info.Mode().Perm() != perm {
			t.Fatalf("%s: %v %v", name, info, err)
		}
	}
	key, err := aisecCrypto.ReadKeyFile(filepath.Join(out, regKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	crt, err := os.ReadFile(filepath.Join(out, regCertFile)) //nolint:gosec // G304: путь во временном каталоге теста
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tp.ClientCertConfig(ca.CertPEM(), crt, key); err != nil {
		t.Fatalf("ключ и сертификат не парные: %v", err)
	}
	// Повтор в тот же каталог: отказ до обращения к серверу.
	tok2, _, err := svc.IssueToken(context.Background(), gwregistry.TokenInput{Name: "gw-1", Reregister: true, Actor: audit.Actor{Type: audit.ActorCLI, ID: "uid:0"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Token = tok2
	if err := runRegister(context.Background(), cfg, io.Discard); err == nil || !strings.Contains(err.Error(), "уже существует") {
		t.Fatalf("повтор в тот же каталог: %v", err)
	}
	// Каталог, доступный группе, — отказ.
	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o750); err != nil { //nolint:gosec // G302: каталог, открытый группе, — проверяемый отказ
		t.Fatal(err)
	}
	cfg.OutDir = open
	if err := runRegister(context.Background(), cfg, io.Discard); err == nil {
		t.Fatal("каталог 0750 принят")
	}
	// Токен не потрачен неудачными попытками: регистрация в новый каталог проходит.
	fresh := filepath.Join(dir, "fresh")
	if err := os.Mkdir(fresh, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.OutDir = fresh
	if err := runRegister(context.Background(), cfg, io.Discard); err != nil {
		t.Fatalf("регистрация после отказов: %v", err)
	}
}
