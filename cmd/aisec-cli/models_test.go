package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/httpserver"
	"github.com/azuresong-afk/ai_railway/internal/inventory"
)

// aisec-cli models scan и verify (задачи 5.21 и 5.22 этапа 5): отчёт без
// весов уходит на сервер по TLS с токеном из файла; запрет модели — код
// выхода 3; расхождения с эталоном видны на узле до отправки.

const (
	modelsTestID    = "01900000-0000-7000-8000-0000000000d1"
	modelsTestToken = "aisec_pat_synthetic_models_0123456789" //nolint:gosec // G101: синтетический токен теста
	shaABC          = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)

// fakeAPI — сервер управления: эталон и приём отчёта.
type fakeAPI struct {
	mu      sync.Mutex
	reports []inventory.ReportInput
	auth    []string
	result  map[string]any
	ref     inventory.Reference
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/inventory/models/"+modelsTestID+"/reference":
		_ = json.NewEncoder(w).Encode(f.ref) //nolint:gosec // G104: ответ тестового сервера
	case r.Method == "POST" && r.URL.Path == "/api/v1/inventory/models/"+modelsTestID+"/scan-reports":
		body, _ := io.ReadAll(io.LimitReader(r.Body, inventory.MaxReportBody+1)) //nolint:gosec // G104: тестовый сервер
		in, err := inventory.ParseReport(body)
		if err != nil {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"code":"invalid_request","detail":%q}`, err.Error()) //nolint:gosec // G104: ответ тестового сервера
			return
		}
		f.reports = append(f.reports, in)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(f.result) //nolint:gosec // G104: ответ тестового сервера
	default:
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"not_found","detail":"Модель не найдена."}`)) //nolint:gosec // G104: ответ тестового сервера
	}
}

type modelsEnv struct {
	api            *fakeAPI
	url, ca, token string
	dir, modelDir  string
	stdout, stderr bytes.Buffer
}

func newModelsEnv(t *testing.T) *modelsEnv {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca, err := aisecCrypto.NewCA("models-test", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	e := &modelsEnv{api: &fakeAPI{result: map[string]any{"id": "r1", "verdict": "ok", "hashes": "match", "templates": "none",
		"files": 2, "model_status": "active"}}, dir: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	srv, err := httpserver.New(ctx, httpserver.Config{Addr: "127.0.0.1:0", Handler: e.api, TLS: tp, CertPEM: cert, KeyPEM: key,
		Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	e.url = "https://" + srv.Addr()
	e.ca = filepath.Join(e.dir, "ca.pem")
	e.token = filepath.Join(e.dir, "token")
	if err := os.WriteFile(e.ca, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.token, []byte(modelsTestToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.modelDir = filepath.Join(e.dir, "model")
	for name, data := range map[string]string{"weights/a.bin": "abc", "tokenizer_config.json": `{"chat_template":"{{ messages }}"}`} { //nolint:gosec // G101: имя файла tokenizer_config.json, не учётные данные
		p := filepath.Join(e.modelDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *modelsEnv) run(sub string, extra ...string) int {
	e.stdout.Reset()
	e.stderr.Reset()
	args := append([]string{"models", sub, "-server", e.url, "-ca", e.ca, "-token-file", e.token, "-model", modelsTestID, "-host", "gpu-01"},
		extra...)
	return run(args, &e.stdout, &e.stderr, time.Now())
}

func TestModelsScan(t *testing.T) {
	e := newModelsEnv(t)
	if code := e.run("scan", e.modelDir); code != 0 {
		t.Fatalf("код %d: %s", code, e.stderr.String())
	}
	if len(e.api.reports) != 1 || e.api.auth[0] != "Bearer "+modelsTestToken {
		t.Fatalf("отчёт: %+v, заголовки %v", e.api.reports, e.api.auth)
	}
	in := e.api.reports[0]
	files := map[string]inventory.ReportFile{}
	for _, f := range in.Files {
		files[f.Path] = f
	}
	tc := files["tokenizer_config.json"]
	if in.Kind != inventory.ReportScan || in.Host != "gpu-01" || files["weights/a.bin"].SHA256 != shaABC ||
		len(tc.ChatTemplates) != 1 || tc.ChatTemplates[0].Text != "{{ messages }}" || tc.Format == "" {
		t.Fatalf("содержимое отчёта: %+v", in)
	}
	if !strings.Contains(e.stdout.String(), "Отчёт r1 принят") || strings.Contains(e.stdout.String()+e.stderr.String(), modelsTestToken) {
		t.Fatalf("вывод: %s", e.stdout.String())
	}
	// Запрет — код 3 и пояснение.
	e.api.result = map[string]any{"id": "r2", "verdict": "block", "hashes": "match", "templates": "injection", "files": 2,
		"blocked": true, "block_reasons": []string{"chat_template"}, "model_status": "blocked"}
	if code := e.run("scan", e.modelDir); code != 3 || !strings.Contains(e.stdout.String(), "Причины запрета: chat_template") {
		t.Fatalf("запрет: код %d, %s %s", code, e.stdout.String(), e.stderr.String())
	}
}

func TestModelsVerify(t *testing.T) {
	e := newModelsEnv(t)
	e.api.ref = inventory.Reference{ModelID: modelsTestID, Status: "active", HashAlg: "SHA-256", Files: []inventory.ReferenceFile{
		{Path: "weights/a.bin", Size: 3, Role: "weights", SHA256: shaABC},
		{Path: "weights/b.bin", Size: 3, Role: "weights", SHA256: shaABC}}}
	e.api.result = map[string]any{"id": "r3", "verdict": "block", "hashes": "mismatch", "templates": "none", "files": 2,
		"blocked": true, "block_reasons": []string{"hash_mismatch"}, "mismatch_total": 1, "model_status": "blocked"}
	if code := e.run("verify", e.modelDir); code != 3 {
		t.Fatalf("код %d: %s %s", code, e.stdout.String(), e.stderr.String())
	}
	out := e.stdout.String()
	if !strings.Contains(out, "Нет файла: weights/b.bin") || !strings.Contains(out, "расхождений с эталоном: 1") {
		t.Fatalf("локальная сверка: %s", out)
	}
	in := e.api.reports[0]
	for _, f := range in.Files {
		if f.Format != "" || len(f.Findings) != 0 || len(f.ChatTemplates) != 0 || f.SHA256 == "" {
			t.Fatalf("verify с разбором форматов: %+v", f)
		}
	}
	if in.Kind != inventory.ReportVerify || len(in.Files) != 2 {
		t.Fatalf("отчёт verify: %+v", in)
	}
}

func TestModelsRejects(t *testing.T) {
	e := newModelsEnv(t)
	for name, args := range map[string][]string{
		"нет подкоманды": {"models"},
		"нет пути":       {"models", "scan", "-server", e.url, "-ca", e.ca, "-token-file", e.token, "-model", modelsTestID},
		"два пути":       {"models", "scan", "-server", e.url, "-ca", e.ca, "-token-file", e.token, "-model", modelsTestID, "a", "b"},
		"нет сервера":    {"models", "scan", "-ca", e.ca, "-token-file", e.token, "-model", modelsTestID, e.modelDir},
		"http":           {"models", "scan", "-server", strings.Replace(e.url, "https", "http", 1), "-ca", e.ca, "-token-file", e.token, "-model", modelsTestID, e.modelDir},
		"модель не UUID": {"models", "scan", "-server", e.url, "-ca", e.ca, "-token-file", e.token, "-model", "llama", e.modelDir},
		"имя узла":       {"models", "scan", "-server", e.url, "-ca", e.ca, "-token-file", e.token, "-model", modelsTestID, "-host", "gpu 01", e.modelDir},
		"срок":           {"models", "scan", "-server", e.url, "-ca", e.ca, "-token-file", e.token, "-model", modelsTestID, "-timeout", "1h", e.modelDir},
		"профиль":        {"models", "scan", "-server", e.url, "-ca", e.ca, "-token-file", e.token, "-model", modelsTestID, "-crypto-profile", "x", e.modelDir},
		"токен из флага": {"models", "scan", "-server", e.url, "-ca", e.ca, "-token", modelsTestToken, "-model", modelsTestID, e.modelDir},
		"нет каталога":   {"models", "scan", "-server", e.url, "-ca", e.ca, "-token-file", e.token, "-model", modelsTestID, filepath.Join(e.dir, "нет")},
		"неизвестная":    {"models", "delete"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb, time.Now()); code != 1 && code != 2 {
			t.Errorf("%s: код %d", name, code)
		}
		if strings.Contains(errb.String(), modelsTestToken) {
			t.Errorf("%s: токен в выводе", name)
		}
	}
	// Файл токена, доступный группе, — отказ до запроса.
	if err := os.Chmod(e.token, 0o644); err != nil { //nolint:gosec // G302: проверка отказа на файле токена, доступном группе
		t.Fatal(err)
	}
	if code := e.run("scan", e.modelDir); code == 0 || len(e.api.reports) != 0 || !strings.Contains(e.stderr.String(), "0600") {
		t.Fatalf("права токена: код %d, %s", code, e.stderr.String())
	}
	if err := os.Chmod(e.token, 0o600); err != nil {
		t.Fatal(err)
	}
	// Неизвестная модель на сервере — отказ с текстом сервера.
	args := []string{"models", "verify", "-server", e.url, "-ca", e.ca, "-token-file", e.token, "-model",
		"01900000-0000-7000-8000-0000000000ff", e.modelDir}
	var out, errb bytes.Buffer
	if code := run(args, &out, &errb, time.Now()); code != 1 || !strings.Contains(errb.String(), "Модель не найдена") {
		t.Fatalf("нет модели: код %d, %s", code, errb.String())
	}
}
