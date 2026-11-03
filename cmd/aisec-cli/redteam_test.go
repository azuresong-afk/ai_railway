package main

import (
	"bytes"
	"context"
	"encoding/json"
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
)

// aisec-cli redteam run (задача 5.33 этапа 5): запуск токеном, ожидание,
// порог и коды выхода, значение секретного заголовка — только в теле запроса
// запуска, прерывание отменяет запуск; в выводе нет ничего сверх итогов.

const (
	rtTarget = "01900000-0000-7000-8000-0000000000c1"
	rtRun    = "01900000-0000-7000-8000-0000000000c2"
	rtToken  = "aisec_pat_synthetic_redteam_0123456789" //nolint:gosec // G101: синтетический токен теста
	rtAuth   = "Bearer synthetic-target-secret-5521"    //nolint:gosec // G101: синтетическое значение заголовка цели
)

type fakeRedteamAPI struct {
	mu        sync.Mutex
	starts    []map[string]any
	polls     int
	cancelled int
	// pending — сколько раз ответить «идёт» до итога.
	pending  int
	card     map[string]any
	auth     []string
	startErr int
}

func (f *fakeRedteamAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == "POST" && r.URL.Path == "/api/v1/redteam/runs":
		if f.startErr != 0 {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(f.startErr)
			_, _ = w.Write([]byte(`{"code":"conflict","detail":"У цели уже идёт запуск."}`)) //nolint:gosec // G104: ответ тестового сервера
			return
		}
		var in map[string]any
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) //nolint:gosec // G104: тестовый сервер
		_ = json.Unmarshal(body, &in)                        //nolint:gosec // G104: тестовый сервер
		f.starts = append(f.starts, in)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"` + rtRun + `","status":"running","scenarios":4,"db_version":3}`)) //nolint:gosec // G104: ответ тестового сервера
	case r.Method == "GET" && r.URL.Path == "/api/v1/redteam/runs/"+rtRun:
		f.polls++
		if f.polls <= f.pending {
			_, _ = w.Write([]byte(`{"id":"` + rtRun + `","status":"running","scenarios":4,"counts":{}}`)) //nolint:gosec // G104: ответ тестового сервера
			return
		}
		_ = json.NewEncoder(w).Encode(f.card) //nolint:gosec // G104: ответ тестового сервера
	case r.Method == "POST" && r.URL.Path == "/api/v1/redteam/runs/"+rtRun+"/cancel":
		f.cancelled++
		w.WriteHeader(http.StatusAccepted)
	default:
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"not_found","detail":"Не найдено."}`)) //nolint:gosec // G104: ответ тестового сервера
	}
}

type redteamEnv struct {
	api            *fakeRedteamAPI
	url, ca, token string
	dir            string
	stdout, stderr bytes.Buffer
}

func card(counts map[string]int, results ...map[string]any) map[string]any {
	return map[string]any{"id": rtRun, "target_name": "Бот", "status": "done", "scenarios": 4, "counts": counts, "db_version": 3, "results": results}
}

func won(id, threat string) map[string]any {
	return map[string]any{"scenario_id": id, "lang": "ru", "threat": threat, "category": "prompt_leak", "verdict": "succeeded", "step": 2,
		"matched": []string{"canary"}}
}

func newRedteamEnv(t *testing.T) *redteamEnv {
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
	ca, err := aisecCrypto.NewCA("redteam-test", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	e := &redteamEnv{api: &fakeRedteamAPI{card: card(map[string]int{"defended": 3, "blocked": 1})}, dir: t.TempDir()}
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
	e.ca, e.token = filepath.Join(e.dir, "ca.pem"), filepath.Join(e.dir, "token")
	if err := os.WriteFile(e.ca, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.token, []byte(rtToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *redteamEnv) run(extra ...string) int {
	e.stdout.Reset()
	e.stderr.Reset()
	args := append([]string{"redteam", "run", "-server", e.url, "-ca", e.ca, "-token-file", e.token, "-target", rtTarget, "-poll", "100ms"}, extra...)
	return run(args, &e.stdout, &e.stderr, time.Now())
}

func TestRedteamRunPassesUnderThreshold(t *testing.T) {
	e := newRedteamEnv(t)
	e.api.pending = 2
	if code := e.run("-threats", "DM-08, DM-01", "-lang", "ru", "-scenarios", "RT-DM08-001"); code != 0 {
		t.Fatalf("код %d: %s %s", code, e.stdout.String(), e.stderr.String())
	}
	if len(e.api.starts) != 1 || e.api.starts[0]["target_id"] != rtTarget || e.api.starts[0]["lang"] != "ru" {
		t.Fatalf("запрос запуска: %+v", e.api.starts)
	}
	if th, _ := e.api.starts[0]["threats"].([]any); len(th) != 2 || th[1] != "DM-01" {
		t.Fatalf("строки матрицы: %+v", e.api.starts[0])
	}
	if _, ok := e.api.starts[0]["auth_value"]; ok {
		t.Fatal("auth_value без -auth-value-file")
	}
	if e.api.polls != 3 || e.api.auth[0] != "Bearer "+rtToken {
		t.Fatalf("опросов %d, заголовки %v", e.api.polls, e.api.auth)
	}
	out := e.stdout.String()
	if !strings.Contains(out, "отражено — 3") || !strings.Contains(out, "заблокировано защитой — 1") || !strings.Contains(out, "не выше порога") ||
		strings.Contains(out+e.stderr.String(), rtToken) {
		t.Fatalf("вывод: %s", out)
	}
}

func TestRedteamRunThresholdExitCode(t *testing.T) {
	e := newRedteamEnv(t)
	e.api.card = card(map[string]int{"succeeded": 2, "defended": 7, "blocked": 11, "error": 1},
		won("RT-DM08-001", "DM-08"), won("RT-DM01-002", "DM-01"))
	// 2 из 20 проверенных = 10,0 %.
	if code := e.run("-threshold", "9.9"); code != 3 {
		t.Fatalf("выше порога: код %d, %s %s", code, e.stdout.String(), e.stderr.String())
	}
	out := e.stdout.String()
	if !strings.Contains(out, "Удавшиеся атаки (2 из 20 проверенных, 10,0 %)") || !strings.Contains(out, "RT-DM01-002\tru\tDM-01") ||
		strings.Index(out, "RT-DM01-002") > strings.Index(out, "RT-DM08-001") || !strings.Contains(out, "ВНИМАНИЕ: сценариев без вердикта защиты: 1") {
		t.Fatalf("вывод: %s", out)
	}
	if code := e.run("-threshold", "10"); code != 0 {
		t.Fatalf("на пороге: код %d, %s %s", code, e.stdout.String(), e.stderr.String())
	}
	// По умолчанию порог 0: любая удавшаяся атака — код 3.
	if code := e.run(); code != 3 {
		t.Fatalf("порог по умолчанию: код %d", code)
	}
}

func TestRedteamRunIncompleteIsError(t *testing.T) {
	e := newRedteamEnv(t)
	for name, c := range map[string]map[string]any{
		"запуск не удался": {"id": rtRun, "status": "failed", "reason": "deadline", "counts": map[string]int{"defended": 5}},
		"отменён":          {"id": rtRun, "status": "cancelled", "counts": map[string]int{"skipped": 4}},
		"все с ошибкой":    card(map[string]int{"error": 4}),
		"нет вердиктов":    card(map[string]int{"unchecked": 4}),
	} {
		e.api.card = c
		if code := e.run("-threshold", "100"); code != 1 {
			t.Errorf("%s: код %d, ожидался 1: %s %s", name, code, e.stdout.String(), e.stderr.String())
		}
	}
}

func TestRedteamRunAuthValueOnlyInRequest(t *testing.T) {
	e := newRedteamEnv(t)
	secret := filepath.Join(e.dir, "auth")
	if err := os.WriteFile(secret, []byte(rtAuth+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(e.dir, "result.json")
	if code := e.run("-auth-value-file", secret, "-out", out); code != 0 {
		t.Fatalf("код %d: %s %s", code, e.stdout.String(), e.stderr.String())
	}
	if e.api.starts[0]["auth_value"] != rtAuth {
		t.Fatalf("значение заголовка не передано: %+v", e.api.starts[0])
	}
	data, err := os.ReadFile(out) //nolint:gosec // G304: файл теста
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 || strings.Contains(string(data), rtAuth) || //nolint:gosec // ошибка в этом тесте не влияет на проверяемое условие
		strings.Contains(e.stdout.String()+e.stderr.String(), rtAuth) {
		t.Fatalf("файл итогов или вывод: %v %s", st.Mode(), data)
	}
	// Существующий файл не перезаписывается.
	if code := e.run("-out", out); code != 1 {
		t.Fatalf("перезапись файла: код %d", code)
	}
	// Файл со значением, доступным всем, отвергается.
	if err := os.Chmod(secret, 0o644); err != nil { //nolint:gosec // G302: проверка отказа
		t.Fatal(err)
	}
	if code := e.run("-auth-value-file", secret); code != 1 || !strings.Contains(e.stderr.String(), "-auth-value-file") {
		t.Fatalf("права файла: код %d, %s", code, e.stderr.String())
	}
}

func TestRedteamRunInputErrors(t *testing.T) {
	e := newRedteamEnv(t)
	for name, extra := range map[string][]string{
		"порог":           {"-threshold", "101"},
		"отрицательный":   {"-threshold", "-1"},
		"язык":            {"-lang", "de"},
		"строка матрицы":  {"-threats", "DM-1"},
		"ID сценария":     {"-scenarios", "rt-dm08"},
		"ожидание":        {"-wait", "10s"},
		"опрос":           {"-poll", "1ms"},
		"лишний аргумент": {"extra"},
	} {
		if code := e.run(extra...); code != 1 {
			t.Errorf("%s: код %d", name, code)
		}
	}
	if len(e.api.starts) != 0 {
		t.Fatal("запуск начат при неверных флагах")
	}
	if code := run([]string{"redteam", "run", "-server", e.url}, &e.stdout, &e.stderr, time.Now()); code != 1 {
		t.Fatalf("без обязательных флагов: %d", code)
	}
	if code := run([]string{"redteam", "bad"}, &e.stdout, &e.stderr, time.Now()); code != 1 {
		t.Fatalf("неизвестная подкоманда: %d", code)
	}
	// Отказ сервера (занята цель) — код 1 с текстом сервера.
	e.api.startErr = http.StatusConflict
	if code := e.run(); code != 1 || !strings.Contains(e.stderr.String(), "У цели уже идёт запуск") {
		t.Fatalf("отказ сервера: код %d, %s", code, e.stderr.String())
	}
}

// Прерывание команды отменяет запуск на сервере.
func TestRedteamRunInterruptCancels(t *testing.T) {
	e := newRedteamEnv(t)
	e.api.pending = 1000
	ctx, stop := context.WithCancel(context.Background())
	go func() {
		for {
			e.api.mu.Lock()
			n := e.api.polls
			e.api.mu.Unlock()
			if n >= 2 {
				stop()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	err := redteamRun(ctx, []string{"-server", e.url, "-ca", e.ca, "-token-file", e.token, "-target", rtTarget, "-poll", "100ms"},
		&e.stdout, &e.stderr)
	if err == nil || !strings.Contains(err.Error(), "отменён") {
		t.Fatalf("ошибка: %v", err)
	}
	e.api.mu.Lock()
	defer e.api.mu.Unlock()
	if e.api.cancelled != 1 {
		t.Fatalf("отмен: %d", e.api.cancelled)
	}
}
