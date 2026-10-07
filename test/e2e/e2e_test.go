//go:build e2e

// Пакет e2e — сквозные тесты: настоящие бинарники шлюза и mock-llm запускаются
// отдельными процессами, запросы идут по TLS (критерий приёмки этапа 0, ТЗ 14).
// Запуск: make e2e (собирает бинарники и передаёт каталог флагом -bin).
package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

var binDir = flag.String("bin", "../../build/bin", "каталог с собранными бинарниками")

// keys выпускает УЦ и серверный сертификат во временный каталог.
type keys struct{ dir, ca, cert, key string }

func newKeys(t *testing.T) keys {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	ca, err := aisecCrypto.NewCA("e2e CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{"127.0.0.1", "localhost"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	k := keys{dir, filepath.Join(dir, "ca.pem"), filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem")}
	for path, data := range map[string][]byte{k.ca: ca.CertPEM(), k.cert: cert, k.key: key} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return k
}

// promptMarker — текст промпта, которого не должно быть в журналах компонентов.
const promptMarker = "секретный-промпт-e2e"

// start запускает компонент на свободном порту и возвращает адрес из строки
// журнала «сервер запущен». После теста проверяет, что в журнал не попал
// текст промпта (технические логи — без содержимого запросов).
func start(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, filepath.Join(*binDir, name), args...) //nolint:gosec // G204: тест запускает собственные бинарники из каталога сборки
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("%s: %v (выполните make build)", name, err)
	}
	logs := &strings.Builder{}
	addr := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			logs.WriteString(line + "\n")
			var entry struct{ Msg, Addr string }
			if json.Unmarshal([]byte(line), &entry) == nil && entry.Msg == "сервер запущен" {
				addr <- entry.Addr
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		if err := cmd.Wait(); err != nil && !errors.Is(ctx.Err(), context.Canceled) {
			t.Errorf("%s завершился с ошибкой: %v", name, err)
		}
		<-done
		if strings.Contains(logs.String(), promptMarker) {
			t.Errorf("текст промпта попал в журнал %s", name)
		}
		// Ключи приложений (и даже их префиксы) в технический журнал не пишутся.
		if strings.Contains(logs.String(), "aisec_") {
			t.Errorf("ключ приложения попал в журнал %s", name)
		}
		if t.Failed() {
			t.Logf("журнал %s:\n%s", name, logs.String())
		}
	})
	select {
	case a := <-addr:
		return a
	case <-time.After(10 * time.Second):
		t.Fatalf("%s не запустился за 10 с", name)
		return ""
	}
}

// env — поднятый стенд: адрес шлюза, клиент с доверием к УЦ стенда, ключ
// приложения и файл событий шлюза.
type env struct {
	url    string
	client *http.Client
	key    string
	events string
}

// gatewayConfig пишет файл конфигурации шлюза с одним приложением и
// возвращает выпущенный для него ключ.
func gatewayConfig(t *testing.T, dir, mockAddr string, p aisecCrypto.Provider) (path, key, eventsFile string) {
	t.Helper()
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	key, prefix, hash, err := auth.NewAppKey(rnd, h)
	if err != nil {
		t.Fatal(err)
	}
	eventsFile = filepath.Join(dir, "events.jsonl")
	cfg := `schema_version: 1
gateway:
  events_file: ` + eventsFile + `
providers:
  - id: mock
    type: openai
    base_url: https://` + mockAddr + `/v1
    ca_file: ` + filepath.Join(dir, "ca.pem") + `
applications:
  - id: e2e-app
    name: Сквозные тесты
    env: test
    provider: mock
    models: [mock-echo, mock-stream-slow, mock-error-429]
    policy: base
    policy_mode: monitor
    fail_mode: fail_closed
    storage: none
    user_from: none
    keys:
` + auth.FormatKeyEntry(prefix, hash, "")
	path = filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, key, eventsFile
}

// stand поднимает mock-llm и шлюз перед ним.
func stand(t *testing.T) *env {
	t.Helper()
	k := newKeys(t)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	mock := start(t, "mock-llm", "-listen", "127.0.0.1:0", "-cert", k.cert, "-key", k.key)
	cfgPath, key, eventsFile := gatewayConfig(t, k.dir, mock, p)
	gw := start(t, "aisec-gateway", "-config", cfgPath, "-listen", "127.0.0.1:0", "-tls-cert", k.cert, "-tls-key", k.key)
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	roots, err := os.ReadFile(k.ca)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tp.ClientConfig(roots)
	if err != nil {
		t.Fatal(err)
	}
	return &env{url: "https://" + gw, client: &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 30 * time.Second},
		key: key, events: eventsFile}
}

// chat отправляет запрос с ключом приложения стенда; заголовок Authorization
// в hdr заменяет ключ, пустое значение — убирает его.
func chat(t *testing.T, e *env, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, e.url+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.key)
	for k, v := range hdr {
		req.Header.Set(k, v)
		if v == "" {
			req.Header.Del(k)
		}
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp // тело закрывает вызывающий тест
}

func TestE2EChatThroughGateway(t *testing.T) {
	e := stand(t)
	resp := chat(t, e, `{"model":"mock-echo","messages":[{"role":"user","content":"привет через шлюз `+promptMarker+`"}]}`, nil)
	defer resp.Body.Close() //nolint:errcheck // тело прочитано; ошибка закрытия в тесте не важна
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код %d", resp.StatusCode)
	}
	var out struct {
		Choices []struct{ Message struct{ Content string } }
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Choices) != 1 || out.Choices[0].Message.Content != "привет через шлюз "+promptMarker {
		t.Fatalf("ответ: %+v", out)
	}
}

func TestE2EStreamingThroughGateway(t *testing.T) {
	e := stand(t)
	body := `{"model":"mock-stream-slow","stream":true,"messages":[{"role":"user","content":"раз два три четыре пять"}]}`
	start := time.Now()
	resp := chat(t, e, body, nil)
	defer resp.Body.Close() //nolint:errcheck // тело прочитано; ошибка закрытия в тесте не важна
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("код %d, тип %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	sc := bufio.NewScanner(resp.Body)
	var text strings.Builder
	var firstAt time.Duration
	done := false
	for sc.Scan() {
		payload, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		if firstAt == 0 {
			firstAt = time.Since(start)
		}
		if payload == "[DONE]" {
			done = true
			break
		}
		var chunk struct {
			Choices []struct{ Delta struct{ Content string } }
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			t.Fatalf("часть потока: %q", payload)
		}
		text.WriteString(chunk.Choices[0].Delta.Content)
	}
	total := time.Since(start)
	if !done || text.String() != "раз два три четыре пять" {
		t.Fatalf("поток: %q, завершён %v", text.String(), done)
	}
	// stream-slow отдаёт 5 частей с паузой 50 мс: первая часть должна прийти
	// заметно раньше конца потока, иначе шлюз буферизует SSE.
	if total-firstAt < 150*time.Millisecond {
		t.Fatalf("поток пришёл одним куском: первая часть через %s, конец через %s", firstAt, total)
	}
}

func TestE2EUpstreamErrorPassedThrough(t *testing.T) {
	e := stand(t)
	resp := chat(t, e, `{"model":"mock-error-429","messages":[{"role":"user","content":"x"}]}`, nil)
	defer resp.Body.Close() //nolint:errcheck // тело прочитано; ошибка закрытия в тесте не важна
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" || !strings.Contains(string(b), "rate_limit_exceeded") {
		t.Fatalf("ошибка провайдера: %d %s %q", resp.StatusCode, resp.Header.Get("Retry-After"), b)
	}
}

func TestE2EPlainHTTPRejected(t *testing.T) {
	e := stand(t)
	plain := strings.Replace(e.url, "https://", "http://", 1)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, plain+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return // соединение отвергнуто — тоже допустимо
	}
	defer resp.Body.Close() //nolint:errcheck // тест проверяет только код
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("шлюз ответил по HTTP без TLS: %d", resp.StatusCode)
	}
}

// Неудачная аутентификация: 401 без подробностей, событие auth_failure с
// адресом, префиксом и причиной, без самого ключа (критерий приёмки этапа 1).
func TestE2EDM38_AuthFailureEvent(t *testing.T) {
	e := stand(t)
	body := `{"model":"mock-echo","messages":[{"role":"user","content":"` + promptMarker + `"}]}`
	forged := e.key[:len(e.key)-4] + "AAAA"
	if forged == e.key {
		forged = e.key[:len(e.key)-4] + "BBBB"
	}
	for _, authz := range []string{"", "Bearer " + forged} {
		resp := chat(t, e, body, map[string]string{"Authorization": authz})
		b, err := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); err != nil || cerr != nil {
			t.Fatal(err, cerr)
		}
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(b), "invalid_api_key") {
			t.Fatalf("%q: %d %s", authz, resp.StatusCode, b)
		}
	}
	// Очередь сбрасывает события раз в секунду.
	var got []events.Event
	deadline := time.Now().Add(5 * time.Second)
	for len(got) < 2 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		got = readEvents(t, e.events)
	}
	if len(got) != 2 {
		t.Fatalf("событий auth_failure: %d", len(got))
	}
	reasons := map[string]string{}
	for _, ev := range got {
		if ev.Type != events.TypeAuthFailure || ev.AuthFailure == nil || ev.AuthFailure.RemoteAddr != "127.0.0.1" {
			t.Fatalf("событие: %+v", ev)
		}
		reasons[ev.AuthFailure.Reason] = ev.AuthFailure.KeyPrefix
	}
	if _, ok := reasons[auth.ReasonMissing]; !ok || reasons[auth.ReasonInvalid] != e.key[:len("aisec_12345678")] {
		t.Fatalf("причины и префиксы: %v", reasons)
	}
	raw, err := os.ReadFile(e.events) //nolint:gosec // G304: файл событий стенда во временном каталоге теста
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), forged) || strings.Contains(string(raw), promptMarker) {
		t.Fatal("в файл событий попал ключ или содержимое запроса")
	}
}

func readEvents(t *testing.T, path string) []events.Event {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: файл событий стенда во временном каталоге теста
	if err != nil {
		t.Fatal(err)
	}
	var out []events.Event
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var ev events.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("строка событий: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

// Неразрешённая модель отклоняется шлюзом, список моделей — только
// разрешённые приложению (DM-33).
func TestE2EDM33_ModelNotAllowed(t *testing.T) {
	e := stand(t)
	resp := chat(t, e, `{"model":"mock-fixed","messages":[{"role":"user","content":"x"}]}`, nil)
	b, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err != nil || cerr != nil {
		t.Fatal(err, cerr)
	}
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(b), "model_not_found") {
		t.Fatalf("неразрешённая модель: %d %s", resp.StatusCode, b)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, e.url+"/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+e.key)
	mr, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Body.Close() //nolint:errcheck // тело прочитано ниже
	var list struct{ Data []struct{ ID string } }
	if err := json.NewDecoder(mr.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range list.Data {
		ids = append(ids, m.ID)
	}
	if strings.Join(ids, ",") != "mock-echo,mock-error-429,mock-stream-slow" {
		t.Fatalf("/v1/models: %v", ids)
	}
}
