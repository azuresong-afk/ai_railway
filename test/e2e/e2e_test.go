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

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
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

// stand поднимает mock-llm и шлюз перед ним.
func stand(t *testing.T) (gatewayURL string, client *http.Client) {
	t.Helper()
	k := newKeys(t)
	mock := start(t, "mock-llm", "-listen", "127.0.0.1:0", "-cert", k.cert, "-key", k.key)
	gw := start(t, "aisec-gateway", "-listen", "127.0.0.1:0", "-tls-cert", k.cert, "-tls-key", k.key,
		"-upstream-url", "https://"+mock, "-upstream-ca", k.ca, "-forward-headers", "X-Mock-Scenario")
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
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
	return "https://" + gw, &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 30 * time.Second}
}

func chat(t *testing.T, client *http.Client, url, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp // тело закрывает вызывающий тест
}

func TestE2EChatThroughGateway(t *testing.T) {
	url, client := stand(t)
	resp := chat(t, client, url, `{"model":"mock-echo","messages":[{"role":"user","content":"привет через шлюз `+promptMarker+`"}]}`, nil)
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
	url, client := stand(t)
	body := `{"model":"x","stream":true,"messages":[{"role":"user","content":"раз два три четыре пять"}]}`
	start := time.Now()
	resp := chat(t, client, url, body, map[string]string{"X-Mock-Scenario": "stream-slow"})
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
	url, client := stand(t)
	resp := chat(t, client, url, `{"model":"m","messages":[{"role":"user","content":"x"}]}`, map[string]string{"X-Mock-Scenario": "error-429"})
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
	url, _ := stand(t)
	plain := strings.Replace(url, "https://", "http://", 1)
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
