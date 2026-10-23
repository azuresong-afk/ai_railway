//go:build e2e

package e2e

// DAST пилота (задача 3.30 этапа 3, решение Р10): OWASP ZAP baseline против
// консоли и шлюза установки, поднятой по install-pilot.md (стенд — как у
// pilot_stand_test.go). Пассивная проверка: ZAP обходит страницы и
// анализирует ответы, активных атак нет. Отчёты (JSON и HTML) складываются в
// AISEC_DAST_OUT; решение по находкам принимает tools/dast-triage
// (make dast), а не этот тест: тест отвечает за то, чтобы проверка состоялась
// и отчёты появились.
//
// Нужны Docker с compose, root и образ ZAP (deploy/compose/pilot/dast).
// Без AISEC_E2E_DAST=1 тест пропускается; запуск — make dast.

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pilotDASTGatewayHost — имя шлюза для ZAP; адрес закреплён в compose.e2e.yaml.
const pilotDASTGatewayHost = pilotGatewayHost

func TestE2EPilot_DAST(t *testing.T) {
	if os.Getenv("AISEC_E2E_DAST") != "1" {
		t.Skip("AISEC_E2E_DAST не задан: DAST пилота — make dast")
	}
	out := os.Getenv("AISEC_DAST_OUT")
	if out == "" {
		t.Fatal("задайте AISEC_DAST_OUT — каталог отчётов")
	}
	out, err := filepath.Abs(out)
	if err != nil {
		t.Fatal(err)
	}
	// ZAP работает от пользователя 1000 и пишет отчёты в этот каталог.
	if err := os.MkdirAll(out, 0o777); err != nil { //nolint:gosec // G301: каталог отчётов CI без секретов, ZAP пишет от другого пользователя
		t.Fatal(err)
	}
	if err := os.Chmod(out, 0o777); err != nil { //nolint:gosec // G302: см. выше
		t.Fatal(err)
	}
	rules, err := filepath.Abs(filepath.Join("..", "..", "deploy", "compose", "pilot", "dast", "zap-rules.conf"))
	if err != nil {
		t.Fatal(err)
	}
	// Правила читает ZAP от другого пользователя, поэтому права 0644.
	if err := os.WriteFile(filepath.Join(out, "zap-rules.conf"), mustRead(t, rules), 0o644); err != nil { //nolint:gosec // G306, G703: файл правил без секретов в каталоге отчётов теста
		t.Fatal(err)
	}

	cfg := pilotConfigFromEnv(t)
	tls := newPilotTLS(t)
	p := newPilotInstall(t, cfg, tls, "dast")
	s, admin := p.install()

	// Рабочая установка: провайдер, приложение — у шлюза есть пакет и сеанс.
	mock := addProvider(t, admin, "mock", "https://mock-llm:9443/v1", tls.ca)
	app := addApp(t, admin, "crm", mock)
	p.waitChat(s, 1, app.key, "dast")

	overlay, err := filepath.Abs(filepath.Join("..", "..", "deploy", "compose", "pilot", "dast", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	env := []string{
		"COMPOSE_FILE=" + filepath.Join(p.dir, "compose.yaml") + string(os.PathListSeparator) + p.overlay + string(os.PathListSeparator) + overlay,
		"AISEC_DAST_OUT=" + out,
		"AISEC_DAST_CONSOLE_ADDR=" + pilotConsoleAddr,
		"AISEC_DAST_GATEWAY_HOST=" + pilotDASTGatewayHost,
		"AISEC_DAST_GATEWAY_ADDR=" + pilotGatewayAddr,
	}
	targets := []struct{ name, url string }{
		{"console", "https://" + pilotConsoleHost + ":8444/"},
		{"gateway", "https://" + pilotDASTGatewayHost + ":8443/readyz"},
	}
	for _, tg := range targets {
		// -I: код возврата ZAP не влияет, решение — у tools/dast-triage;
		// -m 5: обход не дольше пяти минут. -silent и start.checkForUpdates:
		// ZAP не проверяет обновления и дополнения.
		res, code := p.run(nil, env, "docker", "compose", "--profile", "dast", "run", "--rm", "-T", "zap",
			"zap-baseline.py", "-t", tg.url, "-c", "zap-rules.conf", "-J", tg.name+".json", "-r", tg.name+".html",
			"-I", "-m", "5", "-z", "-silent -config start.checkForUpdates=false")
		t.Logf("ZAP %s: код %d\n%s", tg.name, code, tail(res, 40))
		if code != 0 {
			t.Fatalf("ZAP baseline по %s завершился с кодом %d", tg.name, code)
		}
		st, err := os.Stat(filepath.Join(out, tg.name+".json")) //nolint:gosec // G703: путь из каталога отчётов теста и литеральных имён целей
		if err != nil || st.Size() == 0 {
			t.Fatalf("нет отчёта %s.json: %v", tg.name, err)
		}
	}
	// После обхода шлюз остаётся рабочим: ZAP не должен его ронять.
	if !s2WaitFor(30*time.Second, func() bool { return p.gatewayReady(s) == http.StatusOK }) {
		t.Fatalf("шлюз не готов после DAST: /readyz %d", p.gatewayReady(s))
	}
}

// tail — последние n строк вывода.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
