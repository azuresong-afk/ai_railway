//go:build e2e

package e2e

// Сквозной сценарий консоли на настоящем сервере (H-Р7, задача 2.28, часть 2):
// Go готовит БД, сервер и администратора со вторым фактором, затем Playwright
// проходит web/e2e/live.spec.ts в Chromium при строгом CSP сервера. Нужны
// PostgreSQL (AISEC_TEST_DATABASE_URL), консоль, встроенная в aisec-server
// (make web-build до make build), web/node_modules и Chromium; чего-то нет —
// тест пропускается с причиной.

import (
	"context"
	"encoding/base32"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestE2EStage2_ConsoleLive(t *testing.T) {
	webDir, err := filepath.Abs("../../web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(webDir, "node_modules", ".package-lock.json")); err != nil {
		t.Skip("нет web/node_modules: выполните make web-deps")
	}
	npx, err := exec.LookPath("npx")
	if err != nil {
		t.Skip("нет Node.js (npx): сценарий консоли пропущен")
	}
	if os.Getenv("AISEC_CHROMIUM") == "" && os.Getenv("PLAYWRIGHT_BROWSERS_PATH") == "" {
		t.Skip("не задан браузер: AISEC_CHROMIUM или PLAYWRIGHT_BROWSERS_PATH")
	}

	s := s2NewStand(t)
	s.mustStart()
	admin := s.setupAdmin()
	if r := admin.do("GET", "/", nil); r.code != http.StatusOK {
		t.Skipf("консоль не встроена в aisec-server (/ отвечает %d): сначала make web-build, затем make build", r.code)
	}
	// Провайдер для мастера подключения: создаётся тем же API, что и в консоли.
	if r := admin.do("POST", "/api/v1/providers", map[string]any{"slug": "mock", "name": "Mock", "type": "openai",
		"base_url": "https://127.0.0.1:9", "ca_pem": string(mustRead(t, s.tls.ca))}); r.code != http.StatusCreated {
		t.Fatalf("создание провайдера: %s", r)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, npx, "playwright", "test", "-c", "e2e/live.config.ts") //nolint:gosec // G204: фиксированная команда тестовой обвязки
	cmd.Dir = webDir
	cmd.Env = append(os.Environ(),
		"AISEC_LIVE_URL="+s.base,
		"AISEC_LIVE_LOGIN="+s.admin.login,
		"AISEC_LIVE_PASSWORD="+s.admin.pass,
		"AISEC_LIVE_TOTP_SECRET="+strings.TrimRight(base32.StdEncoding.EncodeToString(s.admin.secret), "="),
		"AISEC_LIVE_TOTP_STEP="+strconv.FormatInt(s.admin.lastStep, 10))
	out, err := cmd.CombinedOutput()
	t.Logf("playwright:\n%s", out)
	if err != nil {
		t.Fatalf("сценарий консоли не прошёл: %v", err)
	}
}
