//go:build e2e

package e2e

// Стенд e2e пилота (задачи 3.7 и 3.8 этапа 3): compose пилота из
// deploy/compose/pilot с наложением testdata/pilot/compose.e2e.yaml — все
// сети внутренние, провайдер LLM — mock-llm, ловушка сети netwatch.
// Установка идёт по шагам docs/user/install-pilot.md: prepare-host.sh,
// migrate, init, первичная настройка, регистрация шлюза.
//
// Нужны Docker с compose и запуск от root: prepare-host.sh создаёт
// пользователей хоста aisec, aisec-gw, aisec-db (они остаются после теста).
// Образы — make images-test, ловушка и мок — make e2e-pilot-bin; всё вместе
// запускает make e2e-pilot. Без AISEC_E2E_PILOT=1 тесты пропускаются.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Имена и адреса стенда; адреса закреплены в compose.e2e.yaml.
const (
	pilotConsoleHost = "aisec-e2e.test"
	pilotGatewayHost = "gw-e2e.test"
	pilotConsoleAddr = "10.231.13.10"
	pilotGatewayAddr = "10.231.14.20"
	pilotMockModel   = "mock-echo"
)

// pilotConfig — параметры стенда из окружения (цель make e2e-pilot).
type pilotConfig struct {
	version, repo, tools, postgres string
}

func pilotConfigFromEnv(t *testing.T) pilotConfig {
	t.Helper()
	if os.Getenv("AISEC_E2E_PILOT") != "1" {
		t.Skip("AISEC_E2E_PILOT не задан: e2e пилота в docker compose — make e2e-pilot")
	}
	if os.Geteuid() != 0 {
		t.Fatal("e2e пилота запускается от root: prepare-host.sh создаёт пользователей хоста")
	}
	c := pilotConfig{version: os.Getenv("AISEC_VERSION"), repo: os.Getenv("AISEC_IMAGE_REPO"),
		tools: os.Getenv("AISEC_E2E_TOOLS"), postgres: os.Getenv("AISEC_POSTGRES_IMAGE")}
	if c.repo == "" {
		c.repo = "aisec-test"
	}
	if c.version == "" || c.tools == "" {
		t.Fatal("задайте AISEC_VERSION (тег образов make images-test) и AISEC_E2E_TOOLS (make e2e-pilot-bin)")
	}
	tools, err := filepath.Abs(c.tools)
	if err != nil {
		t.Fatal(err)
	}
	c.tools = tools
	return c
}

// pilotTLS — сертификаты стенда: консоль, шлюз и mock-llm от одного УЦ.
type pilotTLS struct {
	ca                   []byte
	console, consoleKey  []byte
	gateway, gatewayKey  []byte
	mockDir              string // mock.crt, mock.key
	mockCert, mockKeyPEM []byte
}

func newPilotTLS(t *testing.T) pilotTLS {
	t.Helper()
	now := time.Now()
	ca, err := aisecCrypto.NewCA("aisec e2e pilot CA", 48*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	var p pilotTLS
	p.ca = ca.CertPEM()
	if p.console, p.consoleKey, err = ca.IssueServer([]string{pilotConsoleHost}, 24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if p.gateway, p.gatewayKey, err = ca.IssueServer([]string{pilotGatewayHost}, 24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if p.mockCert, p.mockKeyPEM, err = ca.IssueServer([]string{"mock-llm"}, 24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	p.mockDir = filepath.Join(t.TempDir(), "mock-tls")
	if err := os.Mkdir(p.mockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(p.mockDir, "mock.crt"), p.mockCert)
	mustWrite(t, filepath.Join(p.mockDir, "mock.key"), p.mockKeyPEM)
	return p
}

// pilotInstall — одна установка пилота: свой каталог compose, свой
// AISEC_DATA_DIR и свой проект compose.
type pilotInstall struct {
	t       *testing.T
	cfg     pilotConfig
	tls     pilotTLS
	dir     string // копия deploy/compose/pilot с .env
	data    string // AISEC_DATA_DIR
	project string
	overlay string
	ids     map[string]int // AISEC_UID… из .env после prepare-host.sh
	ml      bool           // compose.ml.yaml и профиль ml (withML)
}

// newPilotInstall копирует compose пилота во временный каталог, заполняет
// .env, выполняет prepare-host.sh и кладёт сертификаты. Сервисы не запускает.
func newPilotInstall(t *testing.T, cfg pilotConfig, tls pilotTLS, name string) *pilotInstall {
	t.Helper()
	root := t.TempDir()
	// Как /srv на хосте: путь к AISEC_DATA_DIR проходим для пользователей
	// сервисов (prepare-host.sh читает якорь от имени aisec).
	for _, d := range []string{filepath.Dir(root), root} {
		if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // G302: каталог без секретов, как /srv
			t.Fatal(err)
		}
	}
	p := &pilotInstall{t: t, cfg: cfg, tls: tls, dir: filepath.Join(root, "pilot"), data: filepath.Join(root, "data"),
		project: fmt.Sprintf("aisec-e2e-%s-%d", name, os.Getpid())}
	overlay, err := filepath.Abs(filepath.Join("testdata", "pilot", "compose.e2e.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p.overlay = overlay
	src := filepath.Join("..", "..", "deploy", "compose", "pilot")
	for _, f := range []string{"compose.yaml", ".env.example", "prepare-host.sh", "backup.sh", "restore.sh",
		filepath.Join("initdb", "10-aisec-roles.sql")} {
		perm := os.FileMode(0o644)
		if strings.HasSuffix(f, ".sh") {
			perm = 0o755
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(p.dir, f)), 0o755); err != nil { //nolint:gosec // G301: initdb/ читает PostgreSQL от aisec-db, как в поставке
			t.Fatal(err)
		}
		s2Copy(t, filepath.Join(src, f), filepath.Join(p.dir, f), perm)
	}
	// .env — из образца с заменой значений стенда.
	set := map[string]string{"AISEC_VERSION": cfg.version, "AISEC_IMAGE_REPO": cfg.repo, "AISEC_DATA_DIR": p.data,
		"AISEC_CONSOLE_HOST": pilotConsoleHost}
	if cfg.postgres != "" {
		set["AISEC_POSTGRES_IMAGE"] = cfg.postgres
	}
	var env strings.Builder
	for _, line := range strings.Split(string(mustRead(t, filepath.Join(p.dir, ".env.example"))), "\n") {
		if k, _, ok := strings.Cut(line, "="); ok && set[k] != "" {
			line = k + "=" + set[k]
		}
		env.WriteString(line + "\n")
	}
	mustWrite(t, filepath.Join(p.dir, ".env"), []byte(env.String()))
	t.Cleanup(p.down)

	p.sh("prepare-host.sh")
	p.ids = map[string]int{}
	for _, line := range strings.Split(string(mustRead(t, filepath.Join(p.dir, ".env"))), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.HasSuffix(k, "ID") && strings.HasPrefix(k, "AISEC_") {
			if n, err := strconv.Atoi(v); err == nil {
				p.ids[k] = n
			}
		}
	}
	return p
}

// putCerts кладёт сертификаты TLS, как велит install-pilot.md, шаг 2.4.
func (p *pilotInstall) putCerts() {
	p.t.Helper()
	sec := filepath.Join(p.data, "secrets")
	aisec, gw := [2]int{p.ids["AISEC_UID"], p.ids["AISEC_GID"]}, [2]int{p.ids["AISEC_GW_UID"], p.ids["AISEC_GW_GID"]}
	for _, f := range []struct {
		name  string
		data  []byte
		owner [2]int
		perm  os.FileMode
	}{
		{"console.crt", p.tls.console, aisec, 0o644},
		{"console.key", p.tls.consoleKey, aisec, 0o600},
		{"console-ca.crt", p.tls.ca, [2]int{0, 0}, 0o644},
		{"gateway.crt", p.tls.gateway, gw, 0o644},
		{"gateway.key", p.tls.gatewayKey, gw, 0o600},
	} {
		path := filepath.Join(sec, f.name)
		if err := os.WriteFile(path, f.data, f.perm); err != nil {
			p.t.Fatal(err)
		}
		if err := os.Chown(path, f.owner[0], f.owner[1]); err != nil {
			p.t.Fatal(err)
		}
		if err := os.Chmod(path, f.perm); err != nil {
			p.t.Fatal(err)
		}
	}
}

// env — окружение команд compose и скриптов установки: наложение e2e и
// проект через переменные compose, чтобы backup.sh и restore.sh работали с
// тем же стендом без правки.
func (p *pilotInstall) env() []string {
	files := []string{filepath.Join(p.dir, "compose.yaml")}
	var extra []string
	if p.ml {
		files = append(files, filepath.Join(p.dir, "compose.ml.yaml"))
		extra = append(extra, "COMPOSE_PROFILES=db,ml")
	}
	files = append(files, p.overlay)
	return append(append(os.Environ(),
		"COMPOSE_FILE="+strings.Join(files, string(os.PathListSeparator)),
		"COMPOSE_PROJECT_NAME="+p.project,
		"AISEC_E2E_TOOLS="+p.cfg.tools,
		"AISEC_E2E_TLS="+p.tls.mockDir), extra...)
}

// withML включает ML-детекторы, как README пилота, «ML-детекторы»:
// compose.ml.yaml и профиль ml. Вызывается до install.
func (p *pilotInstall) withML() {
	p.t.Helper()
	s2Copy(p.t, filepath.Join("..", "..", "deploy", "compose", "pilot", "compose.ml.yaml"), filepath.Join(p.dir, "compose.ml.yaml"), 0o644)
	p.ml = true
}

// run выполняет команду в каталоге compose и возвращает вывод и код.
func (p *pilotInstall) run(stdin io.Reader, extraEnv []string, name string, args ...string) (string, int) {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: тест запускает docker и скрипты установки
	cmd.Dir = p.dir
	cmd.Env = append(p.env(), extraEnv...)
	cmd.Stdin = stdin
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		code = -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
	}
	return string(out), code
}

// compose — docker compose …; ненулевой код — провал теста.
func (p *pilotInstall) compose(args ...string) string {
	p.t.Helper()
	out, code := p.run(nil, nil, "docker", append([]string{"compose"}, args...)...)
	if code != 0 {
		p.t.Fatalf("docker compose %s: код %d\n%s", strings.Join(args, " "), code, out)
	}
	return out
}

// sh — скрипт установки из каталога compose; ненулевой код — провал теста.
func (p *pilotInstall) sh(script string, args ...string) string {
	p.t.Helper()
	out, code := p.run(nil, nil, filepath.Join(p.dir, script), args...)
	if code != 0 {
		p.t.Fatalf("%s %s: код %d\n%s", script, strings.Join(args, " "), code, out)
	}
	return out
}

// cli — docker compose run --rm aisec-cli …
func (p *pilotInstall) cli(args ...string) string {
	p.t.Helper()
	return p.compose(append([]string{"run", "--rm", "-T", "aisec-cli"}, args...)...)
}

// down останавливает установку; при провале теста сначала сохраняет журналы.
func (p *pilotInstall) down() {
	if p.t.Failed() {
		out, _ := p.run(nil, nil, "docker", "compose", "logs", "--no-color", "--tail", "80")
		p.t.Logf("журналы установки %s:\n%s", p.project, out)
	}
	if out, code := p.run(nil, nil, "docker", "compose", "down", "--remove-orphans", "--timeout", "10"); code != 0 {
		p.t.Logf("docker compose down: код %d\n%s", code, out)
	}
}

// install выполняет первый запуск по install-pilot.md, раздел 3: БД,
// миграции, ключи, якорь шлюза, сервер, первичная настройка, регистрация
// шлюза, запуск всего. Возвращает клиента администратора безопасности.
func (p *pilotInstall) install() (*s2Stand, *s2Client) {
	p.t.Helper()
	p.putCerts()
	p.compose("up", "-d", "--wait", "postgres")
	p.cli("migrate")
	out := p.cli("init", "-dir", "/etc/aisec/keys")
	token := s2SetupToken.FindString(out)
	if token == "" {
		p.t.Fatalf("в выводе init нет токена первичной настройки:\n%s", out)
	}
	p.sh("prepare-host.sh")
	if len(mustRead(p.t, filepath.Join(p.data, "secrets", "gateway-bundle-anchor.pub"))) == 0 {
		p.t.Fatal("prepare-host.sh не положил якорь шлюза")
	}
	p.compose("up", "-d", "aisec-server")
	s := p.stand()
	s.setupToken = token
	if !s2WaitFor(90*time.Second, func() bool { return p.consoleUp(s) }) {
		p.t.Fatal("консоль не ответила за 90 с")
	}
	admin := s.setupAdmin()
	p.registerGateway()
	p.compose("up", "-d")
	p.waitGatewayReady(s)
	return s, admin
}

// stand — клиентская часть стенда этапа 2 для консоли и шлюза пилота.
func (p *pilotInstall) stand() *s2Stand {
	return &s2Stand{t: p.t, base: "https://" + pilotConsoleHost + ":8444", roots: p.tls.ca,
		dial: map[string]string{
			pilotConsoleHost + ":8444": pilotConsoleAddr + ":8444",
			pilotGatewayHost + ":8443": pilotGatewayAddr + ":8443",
		}}
}

func (p *pilotInstall) consoleUp(s *s2Stand) bool {
	hc := &http.Client{Transport: s.transport(), Timeout: 5 * time.Second}
	defer hc.CloseIdleConnections()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.base+"/healthz", nil)
	if err != nil {
		p.t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close() //nolint:gosec // G104: тело не читается
	return resp.StatusCode == http.StatusOK
}

// registerGateway — install-pilot.md, раздел 3, шаг 5.
func (p *pilotInstall) registerGateway() {
	p.t.Helper()
	out := p.cli("gateway", "token", "-name", "gw-1", "-ttl", "1h")
	token := gatewayToken.FindString(out)
	if token == "" {
		p.t.Fatalf("в выводе нет токена регистрации шлюза:\n%s", out)
	}
	out, code := p.run(nil, []string{"AISEC_GATEWAY_REGISTRATION_TOKEN=" + token}, "docker", "compose", "run", "--rm", "-T",
		"--no-deps", "-e", "AISEC_GATEWAY_REGISTRATION_TOKEN", "aisec-gateway", "register",
		"-console", "https://"+pilotConsoleHost+":8444", "-console-ca", "/run/secrets/console-ca",
		"-out-dir", "/var/lib/aisec-gateway/reg", "-state-dir", "/var/lib/aisec-gateway/state")
	if code != 0 {
		p.t.Fatalf("aisec-gateway register: код %d\n%s", code, out)
	}
}

// gatewayReady — код GET /readyz шлюза (0 — нет связи).
func (p *pilotInstall) gatewayReady(s *s2Stand) int {
	hc := &http.Client{Transport: s.transport(), Timeout: 5 * time.Second}
	defer hc.CloseIdleConnections()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+pilotGatewayHost+":8443/readyz", nil)
	if err != nil {
		p.t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close() //nolint:gosec // G104: тело не читается
	return resp.StatusCode
}

func (p *pilotInstall) waitGatewayReady(s *s2Stand) {
	p.t.Helper()
	if !s2WaitFor(90*time.Second, func() bool { return p.gatewayReady(s) == http.StatusOK }) {
		p.t.Fatalf("шлюз не готов за 90 с: /readyz %d", p.gatewayReady(s))
	}
}

// pilotApp — приложение стенда с ключом для шлюза.
type pilotApp struct{ id, slug, key string }

// addProvider заводит провайдера OpenAI-совместимого типа с адресом baseURL.
func addProvider(t *testing.T, admin *s2Client, slug, baseURL string, ca []byte) string {
	t.Helper()
	r := admin.do("POST", "/api/v1/providers", map[string]any{"slug": slug, "name": "Провайдер " + slug, "type": "openai",
		"base_url": baseURL, "ca_pem": string(ca)})
	if r.code != http.StatusCreated {
		t.Fatalf("создание провайдера %s: %s", slug, r)
	}
	var prov struct{ ID string }
	r.json(t, &prov)
	return prov.ID
}

// addApp заводит приложение с провайдером и выпускает ему ключ.
func addApp(t *testing.T, admin *s2Client, slug, providerID string) pilotApp {
	t.Helper()
	r := admin.do("POST", "/api/v1/applications", map[string]any{"slug": slug, "name": "Приложение " + slug, "env": "prod",
		"provider_id": providerID, "models": []string{pilotMockModel}})
	if r.code != http.StatusCreated {
		t.Fatalf("создание приложения %s: %s", slug, r)
	}
	var app struct{ ID string }
	r.json(t, &app)
	r = admin.do("POST", "/api/v1/applications/"+app.ID+"/keys", map[string]any{"name": "e2e", "expires_in_days": 30})
	if r.code != http.StatusCreated {
		t.Fatalf("ключ приложения %s: %s", slug, r)
	}
	var key struct{ Key string }
	r.json(t, &key)
	return pilotApp{id: app.ID, slug: slug, key: key.Key}
}

// chat отправляет запрос в шлюз пилота с ключом приложения; возвращает код
// и тело ответа.
func (p *pilotInstall) chat(s *s2Stand, key, text string) (int, string) {
	p.t.Helper()
	hc := &http.Client{Transport: s.transport(), Timeout: 30 * time.Second}
	defer hc.CloseIdleConnections()
	body := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}]}`, pilotMockModel, text)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+pilotGatewayHost+":8443/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		p.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close() //nolint:errcheck // ошибка закрытия тела ответа не влияет на тест
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		p.t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

// waitBundle ждёт, пока шлюз применит пакет с apps приложениями. Запросы с
// ещё неизвестным шлюзу ключом не годятся для ожидания: после нескольких
// отказов шлюз блокирует адрес теста (DM-38).
func (p *pilotInstall) waitBundle(apps int) {
	p.t.Helper()
	want := fmt.Sprintf(`"source":"server","applications":%d,`, apps)
	if !s2WaitFor(90*time.Second, func() bool {
		out, _ := p.run(nil, nil, "docker", "compose", "logs", "--no-color", "aisec-gateway")
		return strings.Contains(out, want)
	}) {
		p.t.Fatalf("шлюз не применил пакет с %d приложениями за 90 с", apps)
	}
}

// waitChat ждёт пакет с apps приложениями и проверяет, что шлюз пропускает
// запрос приложения с ключом key.
func (p *pilotInstall) waitChat(s *s2Stand, apps int, key, text string) {
	p.t.Helper()
	p.waitBundle(apps)
	if code, body := p.chat(s, key, text); code != http.StatusOK {
		p.t.Fatalf("шлюз не пропустил запрос приложения: %d %s", code, body)
	}
}

// eventCount — число событий запросов приложения slug в консоли.
func eventCount(t *testing.T, admin *s2Client, slug string) int {
	t.Helper()
	r := admin.do("GET", "/api/v1/events?limit=100&filter="+url.QueryEscape(fmt.Sprintf(`app = %q`, slug)), nil)
	if r.code != http.StatusOK {
		t.Fatalf("события: %s", r)
	}
	var page struct {
		Items []struct{ App, Type string }
	}
	r.json(t, &page)
	n := 0
	for _, e := range page.Items {
		if e.App == slug && e.Type == "gateway_request" {
			n++
		}
	}
	return n
}

// trapRecord — строка журнала ловушки netwatch.
type trapRecord struct {
	Kind, Src, Name, Proto, Error string
	Type, Port                    uint16
}

func (r trapRecord) String() string {
	switch r.Kind {
	case "dns":
		return fmt.Sprintf("запрос имени %s (тип %d) от %s", r.Name, r.Type, r.Src)
	case "conn":
		return fmt.Sprintf("соединение %s/%d от %s", r.Proto, r.Port, r.Src)
	default:
		return fmt.Sprintf("%s %s", r.Kind, r.Error)
	}
}

// trap читает журнал ловушки. Ловушка должна быть готова (запись ready) и
// без ошибок: иначе пустой журнал ничего не доказывает.
func (p *pilotInstall) trap() []trapRecord {
	p.t.Helper()
	out := p.compose("logs", "--no-color", "--no-log-prefix", "netwatch")
	var recs []trapRecord
	ready := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r trapRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			p.t.Fatalf("журнал ловушки: %v: %s", err, line)
		}
		switch r.Kind {
		case "ready":
			ready = true
		case "error":
			p.t.Fatalf("ошибка ловушки: %s", r.Error)
		default:
			recs = append(recs, r)
		}
	}
	if !ready {
		p.t.Fatalf("ловушка не сообщила о готовности:\n%s", out)
	}
	return recs
}

// assertOffline проверяет, что ни один контейнер не обращался по имени
// вне установки, кроме разрешённых записей allowed.
func (p *pilotInstall) assertOffline(allowed func(trapRecord) bool) []trapRecord {
	p.t.Helper()
	var seen []trapRecord
	for _, r := range p.trap() {
		if allowed != nil && allowed(r) {
			seen = append(seen, r)
			continue
		}
		p.t.Errorf("обращение вне установки: %s", r)
	}
	return seen
}

// appKeyLeak — ключ приложения (и даже его префикс) в техническом журнале.
var appKeyLeak = regexp.MustCompile(`aisec_[a-z0-9]{8}_`)

// assertLogsClean проверяет технические журналы сервисов: нет текста
// промпта и ключей приложений.
func (p *pilotInstall) assertLogsClean(marker string) {
	p.t.Helper()
	out := p.compose("logs", "--no-color", "aisec-server", "aisec-gateway")
	if strings.Contains(out, marker) {
		p.t.Error("текст промпта попал в технический журнал")
	}
	if appKeyLeak.MatchString(out) {
		p.t.Error("ключ приложения попал в технический журнал")
	}
}
