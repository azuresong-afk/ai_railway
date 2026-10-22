//go:build e2e

package e2e

// Стенд сквозных тестов этапа 2 (задача 2.28): настоящие aisec-cli и
// aisec-server, отдельная БД PostgreSQL на каждый тест, вход в консоль по HTTPS
// с паролем и вторым фактором. Тесты не меняют продукт: состояние готовят
// командами aisec-cli и обычным API, а подмену данных делают так, как это
// сделал бы злоумышленник с доступом к СУБД.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

// Синтетические пароли стенда: проходят парольную политику по умолчанию
// (12 знаков, три класса), настоящим людям не принадлежат.
const (
	s2AdminLogin = "e2e-secadmin"
	s2AdminPass  = "Syn-Passw0rd-e2e-1" //nolint:gosec // G101: синтетический пароль стенда e2e
	s2UserPass   = "Syn-Passw0rd-e2e-2" //nolint:gosec // G101: синтетический пароль стенда e2e
	// s2CSRFCookie — cookie двойной отправки (решение Р6).
	s2CSRFCookie = "__Host-aisec_csrf"
)

var s2SetupToken = regexp.MustCompile(`aisec_setup_[A-Za-z0-9_-]+`)

// s2Proc — запущенный процесс продукта: журнал stderr, адрес из строки
// «сервер запущен» и канал завершения.
type s2Proc struct {
	t    *testing.T
	name string
	cmd  *exec.Cmd
	mu   sync.Mutex
	logs strings.Builder
	addr chan string
	done chan struct{}
	err  error
}

func (p *s2Proc) log() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logs.String()
}

// exitCode ждёт завершения процесса до d; -1 — не завершился.
func (p *s2Proc) exitCode(d time.Duration) int {
	select {
	case <-p.done:
		var ee *exec.ExitError
		if errors.As(p.err, &ee) {
			return ee.ExitCode()
		}
		if p.err != nil {
			return -2
		}
		return 0
	case <-time.After(d):
		return -1
	}
}

// stop завершает процесс сигналом прерывания и ждёт; зависший добивается.
func (p *s2Proc) stop() {
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(os.Interrupt) //nolint:gosec // G104: процесс мог завершиться сам
	select {
	case <-p.done:
	case <-time.After(15 * time.Second):
		_ = p.cmd.Process.Kill() //nolint:gosec // G104: добиваем зависший процесс
		<-p.done
	}
}

// s2Start запускает бинарник и ждёт строку «сервер запущен». Если процесс
// завершился раньше, возвращается его код и журнал.
func s2Start(t *testing.T, bin string, env []string, args ...string) (*s2Proc, string) {
	t.Helper()
	// Без отмены по контексту: процесс живёт до stop() — сигнал прерывания, затем Kill.
	cmd := exec.CommandContext(context.Background(), bin, args...) //nolint:gosec // G204: тест запускает собственные бинарники из каталога сборки
	cmd.Env = append(os.Environ(), env...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &s2Proc{t: t, name: filepath.Base(bin), cmd: cmd, addr: make(chan string, 1), done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		t.Fatalf("%s: %v (выполните make build)", bin, err)
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			p.mu.Lock()
			p.logs.WriteString(line + "\n")
			p.mu.Unlock()
			var entry struct{ Msg, Addr string }
			if json.Unmarshal([]byte(line), &entry) == nil && entry.Msg == "сервер запущен" {
				select {
				case p.addr <- entry.Addr:
				default:
				}
			}
		}
	}()
	go func() {
		<-readDone // Wait закрывает канал чтения: сначала дочитываем журнал
		p.err = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		p.stop()
		if t.Failed() {
			t.Logf("журнал %s:\n%s", p.name, p.log())
		}
	})
	select {
	case a := <-p.addr:
		return p, a
	case <-p.done:
		return p, ""
	case <-time.After(30 * time.Second):
		t.Fatalf("%s не запустился за 30 с\n%s", bin, p.log())
		return nil, ""
	}
}

// s2Run запускает команду до завершения и возвращает вывод (stdout и
// stderr вместе) и код возврата.
func s2Run(t *testing.T, bin string, env []string, args ...string) (string, int) {
	t.Helper()
	return s2RunDir(t, "", bin, env, args...)
}

// s2RunDir — s2Run с рабочим каталогом dir.
func s2RunDir(t *testing.T, dir, bin string, env []string, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: тест запускает собственные бинарники из каталога сборки
	cmd.Env = append(os.Environ(), env...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return out.String(), 0
	case errors.As(err, &ee):
		return out.String(), ee.ExitCode()
	default:
		t.Fatalf("%s %v: %v", bin, args, err)
		return "", -1
	}
}

// s2Install — копия установки: bin/ с четырьмя бинарниками продукта и
// подписанный манифест рядом (по умолчанию ../aisec-manifest.json от
// каталога бинарника). Подмену бинарника делают в копии, не в сборке.
type s2Install struct{ root, bin string }

func (i s2Install) path(name string) string { return filepath.Join(i.bin, name) }
func (i s2Install) manifest() string        { return filepath.Join(i.root, "aisec-manifest.json") }

func s2NewInstall(t *testing.T) s2Install {
	t.Helper()
	root := t.TempDir()
	in := s2Install{root: root, bin: filepath.Join(root, "bin")}
	if err := os.Mkdir(in.bin, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"aisec-cli", "aisec-server", "aisec-gateway", "aisec-media"} {
		s2Copy(t, filepath.Join(*binDir, name), in.path(name), 0o700)
	}
	src := filepath.Join(*binDir, "..", "aisec-manifest.json")
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("нет подписанного манифеста %s (выполните make manifest): %v", src, err)
	}
	s2Copy(t, src, in.manifest(), 0o600)
	s2Copy(t, src+".sig", in.manifest()+".sig", 0o600)
	return in
}

// clone — независимая копия установки для подмены файлов.
func (i s2Install) clone(t *testing.T) s2Install {
	t.Helper()
	root := t.TempDir()
	out := s2Install{root: root, bin: filepath.Join(root, "bin")}
	if err := os.Mkdir(out.bin, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"aisec-cli", "aisec-server", "aisec-gateway", "aisec-media"} {
		s2Copy(t, i.path(name), out.path(name), 0o700)
	}
	s2Copy(t, i.manifest(), out.manifest(), 0o600)
	s2Copy(t, i.manifest()+".sig", out.manifest()+".sig", 0o600)
	return out
}

// s2Append дописывает байт в конец файла: хеш меняется, исполняемый файл
// продолжает запускаться (подмена без порчи формата).
func s2Append(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // G304: копия установки во временном каталоге теста
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func s2Copy(t *testing.T, from, to string, perm os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(from) //nolint:gosec // G304: путь собирается из каталога сборки и констант
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, perm); err != nil { //nolint:gosec // G703: путь во временном каталоге теста
		t.Fatal(err)
	}
}

// s2Stand — стенд: отдельная БД, ключи установки и сервер.
type s2Stand struct {
	t       *testing.T
	in      s2Install
	tls     keys
	keysDir string
	// suDSN — суперпользователь тестовой СУБД на базе стенда (миграции, init,
	// CLI, подмена данных); appDSN — роль приложения, под которой работает сервер.
	suDSN, appDSN string
	setupToken    string
	srvArgs       []string
	srv           *s2Proc
	base          string
	roots         []byte
	admin         *s2User
}

// s2NewStand готовит БД, ключи и токен первичной настройки, сервер не
// запускает. Без AISEC_TEST_DATABASE_URL тест пропускается: в CI нет PostgreSQL.
func s2NewStand(t *testing.T) *s2Stand {
	t.Helper()
	root := os.Getenv("AISEC_TEST_DATABASE_URL")
	if root == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан: сквозные тесты этапа 2 идут на живой PostgreSQL")
	}
	s := &s2Stand{t: t, in: s2NewInstall(t), tls: newKeys(t)}
	var err error
	if s.roots, err = os.ReadFile(s.tls.ca); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rootURL, err := url.Parse(root)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d_%d", os.Getpid(), time.Now().UnixNano()%1_000_000_000)
	dbName, appRole := "e2e_"+suffix, "e2e_app_"+suffix
	conn, err := pgx.Connect(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `CREATE DATABASE `+dbName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer func() { _ = conn.Close(ctx) }() //nolint:gosec // G104: закрытие соединения очистки
		if _, err := conn.Exec(ctx, `DROP DATABASE IF EXISTS `+dbName+` WITH (FORCE)`); err != nil {
			t.Logf("очистка: удаление БД %s: %v", dbName, err)
		}
		if _, err := conn.Exec(ctx, `DROP ROLE IF EXISTS `+appRole); err != nil {
			t.Logf("очистка: удаление роли %s: %v", appRole, err)
		}
	})
	su := *rootURL
	su.Path = "/" + dbName
	s.suDSN = su.String()
	if _, code := s2Run(t, s.in.path("aisec-cli"), []string{"AISEC_DATABASE_URL=" + s.suDSN}, "migrate"); code != 0 {
		t.Fatalf("aisec-cli migrate: код %d", code)
	}
	// Роль aisec_app создаёт миграция; сервер работает под входной ролью в
	// ней, как в поставке: журнал аудита — только добавление.
	if _, err := conn.Exec(ctx, `CREATE ROLE `+appRole+` LOGIN PASSWORD 'e2e-app-pass' IN ROLE aisec_app`); err != nil {
		t.Fatal(err)
	}
	app := su
	app.User = url.UserPassword(appRole, "e2e-app-pass")
	s.appDSN = app.String()

	s.keysDir = filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(s.keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	out, code := s2Run(t, s.in.path("aisec-cli"), []string{"AISEC_DATABASE_URL=" + s.suDSN}, "init", "-dir", s.keysDir)
	if code != 0 {
		t.Fatalf("aisec-cli init: код %d\n%s", code, out)
	}
	if s.setupToken = s2SetupToken.FindString(out); s.setupToken == "" {
		t.Fatalf("в выводе init нет токена первичной настройки:\n%s", out)
	}
	s.srvArgs = []string{"-listen", "127.0.0.1:0", "-tls-cert", s.tls.cert, "-tls-key", s.tls.key,
		"-keys-dir", s.keysDir, "-audit-signing-pub", filepath.Join(s.keysDir, "audit-signing.pub"),
		// Клиенты стенда различаются адресом в X-Forwarded-For: у каждого
		// свой предел частоты и свой адрес в журнале аудита.
		"-trusted-proxies", "127.0.0.1/32"}
	return s
}

func (s *s2Stand) cli(args ...string) (string, int) {
	s.t.Helper()
	return s2Run(s.t, s.in.path("aisec-cli"), []string{"AISEC_DATABASE_URL=" + s.suDSN}, args...)
}

// startServer запускает сервер из установки in с дополнительными аргументами.
// ok=false — сервер завершился, не начав слушать порт (журнал в p.log()).
func (s *s2Stand) startServer(in s2Install, extra ...string) (p *s2Proc, ok bool) {
	s.t.Helper()
	args := append(append([]string{}, s.srvArgs...), extra...)
	p, addr := s2Start(s.t, in.path("aisec-server"), []string{"AISEC_DATABASE_URL=" + s.appDSN}, args...)
	if addr == "" {
		return p, false
	}
	s.srv, s.base = p, "https://"+addr
	return p, true
}

// mustStart — запуск, который обязан удаться.
func (s *s2Stand) mustStart(extra ...string) {
	s.t.Helper()
	if p, ok := s.startServer(s.in, extra...); !ok {
		s.t.Fatalf("сервер не запустился (код %d):\n%s", p.exitCode(time.Second), p.log())
	}
}

// transport строит HTTPS-транспорт с доверием к УЦ стенда.
func (s *s2Stand) transport() *http.Transport {
	s.t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		s.t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		s.t.Fatal(err)
	}
	cfg, err := tp.ClientConfig(s.roots)
	if err != nil {
		s.t.Fatal(err)
	}
	return &http.Transport{TLSClientConfig: cfg}
}

// s2User — учётная запись стенда с её текущим паролем и секретом TOTP.
type s2User struct {
	id, login, pass string
	role            auth.Role
	secret          []byte
	lastStep        int64
}

// s2Client — клиент консоли: свои cookie и свой адрес в X-Forwarded-For.
type s2Client struct {
	s      *s2Stand
	hc     *http.Client
	jar    *cookiejar.Jar
	xff    string
	bearer string
}

func (s *s2Stand) client(xff string) *s2Client {
	s.t.Helper()
	if _, err := netip.ParseAddr(xff); err != nil {
		s.t.Fatalf("адрес клиента %q: %v", xff, err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		s.t.Fatal(err)
	}
	hc := &http.Client{Transport: s.transport(), Jar: jar, Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	s.t.Cleanup(hc.CloseIdleConnections)
	return &s2Client{s: s, hc: hc, jar: jar, xff: xff}
}

// s2Resp — ответ сервера: код, заголовки и тело.
type s2Resp struct {
	code int
	hdr  http.Header
	body []byte
}

func (r s2Resp) String() string { return fmt.Sprintf("%d %s", r.code, r.body) }

func (r s2Resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("ответ не JSON: %v: %s", err, r.body)
	}
}

// do отправляет запрос. Тело — строка JSON или значение для кодирования;
// изменяющий запрос сессии получает X-CSRF-Token из cookie.
func (c *s2Client) do(method, path string, body any) s2Resp {
	c.s.t.Helper()
	return c.doOpt(method, path, body, true)
}

func (c *s2Client) doOpt(method, path string, body any, csrf bool) s2Resp {
	c.s.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			c.s.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.s.base+path, rd)
	if err != nil {
		c.s.t.Fatal(err)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Forwarded-For", c.xff)
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if csrf && method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("X-CSRF-Token", c.csrfToken())
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // ошибка закрытия тела ответа не влияет на тест
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		c.s.t.Fatalf("%s %s: чтение ответа: %v", method, path, err)
	}
	return s2Resp{code: resp.StatusCode, hdr: resp.Header, body: raw}
}

func (c *s2Client) csrfToken() string {
	u, err := url.Parse(c.s.base)
	if err != nil {
		c.s.t.Fatal(err)
	}
	for _, ck := range c.jar.Cookies(u) {
		if ck.Name == s2CSRFCookie {
			return ck.Value
		}
	}
	return ""
}

// totpCode даёт код, который сервер ещё не принимал: шаг строго больше
// последнего принятого этим пользователем (защита от повтора, ИАФ.5). Если
// подходящих шагов в окне ±1 нет, ждёт следующего.
func (u *s2User) totpCode(t *testing.T) string {
	t.Helper()
	const period = int64(aisecCrypto.TOTPPeriod / time.Second)
	for {
		cur := time.Now().Unix() / period
		for step := cur - 1; step <= cur+1; step++ {
			if step <= u.lastStep {
				continue
			}
			code, err := cryptotest.TOTPCode(u.secret, time.Unix(step*period, 0))
			if err != nil {
				t.Fatal(err)
			}
			u.lastStep = step
			return code
		}
		time.Sleep(time.Until(time.Unix(u.lastStep*period, 0)) + 200*time.Millisecond)
	}
}

type s2Me struct {
	User struct {
		ID, Login string
		Role      string
	}
	SessionState string `json:"session_state"`
	Permissions  []string
}

// signIn проходит вход до полной сессии: пароль, при необходимости
// подключение второго фактора или его проверка, смена временного пароля.
func (c *s2Client) signIn(u *s2User) s2Me {
	c.s.t.Helper()
	t := c.s.t
	r := c.do("POST", "/api/v1/auth/login", map[string]string{"login": u.login, "password": u.pass})
	if r.code != http.StatusOK {
		t.Fatalf("вход %s: %s", u.login, r)
	}
	for range 6 {
		var me s2Me
		r.json(t, &me)
		switch me.SessionState {
		case "active":
			return me
		case "mfa_setup":
			r = c.do("POST", "/api/v1/auth/mfa/setup", `{}`)
			var ms struct{ Secret string }
			if r.code != http.StatusOK {
				t.Fatalf("подключение второго фактора %s: %s", u.login, r)
			}
			r.json(t, &ms)
			secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(ms.Secret))
			if err != nil {
				t.Fatal(err)
			}
			u.secret = secret
			if r = c.do("POST", "/api/v1/auth/mfa/setup/confirm", map[string]string{"code": u.totpCode(t)}); r.code != http.StatusOK {
				t.Fatalf("подтверждение второго фактора %s: %s", u.login, r)
			}
		case "mfa_pending":
			if r = c.do("POST", "/api/v1/auth/mfa/verify", map[string]string{"code": u.totpCode(t)}); r.code != http.StatusOK {
				t.Fatalf("второй фактор %s: %s", u.login, r)
			}
			continue // ответ — Me с новым состоянием
		case "password_change":
			next := s2UserPass
			if u.pass == s2UserPass {
				next = s2UserPass + "x"
			}
			if r = c.do("POST", "/api/v1/auth/password", map[string]string{"current_password": u.pass, "new_password": next}); r.code != http.StatusNoContent {
				t.Fatalf("смена пароля %s: %s", u.login, r)
			}
			u.pass = next
		default:
			t.Fatalf("вход %s: состояние сессии %q", u.login, me.SessionState)
		}
		// Состояние после шага читаем явно: не все ответы несут Me.
		if r = c.do("GET", "/api/v1/me", nil); r.code != http.StatusOK {
			t.Fatalf("/me после шага входа %s: %s", u.login, r)
		}
	}
	t.Fatalf("вход %s не завершился за шесть шагов", u.login)
	return s2Me{}
}

// setupAdmin выполняет первичную настройку и входит администратором безопасности.
func (s *s2Stand) setupAdmin() *s2Client {
	s.t.Helper()
	c := s.client("198.51.100.10")
	r := c.do("POST", "/api/v1/auth/setup", map[string]string{"token": s.setupToken, "login": s2AdminLogin,
		"display_name": "Администратор стенда", "password": s2AdminPass})
	if r.code != http.StatusCreated {
		s.t.Fatalf("первичная настройка: %s", r)
	}
	s.admin = &s2User{login: s2AdminLogin, pass: s2AdminPass, role: auth.RoleSecurityAdmin}
	c.signIn(s.admin)
	return c
}

// createUser заводит пользователя роли role от имени admin и возвращает его
// с временным паролем (вход и смена пароля — в signIn).
func (c *s2Client) createUser(login string, role auth.Role) *s2User {
	c.s.t.Helper()
	r := c.do("POST", "/api/v1/users", map[string]string{"login": login, "display_name": "Синтетический " + login, "role": string(role)})
	if r.code != http.StatusCreated {
		c.s.t.Fatalf("создание %s: %s", login, r)
	}
	var out struct {
		User          struct{ ID string }
		TemporaryPass string `json:"temporary_password"`
	}
	r.json(c.s.t, &out)
	return &s2User{id: out.User.ID, login: login, pass: out.TemporaryPass, role: role}
}

// pg открывает соединение суперпользователя с БД стенда: так действует
// злоумышленник с доступом к СУБД.
func (s *s2Stand) pg() *pgx.Conn {
	s.t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, s.suDSN)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { _ = conn.Close(ctx) }) //nolint:gosec // G104: закрытие соединения очистки
	return conn
}

// auditCount — число записей аудита с действием action (и результатом, если задан).
func (s *s2Stand) auditCount(action string) int {
	s.t.Helper()
	var n int
	if err := s.pg().QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

// s2WaitFor повторяет check раз в 500 мс до таймаута; false — не дождались.
func s2WaitFor(d time.Duration, check func() bool) bool {
	deadline := time.Now().Add(d)
	for {
		if check() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
}
