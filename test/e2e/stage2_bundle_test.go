//go:build e2e

package e2e

// DM-42 для пакета конфигурации (задача 2.28, часть 2; ОЦЛ.3, ADR-0009):
// настоящие aisec-server, aisec-cli и aisec-gateway со своим сертификатом,
// между шлюзом и сервером — прокси теста. Прокси передаёт запросы серверу
// от имени шлюза и подменяет ответ так, как это сделал бы злоумышленник на
// пути между ними. Подмену файла состояния делает тест, как человек с
// доступом к диску шлюза.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
)

// Режимы прокси между шлюзом и сервером.
const (
	proxyPass    = "pass"    // ответы сервера без изменений
	proxyFlip    = "flip"    // изменён один бит содержимого пакета
	proxyForeign = "foreign" // содержимое пакета подписано чужим ключом
	proxyReplay  = "replay"  // вместо нового пакета — записанный старый
	proxyDown    = "down"    // сервер недоступен (503 на всё)
)

// bundleProxy — mTLS-прокси перед внутренним портом сервера.
type bundleProxy struct {
	t        *testing.T
	upstream string
	up       *http.Client
	foreign  *bundletest.Fixture

	mu       sync.Mutex
	mode     string
	replay   string            // ETag записанного пакета для режима replay
	recorded map[string][]byte // подлинные пакеты по ETag
	served   int               // сколько раз отдан пакет в режиме, отличном от pass
	key      string            // последний ключ получателя из заголовка шлюза
}

// recipient — ключ получателя шлюза (AISec-Bundle-Key), как в запросе.
func (p *bundleProxy) recipient() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.key
}

func (p *bundleProxy) setMode(mode, replay string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mode, p.replay, p.served = mode, replay, 0
}

func (p *bundleProxy) servedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.served
}

func (p *bundleProxy) record(etag string) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.recorded[etag]
}

func (p *bundleProxy) lastETag() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	last := ""
	for e := range p.recorded {
		if last == "" || len(e) > len(last) || (len(e) == len(last) && e > last) {
			last = e
		}
	}
	return last
}

func (p *bundleProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	mode, replay := p.mode, p.replay
	p.mu.Unlock()
	if mode == proxyDown {
		http.Error(w, "прокси теста: сервер недоступен", http.StatusServiceUnavailable)
		return
	}
	if k := r.Header.Get(gateway.BundleKeyHeader); k != "" {
		p.mu.Lock()
		p.key = k
		p.mu.Unlock()
	}
	isBundle := r.Method == http.MethodGet && r.URL.Path == "/internal/v1/policies/bundle"
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, p.upstream+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req.Header = r.Header.Clone()
	if isBundle && mode != proxyPass {
		// Без If-None-Match сервер всегда присылает тело: подменять есть что.
		req.Header.Del("If-None-Match")
	}
	resp, err := p.up.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }() //nolint:gosec // G104: тело прочитано полностью
	data, err := io.ReadAll(io.LimitReader(resp.Body, bundle.MaxSize+1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if isBundle && resp.StatusCode == http.StatusOK {
		etag := resp.Header.Get("ETag")
		p.mu.Lock()
		if p.recorded[etag] == nil {
			p.recorded[etag] = data
		}
		p.mu.Unlock()
		switch mode {
		case proxyFlip:
			data = p.flip(data)
		case proxyForeign:
			data = p.foreignSigned(data, r.Header.Get(gateway.BundleKeyHeader))
		case proxyReplay:
			old := p.record(replay)
			if old == nil {
				p.t.Errorf("прокси: нет записанного пакета %s", replay)
			}
			data, etag = old, replay
		}
		if mode != proxyPass {
			p.mu.Lock()
			p.served++
			p.mu.Unlock()
		}
		resp.Header.Set("ETag", etag)
	}
	for _, h := range []string{"Content-Type", "ETag", "Retry-After"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(data) //nolint:gosec // G104: обрыв клиента тесту безразличен
}

// envelopeParts разбирает конверт пакета в карту «часть → текст».
func envelopeParts(t *testing.T, data []byte) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("конверт пакета не разобран: %v", err)
	}
	return m
}

// flipBundleByte меняет один бит в содержимом пакета, подпись остаётся прежней.
func flipBundleByte(t *testing.T, data []byte) []byte {
	t.Helper()
	m := envelopeParts(t, data)
	content, err := base64.StdEncoding.DecodeString(m["content"])
	if err != nil || len(content) < 10 {
		t.Fatalf("содержимое пакета: %v", err)
	}
	content[len(content)/2] ^= 0x01
	m["content"] = base64.StdEncoding.EncodeToString(content)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (p *bundleProxy) flip(data []byte) []byte { return flipBundleByte(p.t, data) }

// foreignSigned пересобирает пакет с тем же содержимым и заголовком, но с
// подписью чужого ключа: так выглядит пакет, выпущенный не нашим сервером.
func (p *bundleProxy) foreignSigned(data []byte, recipientKey string) []byte {
	p.t.Helper()
	return foreignSealed(p.t, p.foreign, data, recipientKey)
}

func foreignSealed(t *testing.T, fx *bundletest.Fixture, data []byte, recipientKey string) []byte {
	t.Helper()
	m := envelopeParts(t, data)
	header, err := base64.StdEncoding.DecodeString(m["header"])
	if err != nil {
		t.Fatal(err)
	}
	var h bundle.Header
	if err := json.Unmarshal(header, &h); err != nil {
		t.Fatal(err)
	}
	content, err := base64.StdEncoding.DecodeString(m["content"])
	if err != nil {
		t.Fatal(err)
	}
	key, err := base64.RawURLEncoding.DecodeString(recipientKey)
	if err != nil {
		t.Fatalf("ключ получателя в заголовке: %v", err)
	}
	out, err := fx.Sealer.Seal(bundle.SealInput{Version: h.Version, IssuedAt: h.IssuedAt, GatewayID: h.GatewayID,
		Content: content, RecipientKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// freeAddr возвращает свободный адрес 127.0.0.1:порт.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

var gatewayToken = regexp.MustCompile(`aisec_gwreg_[A-Za-z0-9_-]+`)

// s2GatewayEnv — зарегистрированный шлюз и всё, что нужно для его запуска.
type s2GatewayEnv struct {
	s          *s2Stand
	regDir     string // gateway.key, gateway.crt, ca.crt
	stateDir   string
	proxyAddr  string
	proxy      *bundleProxy
	bundleFile string
}

// newS2GatewayEnv заводит шлюз в реестре сервера, регистрирует его и
// поднимает прокси перед внутренним портом.
func newS2GatewayEnv(t *testing.T, s *s2Stand, internalAddr string) *s2GatewayEnv {
	t.Helper()
	out, code := s.cli("gateway", "token", "-name", "gw-e2e")
	if code != 0 {
		t.Fatalf("aisec-cli gateway token: код %d\n%s", code, out)
	}
	token := gatewayToken.FindString(out)
	if token == "" {
		t.Fatalf("в выводе нет токена регистрации шлюза:\n%s", out)
	}
	e := &s2GatewayEnv{s: s, regDir: filepath.Join(t.TempDir(), "reg"), stateDir: filepath.Join(t.TempDir(), "state")}
	for _, d := range []string{e.regDir, e.stateDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.bundleFile = filepath.Join(e.stateDir, gateway.BundleFile)
	out, code = s2Run(t, s.in.path("aisec-gateway"), []string{"AISEC_GATEWAY_REGISTRATION_TOKEN=" + token},
		"register", "-console", s.base, "-console-ca", s.tls.ca, "-out-dir", e.regDir)
	if code != 0 {
		t.Fatalf("aisec-gateway register: код %d\n%s", code, out)
	}

	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	read := func(path string) []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	gwCert, gwKey := read(filepath.Join(e.regDir, regCertName)), read(filepath.Join(e.regDir, regKeyName))
	internalCA := read(filepath.Join(e.regDir, regCAName))
	transport, err := gateway.ControlTransport(tp, read(s.tls.ca), gwCert, gwKey)
	if err != nil {
		t.Fatal(err)
	}
	e.proxy = &bundleProxy{t: t, upstream: "https://" + internalAddr, up: &http.Client{Transport: transport},
		foreign: bundletest.New(t), mode: proxyPass, recorded: map[string][]byte{}}
	srvTLS, err := tp.MutualServerConfig(read(s.tls.cert), read(s.tls.key), internalCA)
	if err != nil {
		t.Fatal(err)
	}
	e.proxyAddr = freeAddr(t)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", e.proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: e.proxy, TLSConfig: srvTLS, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.ServeTLS(ln, "", "") }() //nolint:gosec // G104: ошибка закрытия сервера при очистке теста не важна
	t.Cleanup(func() { _ = srv.Close() })        //nolint:gosec // G104: очистка теста
	return e
}

// Имена файлов aisec-gateway register.
const (
	regKeyName  = "gateway.key"
	regCertName = "gateway.crt"
	regCAName   = "ca.crt"
)

// gwProc — запущенный шлюз: адрес данных и журнал.
type gwProc struct {
	*s2Proc
	base string
}

// start запускает шлюз с пакетами от сервера; каталог состояния сохраняется
// между запусками.
func (e *s2GatewayEnv) start(t *testing.T) *gwProc {
	t.Helper()
	p, addr := s2Start(t, e.s.in.path("aisec-gateway"), nil,
		"-listen", "127.0.0.1:0", "-tls-cert", e.s.tls.cert, "-tls-key", e.s.tls.key,
		"-server", "https://"+e.proxyAddr, "-server-ca", e.s.tls.ca,
		"-client-cert", filepath.Join(e.regDir, regCertName), "-client-key", filepath.Join(e.regDir, regKeyName),
		"-bundle-pub", filepath.Join(e.s.keysDir, "bundle-signing.pub"), "-state-dir", e.stateDir)
	if addr == "" {
		t.Fatalf("шлюз не запустился (код %d):\n%s", p.exitCode(time.Second), p.log())
	}
	return &gwProc{s2Proc: p, base: "https://" + addr}
}

// ready возвращает код GET /readyz шлюза.
func (g *gwProc) ready(t *testing.T, e *s2GatewayEnv) int {
	t.Helper()
	hc := &http.Client{Transport: e.s.transport(), Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, g.base+"/readyz", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("GET /readyz шлюза: %v", err)
	}
	_ = resp.Body.Close() //nolint:gosec // G104: тело не читается
	return resp.StatusCode
}

// waitLog ждёт подстроку в журнале шлюза.
func (g *gwProc) waitLog(sub string, d time.Duration) bool {
	return s2WaitFor(d, func() bool { return strings.Contains(g.log(), sub) })
}

// bundleAudit — число записей аудита по пакетам с действием action и причиной
// reason в details (пусто — любая).
func (s *s2Stand) bundleAudit(action, reason string) int {
	s.t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, s.suDSN)
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }() //nolint:gosec // G104: закрытие короткого соединения
	var n int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE action = $1 AND ($2 = '' OR details->>'reason' = $2)`, action, reason).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestE2EStage2_BundleTampered — DM-42 для пакета политик (ОЦЛ.3): подмена
// байта, чужая подпись, откат на старую версию, повреждённый и подменённый
// файл на диске шлюза. В каждом случае шлюз отказывает, остаётся на
// последнем корректном пакете (или, если его нет, не принимает запросы),
// пишет причину в технический журнал и отчёт серверу (bundle.rejected).
func TestE2EStage2_BundleTampered(t *testing.T) {
	s := s2NewStand(t)
	keys := s.keysDir
	console, internal := freeAddr(t), freeAddr(t)
	s.mustStart("-listen", console, "-ca-cert", filepath.Join(keys, "ca.crt"), "-ca-key", filepath.Join(keys, "ca.key"),
		"-internal-listen", internal)
	s.base = "https://" + console
	admin := s.setupAdmin()
	e := newS2GatewayEnv(t, s, internal)

	// Первый пакет: шлюз получает его, применяет и сохраняет на диск.
	gw := e.start(t)
	if !s2WaitFor(30*time.Second, func() bool { return gw.ready(t, e) == http.StatusOK }) {
		t.Fatalf("шлюз не готов после первого пакета:\n%s", gw.log())
	}
	v1 := e.proxy.lastETag()
	if v1 == "" || len(mustRead(t, e.bundleFile)) == 0 {
		t.Fatalf("первый пакет не получен или не сохранён: %q", v1)
	}
	gw.stop()

	// Вторая версия: меняем данные сервера (новый провайдер), шлюз берёт её.
	r := admin.do("POST", "/api/v1/providers", map[string]any{"slug": "mock", "name": "Mock", "type": "openai",
		"base_url": "https://127.0.0.1:9", "ca_pem": string(mustRead(t, s.tls.ca))})
	if r.code != http.StatusCreated {
		t.Fatalf("создание провайдера: %s", r)
	}
	var prov struct{ ID string }
	r.json(t, &prov)
	// Провайдер попадает в пакет вместе с приложением, которое его использует.
	if r := admin.do("POST", "/api/v1/applications", map[string]any{"slug": "crm", "name": "CRM", "env": "prod",
		"provider_id": prov.ID, "models": []string{"mock-1"}}); r.code != http.StatusCreated {
		t.Fatalf("создание приложения: %s", r)
	}
	gw = e.start(t)
	// Сначала применяется сохранённый v1 (файл), затем v2 с сервера.
	if !s2WaitFor(30*time.Second, func() bool {
		return strings.Count(gw.log(), "пакет конфигурации применён") >= 2 && e.proxy.lastETag() != v1
	}) {
		t.Fatalf("вторая версия пакета не применена:\n%s", gw.log())
	}
	v2 := e.proxy.lastETag()
	good := mustRead(t, e.bundleFile)
	if v2 == v1 || !bytes.Contains(good, []byte(`"key_id"`)) {
		t.Fatalf("версия не выросла: %s -> %s", v1, v2)
	}
	gw.stop()
	if n := s.bundleAudit("bundle.rejected", ""); n != 0 {
		t.Fatalf("до подмены в аудите уже есть bundle.rejected: %d", n)
	}

	// Подмены на пути: шлюз при каждом запуске берёт сохранённый пакет v2,
	// затем получает подменённый и отказывает; остаётся готов на v2.
	// Сервер не пишет в аудит одинаковые отчёты шлюза чаще раза в минуту
	// (шлюз, итог, причина, версия): повтор причины signature для v2 в аудит
	// не попадает, но шлюз журналирует отказ каждый раз.
	onPath := []struct {
		name, mode, reason string
		audited            bool
	}{
		{"подменён байт содержимого", proxyFlip, bundle.ReasonSignature, true},
		{"подпись чужого ключа", proxyForeign, bundle.ReasonSignature, false},
		{"откат на старую версию", proxyReplay, bundle.ReasonRollback, true},
	}
	rejected := 0
	for _, c := range onPath {
		t.Run(c.name, func(t *testing.T) {
			e.proxy.setMode(c.mode, v1)
			gw := e.start(t)
			if !s2WaitFor(30*time.Second, func() bool { return e.proxy.servedCount() > 0 }) {
				t.Fatalf("прокси не отдал подменённый пакет:\n%s", gw.log())
			}
			if !gw.waitLog(`"reason":"`+c.reason+`"`, 15*time.Second) || !gw.waitLog("пакет конфигурации отклонён; действует прежний", time.Second) {
				t.Fatalf("в журнале шлюза нет отказа с причиной %s:\n%s", c.reason, gw.log())
			}
			if c.audited {
				rejected++
				if !s2WaitFor(15*time.Second, func() bool {
					return s.bundleAudit("bundle.rejected", c.reason) >= 1 && s.bundleAudit("bundle.rejected", "") >= rejected
				}) {
					t.Fatalf("сервер не записал bundle.rejected (%s): %d", c.reason, s.bundleAudit("bundle.rejected", ""))
				}
			}
			if code := gw.ready(t, e); code != http.StatusOK {
				t.Fatalf("после отказа шлюз не на последнем пакете: /readyz %d", code)
			}
			if !bytes.Equal(mustRead(t, e.bundleFile), good) {
				t.Fatal("файл последнего корректного пакета изменился")
			}
			if strings.Contains(gw.log(), "sk-") {
				t.Fatal("в журнале шлюза секрет")
			}
			gw.stop()
		})
	}

	// Файл состояния на диске шлюза: пока сервер недоступен, шлюз остаётся
	// без пакета и не принимает запросы приложений. Когда сервер доступен
	// (шлюз перезапущен), он берёт пакет с сервера и сообщает об отказе по файлу.
	onDisk := []struct {
		name    string
		audited bool // отчёт по файлу (версия 0) в аудит попадает раз в минуту
		mark    func(t *testing.T) []byte
	}{
		{"повреждён файл на диске", true, func(t *testing.T) []byte { return flipBundleByte(t, good) }},
		{"файл на диске подписан чужим ключом", false, func(t *testing.T) []byte {
			return foreignSealed(t, e.proxy.foreign, good, e.proxy.recipient())
		}},
	}
	for _, c := range onDisk {
		t.Run(c.name, func(t *testing.T) {
			before := s.bundleAudit("bundle.rejected", bundle.ReasonSignature)
			bad := c.mark(t)
			mustWrite(t, e.bundleFile, bad)
			e.proxy.setMode(proxyDown, "")
			gw := e.start(t)
			if !gw.waitLog(`"source":"file"`, 15*time.Second) || !gw.waitLog(`"reason":"`+bundle.ReasonSignature+`"`, time.Second) {
				t.Fatalf("в журнале шлюза нет отказа по файлу на диске:\n%s", gw.log())
			}
			if code := gw.ready(t, e); code != http.StatusServiceUnavailable {
				t.Fatalf("без исправного пакета шлюз должен отвечать /readyz 503, а ответил %d", code)
			}
			gw.stop()
			if !bytes.Equal(mustRead(t, e.bundleFile), bad) {
				t.Fatal("шлюз перезаписал файл, не получив пакет от сервера")
			}
			// Сервер доступен: пакет приходит с сервера, файл заменяется исправным.
			e.proxy.setMode(proxyPass, "")
			gw = e.start(t)
			if !s2WaitFor(30*time.Second, func() bool { return gw.ready(t, e) == http.StatusOK }) {
				t.Fatalf("шлюз не получил пакет от сервера после подмены файла:\n%s", gw.log())
			}
			if c.audited && !s2WaitFor(15*time.Second, func() bool { return s.bundleAudit("bundle.rejected", bundle.ReasonSignature) > before }) {
				t.Fatal("сервер не записал bundle.rejected по файлу на диске")
			}
			// Подпись и шифрование секретов при каждой выдаче новые: сравниваем
			// не с прежним файлом, а с подмененным.
			if !s2WaitFor(10*time.Second, func() bool { return !bytes.Equal(mustRead(t, e.bundleFile), bad) }) {
				t.Fatal("подменённый файл на диске не заменён пакетом сервера")
			}
			gw.stop()
		})
	}
}
