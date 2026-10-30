//go:build e2e

package e2e

// Общий стенд сценариев этапа 3 (задача 3.32): сервер с внутренним УЦ,
// зарегистрированный шлюз, mock-llm, приложения с политикой и ключами и,
// по желанию, тестовый приёмник syslog по TLS с каналом уведомлений.
// Всё на живой PostgreSQL (AISEC_TEST_DATABASE_URL), как в тестах этапа 2.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/mockllm"
)

// s3Syslog — приёмник syslog по TLS (RFC 5424, octet counting по RFC 6587):
// принятые записи копятся в порядке прихода. stop и restart имитируют
// недоступность приёмника на том же адресе.
type s3Syslog struct {
	t    *testing.T
	host string
	port int
	wrap func(net.Listener) net.Listener
	mu   sync.Mutex
	l    net.Listener
	recs []string
}

func newS3Syslog(t *testing.T, s *s2Stand) *s3Syslog {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tp.ServerConfig(mustRead(t, s.tls.cert), mustRead(t, s.tls.key))
	if err != nil {
		t.Fatal(err)
	}
	sl := &s3Syslog{t: t, wrap: func(l net.Listener) net.Listener { return aisecCrypto.TLSListener(l, cfg) }}
	sl.listen("127.0.0.1:0")
	t.Cleanup(sl.stop)
	return sl
}

// listen начинает слушать адрес addr и принимать записи.
func (sl *s3Syslog) listen(addr string) {
	sl.t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		sl.t.Fatal(err)
	}
	tl := sl.wrap(l)
	host, portStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		sl.t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		sl.t.Fatal(err)
	}
	sl.mu.Lock()
	sl.l, sl.host, sl.port = tl, host, port
	sl.mu.Unlock()
	go func() {
		for {
			conn, err := tl.Accept()
			if err != nil {
				return
			}
			go sl.serve(conn)
		}
	}()
}

// stop закрывает приёмник: новые соединения отклоняются.
func (sl *s3Syslog) stop() {
	sl.mu.Lock()
	l := sl.l
	sl.l = nil
	sl.mu.Unlock()
	if l != nil {
		_ = l.Close() //nolint:gosec // G104: закрытие тестового приёмника
	}
}

// restart снова слушает прежний адрес.
func (sl *s3Syslog) restart() {
	sl.t.Helper()
	sl.mu.Lock()
	addr := net.JoinHostPort(sl.host, strconv.Itoa(sl.port))
	sl.mu.Unlock()
	sl.listen(addr)
}

// serve читает записи одного соединения до его закрытия.
func (sl *s3Syslog) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()                    //nolint:gosec // G104: закрытие тестового приёмника
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:gosec // G104: срок соединения тестового приёмника
	r := bufio.NewReader(conn)
	for {
		n, err := r.ReadString(' ')
		if err != nil {
			return
		}
		size, err := strconv.Atoi(strings.TrimSuffix(n, " "))
		if err != nil || size <= 0 || size > 1<<20 {
			sl.add("BAD FRAME " + n)
			return
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(r, buf); err != nil {
			return
		}
		sl.add(string(buf))
	}
}

func (sl *s3Syslog) add(rec string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.recs = append(sl.recs, rec)
}

// s3SyslogAlert — разобранная запись оповещения в общем формате JSON.
type s3SyslogAlert struct {
	Type     string            `json:"type"`
	ID       string            `json:"id"`
	Rule     string            `json:"rule"`
	RuleName string            `json:"rule_name"`
	Severity string            `json:"severity"`
	Title    string            `json:"title"`
	Count    int64             `json:"count"`
	Group    map[string]string `json:"group"`
	Raw      string            `json:"-"`
}

// alerts — разобранные записи оповещений (MSGID alert) среди принятых.
func (sl *s3Syslog) alerts() []s3SyslogAlert {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	var out []s3SyslogAlert
	for _, rec := range sl.recs {
		// <PRI>1 TS HOST aisec - alert - {json}
		if !strings.Contains(rec, " aisec - alert - ") {
			continue
		}
		i := strings.Index(rec, "{")
		var a s3SyslogAlert
		if i < 0 || json.Unmarshal([]byte(rec[i:]), &a) != nil {
			continue
		}
		a.Raw = rec
		out = append(out, a)
	}
	return out
}

// waitAlert ждёт запись оповещения по встроенному правилу rule.
func (sl *s3Syslog) waitAlert(t *testing.T, rule string, d time.Duration) s3SyslogAlert {
	t.Helper()
	var found s3SyslogAlert
	if !s2WaitFor(d, func() bool {
		for _, a := range sl.alerts() {
			if a.Rule == rule {
				found = a
				return true
			}
		}
		return false
	}) {
		sl.mu.Lock()
		defer sl.mu.Unlock()
		t.Fatalf("в приёмник syslog не пришло оповещение правила %s; принято %d записей: %q", rule, len(sl.recs), sl.recs)
	}
	return found
}

// s3Opts — параметры стенда.
type s3Opts struct {
	// mockArgs — аргументы mock-llm сверх -record-last.
	mockArgs []string
	// syslog — поднять приёмник и канал уведомлений на него.
	syslog bool
	// auditStream — канал ещё и передаёт журнал аудита в SIEM (РСБ.6).
	auditStream bool
	// serverArgs — аргументы сервера сверх обязательных.
	serverArgs []string
	// serverArgsFn — аргументы сервера, которым нужны файлы стенда (ключи
	// и сертификаты TLS появляются вместе со стендом).
	serverArgsFn func(s *s2Stand) []string
}

// s3Stack — сервер, шлюз, mock-llm и (по желанию) приёмник syslog.
type s3Stack struct {
	t     *testing.T
	s     *s2Stand
	admin *s2Client
	env   *s2GatewayEnv
	gw    *gwProc
	mock  string
	prov  string
	sys   *s3Syslog
	apps  int
}

// s3NewStack поднимает сервер и mock-llm; шлюз стартует в startGateway,
// когда в консоли заведены приложения.
func s3NewStack(t *testing.T, o s3Opts) *s3Stack {
	t.Helper()
	s := s2NewStand(t)
	console, internal := freeAddr(t), freeAddr(t)
	args := []string{"-listen", console, "-ca-cert", filepath.Join(s.keysDir, "ca.crt"), "-ca-key", filepath.Join(s.keysDir, "ca.key"),
		"-internal-listen", internal}
	if o.syslog {
		// Приёмник — на loopback теста: каналы по умолчанию его не принимают.
		args = append(args, "-notify-allowed-networks", "127.0.0.0/8")
	}
	args = append(args, o.serverArgs...)
	if o.serverArgsFn != nil {
		args = append(args, o.serverArgsFn(s)...)
	}
	s.mustStart(args...)
	s.base = "https://" + console
	st := &s3Stack{t: t, s: s, admin: s.setupAdmin()}
	st.env = newS2GatewayEnv(t, s, internal)
	st.mock = start(t, "mock-llm", append([]string{"-listen", "127.0.0.1:0", "-cert", s.tls.cert, "-key", s.tls.key, "-record-last"},
		o.mockArgs...)...)
	st.prov = addProvider(t, st.admin, "mock", "https://"+st.mock+"/v1", mustRead(t, s.tls.ca))
	if o.syslog {
		st.sys = newS3Syslog(t, s)
		r := st.admin.do("POST", "/api/v1/notify-channels", map[string]any{"name": "SIEM e2e", "type": "syslog",
			"min_severity": "info", "audit_stream": o.auditStream, "settings": map[string]any{"host": st.sys.host, "port": st.sys.port, "format": "json",
				"ca_pem": string(mustRead(t, s.tls.ca))}})
		if r.code != http.StatusCreated {
			t.Fatalf("канал syslog: %s", r)
		}
	}
	return st
}

// s3Policy создаёт политику «Базовая защита» для enforce: инъекция блокируется,
// ПДн псевдонимизируются на входе и скрываются в ответе, канарейка в ответе
// блокируется.
func (st *s3Stack) policy(id string) {
	st.t.Helper()
	spec := map[string]any{"name": "Базовая защита e2e", "mode": "enforce", "rules": []map[string]any{
		{"id": "injection", "detector": "injection.heuristic", "directions": []string{"input"}, "action": "block", "severity": "high"},
		{"id": "pii-input", "detector": "pii.ru", "directions": []string{"input"}, "action": "pseudonymize", "severity": "medium"},
		{"id": "pii-output", "detector": "pii.ru", "directions": []string{"output"}, "action": "redact", "severity": "medium"},
		{"id": "canary", "detector": "canary", "directions": []string{"output"}, "action": "block", "severity": "critical"},
	}}
	if r := st.admin.do("POST", "/api/v1/policies", map[string]any{"id": id, "spec": spec}); r.code != http.StatusCreated {
		st.t.Fatalf("политика %s: %s", id, r)
	}
}

// s3App — приложение стенда с ключом.
type s3App struct{ id, slug, key string }

// app заводит приложение под политику policy в режиме enforce и выпускает ключ.
func (st *s3Stack) app(slug, policy string) s3App {
	st.t.Helper()
	r := st.admin.do("POST", "/api/v1/applications", map[string]any{"slug": slug, "name": "Приложение " + slug, "env": "prod",
		"provider_id": st.prov, "models": []string{"mock-echo"}, "policy": policy, "policy_mode": "enforce"})
	if r.code != http.StatusCreated {
		st.t.Fatalf("приложение %s: %s", slug, r)
	}
	var a struct{ ID string }
	r.json(st.t, &a)
	r = st.admin.do("POST", "/api/v1/applications/"+a.ID+"/keys", map[string]any{"name": "e2e", "expires_in_days": 30})
	if r.code != http.StatusCreated {
		st.t.Fatalf("ключ приложения %s: %s", slug, r)
	}
	var k struct{ Key string }
	r.json(st.t, &k)
	st.apps++
	return s3App{id: a.ID, slug: slug, key: k.Key}
}

// startGateway запускает шлюз и ждёт пакет со всеми заведёнными приложениями.
func (st *s3Stack) startGateway() {
	st.t.Helper()
	st.gw = st.env.start(st.t)
	if !st.gw.waitLog(fmt.Sprintf(`"source":"server","applications":%d,`, st.apps), 90*time.Second) {
		st.t.Fatalf("шлюз не применил пакет с %d приложениями:\n%s", st.apps, st.gw.log())
	}
}

// chat отправляет запрос ключом key; model — mock-echo.
func (st *s3Stack) chat(key, text string) (int, string) {
	st.t.Helper()
	return s3Chat(st.t, st.s, st.gw, key, text)
}

// mockLast — последний запрос, дошедший до mock-llm.
func (st *s3Stack) mockLast() mockllm.LastRequest {
	st.t.Helper()
	hc := &http.Client{Transport: st.s.transport(), Timeout: 10 * time.Second}
	defer hc.CloseIdleConnections()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+st.mock+mockllm.LastRequestPath, nil)
	if err != nil {
		st.t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		st.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // тело прочитано ниже
	var last mockllm.LastRequest
	if err := json.NewDecoder(resp.Body).Decode(&last); err != nil {
		st.t.Fatal(err)
	}
	return last
}

// s3AlertItem — оповещение из списка консоли.
type s3AlertItem struct {
	ID         string            `json:"id"`
	RuleID     string            `json:"rule_id"`
	RuleName   string            `json:"rule_name"`
	Severity   string            `json:"severity"`
	Title      string            `json:"title"`
	Status     string            `json:"status"`
	Count      int               `json:"count"`
	Group      map[string]string `json:"group"`
	IncidentID string            `json:"incident_id"`
}

// ruleID — ID встроенного правила по ключу builtin.
func (st *s3Stack) ruleID(builtin string) string {
	st.t.Helper()
	r := st.admin.do("GET", "/api/v1/alert-rules", nil)
	if r.code != http.StatusOK {
		st.t.Fatalf("правила оповещений: %s", r)
	}
	var page struct {
		Items []struct{ ID, Builtin string }
	}
	r.json(st.t, &page)
	for _, it := range page.Items {
		if it.Builtin == builtin {
			return it.ID
		}
	}
	st.t.Fatalf("нет встроенного правила %s: %s", builtin, r.body)
	return ""
}

// waitAlert ждёт оповещение встроенного правила builtin и возвращает его.
func (st *s3Stack) waitAlert(builtin string, d time.Duration) s3AlertItem {
	st.t.Helper()
	id := st.ruleID(builtin)
	var found s3AlertItem
	if !s2WaitFor(d, func() bool {
		r := st.admin.do("GET", "/api/v1/alerts?limit=50&rule_id="+url.QueryEscape(id), nil)
		if r.code != http.StatusOK {
			st.t.Fatalf("оповещения: %s", r)
		}
		var page struct{ Items []s3AlertItem }
		r.json(st.t, &page)
		if len(page.Items) == 0 {
			return false
		}
		found = page.Items[0]
		return true
	}) {
		st.t.Fatalf("нет оповещения правила %s за %v", builtin, d)
	}
	return found
}

// alertCard — карточка оповещения: события и подробности.
type s3AlertCard struct {
	s3AlertItem
	Events  []struct{ ID string } `json:"events"`
	Details map[string]any        `json:"details"`
}

func (st *s3Stack) alertCard(id string) s3AlertCard {
	st.t.Helper()
	r := st.admin.do("GET", "/api/v1/alerts/"+id, nil)
	if r.code != http.StatusOK {
		st.t.Fatalf("карточка оповещения: %s", r)
	}
	var c s3AlertCard
	r.json(st.t, &c)
	return c
}

// mockReset забывает последний запрос mock-llm.
func (st *s3Stack) mockReset() {
	st.t.Helper()
	hc := &http.Client{Transport: st.s.transport(), Timeout: 10 * time.Second}
	defer hc.CloseIdleConnections()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, "https://"+st.mock+mockllm.LastRequestPath, nil)
	if err != nil {
		st.t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		st.t.Fatal(err)
	}
	_ = resp.Body.Close() //nolint:gosec // G104: тело не читается
}

// waitAlertOnce — оповещение правила builtin без ожидания (нулевое, если нет).
func (st *s3Stack) waitAlertOnce(builtin string) s3AlertItem {
	st.t.Helper()
	r := st.admin.do("GET", "/api/v1/alerts?limit=50&rule_id="+url.QueryEscape(st.ruleID(builtin)), nil)
	if r.code != http.StatusOK {
		st.t.Fatalf("оповещения: %s", r)
	}
	var page struct{ Items []s3AlertItem }
	r.json(st.t, &page)
	if len(page.Items) == 0 {
		return s3AlertItem{}
	}
	return page.Items[0]
}

// incidentCount — число инцидентов в консоли.
func (st *s3Stack) incidentCount() int {
	st.t.Helper()
	r := st.admin.do("GET", "/api/v1/incidents?limit=100", nil)
	if r.code != http.StatusOK {
		st.t.Fatalf("инциденты: %s", r)
	}
	var page struct{ Items []struct{ ID string } }
	r.json(st.t, &page)
	return len(page.Items)
}

// alertsOf — оповещения встроенного правила builtin, новые первыми.
func (st *s3Stack) alertsOf(builtin string) []s3AlertItem {
	st.t.Helper()
	r := st.admin.do("GET", "/api/v1/alerts?limit=100&rule_id="+url.QueryEscape(st.ruleID(builtin)), nil)
	if r.code != http.StatusOK {
		st.t.Fatalf("оповещения: %s", r)
	}
	var page struct{ Items []s3AlertItem }
	r.json(st.t, &page)
	return page.Items
}
