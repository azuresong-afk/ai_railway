//go:build e2e

package e2e

// Сценарий S11 этапа 4 (задача 4.30): теневой ИИ. Администратор загружает
// подписанный каталог ИИ-сервисов и журнал прокси файлом, затем прокси
// присылает строки по syslog через TLS; консоль показывает сервисы и
// пользователей (псевдонимами), динамику и оповещение о новом сервисе
// (DM-37). На настоящем сервере и живой PostgreSQL; каталог — тестовый
// подписанный testdata/shadowai/catalog-test.aisecdb.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// doRaw — запрос консоли с произвольным телом и типом содержимого (загрузка
// каталога и журнала): cookie, адрес и CSRF — как у do.
func (c *s2Client) doRaw(method, path, contentType string, body []byte) s2Resp {
	c.s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.s.base+path, bytes.NewReader(body))
	if err != nil {
		c.s.t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Forwarded-For", c.xff)
	req.Header.Set("X-CSRF-Token", c.csrfToken())
	resp, err := c.hc.Do(req)
	if err != nil {
		c.s.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // ошибка закрытия тела ответа не влияет на тест
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		c.s.t.Fatalf("%s %s: чтение ответа: %v", method, path, err)
	}
	return s2Resp{code: resp.StatusCode, hdr: resp.Header, body: raw}
}

// s11Squid — строка журнала Squid (native): момент, клиент, узел и логин.
func s11Squid(at time.Time, client, host, user string, bytes int) string {
	return fmt.Sprintf("%d.000    120 %s TCP_TUNNEL/200 %d CONNECT %s:443 %s HIER_DIRECT/203.0.113.10 -",
		at.Unix(), client, bytes, host, user)
}

// s11Service — сервис из ответа консоли.
type s11Service struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Requests int64  `json:"requests"`
	Users    int64  `json:"users"`
}

func s11Services(t *testing.T, c *s2Client) map[string]s11Service {
	t.Helper()
	r := c.do("GET", "/api/v1/shadow-ai/services", nil)
	if r.code != http.StatusOK {
		t.Fatalf("сервисы теневого ИИ: %s", r)
	}
	var page struct{ Items []s11Service }
	r.json(t, &page)
	out := map[string]s11Service{}
	for _, it := range page.Items {
		out[it.ID] = it
	}
	return out
}

func TestE2EStage4_S11_ShadowAI(t *testing.T) {
	var syslogAddr string
	st := s3NewStack(t, s3Opts{serverArgsFn: func(s *s2Stand) []string {
		keyFile := filepath.Join(t.TempDir(), "user-hmac.key")
		if err := os.WriteFile(keyFile, []byte("e2e-user-pseudonym-key-0123456789"), 0o600); err != nil {
			t.Fatal(err)
		}
		syslogAddr = freeAddr(t)
		return []string{"-user-hmac-key", keyFile, "-shadow-ai-syslog-listen", syslogAddr, "-shadow-ai-syslog-format", "squid",
			"-shadow-ai-syslog-tls-cert", s.tls.cert, "-shadow-ai-syslog-tls-key", s.tls.key}
	}})
	admin := st.admin
	now := time.Now().UTC().Truncate(time.Second)

	// Без каталога импорт невозможен.
	file := strings.Join([]string{
		s11Squid(now.Add(-3*time.Hour), "10.0.12.34", "chatgpt.com", "ivanov.ia", 5120),
		s11Squid(now.Add(-150*time.Minute), "10.0.12.34", "chat.openai.com", "ivanov.ia", 2048),
		s11Squid(now.Add(-2*time.Hour), "10.0.12.35", "giga.chat", "petrova.ms", 7000),
		s11Squid(now.Add(-110*time.Minute), "10.0.12.35", "www.example.ru", "petrova.ms", 900),
		"строка, которая не похожа на журнал Squid",
	}, "\n") + "\n"
	if r := admin.doRaw("POST", "/api/v1/shadow-ai/imports?format=squid", "text/plain", []byte(file)); r.code != http.StatusConflict {
		t.Fatalf("импорт без каталога: %s", r)
	}
	// Каталог — подписанный файл; управлять может только держатель shadow_ai.manage.
	catalog, err := os.ReadFile("../../testdata/shadowai/catalog-test.aisecdb")
	if err != nil {
		t.Fatal(err)
	}
	auditor := admin.createUser("auditor-s11", auth.RoleAuditor)
	ac := st.s.client("198.51.100.61")
	ac.signIn(auditor)
	if r := ac.doRaw("PUT", "/api/v1/shadow-ai/catalog", "application/octet-stream", catalog); r.code != http.StatusForbidden {
		t.Fatalf("загрузка каталога аудитором: %s", r)
	}
	if r := ac.doRaw("POST", "/api/v1/shadow-ai/imports?format=squid", "text/plain", []byte(file)); r.code != http.StatusForbidden {
		t.Fatalf("импорт журнала аудитором: %s", r)
	}
	broken := append([]byte(nil), catalog...)
	broken[len(broken)/2] ^= 0xff
	if r := admin.doRaw("PUT", "/api/v1/shadow-ai/catalog", "application/octet-stream", broken); r.code != http.StatusUnprocessableEntity {
		t.Fatalf("загрузка испорченного каталога: %s", r)
	}
	if r := admin.doRaw("PUT", "/api/v1/shadow-ai/catalog", "application/octet-stream", catalog); r.code != http.StatusOK {
		t.Fatalf("загрузка каталога: %s", r)
	}
	if st.s.auditCount("shadow_ai.catalog_loaded") != 1 || st.s.auditCount("shadow_ai.catalog_rejected") != 1 {
		t.Fatal("в аудите нет записей о загрузке и отклонении каталога")
	}

	// Импорт журнала: свои сервисы найдены, чужие узлы и мусор посчитаны, логины не хранятся.
	r := admin.doRaw("POST", "/api/v1/shadow-ai/imports?format=squid", "text/plain", []byte(file))
	var imp struct {
		Lines, Matched, Unmatched, Errors int64
		ErrorLines                        []int64 `json:"error_lines"`
		UsersPseudonymized                bool    `json:"users_pseudonymized"`
		Services                          int
	}
	r.json(t, &imp)
	if r.code != http.StatusCreated || imp.Lines != 5 || imp.Matched != 3 || imp.Unmatched != 1 || imp.Errors != 1 ||
		len(imp.ErrorLines) != 1 || imp.ErrorLines[0] != 5 || !imp.UsersPseudonymized || imp.Services != 2 {
		t.Fatalf("импорт журнала: %s", r)
	}
	if r := admin.doRaw("POST", "/api/v1/shadow-ai/imports?format=squid", "text/plain", []byte(file)); r.code != http.StatusConflict {
		t.Fatalf("повторный импорт того же файла: %s", r)
	}
	svc := s11Services(t, admin)
	if svc["chatgpt"].Requests != 2 || svc["chatgpt"].Users != 1 || svc["gigachat"].Requests != 1 || len(svc) != 2 {
		t.Fatalf("сервисы после импорта: %+v", svc)
	}
	// Пользователи — только псевдонимами; ни логинов, ни адресов в ответах.
	users := admin.do("GET", "/api/v1/shadow-ai/users", nil)
	var ul struct {
		Items []struct{ Alias, Kind string }
	}
	users.json(t, &ul)
	if users.code != http.StatusOK || len(ul.Items) != 2 {
		t.Fatalf("пользователи теневого ИИ: %s", users)
	}
	for _, it := range ul.Items {
		if len(it.Alias) != 32 || it.Kind != "user" {
			t.Fatalf("пользователь не псевдоним: %+v", it)
		}
	}
	for _, path := range []string{"/api/v1/shadow-ai/users", "/api/v1/shadow-ai/services", "/api/v1/shadow-ai/imports", "/api/v1/audit?limit=50"} {
		r := admin.do("GET", path, nil)
		if r.code != http.StatusOK {
			t.Fatalf("%s: %d (проверка «содержимого нет» без ответа 200 ничего не доказывает, 4Н36)", path, r.code)
		}
		if body := string(r.body); strings.Contains(body, "ivanov.ia") || strings.Contains(body, "petrova.ms") ||
			strings.Contains(body, "10.0.12.3") || strings.Contains(body, "example.ru") {
			t.Fatalf("в ответе %s логин, адрес или узел из журнала: %.400s", path, body)
		}
	}
	// Динамика по часам: обращения за период видны.
	tl := admin.do("GET", "/api/v1/shadow-ai/timeline?step=hour&from="+now.Add(-6*time.Hour).Format(time.RFC3339)+"&to="+now.Add(time.Hour).Format(time.RFC3339), nil)
	if tl.code != http.StatusOK || !strings.Contains(string(tl.body), `"requests":`) || strings.Contains(string(tl.body), `"items":[]`) {
		t.Fatalf("динамика теневого ИИ: %s", tl)
	}
	// Оповещение DM-37: новые для установки сервисы (по одному на сервис).
	if !s2WaitFor(60*time.Second, func() bool { return len(st.alertsOf(alerting.BuiltinShadowNewService)) >= 2 }) {
		t.Fatalf("оповещения о новых сервисах после импорта: %+v", st.alertsOf(alerting.BuiltinShadowNewService))
	}

	// Приём по syslog через TLS: Claude — ещё один новый сервис; строки RFC 5424
	// с октетным счётом и RFC 3164; без доверия к УЦ соединение не проходит.
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tp.ClientConfig(st.s.roots)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerName = "127.0.0.1"
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", syslogAddr)
	if err != nil {
		t.Fatalf("порт syslog: %v", err)
	}
	conn, err := aisecCrypto.ClientTLS(context.Background(), raw, cfg)
	if err != nil {
		t.Fatalf("TLS к слушателю syslog: %v", err)
	}
	defer conn.Close() //nolint:errcheck // соединение теста
	msgs := []string{
		"<134>1 " + now.Format(time.RFC3339) + " proxy squid 42 - - " + s11Squid(now.Add(-time.Minute), "10.0.12.40", "claude.ai", "sidorov.vp", 4096),
		"<134>1 " + now.Format(time.RFC3339) + " proxy squid 42 - - " + s11Squid(now.Add(-time.Minute), "10.0.12.40", "claude.ai", "sidorov.vp", 1024),
	}
	var frames strings.Builder
	for _, m := range msgs {
		frames.WriteString(strconv.Itoa(len(m)) + " " + m)
	}
	if _, err := conn.Write([]byte(frames.String())); err != nil {
		t.Fatalf("запись в syslog: %v", err)
	}
	// Сводки копятся в памяти и пишутся раз в минуту.
	if !s2WaitFor(150*time.Second, func() bool { return s11Services(t, admin)["claude"].Requests == 2 }) {
		t.Fatalf("строки syslog не дошли до сводок: %+v", s11Services(t, admin))
	}
	var named string
	if !s2WaitFor(60*time.Second, func() bool {
		for _, al := range st.alertsOf(alerting.BuiltinShadowNewService) {
			for _, g := range al.Group {
				if strings.Contains(g, "Claude") {
					named = g
					return true
				}
			}
		}
		return false
	}) {
		t.Fatalf("нет оповещения о новом сервисе Claude из syslog: %+v", st.alertsOf(alerting.BuiltinShadowNewService))
	}
	if strings.Contains(named, "sidorov") {
		t.Fatalf("в оповещении логин: %s", named)
	}
	// Состояние слушателя: принято, разобрано, ошибок рукопожатия нет.
	sr := admin.do("GET", "/api/v1/shadow-ai/syslog", nil)
	var stat struct {
		Enabled, Running, TLS bool
		Lines, Matched        int64
	}
	sr.json(t, &stat)
	if sr.code != http.StatusOK || !stat.Enabled || !stat.Running || !stat.TLS || stat.Lines < 2 || stat.Matched < 2 {
		t.Fatalf("состояние приёма syslog: %s", sr)
	}
	if body := string(admin.do("GET", "/api/v1/shadow-ai/users", nil).body); strings.Contains(body, "sidorov.vp") {
		t.Fatalf("в ответе логин из syslog: %.300s", body)
	}
}
