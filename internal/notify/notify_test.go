package notify

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

const testSigningKey = "0123456789abcdef0123456789abcdef-test-key"

func ptr[T any](v T) *T { return &v }

type env struct {
	p     aisecCrypto.Provider
	tp    aisecCrypto.TLSProvider
	caPEM string
	cert  []byte
	key   []byte
	mem   *Memory
	svc   *Service
	tr    *Transport
	now   time.Time
	by    By
	// ids — счётчик идентификаторов записей журнала в тестах передачи.
	ids      int
	lastHash []byte
}

func newEnv(t *testing.T) *env {
	t.Helper()
	p := testProvider(t)
	caPEM, tp, cert, key := newPKI(t, p)
	tr, err := NewTransport(p, "1.2.3", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Приёмники тестов слушают loopback: сеть разрешена явно (3Н31 ревью 3.r2).
	tr.AllowNetworks(loopbackNets)
	e := &env{p: p, tp: tp, caPEM: caPEM, cert: cert, key: key, mem: NewMemory(), tr: tr,
		now: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	e.mem.SetNow(func() time.Time { return e.now })
	e.svc, err = New(Options{Store: e.mem, Box: testBox(t, p), Provider: p, Transport: tr, Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	e.by = By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000a1", Name: "ivanova"},
		Confirm: func(context.Context) error { return nil }}
	return e
}

func sampleAlert() Message {
	return Message{Kind: KindAlert, ID: "01900000-0000-7000-8000-00000000aa01", Rule: "security.console_bruteforce",
		RuleName: "Перебор паролей консоли", AlertKind: "security", Severity: "high",
		Title: "Перебор паролей консоли — 192.0.2.10", Count: 10,
		Group:     map[string]string{"source_ip": "192.0.2.10", "account": "admin\r\nBcc: evil@example.org @channel"},
		CreatedAt: time.Date(2026, 10, 22, 11, 59, 0, 0, time.UTC)}
}

func (e *env) emailInput(addr string, user string) ChannelInput {
	h, p := hostPortStr(addr)
	in := ChannelInput{Name: "Почта SOC", Type: TypeEmail, MinSeverity: "medium",
		Settings: Settings{Host: h, Port: p, CAPEM: e.caPEM, From: "aisec@example.ru", To: []string{"soc@example.ru", "duty@example.ru"}}}
	if user != "" {
		in.Settings.Username = user
		in.Secrets.Password = ptr("synthetic-Pa55")
	}
	return in
}

func hostPortStr(addr string) (string, int) {
	i := strings.LastIndex(addr, ":")
	n, _ := strconv.Atoi(addr[i+1:]) //nolint:gosec // G104: адрес тестового приёмника корректен
	return addr[:i], n
}

// Почта: STARTTLS до AUTH и письма, тема RFC 2047, значения нарушителя не
// добавляют заголовков; пароль уходит только внутри TLS.
func TestEmailDelivery(t *testing.T) {
	e := newEnv(t)
	smtpSrv := newSMTPServer(t, e.tp, e.cert, e.key, true)
	c, err := e.svc.CreateChannel(testCtx(t), e.by, e.emailInput(smtpSrv.addr, "aisec"))
	if err != nil {
		t.Fatal(err)
	}
	sec, err := e.svc.secrets(testCtx(t), c)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.tr.Send(testCtx(t), c, sec, sampleAlert()); err != nil {
		t.Fatal(err)
	}
	smtpSrv.mu.Lock()
	defer smtpSrv.mu.Unlock()
	if !smtpSrv.tlsUsed || len(smtpSrv.auth) != 1 || smtpSrv.auth[0] != "\x00aisec\x00synthetic-Pa55" {
		t.Fatalf("STARTTLS/AUTH: tls=%v auth=%q", smtpSrv.tlsUsed, smtpSrv.auth)
	}
	if len(smtpSrv.rcpt) != 2 || len(smtpSrv.data) != 1 {
		t.Fatalf("получатели и письмо: %q %d", smtpSrv.rcpt, len(smtpSrv.data))
	}
	msg := smtpSrv.data[0]
	head, body, ok := strings.Cut(msg, "\r\n\r\n")
	if !ok {
		t.Fatalf("письмо без заголовков: %q", msg)
	}
	if strings.Contains(head, "Bcc") || strings.Count(head, "\r\n") != 8 {
		t.Fatalf("заголовки: %q", head)
	}
	var subject string
	for _, l := range strings.Split(head, "\r\n") {
		if v, ok := strings.CutPrefix(l, "Subject: "); ok {
			subject, err = new(mime.WordDecoder).DecodeHeader(v)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if subject != "[AISec] высокая: Перебор паролей консоли — 192.0.2.10" {
		t.Fatalf("тема: %q", subject)
	}
	text, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(body), "\r\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), "account: admin  Bcc: evil@example.org @channel") ||
		!strings.Contains(string(text), "Серьёзность: высокая") {
		t.Fatalf("текст: %q", text)
	}
}

// Сервер без STARTTLS — отказ до AUTH и письма; неверный корень УЦ — ошибка
// TLS; неверный пароль — auth.
func TestEmailNegative(t *testing.T) {
	e := newEnv(t)
	plain := newSMTPServer(t, e.tp, e.cert, e.key, false)
	c, err := e.svc.CreateChannel(testCtx(t), e.by, e.emailInput(plain.addr, "aisec"))
	if err != nil {
		t.Fatal(err)
	}
	sec, _ := e.svc.secrets(testCtx(t), c) //nolint:gosec // G104: ошибку покажет следующая проверка теста
	if err := e.tr.Send(testCtx(t), c, sec, sampleAlert()); ErrorCode(err) != ErrCodeNoSTARTTLS {
		t.Fatalf("без STARTTLS: %v", err)
	}
	plain.mu.Lock()
	if len(plain.auth)+len(plain.from)+len(plain.data) != 0 {
		t.Fatalf("данные ушли без TLS: %q %q", plain.auth, plain.from)
	}
	plain.mu.Unlock()

	srv := newSMTPServer(t, e.tp, e.cert, e.key, true)
	other, _, _, _ := newPKI(t, e.p)
	c.Settings.Host, c.Settings.Port = hostPortStr(srv.addr)
	c2 := c
	c2.Settings.CAPEM = other
	if err := e.tr.Send(testCtx(t), c2, sec, sampleAlert()); ErrorCode(err) != ErrCodeTLS {
		t.Fatalf("чужой УЦ: %v", err)
	}
	if err := e.tr.Send(testCtx(t), c, Secrets{Password: "wrong"}, sampleAlert()); ErrorCode(err) != ErrCodeAuth {
		t.Fatalf("неверный пароль: %v", err)
	}
	c3 := c
	c3.Settings.Port = 1
	if err := e.tr.Send(testCtx(t), c3, sec, sampleAlert()); ErrorCode(err) != ErrCodeDial {
		t.Fatalf("нет соединения: %v", err)
	}
}

func (e *env) webhookChannel(t *testing.T, ws *webhookServer, format string) (Channel, Secrets) {
	t.Helper()
	c, err := e.svc.CreateChannel(testCtx(t), e.by, ChannelInput{Name: "Webhook " + format, Type: TypeWebhook,
		Settings: Settings{Format: format, CAPEM: e.caPEM},
		Secrets:  SecretsInput{URL: ptr(ws.srv.URL + "/hooks/secret-token"), SigningKey: ptr(testSigningKey)}})
	if err != nil {
		t.Fatal(err)
	}
	sec, err := e.svc.secrets(testCtx(t), c)
	if err != nil {
		t.Fatal(err)
	}
	return c, sec
}

// Webhook: подпись t=…,v1=… MAC профиля от «t.тело», общий формат JSON и
// формат Mattermost без срабатывания упоминаний; перенаправление не
// выполняется; ответ не 2xx — код http_NNN.
func TestWebhookDelivery(t *testing.T) {
	e := newEnv(t)
	e.tr.now = func() time.Time { return e.now }
	ws := newWebhookServer(t, e.tp, e.cert, e.key)
	c, sec := e.webhookChannel(t, ws, FormatGeneric)
	if c.Settings.URLOrigin != ws.srv.URL || strings.Contains(c.Settings.URLOrigin, "secret-token") {
		t.Fatalf("показ адреса: %q", c.Settings.URLOrigin)
	}
	if err := e.tr.Send(testCtx(t), c, sec, sampleAlert()); err != nil {
		t.Fatal(err)
	}
	bodies, sigs := ws.received()
	if len(bodies) != 1 {
		t.Fatalf("тел: %d", len(bodies))
	}
	ts, mac, ok := strings.Cut(strings.TrimPrefix(sigs[0], "t="), ",v1=")
	if !ok || ts != strconv.FormatInt(e.now.Unix(), 10) {
		t.Fatalf("заголовок подписи: %q", sigs[0])
	}
	m, err := e.p.NewMAC([]byte(testSigningKey))
	if err != nil {
		t.Fatal(err)
	}
	tag, err := hex.DecodeString(mac)
	if err != nil || !m.Verify(append([]byte(ts+"."), bodies[0]...), tag) {
		t.Fatalf("подпись не сходится: %q", sigs[0])
	}
	var got payload
	if err := json.Unmarshal(bodies[0], &got); err != nil {
		t.Fatal(err)
	}
	if got.Product != "AISec" || got.Version != "1.2.3" || got.Severity != "high" || got.Rule != "security.console_bruteforce" ||
		got.Group["source_ip"] != "192.0.2.10" || got.Type != KindAlert {
		t.Fatalf("тело: %+v", got)
	}

	mm, msec := e.webhookChannel(t, ws, FormatMattermost)
	if err := e.tr.Send(testCtx(t), mm, msec, sampleAlert()); err != nil {
		t.Fatal(err)
	}
	bodies, _ = ws.received()
	var md map[string]string
	if err := json.Unmarshal(bodies[1], &md); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(md["text"], "**Перебор паролей консоли") || strings.Contains(md["text"], " @channel") ||
		strings.Contains(md["text"], "\r") {
		t.Fatalf("Mattermost: %q", md["text"])
	}

	for code, want := range map[int]string{http.StatusFound: "http_302", http.StatusInternalServerError: "http_500"} {
		ws.setStatus(code)
		if err := e.tr.Send(testCtx(t), c, sec, sampleAlert()); ErrorCode(err) != want {
			t.Fatalf("ответ %d: %v", code, err)
		}
	}
	bodies, _ = ws.received()
	if len(bodies) != 4 {
		t.Fatalf("перенаправление выполнено: %d запросов", len(bodies))
	}
	other, _, _, _ := newPKI(t, e.p)
	c.Settings.CAPEM = other
	if err := e.tr.Send(testCtx(t), c, sec, sampleAlert()); ErrorCode(err) != ErrCodeTLS {
		t.Fatalf("чужой УЦ: %v", err)
	}
}

// Syslog: RFC 5424 по TLS с octet counting; тело JSON или CEF 0.
func TestSyslogDelivery(t *testing.T) {
	e := newEnv(t)
	srv := newSyslogServer(t, e.tp, e.cert, e.key)
	h, p := hostPortStr(srv.addr)
	for _, format := range []string{FormatJSON, FormatCEF} {
		c, err := e.svc.CreateChannel(testCtx(t), e.by, ChannelInput{Name: "SIEM " + format, Type: TypeSyslog,
			Settings: Settings{Host: h, Port: p, Format: format, CAPEM: e.caPEM}})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.tr.Send(testCtx(t), c, Secrets{}, sampleAlert()); err != nil {
			t.Fatal(err)
		}
		rec := srv.next(t)
		// PRI = authpriv(10)·8 + error(3) = 83.
		prefix := "<83>1 2026-10-22T11:59:00.000000Z aisec-server aisec - alert - "
		if !strings.HasPrefix(rec, prefix) {
			t.Fatalf("%s: заголовок RFC 5424: %q", format, rec)
		}
		msg := strings.TrimPrefix(rec, prefix)
		switch format {
		case FormatJSON:
			var got payload
			if err := json.Unmarshal([]byte(msg), &got); err != nil || got.ID != sampleAlert().ID {
				t.Fatalf("JSON: %q %v", msg, err)
			}
		case FormatCEF:
			if !strings.HasPrefix(msg, "CEF:0|AISec|AISec|1.2.3|security.console_bruteforce|Перебор паролей консоли — 192.0.2.10|8|rt=") ||
				!strings.Contains(msg, `account: admin  Bcc: evil@example.org @channel; source_ip: 192.0.2.10`) {
				t.Fatalf("CEF: %q", msg)
			}
		}
	}
}

// Экранирование CEF: заголовок — «\» и «|», расширение — «\», «=» и
// переводы строк (спецификация CEF, ревизия 25).
func TestCEFEscaping(t *testing.T) {
	m := sampleAlert()
	m.Rule = `a|b\c`
	m.Title = "x|y\nz"
	m.RuleName = `k=v\w`
	m.Group = nil
	got := string(cefBody(m, "1|0"))
	want := `CEF:0|AISec|AISec|1\|0|a\|b\\c|x\|y z|8|`
	if !strings.HasPrefix(got, want) || !strings.Contains(got, `cs1=k\=v\\w`) {
		t.Fatalf("CEF: %q", got)
	}
	// 3Н32 ревью 3.r2: управляющие символы и разделители строк Unicode в
	// значениях расширения не обрезают и не разбивают запись в SIEM.
	m.RuleName = "a\x00b\u0085c\u2028d\re"
	m.Group = map[string]string{"account": "x\u2029y"}
	got = string(cefBody(m, "1"))
	for _, bad := range []string{"\x00", "\u0085", "\u2028", "\u2029", "\r"} {
		if strings.Contains(got, bad) {
			t.Fatalf("CEF с управляющим символом %q: %q", bad, got)
		}
	}
}

func TestBackoff(t *testing.T) {
	want := []time.Duration{30 * time.Second, 2 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	for i, w := range want {
		if got := Backoff(i + 1); got != w {
			t.Fatalf("попытка %d: %s, ожидалось %s", i+1, got, w)
		}
	}
}

// Проверка ввода: обязательные поля, TLS только с корнями УЦ, адреса
// без перевода строк, только https, чужие для типа поля отклоняются.
func TestNormalize(t *testing.T) {
	e := newEnv(t)
	good := map[string]ChannelInput{
		"email": {Name: "Почта", Type: TypeEmail, Settings: Settings{Host: "smtp.example.ru", CAPEM: e.caPEM, From: "a@example.ru",
			To: []string{"b@example.ru"}}},
		"webhook": {Name: "Hook", Type: TypeWebhook, Settings: Settings{CAPEM: e.caPEM},
			Secrets: SecretsInput{URL: ptr("https://hooks.example.ru:8443/x?y=1"), SigningKey: ptr(testSigningKey)}},
		"syslog": {Name: "SIEM", Type: TypeSyslog, Settings: Settings{Host: "10.0.0.5", CAPEM: e.caPEM}},
	}
	for name, in := range good {
		if _, err := normalize(&in, Secrets{}, e.tp); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		switch in.Type {
		case TypeEmail:
			if in.Settings.Port != DefaultSMTPPort || in.MinSeverity != "info" || !*in.Enabled {
				t.Fatalf("умолчания почты: %+v", in)
			}
		case TypeSyslog:
			if in.Settings.Port != DefaultSyslogPort || *in.Settings.Facility != DefaultFacility || in.Settings.Format != FormatJSON {
				t.Fatalf("умолчания syslog: %+v", in.Settings)
			}
		case TypeWebhook:
			if in.Settings.URLOrigin != "https://hooks.example.ru:8443" || in.Settings.Format != FormatGeneric {
				t.Fatalf("webhook: %+v", in.Settings)
			}
		}
	}
	bad := []struct {
		name  string
		field string
		edit  func(*ChannelInput)
	}{
		{"нет корней УЦ", "ca_pem", func(in *ChannelInput) { in.Settings.CAPEM = "" }},
		{"корни не PEM", "ca_pem", func(in *ChannelInput) { in.Settings.CAPEM = "not a cert" }},
		{"корни больше предела", "ca_pem", func(in *ChannelInput) { in.Settings.CAPEM = strings.Repeat("a", MaxCAPEM+1) }},
		{"перевод строки в адресе", "settings.to[0]", func(in *ChannelInput) { in.Settings.To = []string{"b@example.ru\r\nBcc: x@y.ru"} }},
		{"имя в адресе", "settings.from", func(in *ChannelInput) { in.Settings.From = "Иван <a@example.ru>" }},
		{"нет получателей", "settings.to", func(in *ChannelInput) { in.Settings.To = nil }},
		{"повтор получателя", "settings.to", func(in *ChannelInput) { in.Settings.To = []string{"b@example.ru", "b@example.ru"} }},
		{"21 получатель", "settings.to", func(in *ChannelInput) {
			in.Settings.To = nil
			for i := range MaxRecipients + 1 {
				in.Settings.To = append(in.Settings.To, "u"+strconv.Itoa(i)+"@example.ru")
			}
		}},
		{"узел со схемой", "settings.host", func(in *ChannelInput) { in.Settings.Host = "smtp://example.ru" }},
		{"порт 0 после умолчания нельзя, 70000", "settings.port", func(in *ChannelInput) { in.Settings.Port = 70000 }},
		{"пароль без имени", "settings.username", func(in *ChannelInput) { in.Secrets.Password = ptr("x") }},
		{"имя без пароля", "secrets.password", func(in *ChannelInput) { in.Settings.Username = "u" }},
		{"поле syslog у почты", "settings", func(in *ChannelInput) { in.Settings.Format = FormatJSON }},
		{"неизвестный тип", "type", func(in *ChannelInput) { in.Type = "sms" }},
		{"пустое имя", "name", func(in *ChannelInput) { in.Name = " " }},
		{"имя с переводом строки", "name", func(in *ChannelInput) { in.Name = "a\nb" }},
		{"длинное имя", "name", func(in *ChannelInput) { in.Name = strings.Repeat("я", MaxName+1) }},
		{"порог", "min_severity", func(in *ChannelInput) { in.MinSeverity = "urgent" }},
	}
	for _, c := range bad {
		in := good["email"]
		in.Settings.To = slices.Clone(in.Settings.To)
		c.edit(&in)
		_, err := normalize(&in, Secrets{}, e.tp)
		var ie *InputError
		if !errors.As(err, &ie) || !strings.Contains(err.Error(), c.field) {
			t.Fatalf("%s: ожидалась ошибка поля %s, получено %v", c.name, c.field, err)
		}
	}
	hook := []struct{ name, url, key string }{
		{"http", "http://hooks.example.ru/x", testSigningKey},
		{"учётные данные в адресе", "https://u:p@hooks.example.ru/x", testSigningKey},
		{"фрагмент", "https://hooks.example.ru/x#f", testSigningKey},
		{"нет узла", "https:///x", testSigningKey},
		{"перевод строки", "https://hooks.example.ru/x\n", testSigningKey},
		{"короткий ключ", "https://hooks.example.ru/x", strings.Repeat("k", MinSigningKey-1)},
	}
	for _, c := range hook {
		in := good["webhook"]
		in.Secrets = SecretsInput{URL: ptr(c.url), SigningKey: ptr(c.key)}
		if _, err := normalize(&in, Secrets{}, e.tp); err == nil {
			t.Fatalf("webhook %s: принято", c.name)
		}
	}
	// Граница: ключ ровно MinSigningKey байт принимается.
	in := good["webhook"]
	in.Secrets.SigningKey = ptr(strings.Repeat("k", MinSigningKey))
	if _, err := normalize(&in, Secrets{}, e.tp); err != nil {
		t.Fatalf("ключ %d байт: %v", MinSigningKey, err)
	}
	in = good["syslog"]
	in.Settings.Facility = ptr(24)
	if _, err := normalize(&in, Secrets{}, e.tp); err == nil {
		t.Fatal("facility 24 принят")
	}
	in = good["syslog"]
	in.Settings.Hostname = "aisec server"
	if _, err := normalize(&in, Secrets{}, e.tp); err == nil {
		t.Fatal("HOSTNAME с пробелом принят")
	}
}

// Изменение канала: секреты — только признак в аудите; ослабление
// (отключение, порог, адрес, корни УЦ, удаление адресата) — с повторной
// проверкой и weakening (DM-40); тип не меняется; версия сверяется.
func TestChannelUpdateWeakening(t *testing.T) {
	e := newEnv(t)
	ctx := testCtx(t)
	c, err := e.svc.CreateChannel(ctx, e.by, e.emailInput("smtp.example.ru:587", "aisec"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.SecretFields, []string{SecretPassword}) || len(c.Secret) == 0 || c.SecretKeyID == "" {
		t.Fatalf("секрет не зашифрован: %+v", c.SecretFields)
	}
	if strings.Contains(string(c.Secret), "synthetic-Pa55") {
		t.Fatal("пароль в открытом виде")
	}
	if _, err := e.svc.CreateChannel(ctx, e.by, e.emailInput("smtp.example.ru:587", "")); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("повтор названия: %v", err)
	}
	upd := func(by By, edit func(*ChannelInput)) (Channel, error) {
		cur, err := e.svc.Channel(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		in := ChannelInput{Name: cur.Name, Enabled: ptr(cur.Enabled), MinSeverity: cur.MinSeverity, Settings: cur.Settings,
			Version: cur.Version}
		in.Settings.To = slices.Clone(cur.Settings.To)
		edit(&in)
		return e.svc.UpdateChannel(ctx, by, c.ID, in)
	}
	noConfirm := e.by
	noConfirm.Confirm = nil
	// Не ослабление: новый адресат, смена пароля — без проверки.
	if _, err := upd(noConfirm, func(in *ChannelInput) {
		in.Settings.To = append(in.Settings.To, "cert@example.ru")
		in.Secrets.Password = ptr("synthetic-Pa66")
	}); err != nil {
		t.Fatal(err)
	}
	last := e.mem.Audited()[len(e.mem.Audited())-1]
	raw, _ := json.Marshal(last.Details) //nolint:gosec // G104: значение всегда сериализуется
	if last.Action != "notify_channel.update" || strings.Contains(string(raw), "synthetic-Pa") ||
		!strings.Contains(string(raw), `"protected_changed":["password"]`) || !strings.Contains(string(raw), `"weakening":false`) {
		t.Fatalf("аудит изменения: %s", raw)
	}
	weak := []struct {
		reason string
		edit   func(*ChannelInput)
	}{
		{"disabled", func(in *ChannelInput) { in.Enabled = ptr(false) }},
		{"min_severity_raised", func(in *ChannelInput) { in.MinSeverity = "critical" }},
		{"destination_changed", func(in *ChannelInput) { in.Settings.Host = "mx.example.org" }},
		{"recipients_removed", func(in *ChannelInput) { in.Settings.To = in.Settings.To[:1] }},
		{"trust_changed", func(in *ChannelInput) { in.Settings.CAPEM, _, _, _ = newPKI(t, e.p) }},
	}
	for _, w := range weak {
		if _, err := upd(noConfirm, w.edit); !errors.Is(err, ErrConfirmRequired) {
			t.Fatalf("%s без проверки: %v", w.reason, err)
		}
		if _, err := upd(e.by, w.edit); err != nil {
			t.Fatalf("%s: %v", w.reason, err)
		}
		last := e.mem.Audited()[len(e.mem.Audited())-1]
		d := last.Details.(map[string]any)
		if d["weakening"] != true || !slices.Contains(d["weakening_reasons"].([]string), w.reason) {
			t.Fatalf("%s: аудит %+v", w.reason, d)
		}
	}
	if _, err := upd(e.by, func(in *ChannelInput) { in.Version-- }); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("версия: %v", err)
	}
	if _, err := upd(e.by, func(in *ChannelInput) { in.Type = TypeSyslog }); err == nil || !strings.Contains(err.Error(), "type") {
		t.Fatalf("смена типа: %v", err)
	}
	if _, err := e.svc.UpdateChannel(ctx, e.by, "01900000-0000-7000-8000-0000000000ff", ChannelInput{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("нет канала: %v", err)
	}
	// Секреты по-прежнему расшифровываются после замены.
	cur, _ := e.svc.Channel(ctx, c.ID) //nolint:gosec // G104: ошибку покажет следующая проверка теста
	sec, err := e.svc.secrets(ctx, cur)
	if err != nil || sec.Password != "synthetic-Pa66" {
		t.Fatalf("секрет после изменения: %v", err)
	}
}

// Тестовая отправка: строка журнала test, запись аудита с итогом; не чаще
// 5 раз в минуту на канал.
func TestChannelTestSend(t *testing.T) {
	e := newEnv(t)
	ctx := testCtx(t)
	ws := newWebhookServer(t, e.tp, e.cert, e.key)
	c, _ := e.webhookChannel(t, ws, FormatGeneric)
	d, err := e.svc.TestChannel(ctx, e.by, c.ID)
	if err != nil || d.Status != StatusSent || d.Kind != KindTest || d.AlertID != "" {
		t.Fatalf("тест: %+v %v", d, err)
	}
	ws.setStatus(http.StatusUnauthorized)
	d, err = e.svc.TestChannel(ctx, e.by, c.ID)
	if err != nil || d.Status != StatusFailed || d.Error != "http_401" {
		t.Fatalf("тест с отказом: %+v %v", d, err)
	}
	last := e.mem.Audited()[len(e.mem.Audited())-1]
	if last.Action != "notify_channel.test" || last.Result != audit.ResultFailure {
		t.Fatalf("аудит теста: %+v", last)
	}
	bodies, _ := ws.received()
	var got payload
	if err := json.Unmarshal(bodies[0], &got); err != nil || got.Type != KindTest {
		t.Fatalf("тело теста: %s", bodies[0])
	}
	for range TestBurst - 2 {
		if _, err := e.svc.TestChannel(ctx, e.by, c.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.TestChannel(ctx, e.by, c.ID); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("предел: %v", err)
	}
	e.now = e.now.Add(TestWindow)
	if _, err := e.svc.TestChannel(ctx, e.by, c.ID); err != nil {
		t.Fatalf("после окна: %v", err)
	}
	list, err := e.svc.Deliveries(ctx, c.ID, 0)
	if err != nil || len(list) != TestBurst+1 {
		t.Fatalf("журнал: %d %v", len(list), err)
	}
}

// Очередь: 5 попыток с задержкой 30 с, 2, 8, 10 минут; после пятой —
// failed и notify.delivery_failed (DM-44); канал ниже порога и
// отключённый не получают; удачная доставка — sent.
func TestDispatchRetries(t *testing.T) {
	e := newEnv(t)
	ctx := testCtx(t)
	ws := newWebhookServer(t, e.tp, e.cert, e.key)
	c, _ := e.webhookChannel(t, ws, FormatGeneric)
	high, err := e.svc.CreateChannel(ctx, e.by, ChannelInput{Name: "Только критичные", Type: TypeWebhook, MinSeverity: "critical",
		Settings: Settings{CAPEM: e.caPEM}, Secrets: SecretsInput{URL: ptr(ws.srv.URL), SigningKey: ptr(testSigningKey)}})
	if err != nil {
		t.Fatal(err)
	}
	seq := 0
	newID := func() string {
		seq++
		return "01900000-0000-7000-8000-0000000d" + strconv.FormatInt(int64(1000+seq), 10)
	}
	if n := e.mem.Enqueue(sampleAlert(), newID); n != 1 {
		t.Fatalf("в очередь: %d", n)
	}
	ws.setStatus(http.StatusServiceUnavailable)
	waits := []time.Duration{0, 30 * time.Second, 2 * time.Minute, 8 * time.Minute, 10 * time.Minute}
	for i, w := range waits {
		e.now = e.now.Add(w - time.Second)
		if n, err := e.svc.DispatchOnce(ctx); err != nil || (n != 0 && w > 0) {
			t.Fatalf("попытка %d раньше срока: %d %v", i+1, n, err)
		}
		e.now = e.now.Add(time.Second)
		if n, err := e.svc.DispatchOnce(ctx); err != nil || n != 1 {
			t.Fatalf("попытка %d: %d %v", i+1, n, err)
		}
	}
	list, _ := e.svc.Deliveries(ctx, c.ID, 0) //nolint:gosec // G104: проверяется результат
	if len(list) != 1 || list[0].Status != StatusFailed || list[0].Attempts != MaxAttempts || list[0].Error != "http_503" {
		t.Fatalf("итог: %+v", list)
	}
	if l, _ := e.svc.Deliveries(ctx, high.ID, 0); len(l) != 0 { //nolint:gosec // G104: проверяется результат
		t.Fatalf("канал выше порога получил: %+v", l)
	}
	last := e.mem.Audited()[len(e.mem.Audited())-1]
	if last.Action != "notify.delivery_failed" || last.Object.ID != c.ID || last.Actor.Type != audit.ActorSystem {
		t.Fatalf("аудит отказа: %+v", last)
	}
	e.now = e.now.Add(time.Hour)
	if n, _ := e.svc.DispatchOnce(ctx); n != 0 { //nolint:gosec // G104: проверяется результат
		t.Fatalf("повтор после failed: %d", n)
	}

	ws.setStatus(http.StatusOK)
	crit := sampleAlert()
	crit.ID, crit.Severity = "01900000-0000-7000-8000-00000000aa02", "critical"
	if n := e.mem.Enqueue(crit, newID); n != 2 {
		t.Fatalf("критичное в очередь: %d", n)
	}
	if n, err := e.svc.DispatchOnce(ctx); err != nil || n != 2 {
		t.Fatalf("доставка: %d %v", n, err)
	}
	if l, _ := e.svc.Deliveries(ctx, high.ID, 1); l[0].Status != StatusSent || l[0].SentAt.IsZero() { //nolint:gosec // G104: проверяется результат
		t.Fatalf("доставка: %+v", l)
	}
	// Канал отключили после постановки в очередь: не отправляется.
	if n := e.mem.Enqueue(Message{Kind: KindAlert, ID: "01900000-0000-7000-8000-00000000aa03", Severity: "critical",
		Title: "x", CreatedAt: e.now}, newID); n != 2 {
		t.Fatalf("в очередь: %d", n)
	}
	cur, _ := e.svc.Channel(ctx, high.ID) //nolint:gosec // G104: ошибку покажет следующая проверка теста
	if _, err := e.svc.UpdateChannel(ctx, e.by, high.ID, ChannelInput{Name: cur.Name, Enabled: ptr(false), MinSeverity: cur.MinSeverity,
		Settings: cur.Settings, Version: cur.Version}); err != nil {
		t.Fatal(err)
	}
	before, _ := ws.received()
	if _, err := e.svc.DispatchOnce(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := ws.received()
	if l, _ := e.svc.Deliveries(ctx, high.ID, 1); l[0].Status != StatusFailed || l[0].Error != ErrCodeDisabled || len(after) != len(before)+1 { //nolint:gosec // G104: проверяется результат
		t.Fatalf("отключённый канал: %+v, запросов %d → %d", l, len(before), len(after))
	}
}

// FuzzDecodeChannelInput — разбор и проверка настроек канала: без паники;
// принятый канал не содержит управляющих символов в полях заголовков и
// записи syslog и укладывается в пределы.
func FuzzDecodeChannelInput(f *testing.F) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		f.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		f.Fatal(err)
	}
	ca, err := aisecCrypto.NewCA("fuzz CA", time.Hour, time.Now())
	if err != nil {
		f.Fatal(err)
	}
	caJSON, _ := json.Marshal(string(ca.CertPEM())) //nolint:gosec // G104: значение всегда сериализуется
	f.Add([]byte(`{"name":"Почта","type":"email","settings":{"host":"smtp.example.ru","from":"a@example.ru","to":["b@example.ru"],"ca_pem":` +
		string(caJSON) + `}}`))
	f.Add([]byte(`{"name":"Hook","type":"webhook","settings":{"format":"mattermost","ca_pem":` + string(caJSON) +
		`},"secrets":{"url":"https://h.example.ru/x","signing_key":"` + testSigningKey + `"}}`))
	f.Add([]byte(`{"name":"S","type":"syslog","settings":{"host":"10.0.0.1","port":6514,"format":"cef","facility":4,"hostname":"gw","ca_pem":` +
		string(caJSON) + `}}`))
	f.Add([]byte(`{"name":"S","type":"syslog","audit_stream":true,"settings":{"host":"10.0.0.1","format":"json","ca_pem":` +
		string(caJSON) + `}}`))
	f.Add([]byte(`{"name":"H","type":"webhook","audit_stream":true,"settings":{"format":"generic","ca_pem":` + string(caJSON) +
		`},"secrets":{"url":"https://h.example.ru/x","signing_key":"` + testSigningKey + `"}}`))
	f.Add([]byte(`{"name":"x","type":"email","unknown":1}`))
	f.Add([]byte(`{"settings":{"to":["a@b\r\nBcc: c@d"]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		in, err := DecodeInput(data)
		if err != nil {
			return
		}
		sec, err := normalize(&in, Secrets{}, tp)
		if err != nil {
			var ie *InputError
			if !errors.As(err, &ie) {
				t.Fatalf("ошибка не ввода: %v", err)
			}
			return
		}
		s := in.Settings
		for _, v := range append([]string{in.Name, s.Host, s.Username, s.From, s.Hostname, sec.Password, sec.URL}, s.To...) {
			if strings.ContainsAny(v, "\r\n\x00") {
				t.Fatalf("управляющий символ принят: %q", v)
			}
		}
		if in.AuditStream == nil || (*in.AuditStream && in.Type != TypeSyslog && (in.Type != TypeWebhook || s.Format != FormatGeneric)) {
			t.Fatalf("подписка на журнал: %+v", in)
		}
		if len(s.CAPEM) > MaxCAPEM || len(s.To) > MaxRecipients || SeverityRank(in.MinSeverity) == 0 {
			t.Fatalf("пределы: %+v", in)
		}
		if raw, err := json.Marshal(s); err != nil || len(raw) > 300000 {
			t.Fatalf("настройки не помещаются в столбец: %d %v", len(raw), err)
		}
		if in.Type == TypeSyslog {
			rec, err := syslogRecord(sampleAlert(), s, "1")
			if err != nil || strings.ContainsAny(string(rec), "\r\n") {
				t.Fatalf("запись syslog: %q %v", rec, err)
			}
		}
	})
}

// loopbackNets — сети приёмников тестов (3Н31 ревью 3.r2).
var loopbackNets = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

// 3Н33 ревью 3.r2: адреса из значений группировки не становятся ссылками
// в Mattermost и Rocket.Chat — в «://» и «www.» вставляется U+200B.
func TestMattermostNoAutolinks(t *testing.T) {
	m := sampleAlert()
	m.Group = map[string]string{"account": "https://evil.example/login www.evil.example"}
	raw, err := mattermostBody(m)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body["text"], "://") || strings.Contains(body["text"], "www.") {
		t.Fatalf("ссылка в тексте: %q", body["text"])
	}
	if !strings.Contains(body["text"], "https:​//evil.example/login") {
		t.Fatalf("адрес искажён: %q", body["text"])
	}
}

// 3Н34 ревью 3.r2: смена ключа подписи webhook и формата syslog —
// ослабление (повторная проверка, weakening); в аудите — отпечатки корневых
// сертификатов канала, а не только их длина.
func TestChannelUpdateWeakeningSigningAndFormat(t *testing.T) {
	e := newEnv(t)
	ctx := testCtx(t)
	noConfirm := e.by
	noConfirm.Confirm = nil
	wh, err := e.svc.CreateChannel(ctx, e.by, ChannelInput{Name: "Webhook", Type: TypeWebhook,
		Settings: Settings{Format: FormatGeneric, CAPEM: e.caPEM},
		Secrets:  SecretsInput{URL: ptr("https://soar.example/hook"), SigningKey: ptr(testSigningKey)}})
	if err != nil {
		t.Fatal(err)
	}
	sys, err := e.svc.CreateChannel(ctx, e.by, ChannelInput{Name: "SIEM", Type: TypeSyslog, AuditStream: ptr(true),
		Settings: Settings{Host: "siem.example", Port: 6514, Format: FormatJSON, CAPEM: e.caPEM}})
	if err != nil {
		t.Fatal(err)
	}
	mail, err := e.svc.CreateChannel(ctx, e.by, ChannelInput{Name: "Почта", Type: TypeEmail,
		Settings: Settings{Host: "smtp.example", Username: "aisec", From: "aisec@example.ru", To: []string{"soc@example.ru"}, CAPEM: e.caPEM},
		Secrets:  SecretsInput{Password: ptr("синтетический-пароль")}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		reason string
		c      Channel
		edit   func(*ChannelInput)
	}{
		{"signing_key_changed", wh, func(in *ChannelInput) { in.Secrets.SigningKey = ptr(strings.Repeat("n", 40)) }},
		{"format_changed", sys, func(in *ChannelInput) { in.Settings.Format = FormatCEF }},
		// Удаление пароля SMTP вместе с логином из консоли (3Н38 ревью
		// 3.r2) — тоже с повторной проверкой. Ключ подписи webhook
		// обязателен: он только заменяется.
		{"password_removed", mail, func(in *ChannelInput) { in.Settings.Username, in.Secrets.Password = "", ptr("") }},
	}
	for _, c := range cases {
		upd := func(by By) error {
			cur, err := e.svc.Channel(ctx, c.c.ID)
			if err != nil {
				t.Fatal(err)
			}
			in := ChannelInput{Name: cur.Name, Enabled: ptr(cur.Enabled), MinSeverity: cur.MinSeverity, Settings: cur.Settings,
				Version: cur.Version}
			c.edit(&in)
			_, err = e.svc.UpdateChannel(ctx, by, c.c.ID, in)
			return err
		}
		if err := upd(noConfirm); !errors.Is(err, ErrConfirmRequired) {
			t.Fatalf("%s без проверки: %v", c.reason, err)
		}
		if err := upd(e.by); err != nil {
			t.Fatalf("%s: %v", c.reason, err)
		}
		d := e.mem.Audited()[len(e.mem.Audited())-1].Details.(map[string]any)
		if d["weakening"] != true || !slices.Contains(d["weakening_reasons"].([]string), c.reason) {
			t.Fatalf("%s: аудит %+v", c.reason, d)
		}
		after := d["after"].(map[string]any)
		if fp, _ := after["ca_fingerprints"].([]string); len(fp) != 1 || len(fp[0]) != 64 {
			t.Fatalf("%s: отпечатки корней %v", c.reason, after["ca_fingerprints"])
		}
	}
	if cur, err := e.svc.Channel(ctx, mail.ID); err != nil || slices.Contains(cur.SecretFields, SecretPassword) {
		t.Fatalf("пароль не удалён: %+v %v", cur.SecretFields, err)
	}
}
