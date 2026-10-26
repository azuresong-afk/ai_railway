package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
)

// Локальные приёмники для тестов каналов: SMTP со STARTTLS, HTTPS и
// syslog по TLS на 127.0.0.1. Внешних адресов тесты не используют.

func testProvider(t *testing.T) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// newPKI — УЦ и серверный сертификат на 127.0.0.1.
func newPKI(t *testing.T, p aisecCrypto.Provider) (string, aisecCrypto.TLSProvider, []byte, []byte) {
	t.Helper()
	now := time.Now()
	ca, err := aisecCrypto.NewCA("AISec test CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{"127.0.0.1", "localhost"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	return string(ca.CertPEM()), tp, cert, key
}

// smtpServer — минимальный SMTP-приёмник (RFC 5321) со STARTTLS (RFC 3207)
// и AUTH PLAIN после TLS.
type smtpServer struct {
	addr     string
	startTLS bool
	mu       sync.Mutex
	auth     []string // расшифрованные AUTH PLAIN
	from     []string
	rcpt     []string
	data     []string
	tlsUsed  bool
}

func newSMTPServer(t *testing.T, tp aisecCrypto.TLSProvider, cert, key []byte, startTLS bool) *smtpServer {
	t.Helper()
	cfg, err := tp.ServerConfig(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() }) //nolint:gosec // G104: закрытие тестового приёмника
	s := &smtpServer{addr: l.Addr().String(), startTLS: startTLS}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, func(c net.Conn) net.Conn { return aisecCrypto.ServerTLS(c, cfg) })
		}
	}()
	return s
}

func (s *smtpServer) serve(conn net.Conn, upgrade func(net.Conn) net.Conn) {
	defer func() { _ = conn.Close() }()                    //nolint:gosec // G104: закрытие тестового приёмника
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:gosec // G104: срок соединения тестового приёмника
	r := bufio.NewReader(conn)
	w := func(line string) { _, _ = io.WriteString(conn, line+"\r\n") } //nolint:gosec // G104: ответ тестового приёмника; обрыв увидит отправитель
	w("220 test ESMTP")
	secure := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch cmd {
		case "EHLO", "HELO":
			switch {
			case !secure && s.startTLS:
				w("250-test")
				w("250 STARTTLS")
			case secure:
				w("250-test")
				w("250 AUTH PLAIN")
			default:
				w("250 test")
			}
		case "STARTTLS":
			w("220 ready")
			conn = upgrade(conn)
			r = bufio.NewReader(conn)
			secure = true
			s.mu.Lock()
			s.tlsUsed = true
			s.mu.Unlock()
		case "AUTH":
			parts := strings.Fields(line)
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1]) //nolint:gosec // G104: неверный base64 даст пустой пароль и отказ AUTH
			s.mu.Lock()
			s.auth = append(s.auth, string(raw))
			s.mu.Unlock()
			if strings.HasSuffix(string(raw), "\x00wrong") {
				w("535 bad credentials")
				continue
			}
			w("235 ok")
		case "MAIL":
			s.mu.Lock()
			s.from = append(s.from, line)
			s.mu.Unlock()
			w("250 ok")
		case "RCPT":
			s.mu.Lock()
			s.rcpt = append(s.rcpt, line)
			s.mu.Unlock()
			w("250 ok")
		case "DATA":
			w("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.data = append(s.data, b.String())
			s.mu.Unlock()
			w("250 queued")
		case "QUIT":
			w("221 bye")
			return
		default:
			w("502 unknown")
		}
	}
}

// webhookServer — HTTPS-приёмник на 127.0.0.1.
type webhookServer struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
	sigs   []string
	status int
}

func newWebhookServer(t *testing.T, tp aisecCrypto.TLSProvider, cert, key []byte) *webhookServer {
	t.Helper()
	cfg, err := tp.ServerConfig(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ws := &webhookServer{status: http.StatusOK}
	ws.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20)) //nolint:gosec // G104: неполное тело проверит тест
		ws.mu.Lock()
		ws.bodies = append(ws.bodies, b)
		ws.sigs = append(ws.sigs, r.Header.Get(SignatureHeader))
		st := ws.status
		ws.mu.Unlock()
		if st == http.StatusFound {
			http.Redirect(w, r, "https://192.0.2.1/elsewhere", st)
			return
		}
		w.WriteHeader(st)
	}))
	ws.srv.TLS = cfg
	ws.srv.StartTLS()
	t.Cleanup(ws.srv.Close)
	return ws
}

func (ws *webhookServer) setStatus(code int) {
	ws.mu.Lock()
	ws.status = code
	ws.mu.Unlock()
}

func (ws *webhookServer) received() ([][]byte, []string) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return append([][]byte(nil), ws.bodies...), append([]string(nil), ws.sigs...)
}

// syslogServer — приёмник syslog по TLS с разбором octet counting.
type syslogServer struct {
	addr    string
	records chan string
}

func newSyslogServer(t *testing.T, tp aisecCrypto.TLSProvider, cert, key []byte) *syslogServer {
	t.Helper()
	cfg, err := tp.ServerConfig(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := aisecCrypto.TLSListener(l, cfg)
	t.Cleanup(func() { _ = tl.Close() }) //nolint:gosec // G104: закрытие тестового приёмника
	s := &syslogServer{addr: l.Addr().String(), records: make(chan string, 16)}
	go func() {
		for {
			conn, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()                    //nolint:gosec // G104: закрытие тестового приёмника
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:gosec // G104: срок соединения тестового приёмника
				r := bufio.NewReader(conn)
				for {
					n, err := r.ReadString(' ')
					if err != nil {
						return
					}
					size, err := strconv.Atoi(strings.TrimSuffix(n, " "))
					if err != nil || size <= 0 || size > 1<<20 {
						s.records <- "BAD FRAME " + n
						return
					}
					buf := make([]byte, size)
					if _, err := io.ReadFull(r, buf); err != nil {
						return
					}
					s.records <- string(buf)
				}
			}()
		}
	}()
	return s
}

func (s *syslogServer) next(t *testing.T) string {
	t.Helper()
	select {
	case r := <-s.records:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("syslog: запись не пришла")
		return ""
	}
}

// testBox — ключ данных в памяти.
func testBox(t *testing.T, p aisecCrypto.Provider) *keyring.Box {
	t.Helper()
	b, err := keyring.NewStaticKey(p, "01900000-0000-7000-8000-00000000d001", make([]byte, aisecCrypto.AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// 3Н31 ревью 3.r2: соединение с loopback, link-local (метаданные облака
// 169.254.169.254), адресами метаданных вне link-local, IPv4-mapped и
// NAT64-формами запрещённых адресов отклоняется с кодом config до
// соединения; явно разрешённая сеть проходит; частная сеть не запрещена.
func TestChannelAddressRestricted(t *testing.T) {
	p := testProvider(t)
	caPEM, tp, cert, key := newPKI(t, p)
	tr, err := NewTransport(p, "test", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	srv := newSyslogServer(t, tp, cert, key)
	h, port := hostPortStr(srv.addr)
	ch := func(host string, port int) Channel {
		return Channel{ID: "c", Type: TypeSyslog, Enabled: true, Settings: Settings{Host: host, Port: port, Format: FormatJSON, CAPEM: caPEM}}
	}
	for _, host := range []string{h, "localhost", "::1", "::ffff:127.0.0.1", "169.254.169.254", "fe80::1", "fd00:ec2::254",
		"100.100.100.200", "64:ff9b::a9fe:a9fe", "0.0.0.0", "224.0.0.1"} {
		if err := tr.Send(testCtx(t), ch(host, port), Secrets{}, sampleAlert()); ErrorCode(err) != ErrCodeConfig {
			t.Fatalf("%s: %v", host, err)
		}
	}
	for _, ip := range []string{"10.1.2.3", "172.16.0.10", "192.168.1.5", "fc00::5", "203.0.113.7"} {
		if blockedAddr(netip.MustParseAddr(ip)) {
			t.Fatalf("%s запрещён", ip)
		}
	}
	tr.AllowNetworks([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	if err := tr.Send(testCtx(t), ch(h, port), Secrets{}, sampleAlert()); err != nil {
		t.Fatalf("разрешённая сеть: %v", err)
	}
	srv.next(t)
	if err := tr.Send(testCtx(t), ch("169.254.169.254", 80), Secrets{}, sampleAlert()); ErrorCode(err) != ErrCodeConfig {
		t.Fatalf("метаданные при разрешённом loopback: %v", err)
	}
}

// 3Н31 ревью 3.r2: сертификат приёмника на чужое имя — tls, молчащий
// приёмник — timeout для всех трёх типов каналов; код тестовой отправки —
// обобщённый unreachable.
func TestReceiverNegatives(t *testing.T) {
	p := testProvider(t)
	_, tp, _, _ := newPKI(t, p)
	now := time.Now()
	ca, err := aisecCrypto.NewCA("AISec other CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{"siem.example"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewTransport(p, "test", 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	tr.AllowNetworks(loopbackNets)
	other := newSyslogServer(t, tp, cert, key)
	h, port := hostPortStr(other.addr)
	sys := Channel{ID: "c", Type: TypeSyslog, Enabled: true, Settings: Settings{Host: h, Port: port, Format: FormatJSON,
		CAPEM: string(ca.CertPEM())}}
	if err := tr.Send(testCtx(t), sys, Secrets{}, sampleAlert()); ErrorCode(err) != ErrCodeTLS {
		t.Fatalf("чужое имя: %v", err)
	}
	// Молчащий приёмник: принимает соединение и ничего не отвечает.
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() }) //nolint:gosec // G104: закрытие тестового приёмника
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() }) //nolint:gosec // G104: закрытие тестового соединения
		}
	}()
	sh, sp := hostPortStr(l.Addr().String())
	silent := []Channel{
		{ID: "e", Type: TypeEmail, Enabled: true, Settings: Settings{Host: sh, Port: sp, From: "aisec@example.org",
			To: []string{"soc@example.org"}, CAPEM: string(ca.CertPEM())}},
		{ID: "w", Type: TypeWebhook, Enabled: true, Settings: Settings{Format: FormatGeneric, CAPEM: string(ca.CertPEM())}},
		{ID: "s", Type: TypeSyslog, Enabled: true, Settings: Settings{Host: sh, Port: sp, Format: FormatJSON, CAPEM: string(ca.CertPEM())}},
	}
	sec := Secrets{URL: "https://" + l.Addr().String() + "/hook", SigningKey: testSigningKey}
	for _, c := range silent {
		if err := tr.Send(testCtx(t), c, sec, sampleAlert()); ErrorCode(err) != ErrCodeTimeout {
			t.Fatalf("%s: молчащий приёмник: %v", c.Type, err)
		}
	}
	for _, code := range []string{ErrCodeDial, ErrCodeTimeout, ErrCodeTLS, ErrCodeNoSTARTTLS, ErrCodeWrite} {
		if testCode(code) != ErrCodeUnreachable {
			t.Fatalf("код теста %s не обобщён", code)
		}
	}
	for _, code := range []string{ErrCodeConfig, ErrCodeAuth, "http_500"} {
		if testCode(code) != code {
			t.Fatalf("код теста %s изменён", code)
		}
	}
}
