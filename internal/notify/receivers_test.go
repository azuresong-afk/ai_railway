package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return h, n
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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
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
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	w := func(line string) { _, _ = io.WriteString(conn, line+"\r\n") }
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
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
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
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := aisecCrypto.TLSListener(l, cfg)
	t.Cleanup(func() { _ = tl.Close() })
	s := &syslogServer{addr: l.Addr().String(), records: make(chan string, 16)}
	go func() {
		for {
			conn, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
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
