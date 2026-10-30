package shadowai

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// syslogTest — запущенный слушатель над хранилищем в памяти.
type syslogTest struct {
	m    *Memory
	svc  *Service
	l    *SyslogListener
	stop func()
}

func startSyslog(t *testing.T, cfg SyslogConfig) *syslogTest {
	t.Helper()
	m := NewMemory()
	svc := newTestService(t, m, true)
	if _, err := svc.UploadCatalog(context.Background(), testBy, readFile(t, testCatalogSigned)); err != nil {
		t.Fatal(err)
	}
	return startSyslogOn(t, m, svc, cfg)
}

func startSyslogOn(t *testing.T, m *Memory, svc *Service, cfg SyslogConfig) *syslogTest {
	t.Helper()
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	if cfg.Format == "" {
		cfg.Format = FormatSquid
	}
	if cfg.TLS == nil && !cfg.Insecure {
		cfg.Insecure, cfg.Allowed = true, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	}
	ctx, cancel := context.WithCancel(context.Background())
	l, err := svc.ListenSyslog(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	st := &syslogTest{m: m, svc: svc, l: l}
	var stopped bool
	st.stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}
	t.Cleanup(st.stop)
	return st
}

func dialFrom(t *testing.T, addr, local string) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: 2 * time.Second}
	if local != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(local)}
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() }) //nolint:gosec // закрытие тестового соединения, ошибка не важна
	return c
}

// waitFor ждёт условия до 5 секунд.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("не дождались: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// closedByServer — сервер закрыл соединение: чтение возвращает EOF или сброс.
func closedByServer(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:gosec // срок чтения в тесте, ошибка проявится при чтении
	if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("соединение не закрыто сервером: %v", err)
	}
}

// squidFrames — строки журнала Squid из testdata как сообщения syslog
// вперемешку: RFC 5424 с octet counting, RFC 3164 и без заголовка с
// переводом строки.
func squidFrames(t *testing.T) (string, int) {
	t.Helper()
	var b strings.Builder
	lines := strings.Split(strings.TrimSpace(string(readFile(t, "../../testdata/shadowai/access-squid.log"))), "\n")
	for i, line := range lines {
		switch i % 3 {
		case 0:
			msg := "<134>1 2026-10-27T10:00:00Z proxy squid 42 - - " + line
			fmt.Fprintf(&b, "%d %s", len(msg), msg)
		case 1:
			b.WriteString("<134>Oct 27 10:00:00 proxy squid[42]: " + line + "\n")
		default:
			b.WriteString(line + "\r\n")
		}
	}
	return b.String(), len(lines)
}

// Приём без TLS из разрешённой сети: те же сводки, что у импорта файлом;
// сводки пишутся при остановке; о новых сервисах — записи аудита от имени
// сервера без псевдонимов.
func TestSyslogReceivesSquid(t *testing.T) {
	st := startSyslog(t, SyslogConfig{})
	stream, n := squidFrames(t)
	c := dialFrom(t, st.l.Addr(), "")
	if _, err := io.WriteString(c, stream); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "строки", func() bool { return st.l.Stats().Lines == int64(n) })
	_ = c.Close() //nolint:gosec // закрытие тестового соединения, ошибка не важна
	st.stop()

	// Тот же журнал импортом файлом — в другом хранилище.
	m2 := NewMemory()
	s2 := newTestService(t, m2, true)
	if _, err := s2.UploadCatalog(context.Background(), testBy, readFile(t, testCatalogSigned)); err != nil {
		t.Fatal(err)
	}
	imp, err := s2.Import(context.Background(), testBy, FormatSquid, strings.NewReader(string(readFile(t, "../../testdata/shadowai/access-squid.log"))))
	if err != nil {
		t.Fatal(err)
	}
	stats := st.l.Stats()
	if stats.Matched != imp.Matched || stats.Errors != imp.Errors || stats.Unmatched != imp.Unmatched || stats.Pending != 0 ||
		stats.LastFlushAt == nil || stats.FlushFailures != 0 {
		t.Fatalf("счётчики syslog %+v, импорт %+v", stats, imp.ImportResult)
	}
	got, want := st.m.Aggregates(), m2.Aggregates()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("сводки syslog %v\nимпорт %v", got, want)
	}
	recs := 0
	for _, r := range st.m.Records() {
		if r.Action != "shadow_ai.new_service" {
			continue
		}
		recs++
		d, _ := r.Details.(map[string]any)
		if r.Actor.Type != audit.ActorSystem || d["source"] != SourceSyslog || strings.Contains(fmt.Sprint(d), "ivanov") {
			t.Fatalf("запись о новом сервисе: %+v", r)
		}
	}
	if recs != imp.Services {
		t.Fatalf("новых сервисов %d, ждали %d", recs, imp.Services)
	}
}

// Источник не из разрешённых сетей — разрыв до чтения и счётчик.
func TestSyslogRejectsNetwork(t *testing.T) {
	st := startSyslog(t, SyslogConfig{Insecure: true, Allowed: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	c := dialFrom(t, st.l.Addr(), "")
	closedByServer(t, c)
	if s := st.l.Stats(); s.RejectedNetwork != 1 || s.Accepted != 0 {
		t.Fatalf("%+v", s)
	}
}

// Пределы соединений всего и с одного адреса: сверх — разрыв и счётчик.
func TestSyslogConnectionLimits(t *testing.T) {
	st := startSyslog(t, SyslogConfig{MaxConns: 2, MaxConnsPerIP: 1})
	open := func(n int) func() bool { return func() bool { return st.l.Stats().Connections == n } }
	dialFrom(t, st.l.Addr(), "127.0.0.1")
	waitFor(t, "первое соединение", open(1))
	closedByServer(t, dialFrom(t, st.l.Addr(), "127.0.0.1"))
	dialFrom(t, st.l.Addr(), "127.0.0.2")
	waitFor(t, "второе соединение", open(2))
	closedByServer(t, dialFrom(t, st.l.Addr(), "127.0.0.3"))
	if s := st.l.Stats(); s.RejectedLimit != 2 || s.Accepted != 2 {
		t.Fatalf("%+v", s)
	}
}

// Кадр длиннее предела, простой и медленный кадр (slowloris) — разрыв и
// счётчик своей причины.
func TestSyslogFrameAndTimeouts(t *testing.T) {
	st := startSyslog(t, SyslogConfig{IdleTimeout: 150 * time.Millisecond, FrameTimeout: 150 * time.Millisecond})
	c := dialFrom(t, st.l.Addr(), "")
	if _, err := io.WriteString(c, "99999 x"); err != nil {
		t.Fatal(err)
	}
	closedByServer(t, c)
	closedByServer(t, dialFrom(t, st.l.Addr(), ""))
	slow := dialFrom(t, st.l.Addr(), "")
	if _, err := io.WriteString(slow, "<134>1 2026-10-27T10:00:00Z начало кадра без конца"); err != nil {
		t.Fatal(err)
	}
	closedByServer(t, slow)
	waitFor(t, "счётчики", func() bool {
		s := st.l.Stats()
		return s.FrameTooLarge == 1 && s.IdleTimeouts == 1 && s.ReadTimeouts == 1 && s.Connections == 0
	})
}

// Предел строк в секунду задерживает чтение, а не обрывает соединение.
func TestSyslogRateLimit(t *testing.T) {
	st := startSyslog(t, SyslogConfig{LinesPerSecond: 50})
	c := dialFrom(t, st.l.Addr(), "")
	line := "<134>1 2026-10-27T10:00:00Z proxy squid 42 - - 1793095200.120 210 10.0.12.34 TCP_TUNNEL/200 5120 CONNECT chatgpt.com:443 u HIER_DIRECT/203.0.113.10 -\n"
	start := time.Now()
	if _, err := io.WriteString(c, strings.Repeat(line, 80)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "строки", func() bool { return st.l.Stats().Lines == 80 })
	if s := st.l.Stats(); s.Throttled == 0 || s.Matched != 80 || time.Since(start) < 400*time.Millisecond {
		t.Fatalf("задержки нет: %+v за %s", s, time.Since(start))
	}
}

// Сбой записи сводок: они остаются в памяти и пишутся следующей записью.
func TestSyslogFlushRetry(t *testing.T) {
	st := startSyslog(t, SyslogConfig{})
	c := dialFrom(t, st.l.Addr(), "")
	stream, n := squidFrames(t)
	if _, err := io.WriteString(c, stream); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "строки", func() bool { return st.l.Stats().Lines == int64(n) })
	st.m.FailNext(errors.New("БД недоступна"))
	if err := st.l.flush(context.Background()); err == nil {
		t.Fatal("ожидалась ошибка записи")
	}
	if s := st.l.Stats(); !s.LastFlushFailed || s.FlushFailures != 1 || s.Pending == 0 || len(st.m.Aggregates()) != 0 {
		t.Fatalf("после сбоя: %+v", s)
	}
	if err := st.l.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := st.l.Stats(); s.LastFlushFailed || s.Pending != 0 || len(st.m.Aggregates()) == 0 {
		t.Fatalf("после повтора: %+v", s)
	}
}

// 4.23-1: при недоступной БД досрочные сигналы записи (каждая отброшенная
// строка) не дают шторма повторов — следующая попытка только после паузы.
func TestSyslogFlushBackoff(t *testing.T) {
	st := startSyslog(t, SyslogConfig{MaxKeys: 2, FlushInterval: time.Hour})
	st.m.FailAll(errors.New("БД недоступна"))
	c := dialFrom(t, st.l.Addr(), "")
	stream, _ := squidFrames(t)
	if _, err := io.WriteString(c, stream); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "первая неудачная запись", func() bool { return st.l.Stats().FlushFailures == 1 })
	for range 5 {
		if _, err := io.WriteString(c, stream); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "отброшенные строки", func() bool { return st.l.Stats().Dropped > 0 })
	time.Sleep(300 * time.Millisecond)
	if n := st.m.SyslogSaves(); n != 1 {
		t.Fatalf("попыток записи за паузу: %d, ждали 1", n)
	}
	if s := st.l.Stats(); !s.LastFlushFailed || s.FlushFailures != 1 {
		t.Fatalf("состояние: %+v", s)
	}
	st.m.FailAll(nil)
}

// flakyListener возвращает временную ошибку Accept заданное число раз.
type flakyListener struct {
	net.Listener
	fails int
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if f.fails > 0 {
		f.fails--
		return nil, errors.New("accept: too many open files")
	}
	return f.Listener.Accept()
}

// 4.23-2: временная ошибка Accept не останавливает приём; закрытый порт
// останавливает, и это видно в состоянии.
func TestSyslogAcceptErrors(t *testing.T) {
	m := NewMemory()
	svc := newTestService(t, m, true)
	if _, err := svc.UploadCatalog(context.Background(), testBy, readFile(t, testCatalogSigned)); err != nil {
		t.Fatal(err)
	}
	l, err := svc.ListenSyslog(context.Background(), SyslogConfig{Addr: "127.0.0.1:0", Format: FormatSquid, Insecure: true,
		Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	inner := l.ln
	l.ln = &flakyListener{Listener: inner, fails: 3}
	done := make(chan error, 1)
	go func() { done <- l.Run(context.Background()) }()
	c := dialFrom(t, l.Addr(), "")
	stream, n := squidFrames(t)
	if _, err := io.WriteString(c, stream); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "строки после ошибок Accept", func() bool { return l.Stats().Lines == int64(n) })
	if s := l.Stats(); s.AcceptErrors != 3 || !s.Running || s.StoppedAt != nil {
		t.Fatalf("после временных ошибок: %+v", s)
	}
	_ = inner.Close() //nolint:gosec // закрытие порта в тесте: проверяется остановка
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("остановка без ошибки")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run не завершился")
	}
	if s := svc.SyslogStats(); !s.Enabled || s.Running || s.StoppedAt == nil || s.LastError == "" {
		t.Fatalf("остановленный приём: %+v", s)
	}
}

// Без каталога строки не учитываются; после загрузки каталога слушатель
// подхватывает его сразу.
func TestSyslogWithoutCatalog(t *testing.T) {
	m := NewMemory()
	svc := newTestService(t, m, true)
	st := startSyslogOn(t, m, svc, SyslogConfig{})
	c := dialFrom(t, st.l.Addr(), "")
	stream, n := squidFrames(t)
	if _, err := io.WriteString(c, stream); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "строки без каталога", func() bool { return st.l.Stats().NoCatalog == int64(n) })
	if _, err := svc.UploadCatalog(context.Background(), testBy, readFile(t, testCatalogSigned)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c, stream); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "строки с каталогом", func() bool { return st.l.Stats().Matched > 0 })
}

// 4В18 ревью 4.r2: без модуля лицензии shadow_ai строки по syslog
// отбрасываются до разбора и сводки не пишутся; сбой проверки лицензии
// модуль не включает; с модулем приём снова учитывает строки.
func TestSyslogWithoutLicenseModule(t *testing.T) {
	var licensed atomic.Bool
	var failing atomic.Bool
	st := startSyslog(t, SyslogConfig{Licensed: func(context.Context) (bool, error) {
		if failing.Load() {
			return true, errors.New("лицензия недоступна")
		}
		return licensed.Load(), nil
	}})
	if s := st.l.Stats(); s.LicenseModule {
		t.Fatalf("модуль до проверки: %+v", s)
	}
	c := dialFrom(t, st.l.Addr(), "")
	stream, n := squidFrames(t)
	if _, err := io.WriteString(c, stream); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "строки без модуля", func() bool { return st.l.Stats().Unlicensed == int64(n) })
	if s := st.l.Stats(); s.Matched != 0 || s.Errors != 0 || s.Pending != 0 {
		t.Fatalf("строки без модуля учтены: %+v", s)
	}
	failing.Store(true)
	st.l.Refresh(context.Background())
	if st.l.Stats().LicenseModule {
		t.Fatal("сбой проверки лицензии включил модуль")
	}
	failing.Store(false)
	licensed.Store(true)
	st.l.Refresh(context.Background())
	if _, err := io.WriteString(c, stream); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "строки с модулем", func() bool { return st.l.Stats().Matched > 0 })
	_ = c.Close() //nolint:gosec // закрытие тестового соединения, ошибка не важна
	st.stop()
	if len(st.m.Aggregates()) == 0 || st.l.Stats().Unlicensed != int64(n) {
		t.Fatalf("сводки с модулем: %d, без модуля строк %d", len(st.m.Aggregates()), st.l.Stats().Unlicensed)
	}
}

// 4Н22: сбой проверки лицензии при запуске — модуль считается выключенным
// (как 503 у API), а не включённым.
func TestSyslogLicenseErrorAtStart(t *testing.T) {
	st := startSyslog(t, SyslogConfig{Licensed: func(context.Context) (bool, error) {
		return true, errors.New("лицензия недоступна")
	}})
	if s := st.l.Stats(); s.LicenseModule {
		t.Fatalf("сбой лицензии на старте включил модуль: %+v", s)
	}
}

// 4Н22 ревью 4.r3 (остаток): лицензия проверяется перед записью сводок —
// модуль выключили, пока они копились, — сброс без записи; сбой проверки —
// сводки остаются в памяти без записи, а сбой после успеха не оставляет
// прежнее «разрешено».
func TestSyslogLicenseCheckedBeforeSave(t *testing.T) {
	var licensed, failing atomic.Bool
	licensed.Store(true)
	st := startSyslog(t, SyslogConfig{Licensed: func(context.Context) (bool, error) {
		if failing.Load() {
			return true, errors.New("лицензия недоступна")
		}
		return licensed.Load(), nil
	}})
	ctx := context.Background()
	c := dialFrom(t, st.l.Addr(), "")
	defer func() { _ = c.Close() }() //nolint:gosec // закрытие тестового соединения, ошибка не важна
	stream, _ := squidFrames(t)
	send := func() {
		if _, err := io.WriteString(c, stream); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "сводки в памяти", func() bool { return st.l.Stats().Pending > 0 })
	}
	send()
	failing.Store(true)
	if err := st.l.flush(ctx); err == nil || len(st.m.Aggregates()) != 0 || st.l.Stats().Pending == 0 {
		t.Fatalf("сбой лицензии: %v, записано %d, в памяти %d", err, len(st.m.Aggregates()), st.l.Stats().Pending)
	}
	st.l.Refresh(ctx)
	if st.l.Stats().LicenseModule {
		t.Fatal("сбой проверки после успеха оставил модуль включённым")
	}
	failing.Store(false)
	licensed.Store(false)
	if err := st.l.flush(ctx); err != nil || len(st.m.Aggregates()) != 0 || st.l.Stats().Pending != 0 || st.l.Stats().Dropped == 0 {
		t.Fatalf("модуль выключен до записи: %v, записано %d, %+v", err, len(st.m.Aggregates()), st.l.Stats())
	}
}

// Исключённый пользователь не попадает в сводки приёма по syslog.
func TestSyslogExcludedUser(t *testing.T) {
	st := startSyslog(t, SyslogConfig{})
	by := testBy
	by.Confirm = func(context.Context) error { return nil }
	if _, err := st.svc.AddExclusion(context.Background(), by, ExclusionInput{Kind: ExcludeUser, Login: "ivanov.ia"}); err != nil {
		t.Fatal(err)
	}
	c := dialFrom(t, st.l.Addr(), "")
	stream, n := squidFrames(t)
	if _, err := io.WriteString(c, stream); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "строки", func() bool { return st.l.Stats().Lines == int64(n) })
	st.stop()
	alias := pseudonym(testMAC(t), "ivanov.ia")
	for _, a := range st.m.Aggregates() {
		if a.UserAlias == alias {
			t.Fatalf("исключённый пользователь в сводках: %+v", a)
		}
	}
	if s := st.l.Stats(); s.Excluded == 0 || len(st.m.Aggregates()) == 0 {
		t.Fatalf("%+v", s)
	}
}

// tlsPair — УЦ, сертификат слушателя и клиентский сертификат.
type tlsPair struct {
	tp                aisecCrypto.TLSProvider
	caPEM             []byte
	cert, key         []byte
	clientCert, clKey []byte
}

func newTLSPair(t *testing.T) tlsPair {
	t.Helper()
	tp, err := provider(t).TLS()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca, err := aisecCrypto.NewCA("syslog-test", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{"127.0.0.1"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	clKey, csr, err := aisecCrypto.NewClientCSR("proxy-01")
	if err != nil {
		t.Fatal(err)
	}
	clCert, _, err := ca.IssueClient(csr, "proxy-01", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	return tlsPair{tp: tp, caPEM: ca.CertPEM(), cert: cert, key: key, clientCert: clCert, clKey: clKey}
}

// TLS с обязательным клиентским сертификатом (RFC 5425): без сертификата —
// отказ рукопожатия и счётчик; с сертификатом УЦ — строки принимаются.
func TestSyslogTLSClientCert(t *testing.T) {
	p := newTLSPair(t)
	srvCfg, err := p.tp.MutualServerConfig(p.cert, p.key, p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	st := startSyslog(t, SyslogConfig{TLS: func(c net.Conn) net.Conn { return aisecCrypto.ServerTLS(c, srvCfg) }, ClientCert: true})
	if s := st.l.Stats(); !s.TLS || !s.ClientCert {
		t.Fatalf("%+v", s)
	}
	ctx := context.Background()

	noCert, err := p.tp.ClientConfig(p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	noCert.ServerName = "127.0.0.1"
	c, err := aisecCrypto.ClientTLS(ctx, dialFrom(t, st.l.Addr(), ""), noCert)
	if err == nil {
		// В TLS 1.3 отказ сервера приходит после рукопожатия клиента.
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:gosec // срок чтения в тесте, ошибка проявится при чтении
		_, err = bufio.NewReader(c).ReadByte()
	}
	if err == nil {
		t.Fatal("соединение без клиентского сертификата принято")
	}
	waitFor(t, "отказ TLS", func() bool { return st.l.Stats().TLSFailed == 1 })

	withCert, err := p.tp.ClientCertConfig(p.caPEM, p.clientCert, p.clKey)
	if err != nil {
		t.Fatal(err)
	}
	withCert.ServerName = "127.0.0.1"
	c, err = aisecCrypto.ClientTLS(ctx, dialFrom(t, st.l.Addr(), ""), withCert)
	if err != nil {
		t.Fatal(err)
	}
	stream, n := squidFrames(t)
	if _, err := io.WriteString(c, stream); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "строки по TLS", func() bool { return st.l.Stats().Lines == int64(n) })
	if s := st.l.Stats(); s.Matched == 0 {
		t.Fatalf("%+v", s)
	}
}

// Настройки слушателя проверяются до открытия порта.
func TestCheckSyslogConfig(t *testing.T) {
	tls := func(c net.Conn) net.Conn { return c }
	nets := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	bad := map[string]SyslogConfig{
		"формат csv":                    {Format: FormatCSV, TLS: tls},
		"без TLS без флага":             {Format: FormatCEF},
		"без TLS без сетей":             {Format: FormatCEF, Insecure: true},
		"TLS и без TLS":                 {Format: FormatCEF, TLS: tls, Insecure: true, Allowed: nets},
		"клиентский сертификат без TLS": {Format: FormatCEF, Insecure: true, Allowed: nets, ClientCert: true},
		"предел отрицательный":          {Format: FormatCEF, TLS: tls, MaxConns: -1},
	}
	for name, c := range bad {
		if err := CheckSyslogConfig(c); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	for name, c := range map[string]SyslogConfig{
		"TLS":     {Format: FormatSquid, TLS: tls},
		"без TLS": {Format: FormatCEF, Insecure: true, Allowed: nets},
	} {
		if err := CheckSyslogConfig(c); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// 4Н23: предел соединений на адрес у IPv6 считается по сети /64.
func TestSyslogLimitKey(t *testing.T) {
	a, b := netip.MustParseAddr("2001:db8:1:2::10"), netip.MustParseAddr("2001:db8:1:2:ffff::1")
	if limitKey(a) != limitKey(b) || limitKey(a) == limitKey(netip.MustParseAddr("2001:db8:1:3::10")) {
		t.Fatalf("IPv6: %v %v", limitKey(a), limitKey(b))
	}
	if v4 := netip.MustParseAddr("192.0.2.1"); limitKey(v4) != v4 {
		t.Fatalf("IPv4: %v", limitKey(v4))
	}
}
