package shadowai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Приём журналов прокси и NGFW по syslog (задача 4.23, ADR-0027, раздел 1
// и дополнение 1). Отдельный слушатель TCP сервера управления, выключен по
// умолчанию: TLS (RFC 5425) с сертификатом слушателя и, по выбору
// администратора, обязательным клиентским сертификатом; без TLS — только
// явным флагом и только из разрешённых сетей. Кадры — RFC 6587. Строки
// разбирают те же разборщики CEF и Squid с тем же пределом длины, что у
// импорта файлом; сводки копятся в памяти по часу и пишутся пакетно не
// реже раза в минуту и при остановке. Содержимое строк никуда, кроме
// разборщика, не попадает: в технических логах — причины и адреса
// источников, в «Состоянии системы» — счётчики.

// Пределы слушателя по умолчанию.
const (
	DefaultSyslogMaxConns       = 256
	DefaultSyslogMaxConnsPerIP  = 16
	DefaultSyslogLinesPerSecond = 5000
	// SyslogIdleTimeout — соединение без единого кадра закрывается.
	SyslogIdleTimeout = 5 * time.Minute
	// SyslogFrameTimeout — кадр должен прийти целиком (slowloris).
	SyslogFrameTimeout = 30 * time.Second
	// SyslogHandshakeTimeout — рукопожатие TLS.
	SyslogHandshakeTimeout = 10 * time.Second
	// SyslogFlushInterval — период записи сводок в БД.
	SyslogFlushInterval = time.Minute
	// SyslogMaxKeys — сводок в памяти между записями; сверх — строки
	// отбрасываются со счётчиком, запись начинается досрочно.
	SyslogMaxKeys = 100_000
	// syslogStopFlush — срок последней записи при остановке.
	syslogStopFlush = 15 * time.Second
	// syslogFlushTimeout — срок одной записи.
	syslogFlushTimeout = 30 * time.Second
	// syslogRetryMin — первая пауза после неудачной записи сводок; дальше
	// пауза удваивается до периода записи (4.23-1).
	syslogRetryMin = 5 * time.Second
	// syslogAcceptRetryMax — наибольшая пауза между повторами Accept после
	// временной ошибки (исчерпаны дескрипторы и т. п., 4.23-2).
	syslogAcceptRetryMax = time.Second
	// syslogLogEvery — не чаще одной строки технического журнала об отказе
	// на причину за этот период (поток отказов не забивает журнал).
	syslogLogEvery = time.Minute
)

// SyslogConfig — настройки слушателя.
type SyslogConfig struct {
	Addr string
	// Format — формат тела: cef или squid.
	Format string
	// TLS — обёртка соединения в TLS из internal/crypto (crypto.ServerTLS с
	// настройками слушателя); nil — без TLS (только при Insecure).
	TLS func(net.Conn) net.Conn
	// ClientCert — настройки TLS требуют клиентский сертификат (для показа).
	ClientCert bool
	// Insecure — приём без TLS разрешён явно.
	Insecure bool
	// Allowed — сети источников; пусто — любые (только с TLS).
	Allowed        []netip.Prefix
	MaxConns       int
	MaxConnsPerIP  int
	LinesPerSecond int
	// Сроки; нули — умолчания (меняются в тестах).
	IdleTimeout      time.Duration
	FrameTimeout     time.Duration
	HandshakeTimeout time.Duration
	FlushInterval    time.Duration
	MaxKeys          int
	// Licensed — модуль лицензии shadow_ai включён (4В18 ревью 4.r2):
	// false — строки не разбираются и не пишутся; ошибка — проверить не
	// удалось, действует прежний ответ. nil — без проверки.
	Licensed func(ctx context.Context) (bool, error)
}

// CheckSyslogConfig проверяет настройки до открытия порта.
func CheckSyslogConfig(c SyslogConfig) error {
	var errs []error
	if c.Format != FormatCEF && c.Format != FormatSquid {
		errs = append(errs, errors.New("формат приёма по syslog — cef или squid"))
	}
	if c.TLS == nil && !c.Insecure {
		errs = append(errs, errors.New("приём по syslog без TLS — только явным флагом"))
	}
	if c.TLS != nil && c.Insecure {
		errs = append(errs, errors.New("приём по syslog: TLS и приём без TLS одновременно не задаются"))
	}
	if c.Insecure && len(c.Allowed) == 0 {
		errs = append(errs, errors.New("приём по syslog без TLS — только из разрешённых сетей"))
	}
	if c.ClientCert && c.TLS == nil {
		errs = append(errs, errors.New("клиентский сертификат проверяется только при TLS"))
	}
	for _, v := range []struct {
		name string
		n    int
	}{{"соединений всего", c.MaxConns}, {"соединений с одного адреса", c.MaxConnsPerIP}, {"строк в секунду", c.LinesPerSecond}} {
		if v.n < 0 || v.n > 1_000_000 {
			errs = append(errs, fmt.Errorf("приём по syslog: предел %s — от 1 до 1000000", v.name))
		}
	}
	return errors.Join(errs...)
}

func (c SyslogConfig) withDefaults() SyslogConfig {
	if c.MaxConns <= 0 {
		c.MaxConns = DefaultSyslogMaxConns
	}
	if c.MaxConnsPerIP <= 0 {
		c.MaxConnsPerIP = DefaultSyslogMaxConnsPerIP
	}
	c.MaxConnsPerIP = min(c.MaxConnsPerIP, c.MaxConns)
	if c.LinesPerSecond <= 0 {
		c.LinesPerSecond = DefaultSyslogLinesPerSecond
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = SyslogIdleTimeout
	}
	if c.FrameTimeout <= 0 {
		c.FrameTimeout = SyslogFrameTimeout
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = SyslogHandshakeTimeout
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = SyslogFlushInterval
	}
	if c.MaxKeys <= 0 {
		c.MaxKeys = SyslogMaxKeys
	}
	return c
}

// SyslogStats — состояние слушателя для экрана и «Состояния системы».
// Счётчики — с запуска сервера.
type SyslogStats struct {
	Enabled bool `json:"enabled"`
	// Running — слушатель принимает соединения; false при Enabled — приём
	// остановлен ошибкой (StoppedAt, LastError).
	Running         bool       `json:"running"`
	StoppedAt       *time.Time `json:"stopped_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	Address         string     `json:"address,omitempty"`
	Format          string     `json:"format,omitempty"`
	TLS             bool       `json:"tls"`
	ClientCert      bool       `json:"client_cert_required"`
	AllowedNetworks []string   `json:"allowed_networks"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	// Connections — открытых соединений сейчас.
	Connections int         `json:"connections"`
	Limits      SyslogLimit `json:"limits"`
	// Accepted — принято соединений; отказы — по причинам.
	Accepted        int64 `json:"accepted"`
	RejectedNetwork int64 `json:"rejected_network"`
	RejectedLimit   int64 `json:"rejected_limit"`
	TLSFailed       int64 `json:"tls_failed"`
	// AcceptErrors — временных ошибок приёма соединений (повторяются с
	// паузой).
	AcceptErrors int64 `json:"accept_errors"`
	// Разрывы: кадр длиннее предела, обрыв внутри кадра, простой, медленный
	// кадр.
	FrameTooLarge int64 `json:"frame_too_large"`
	BadFrame      int64 `json:"bad_frame"`
	IdleTimeouts  int64 `json:"idle_timeouts"`
	ReadTimeouts  int64 `json:"read_timeouts"`
	// Строки: всего, сопоставлено с каталогом, не сопоставлено, не
	// разобрано, исключено, старше срока хранения, без каталога, отброшено
	// сверх предела сводок в памяти.
	Lines     int64 `json:"lines"`
	Matched   int64 `json:"matched"`
	Unmatched int64 `json:"unmatched"`
	Errors    int64 `json:"errors"`
	Excluded  int64 `json:"excluded"`
	Outdated  int64 `json:"outdated"`
	NoCatalog int64 `json:"no_catalog"`
	Dropped   int64 `json:"dropped"`
	// Throttled — кадров, чтение которых задержано пределом строк в секунду.
	Throttled int64 `json:"throttled"`
	// Unlicensed — строк, отброшенных до разбора: модуль shadow_ai не входит
	// в лицензию.
	Unlicensed int64 `json:"unlicensed"`
	// LicenseModule — модуль shadow_ai входит в лицензию (или лицензии нет).
	LicenseModule bool `json:"license_module"`
	// Pending — сводок в памяти до следующей записи.
	Pending       int        `json:"pending"`
	LastFlushAt   *time.Time `json:"last_flush_at,omitempty"`
	FlushFailures int64      `json:"flush_failures"`
	// LastFlushFailed — последняя запись не удалась: сводки ждут следующей.
	LastFlushFailed bool `json:"last_flush_failed"`
}

// SyslogLimit — пределы слушателя.
type SyslogLimit struct {
	MaxConns            int `json:"max_connections"`
	MaxConnsPerIP       int `json:"max_connections_per_address"`
	MaxFrame            int `json:"max_frame_bytes"`
	LinesPerSecond      int `json:"lines_per_second"`
	IdleTimeoutSeconds  int `json:"idle_timeout_seconds"`
	FrameTimeoutSeconds int `json:"frame_timeout_seconds"`
}

type syslogCounters struct {
	accepted, rejectedNetwork, rejectedLimit, tlsFailed atomic.Int64
	frameTooLarge, badFrame, idleTimeouts, readTimeouts atomic.Int64
	lines, matched, unmatched, errs, excluded, outdated atomic.Int64
	noCatalog, dropped, throttled, flushFailures        atomic.Int64
	acceptErrors, unlicensed                            atomic.Int64
}

// syslogEnv — каталог, срок хранения, часовой пояс и исключения; обновляется
// при каждой записи сводок.
type syslogEnv struct {
	catalog *Catalog
	cutoff  time.Time
	loc     *time.Location
	exclude Exclusions
}

// SyslogListener — слушатель приёма по syslog.
type SyslogListener struct {
	svc      *Service
	cfg      SyslogConfig
	ln       net.Listener
	logger   *slog.Logger
	started  time.Time
	c        syslogCounters
	limiter  *rateLimiter
	env      atomic.Pointer[syslogEnv]
	flushNow chan struct{}

	mu     sync.Mutex
	conns  map[net.Conn]netip.Addr
	perIP  map[netip.Addr]int
	acc    *accumulator
	closed bool
	// lastLog — когда последний раз писалась строка журнала о причине отказа.
	lastLog map[string]time.Time

	flushMu sync.Mutex
	// lastFlush — время последней успешной записи, Unix нс; 0 — не было.
	lastFlush   atomic.Int64
	flushFailed atomic.Bool

	// unlicensed — модуль shadow_ai не входит в лицензию: строки не
	// разбираются, сводки не пишутся.
	unlicensed atomic.Bool

	// running — идёт приём; stopped и lastErr — когда и почему остановлен.
	running atomic.Bool
	stopped atomic.Int64
	lastErr atomic.Pointer[string]
}

// ListenSyslog проверяет настройки и открывает порт слушателя. Приём
// начинается в Run.
func (s *Service) ListenSyslog(ctx context.Context, cfg SyslogConfig) (*SyslogListener, error) {
	if err := CheckSyslogConfig(cfg); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("приём по syslog: %w", err)
	}
	l := &SyslogListener{svc: s, cfg: cfg, ln: ln, logger: s.o.Logger.With("listener", "shadow_ai_syslog"),
		started: s.o.Clock().UTC(), limiter: newRateLimiter(cfg.LinesPerSecond, time.Now),
		flushNow: make(chan struct{}, 1), conns: map[net.Conn]netip.Addr{}, perIP: map[netip.Addr]int{},
		lastLog: map[string]time.Time{}}
	if err := l.refresh(ctx); err != nil {
		l.logger.Warn("теневой ИИ: настройки приёма по syslog не прочитаны, строки до следующей записи — без каталога",
			"class", "shadow_ai", "error", err)
	}
	l.resetAcc()
	s.mu.Lock()
	s.syslog = l
	s.mu.Unlock()
	return l, nil
}

// Addr — адрес слушателя.
func (l *SyslogListener) Addr() string { return l.ln.Addr().String() }

// refresh перечитывает модуль лицензии, каталог, срок хранения, пояс и
// исключения. Модуль — первым: сбой чтения остального его не задерживает,
// а сбой проверки лицензии оставляет прежний ответ.
func (l *SyslogListener) refresh(ctx context.Context) error {
	var lerr error
	if l.cfg.Licensed != nil {
		ok, err := l.cfg.Licensed(ctx)
		if err == nil {
			l.unlicensed.Store(!ok)
		}
		lerr = err
	}
	sc, _, err := l.svc.current(ctx)
	if err != nil {
		return err
	}
	loc, err := l.svc.o.Location(ctx)
	if err != nil {
		return err
	}
	days, err := l.svc.o.Store.RetentionDays(ctx, l.svc.o.OrgID)
	if err != nil {
		return err
	}
	ex, err := l.svc.exclusions(ctx)
	if err != nil {
		return err
	}
	env := &syslogEnv{loc: loc, exclude: ex,
		cutoff: l.svc.o.Clock().UTC().Truncate(time.Hour).AddDate(0, 0, -days)}
	if sc != nil {
		env.catalog = sc.Catalog
	}
	l.env.Store(env)
	// Накопленное остаётся: сводки ключуются ID сервиса, смена каталога,
	// срока или исключений их не портит (исключённые отсеет запись в БД).
	l.mu.Lock()
	if l.acc != nil {
		l.acc.catalog, l.acc.cutoff, l.acc.exclude = env.catalog, env.cutoff, env.exclude
	}
	l.mu.Unlock()
	return lerr
}

// Refresh перечитывает каталог и исключения сразу (после их изменения).
func (l *SyslogListener) Refresh(ctx context.Context) {
	if err := l.refresh(ctx); err != nil {
		l.logger.Warn("теневой ИИ: настройки приёма по syslog не обновлены", "class", "shadow_ai", "error", err)
	}
}

func (l *SyslogListener) resetAcc() {
	env := l.env.Load()
	var cat *Catalog
	ex := Exclusions{}
	cutoff := time.Time{}
	if env != nil {
		cat, ex, cutoff = env.catalog, env.exclude, env.cutoff
	}
	l.acc = newAccumulator(cat, l.svc.o.UserMAC, cutoff, ex, l.cfg.MaxKeys)
}

// Run принимает соединения и пишет сводки до отмены ctx; при остановке
// закрывает порт и соединения и пишет накопленное.
func (l *SyslogListener) Run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var wg sync.WaitGroup
	flushDone := make(chan struct{})
	go func() {
		defer close(flushDone)
		l.flushLoop(ctx)
	}()
	stop := context.AfterFunc(ctx, func() { _ = l.ln.Close() }) //nolint:gosec // G104: закрытие порта при остановке
	defer stop()
	l.logger.Info("теневой ИИ: приём по syslog запущен", "address", l.Addr(), "format", l.cfg.Format,
		"tls", l.cfg.TLS != nil, "client_cert", l.cfg.ClientCert)
	var err error
	var pause time.Duration
	l.running.Store(true)
	for {
		conn, aerr := l.ln.Accept()
		if aerr != nil {
			if ctx.Err() != nil {
				break
			}
			if errors.Is(aerr, net.ErrClosed) {
				err = fmt.Errorf("приём по syslog: %w", aerr)
				break
			}
			// Временная ошибка (исчерпаны дескрипторы, соединение сброшено
			// до приёма): повтор с паузой, как в net/http, — иначе
			// исчерпание дескрипторов незаметно выключило бы приём (4.23-2).
			l.c.acceptErrors.Add(1)
			l.note("accept_error", netip.Addr{})
			pause = min(max(2*pause, 5*time.Millisecond), syslogAcceptRetryMax)
			select {
			case <-ctx.Done():
			case <-time.After(pause):
			}
			continue
		}
		pause = 0
		if !l.admit(conn) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.serve(ctx, conn)
		}()
	}
	l.running.Store(false)
	l.stopped.Store(l.svc.o.Clock().UnixNano())
	if err != nil {
		msg := err.Error()
		l.lastErr.Store(&msg)
	}
	cancel()
	l.mu.Lock()
	l.closed = true
	for c := range l.conns {
		_ = c.Close() //nolint:gosec // G104: закрытие соединений при остановке
	}
	l.mu.Unlock()
	wg.Wait()
	<-flushDone
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), syslogStopFlush)
	defer cancel()
	if ferr := l.flush(fctx); ferr != nil {
		l.logger.Error("теневой ИИ: сводки приёма по syslog при остановке не записаны", "class", "db", "error", ferr)
	}
	return err
}

// addrOf — адрес источника без порта.
func addrOf(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		ip, _ := netip.AddrFromSlice(ta.IP)
		return ip.Unmap()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// admit проверяет сеть источника и пределы соединений.
func (l *SyslogListener) admit(conn net.Conn) bool {
	ip := addrOf(conn.RemoteAddr())
	if len(l.cfg.Allowed) > 0 && !allowed(l.cfg.Allowed, ip) {
		l.c.rejectedNetwork.Add(1)
		l.note("not_allowed", ip)
		_ = conn.Close() //nolint:gosec // G104: отказ источнику не из разрешённых сетей
		return false
	}
	l.mu.Lock()
	ok := !l.closed && len(l.conns) < l.cfg.MaxConns && l.perIP[ip] < l.cfg.MaxConnsPerIP
	if ok {
		l.conns[conn] = ip
		l.perIP[ip]++
	}
	l.mu.Unlock()
	if !ok {
		l.c.rejectedLimit.Add(1)
		l.note("connection_limit", ip)
		_ = conn.Close() //nolint:gosec // G104: отказ сверх предела соединений
		return false
	}
	l.c.accepted.Add(1)
	return true
}

func allowed(nets []netip.Prefix, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	for _, p := range nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (l *SyslogListener) release(conn net.Conn) {
	l.mu.Lock()
	if ip, ok := l.conns[conn]; ok {
		delete(l.conns, conn)
		if l.perIP[ip]--; l.perIP[ip] <= 0 {
			delete(l.perIP, ip)
		}
	}
	l.mu.Unlock()
	_ = conn.Close() //nolint:gosec // G104: соединение уже обработано
}

// note пишет причину отказа или разрыва в технический журнал не чаще раза
// в syslogLogEvery на причину — без содержимого строк.
func (l *SyslogListener) note(reason string, ip netip.Addr) {
	now := time.Now()
	l.mu.Lock()
	last := l.lastLog[reason]
	write := now.Sub(last) >= syslogLogEvery
	if write {
		l.lastLog[reason] = now
	}
	l.mu.Unlock()
	if write {
		l.logger.Warn("теневой ИИ: приём по syslog — отказ или разрыв соединения", "class", "shadow_ai", "reason", reason,
			"source", ip.String())
	}
}

// connHooks — сроки чтения соединения для frameReader.
type connHooks struct {
	conn         net.Conn
	idleTimeout  time.Duration
	frameTimeout time.Duration
	waiting      bool
}

func (h *connHooks) idle() {
	h.waiting = true
	_ = h.conn.SetReadDeadline(time.Now().Add(h.idleTimeout)) //nolint:gosec // G104: ошибка проявится при чтении
}

func (h *connHooks) busy() {
	h.waiting = false
	_ = h.conn.SetReadDeadline(time.Now().Add(h.frameTimeout)) //nolint:gosec // G104: ошибка проявится при чтении
}

// handshaker — соединение TLS из internal/crypto (без импорта crypto/tls).
type handshaker interface {
	HandshakeContext(ctx context.Context) error
}

// serve читает кадры одного соединения.
func (l *SyslogListener) serve(ctx context.Context, raw net.Conn) {
	conn := raw
	defer l.release(raw)
	ip := addrOf(raw.RemoteAddr())
	if l.cfg.TLS != nil {
		conn = l.cfg.TLS(raw)
		hs, ok := conn.(handshaker)
		if !ok {
			l.c.tlsFailed.Add(1)
			return
		}
		hctx, cancel := context.WithTimeout(ctx, l.cfg.HandshakeTimeout)
		err := hs.HandshakeContext(hctx)
		cancel()
		if err != nil {
			l.c.tlsFailed.Add(1)
			l.note("tls_failed", ip)
			return
		}
	}
	hooks := &connHooks{conn: raw, idleTimeout: l.cfg.IdleTimeout, frameTimeout: l.cfg.FrameTimeout}
	fr := newFrameReader(conn, DefaultMaxLine, hooks)
	for {
		frame, err := fr.next()
		if err != nil {
			l.closedBy(err, hooks.waiting, ip)
			return
		}
		waited, err := l.limiter.wait(ctx)
		if err != nil {
			return
		}
		if waited {
			l.c.throttled.Add(1)
		}
		l.line(frame, ip)
	}
}

// closedBy учитывает причину разрыва.
func (l *SyslogListener) closedBy(err error, waiting bool, ip netip.Addr) {
	var ne net.Error
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
	case errors.Is(err, ErrFrameTooLarge):
		l.c.frameTooLarge.Add(1)
		l.note("frame_too_large", ip)
	case errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		if waiting {
			l.c.idleTimeouts.Add(1)
			l.note("idle_timeout", ip)
		} else {
			l.c.readTimeouts.Add(1)
			l.note("read_timeout", ip)
		}
	case errors.Is(err, io.ErrUnexpectedEOF):
		l.c.badFrame.Add(1)
		l.note("bad_frame", ip)
	}
}

// line разбирает кадр и учитывает строку в сводках. Без модуля лицензии
// shadow_ai строка отбрасывается до разбора (4В18 ревью 4.r2), как импорт
// файлом отвечает 403 license_module.
func (l *SyslogListener) line(frame []byte, ip netip.Addr) {
	l.c.lines.Add(1)
	if l.unlicensed.Load() {
		l.c.unlicensed.Add(1)
		l.note("license_module", ip)
		return
	}
	env := l.env.Load()
	if env == nil || env.catalog == nil {
		l.c.noCatalog.Add(1)
		return
	}
	body := frame
	if l.cfg.Format == FormatSquid {
		body = syslogBody(frame)
	}
	p, err := newParser(l.cfg.Format, timeBounds{loc: env.loc, max: l.svc.o.Clock().Add(24 * time.Hour)})
	if err != nil {
		l.c.errs.Add(1)
		return
	}
	rec, skip, err := p.parse(body)
	if err != nil || skip {
		l.c.errs.Add(1)
		return
	}
	l.mu.Lock()
	if l.acc.catalog == nil {
		l.mu.Unlock()
		l.c.noCatalog.Add(1)
		return
	}
	o, err := l.acc.add(rec)
	l.mu.Unlock()
	if err != nil {
		l.c.dropped.Add(1)
		select {
		case l.flushNow <- struct{}{}:
		default:
		}
		return
	}
	switch o {
	case outcomeMatched:
		l.c.matched.Add(1)
	case outcomeUnmatched:
		l.c.unmatched.Add(1)
	case outcomeOutdated:
		l.c.outdated.Add(1)
	case outcomeExcluded:
		l.c.excluded.Add(1)
	}
}

// flushLoop пишет сводки раз в период и досрочно по flushNow. После
// неудачной записи — пауза от syslogRetryMin с удвоением до периода: досрочные
// сигналы на это время не действуют, иначе недоступная БД получала бы запись
// на каждую отброшенную строку (4.23-1). Ошибка записи — в журнал не чаще раза
// в syslogLogEvery.
func (l *SyslogListener) flushLoop(ctx context.Context) {
	t := time.NewTicker(l.cfg.FlushInterval)
	defer t.Stop()
	var (
		retry   <-chan time.Time
		retryAt time.Time
		backoff time.Duration
		logged  time.Time
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-l.flushNow:
		case <-retry:
			retry = nil
		}
		if time.Now().Before(retryAt) {
			continue
		}
		fctx, cancel := context.WithTimeout(ctx, syslogFlushTimeout)
		err := l.flush(fctx)
		cancel()
		if err == nil || ctx.Err() != nil {
			backoff, retryAt, retry = 0, time.Time{}, nil
			continue
		}
		backoff = min(max(2*backoff, min(syslogRetryMin, l.cfg.FlushInterval)), l.cfg.FlushInterval)
		retryAt = time.Now().Add(backoff)
		retry = time.After(backoff)
		if now := time.Now(); now.Sub(logged) >= syslogLogEvery {
			logged = now
			l.logger.Error("теневой ИИ: сводки приёма по syslog не записаны, повтор после паузы", "class", "db",
				"retry_in", backoff.String(), "error", err)
		}
	}
}

// flush пишет накопленные сводки. При ошибке они возвращаются в память и
// ждут следующей записи (сверх предела сводок — отбрасываются со счётчиком).
func (l *SyslogListener) flush(ctx context.Context) error {
	l.flushMu.Lock()
	defer l.flushMu.Unlock()
	l.mu.Lock()
	acc := l.acc
	l.resetAcc()
	l.mu.Unlock()
	var err error
	switch {
	// Модуль выключили, пока копились сводки: они не пишутся (счётчик
	// dropped — по числу запросов в них).
	case l.unlicensed.Load():
		for _, a := range acc.aggs {
			l.c.dropped.Add(a.Requests)
		}
	case len(acc.aggs) > 0:
		err = l.svc.o.Store.SaveSyslog(ctx, l.svc.o.OrgID, SyslogBatch{Aggregates: acc.sorted(), ServiceNames: acc.names()})
	}
	if err != nil {
		l.c.flushFailures.Add(1)
		l.flushFailed.Store(true)
		l.mu.Lock()
		l.mergeBack(acc)
		l.mu.Unlock()
		return err
	}
	l.flushFailed.Store(false)
	l.lastFlush.Store(l.svc.o.Clock().UnixNano())
	// Каталог, срок хранения и исключения могли измениться в другом месте.
	l.Refresh(ctx)
	return nil
}

// mergeBack возвращает незаписанные сводки в текущий накопитель.
func (l *SyslogListener) mergeBack(old *accumulator) {
	for k, a := range old.aggs {
		cur := l.acc.aggs[k]
		if cur == nil {
			if len(l.acc.aggs) >= l.cfg.MaxKeys {
				l.c.dropped.Add(a.Requests)
				continue
			}
			cp := *a
			l.acc.aggs[k] = &cp
			l.acc.services[k.service] = struct{}{}
			continue
		}
		cur.Requests = min(cur.Requests+a.Requests, maxCounter)
		cur.Bytes = min(cur.Bytes+a.Bytes, maxCounter)
	}
}

// Stats — состояние слушателя.
func (l *SyslogListener) Stats() SyslogStats {
	started := l.started
	st := SyslogStats{Enabled: true, Address: l.Addr(), Format: l.cfg.Format, TLS: l.cfg.TLS != nil, ClientCert: l.cfg.ClientCert,
		AllowedNetworks: make([]string, 0, len(l.cfg.Allowed)), StartedAt: &started,
		Limits: SyslogLimit{MaxConns: l.cfg.MaxConns, MaxConnsPerIP: l.cfg.MaxConnsPerIP, MaxFrame: DefaultMaxLine,
			LinesPerSecond: l.cfg.LinesPerSecond, IdleTimeoutSeconds: int(l.cfg.IdleTimeout / time.Second),
			FrameTimeoutSeconds: int(l.cfg.FrameTimeout / time.Second)},
		Accepted: l.c.accepted.Load(), RejectedNetwork: l.c.rejectedNetwork.Load(), RejectedLimit: l.c.rejectedLimit.Load(),
		TLSFailed: l.c.tlsFailed.Load(), FrameTooLarge: l.c.frameTooLarge.Load(), BadFrame: l.c.badFrame.Load(),
		IdleTimeouts: l.c.idleTimeouts.Load(), ReadTimeouts: l.c.readTimeouts.Load(), Lines: l.c.lines.Load(),
		Matched: l.c.matched.Load(), Unmatched: l.c.unmatched.Load(), Errors: l.c.errs.Load(), Excluded: l.c.excluded.Load(),
		Outdated: l.c.outdated.Load(), NoCatalog: l.c.noCatalog.Load(), Dropped: l.c.dropped.Load(),
		Throttled: l.c.throttled.Load(), FlushFailures: l.c.flushFailures.Load(), LastFlushFailed: l.flushFailed.Load(),
		Running: l.running.Load(), AcceptErrors: l.c.acceptErrors.Load(), Unlicensed: l.c.unlicensed.Load(),
		LicenseModule: !l.unlicensed.Load()}
	if ns := l.stopped.Load(); ns != 0 {
		t := time.Unix(0, ns).UTC()
		st.StoppedAt = &t
	}
	if e := l.lastErr.Load(); e != nil {
		st.LastError = *e
	}
	for _, p := range l.cfg.Allowed {
		st.AllowedNetworks = append(st.AllowedNetworks, p.String())
	}
	l.mu.Lock()
	st.Connections, st.Pending = len(l.conns), len(l.acc.aggs)
	l.mu.Unlock()
	if ns := l.lastFlush.Load(); ns != 0 {
		t := time.Unix(0, ns).UTC()
		st.LastFlushAt = &t
	}
	return st
}

// SyslogStats — состояние приёма по syslog; Enabled = false — выключен.
func (s *Service) SyslogStats() SyslogStats {
	s.mu.Lock()
	l := s.syslog
	s.mu.Unlock()
	if l == nil {
		return SyslogStats{AllowedNetworks: []string{}}
	}
	return l.Stats()
}

// rateLimiter — общий предел строк в секунду: корзина маркеров на секунду
// приёма. Сверх предела чтение задерживается (TCP придерживает источник), а
// не обрывается: разрыв заставил бы источник повторять отправку.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newRateLimiter(perSecond int, now func() time.Time) *rateLimiter {
	return &rateLimiter{rate: float64(perSecond), tokens: float64(perSecond), last: now(), now: now}
}

// wait берёт маркер; waited — пришлось ждать.
func (r *rateLimiter) wait(ctx context.Context) (bool, error) {
	waited := false
	for {
		r.mu.Lock()
		now := r.now()
		r.tokens = min(r.rate, r.tokens+now.Sub(r.last).Seconds()*r.rate)
		r.last = now
		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return waited, nil
		}
		need := time.Duration((1 - r.tokens) / r.rate * float64(time.Second))
		r.mu.Unlock()
		waited = true
		t := time.NewTimer(max(need, time.Millisecond))
		select {
		case <-ctx.Done():
			t.Stop()
			return waited, ctx.Err()
		case <-t.C:
		}
	}
}
