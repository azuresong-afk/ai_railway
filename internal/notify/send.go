package notify

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/netguard"
)

// Коды ошибок доставки: в журнал доставки и аудит пишется только код, без
// текста ответа получателя и адресов (в адресе webhook бывает токен).
const (
	ErrCodeDial       = "dial"
	ErrCodeTLS        = "tls"
	ErrCodeNoSTARTTLS = "starttls_unsupported"
	ErrCodeAuth       = "auth"
	ErrCodeRejected   = "rejected"
	ErrCodeTimeout    = "timeout"
	ErrCodeWrite      = "write"
	ErrCodeConfig     = "config"
	ErrCodeDisabled   = "channel_disabled"
	ErrCodeInternal   = "internal"
	// ErrCodeUnreachable — обобщённый код тестовой отправки вместо dial,
	// timeout, tls, starttls_unsupported и write: тест не служит
	// сканером портов в сетях сервера (3Н31 ревью 3.r2).
	ErrCodeUnreachable = "unreachable"
	errCodeHTTPPrefix  = "http_"
	maxResponseBody    = 64 << 10
	maxResponseHeaders = 64 << 10
)

// DefaultSendTimeout — предел одной попытки доставки.
const DefaultSendTimeout = 30 * time.Second

// SignatureHeader — подпись тела webhook: «t=<unix>,v1=<hex>» от
// «t + "." + тело» на MAC криптопрофиля (ADR-0020 п. 9). Получатель
// сверяет за постоянное время и отвергает метку старше 5 минут.
const SignatureHeader = "AISec-Signature"

// DeliveryError — неудачная попытка: только код.
type DeliveryError struct{ Code string }

func (e *DeliveryError) Error() string {
	return "уведомление не доставлено: " + e.Code
}

func failed(code string) error { return &DeliveryError{Code: code} }

// ErrorCode — код ошибки доставки для журнала.
func ErrorCode(err error) string {
	var de *DeliveryError
	if errors.As(err, &de) {
		return de.Code
	}
	return ErrCodeInternal
}

// netCode — код сетевой ошибки: истёк срок или нет соединения.
func netCode(err error, fallback string) error {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return failed(ErrCodeTimeout)
	}
	return failed(fallback)
}

// Transport отправляет уведомления по адресам, заданным администратором
// в канале (ЗИ.3): прокси из окружения и перенаправления не используются.
// Соединение с loopback, link-local (в том числе 169.254.169.254),
// групповыми, неуказанными адресами и адресами метаданных облака
// отклоняется по адресу после разрешения имени (закрывает и DNS rebinding) с
// кодом config, если сеть не разрешена явно (AllowNetworks; 3Н31 ревью 3.r2).
// Частные сети (10/8, 172.16/12, 192.168/16, fc00::/7) разрешены: SIEM и
// почта заказчика обычно в них.
type Transport struct {
	tls      aisecCrypto.TLSProvider
	provider aisecCrypto.Provider
	version  string
	now      func() time.Time
	timeout  time.Duration
	allowed  []netip.Prefix
}

// errBlockedAddr — адрес получателя запрещён (3Н31 ревью 3.r2).
var errBlockedAddr = errors.New("уведомления: адрес получателя запрещён")

// AllowNetworks разрешает сети, которые иначе запрещены (например,
// приёмник syslog на 127.0.0.1): явный список администратора, параметр
// сервера -notify-allowed-networks. Вызывается до начала отправки.
func (t *Transport) AllowNetworks(nets []netip.Prefix) { t.allowed = slices.Clone(nets) }

// permitted — соединение с ip разрешено (общее правило адресов с
// MCP-серверами, internal/netguard).
func (t *Transport) permitted(ip netip.Addr) bool { return netguard.Permitted(ip, t.allowed) }

// testCode — обобщённый код тестовой отправки (3Н31 ревью 3.r2).
// PublicCode — код ошибки соединения для ответов API вне журнала доставки:
// без различения dial, timeout и tls (3Н50 ревью 3.r4, 3Н31).
func PublicCode(code string) string { return testCode(code) }

func testCode(code string) string {
	switch code {
	case ErrCodeDial, ErrCodeTimeout, ErrCodeTLS, ErrCodeNoSTARTTLS, ErrCodeWrite:
		return ErrCodeUnreachable
	}
	return code
}

// NewTransport создаёт отправитель на криптопрофиле p.
func NewTransport(p aisecCrypto.Provider, version string, timeout time.Duration) (*Transport, error) {
	if p == nil {
		return nil, errors.New("уведомления: не задан криптопрофиль")
	}
	t, err := p.TLS()
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = DefaultSendTimeout
	}
	if version == "" {
		version = "dev"
	}
	return &Transport{tls: t, provider: p, version: version, now: time.Now, timeout: timeout}, nil
}

// Send — одна попытка доставки msg в канал ch с секретами sec.
func (t *Transport) Send(ctx context.Context, ch Channel, sec Secrets, msg Message) error {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	switch ch.Type {
	case TypeEmail:
		return t.sendEmail(ctx, ch, sec, msg)
	case TypeWebhook:
		return t.sendWebhook(ctx, ch, sec, msg)
	case TypeSyslog:
		return t.sendSyslog(ctx, ch, msg)
	}
	return failed(ErrCodeConfig)
}

// tlsDial — соединение TCP и TLS с корнями канала и проверкой имени узла
// host. Настройки TLS — только из internal/crypto.
func (t *Transport) tlsDial(ctx context.Context, ch Channel, host string, port int) (net.Conn, error) {
	cfg, err := t.tls.ClientConfig([]byte(ch.Settings.CAPEM))
	if err != nil {
		return nil, failed(ErrCodeConfig)
	}
	cfg.ServerName = host
	conn, err := t.dial(ctx, host, port)
	if err != nil {
		return nil, err
	}
	tc, err := aisecCrypto.ClientTLS(ctx, conn, cfg)
	if err != nil {
		return nil, netCode(err, ErrCodeTLS)
	}
	return tc, nil
}

// resolve — адреса узла host, все разрешённые (3Н31 ревью 3.r2): имя
// разрешается здесь, и соединение идёт на уже проверенный адрес, поэтому
// повторное разрешение (DNS rebinding) проверку не обходит. Хотя бы один
// запрещённый адрес среди ответов — отказ.
func (t *Transport) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !t.permitted(ip.WithZone("")) {
			return nil, errBlockedAddr
		}
		return []netip.Addr{ip.WithZone("")}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for i, ip := range ips {
		ips[i] = ip.WithZone("")
		if !t.permitted(ips[i]) {
			return nil, errBlockedAddr
		}
	}
	return ips, nil
}

// dial — TCP-соединение со сроком из ctx на проверенный адрес узла host.
func (t *Transport) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if port < 1 || port > 65535 {
		return nil, failed(ErrCodeConfig)
	}
	ips, err := t.resolve(ctx, host)
	if errors.Is(err, errBlockedAddr) {
		return nil, failed(ErrCodeConfig)
	}
	if err != nil {
		return nil, netCode(err, ErrCodeDial)
	}
	d := net.Dialer{Timeout: t.timeout, KeepAlive: -1}
	var conn net.Conn
	for _, ip := range ips {
		if conn, err = d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, uint16(port)).String()); err == nil { //nolint:gosec // G115: порт проверен выше (1–65535)
			break
		}
	}
	if err != nil {
		return nil, netCode(err, ErrCodeDial)
	}
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			_ = conn.Close() //nolint:gosec // G104: возвращается ошибка установки срока
			return nil, failed(ErrCodeDial)
		}
	}
	return conn, nil
}

// sendEmail — net/smtp: STARTTLS обязателен; сервер без STARTTLS — отказ
// до передачи пароля и письма.
func (t *Transport) sendEmail(ctx context.Context, ch Channel, sec Secrets, msg Message) error {
	_, err := t.smtpSend(ctx, ch, sec, emailMessage(msg, ch.Settings.From, ch.Settings.To, msg.ID, t.now()), nil)
	return err
}

// SendRaw отправляет готовое письмо (RFC 5322) получателям почтового канала
// ch: так уходят отчёты по расписанию (задача 3.25). Условия те же, что у
// уведомлений: STARTTLS обязателен, срок попытки — DefaultSendTimeout.
func (t *Transport) SendRaw(ctx context.Context, ch Channel, sec Secrets, raw []byte) error {
	_, err := t.SendRawSoft(ctx, ch, sec, raw, nil)
	return err
}

// SendRawSoft — SendRaw, в котором отказ сервера в RCPT по адресу из soft
// (адреса пользователей консоли) не срывает письмо: адрес пропускается и
// учитывается в rejected (ревью 4.r1, 4В13). Иначе пользователь, задавший
// себе адрес, который relay не принимает, лишал бы отчёта всех получателей.
// Отказ по адресу канала — по-прежнему ошибка письма.
func (t *Transport) SendRawSoft(ctx context.Context, ch Channel, sec Secrets, raw []byte, soft []string) (rejected int, err error) {
	if ch.Type != TypeEmail {
		return 0, failed(ErrCodeConfig)
	}
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	set := make(map[string]bool, len(soft))
	for _, a := range soft {
		set[strings.ToLower(a)] = true
	}
	return t.smtpSend(ctx, ch, sec, raw, set)
}

// smtpSend передаёт письмо raw: STARTTLS, при заданном имени — вход. Отказ
// сервера в RCPT по адресу из soft пропускается (rejected).
func (t *Transport) smtpSend(ctx context.Context, ch Channel, sec Secrets, raw []byte, soft map[string]bool) (rejected int, err error) {
	defer func() {
		// Обмен прерван закрытием соединения по сроку ctx — это тайм-аут,
		// а не отказ соединения (3Н31 ревью 3.r2).
		if err != nil && ErrorCode(err) != ErrCodeConfig && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = failed(ErrCodeTimeout)
		}
	}()
	s := ch.Settings
	cfg, err := t.tls.ClientConfig([]byte(s.CAPEM))
	if err != nil {
		return 0, failed(ErrCodeConfig)
	}
	cfg.ServerName = s.Host
	conn, err := t.dial(ctx, s.Host, s.Port)
	if err != nil {
		return 0, err
	}
	// Закрытие по отмене ctx прерывает зависший обмен.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() }) //nolint:gosec // G104: соединение прерывается
	defer stop()
	defer func() { _ = conn.Close() }() //nolint:gosec // G104: ошибка закрытия после обмена не важна
	// Ответы сервера SMTP читаются построчно без предела длины строки:
	// объём чтения за попытку ограничен.
	c, err := smtp.NewClient(&limitedConn{Conn: conn, left: maxSMTPRead}, s.Host)
	if err != nil {
		return 0, netCode(err, ErrCodeDial)
	}
	if err := c.Hello(DefaultHostname); err != nil {
		return 0, netCode(err, ErrCodeRejected)
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return 0, failed(ErrCodeNoSTARTTLS)
	}
	if err := c.StartTLS(cfg); err != nil {
		return 0, netCode(err, ErrCodeTLS)
	}
	if s.Username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return 0, failed(ErrCodeAuth)
		}
		if err := c.Auth(smtp.PlainAuth("", s.Username, sec.Password, s.Host)); err != nil {
			return 0, netCode(err, ErrCodeAuth)
		}
	}
	if err := c.Mail(s.From); err != nil {
		return 0, netCode(err, ErrCodeRejected)
	}
	for _, to := range s.To {
		if err := c.Rcpt(to); err != nil {
			var reply *textproto.Error
			if soft[strings.ToLower(to)] && errors.As(err, &reply) {
				rejected++
				continue
			}
			return 0, netCode(err, ErrCodeRejected)
		}
	}
	if rejected == len(s.To) {
		return 0, failed(ErrCodeRejected)
	}
	w, err := c.Data()
	if err != nil {
		return 0, netCode(err, ErrCodeRejected)
	}
	if _, err := w.Write(raw); err != nil {
		return 0, netCode(err, ErrCodeWrite)
	}
	if err := w.Close(); err != nil {
		return 0, netCode(err, ErrCodeRejected)
	}
	_ = c.Quit() //nolint:gosec // G104: письмо принято, ответ на QUIT не важен
	return rejected, nil
}

// maxSMTPRead — предел чтения от сервера SMTP за одну попытку.
const maxSMTPRead = 1 << 20

// limitedConn — соединение, из которого можно прочитать не больше left байт.
type limitedConn struct {
	net.Conn
	left int64
}

func (c *limitedConn) Read(b []byte) (int, error) {
	if c.left <= 0 {
		return 0, errors.New("уведомления: ответ сервера слишком большой")
	}
	if int64(len(b)) > c.left {
		b = b[:c.left]
	}
	n, err := c.Conn.Read(b)
	c.left -= int64(n)
	return n, err
}

// sendWebhook — POST по https с подписью тела. Ответ 2xx — доставлено;
// перенаправление не выполняется и считается отказом.
func (t *Transport) sendWebhook(ctx context.Context, ch Channel, sec Secrets, msg Message) error {
	var body []byte
	var err error
	if ch.Settings.Format == FormatMattermost {
		body, err = mattermostBody(msg)
	} else {
		body, err = jsonBody(msg, t.version)
	}
	if err != nil {
		return failed(ErrCodeInternal)
	}
	return t.postSigned(ctx, ch, sec, body)
}

// postSigned — POST тела body по адресу webhook с подписью AISec-Signature.
func (t *Transport) postSigned(ctx context.Context, ch Channel, sec Secrets, body []byte) error {
	u, err := parseWebhookURL(sec.URL)
	if err != nil {
		return failed(ErrCodeConfig)
	}
	mac, err := t.provider.NewMAC([]byte(sec.SigningKey))
	if err != nil {
		return failed(ErrCodeConfig)
	}
	ts := strconv.FormatInt(t.now().Unix(), 10)
	sig := "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(append([]byte(ts+"."), body...)))

	// Соединение TLS устанавливает tlsDial, HTTP/2 не используется. Код
	// ошибки соединения и рукопожатия сохраняется атомарно: набор может
	// завершиться уже после возврата из Do (отмена).
	var dialErr atomic.Pointer[DeliveryError]
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					dialErr.Store(&DeliveryError{Code: ErrCodeConfig})
					return nil, failed(ErrCodeConfig)
				}
				p, err := strconv.Atoi(port)
				if err != nil {
					dialErr.Store(&DeliveryError{Code: ErrCodeConfig})
					return nil, failed(ErrCodeConfig)
				}
				conn, err := t.tlsDial(ctx, ch, host, p)
				if err != nil {
					dialErr.Store(&DeliveryError{Code: ErrorCode(err)})
				}
				return conn, err
			},
			ResponseHeaderTimeout: t.timeout, MaxResponseHeaderBytes: maxResponseHeaders, DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       t.timeout,
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return failed(ErrCodeConfig)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AISec/"+t.version)
	req.Header.Set(SignatureHeader, sig)
	resp, err := client.Do(req)
	if err != nil {
		if de := dialErr.Load(); de != nil {
			return de
		}
		return netCode(err, ErrCodeWrite)
	}
	defer func() { _ = resp.Body.Close() }()                               //nolint:gosec // G104: тело прочитано
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody)) //nolint:gosec // G104: тело ответа не нужно
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return failed(errCodeHTTPPrefix + strconv.Itoa(resp.StatusCode))
	}
	return nil
}

// sendSyslog — запись RFC 5424 по TLS (RFC 5425) с фреймингом RFC 6587.
func (t *Transport) sendSyslog(ctx context.Context, ch Channel, msg Message) error {
	s := ch.Settings
	rec, err := syslogRecord(msg, s, t.version)
	if err != nil {
		return failed(ErrCodeInternal)
	}
	tc, err := t.tlsDial(ctx, ch, s.Host, s.Port)
	if err != nil {
		return err
	}
	defer func() { _ = tc.Close() }() //nolint:gosec // G104: запись передана
	if _, err := tc.Write(rec); err != nil {
		return netCode(err, ErrCodeWrite)
	}
	return nil
}

// SendAudit — одна попытка передачи пакета записей журнала в канал ch:
// syslog — каждая запись отдельным сообщением по одному соединению TLS,
// webhook — одним подписанным запросом не больше 1 МиБ. Возвращает число
// переданных записей (webhook может взять не весь пакет).
func (t *Transport) SendAudit(ctx context.Context, ch Channel, sec Secrets, recs []audit.Record) (int, error) {
	if len(recs) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	switch ch.Type {
	case TypeSyslog:
		var buf []byte
		for i := range recs {
			rec, err := auditSyslogRecord(&recs[i], ch.Settings, t.version)
			if err != nil {
				return 0, failed(ErrCodeInternal)
			}
			buf = append(buf, rec...)
		}
		tc, err := t.tlsDial(ctx, ch, ch.Settings.Host, ch.Settings.Port)
		if err != nil {
			return 0, err
		}
		// Закрытие отправляет close_notify: ошибка (приёмник оборвал
		// соединение) — неудача попытки, пакет передаётся снова.
		_, werr := tc.Write(buf)
		cerr := tc.Close()
		if werr != nil {
			return 0, netCode(werr, ErrCodeWrite)
		}
		if cerr != nil {
			return 0, netCode(cerr, ErrCodeWrite)
		}
		return len(recs), nil
	case TypeWebhook:
		if ch.Settings.Format != FormatGeneric {
			return 0, failed(ErrCodeConfig)
		}
		body, n, err := auditBatch(recs, t.version)
		if err != nil {
			return 0, failed(ErrCodeInternal)
		}
		if err := t.postSigned(ctx, ch, sec, body); err != nil {
			return 0, err
		}
		return n, nil
	}
	return 0, failed(ErrCodeConfig)
}
