package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Связь шлюза с сервером управления (ИАФ.10, Р8, задача 2.14): регистрация
// по одноразовому токену на порту консоли и heartbeat на внутренний порт по
// mTLS. Ключ шлюза создаётся здесь и сервер его не видит.

// Пределы клиента сервера управления.
const (
	controlTimeout     = 10 * time.Second
	maxControlResponse = 64 << 10
	// maxHeartbeatResponse — ответ heartbeat с разделом budget: расход до
	// 2 000 приложений (задача 3.18).
	maxHeartbeatResponse = 512 << 10
	// Границы периода heartbeat: сервер подсказывает период, но шлюз не
	// уходит в частые запросы и не замолкает надолго.
	minHeartbeatInterval = 10 * time.Second
	maxHeartbeatInterval = 10 * time.Minute
	// heartbeatBackoffMax — предел паузы после ошибок.
	heartbeatBackoffMax = 5 * time.Minute
	// clockSkewWarn — расхождение часов с сервером, о котором шлюз предупреждает (ВРМ.1).
	clockSkewWarn = 30 * time.Second
)

// ControlTransport — транспорт к серверу управления: доверие только rootsPEM,
// без HTTP_PROXY (ЗИ.3), таймауты. С certPEM и keyPEM — клиентский
// сертификат шлюза (mTLS); без них — только проверка сервера (регистрация).
func ControlTransport(tp aisecCrypto.TLSProvider, rootsPEM, certPEM, keyPEM []byte) (*http.Transport, error) {
	// Тип *tls.Config не называется: crypto/* импортирует только internal/crypto.
	cfg, err := tp.ClientConfig(rootsPEM)
	if err == nil && (len(certPEM) > 0 || len(keyPEM) > 0) {
		cfg, err = tp.ClientCertConfig(rootsPEM, certPEM, keyPEM)
	}
	if err != nil {
		return nil, fmt.Errorf("TLS к серверу управления: %w", err)
	}
	t := newControlTransport()
	t.TLSClientConfig = cfg
	return t, nil
}

// ControlTransportSwitch — транспорт к серверу управления с клиентским
// сертификатом из переключателя: после перевыпуска (ADR-0018, п. 6.3) новые
// соединения идут с новым сертификатом без перезапуска шлюза.
func ControlTransportSwitch(tp aisecCrypto.TLSProvider, rootsPEM []byte, sw *aisecCrypto.ClientCertSwitch) (*http.Transport, error) {
	cfg, err := aisecCrypto.SwitchClientConfig(tp, rootsPEM, sw)
	if err != nil {
		return nil, fmt.Errorf("TLS к серверу управления: %w", err)
	}
	t := newControlTransport()
	t.TLSClientConfig = cfg
	return t, nil
}

// newControlTransport — общие настройки транспорта без TLS: тип
// *tls.Config не называется (crypto/* импортирует только internal/crypto),
// поэтому настройки TLS присваиваются у вызывающего.
func newControlTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: controlTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   controlTimeout,
		ResponseHeaderTimeout: controlTimeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// controlError — ответ сервера с ошибкой: код и detail из Problem Details.
type controlError struct {
	Status     int
	Detail     string
	RetryAfter time.Duration
}

func (e *controlError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("сервер управления ответил %d: %s", e.Status, e.Detail)
	}
	return fmt.Sprintf("сервер управления ответил %d", e.Status)
}

// postControl отправляет JSON и разбирает ответ с кодом want в out; out = nil —
// тело ответа не разбирается.
func postControl(ctx context.Context, client *http.Client, u string, in, out any, want int) error {
	return postControlLimit(ctx, client, u, in, out, want, maxControlResponse)
}

// postControlLimit — postControl с пределом размера ответа limit.
func postControlLimit(ctx context.Context, client *http.Client, u string, in, out any, want int, limit int) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aisec-gateway")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:gosec // G104: тело уже прочитано или ответ отброшен; ошибка закрытия не меняет результат
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return err
	}
	if len(data) > limit {
		return errors.New("ответ сервера управления слишком большой")
	}
	if resp.StatusCode != want {
		ce := &controlError{Status: resp.StatusCode}
		var prob struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(data, &prob) == nil && len(prob.Detail) <= 512 {
			ce.Detail = prob.Detail
		}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 && s <= 3600 {
			ce.RetryAfter = time.Duration(s) * time.Second
		}
		return ce
	}
	if out == nil {
		return nil // ответ без тела (204)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("ответ сервера управления — не ожидаемый JSON")
	}
	return nil
}

// Registration — итог регистрации шлюза.
type Registration struct {
	GatewayID string
	Name      string
	KeyPEM    []byte // закрытый ключ шлюза: в файл 0600, не в журнал
	CertPEM   []byte
	CAPEM     []byte // корень внутреннего УЦ: им шлюз может проверять сервер
	NotAfter  time.Time
}

// Register создаёт ключ и CSR шлюза и получает сертификат по токену
// (POST /api/v1/gateways/register на порту консоли). Токен в журнал не
// пишется. bundleKey — открытый ключ получателя HPKE для закрепления на
// сервере (Н27); nil — закрепится при первом запросе пакета.
func Register(ctx context.Context, client *http.Client, console *url.URL, token string, bundleKey []byte) (Registration, error) {
	// Имя в CSR сервер не использует: CN сертификата — ID шлюза из реестра.
	keyPEM, csrPEM, err := aisecCrypto.NewClientCSR("aisec-gateway")
	if err != nil {
		return Registration{}, err
	}
	var resp struct {
		GatewayID     string    `json:"gateway_id"`
		Name          string    `json:"name"`
		Certificate   string    `json:"certificate"`
		CACertificate string    `json:"ca_certificate"`
		NotAfter      time.Time `json:"not_after"`
	}
	u := console.JoinPath("/api/v1/gateways/register").String()
	req := map[string]string{"token": token, "csr": string(csrPEM)}
	if bundleKey != nil {
		req["bundle_key"] = base64.RawURLEncoding.EncodeToString(bundleKey)
	}
	if err := postControl(ctx, client, u, req, &resp, http.StatusCreated); err != nil {
		return Registration{}, fmt.Errorf("регистрация шлюза: %w", err)
	}
	// Сертификат должен подходить к нашему ключу и нести выданный ID.
	info, err := aisecCrypto.ParseCertInfo([]byte(resp.Certificate))
	if err != nil {
		return Registration{}, fmt.Errorf("регистрация шлюза: %w", err)
	}
	if info.CommonName != resp.GatewayID {
		return Registration{}, errors.New("регистрация шлюза: сертификат выдан не на ID шлюза из ответа")
	}
	if _, err := aisecCrypto.ParseCertInfo([]byte(resp.CACertificate)); err != nil {
		return Registration{}, fmt.Errorf("регистрация шлюза: корень УЦ: %w", err)
	}
	return Registration{
		GatewayID: resp.GatewayID, Name: resp.Name, KeyPEM: keyPEM,
		CertPEM: []byte(resp.Certificate), CAPEM: []byte(resp.CACertificate), NotAfter: resp.NotAfter,
	}, nil
}

// HeartbeatConfig — параметры цикла heartbeat.
type HeartbeatConfig struct {
	// Client — HTTP-клиент с транспортом ControlTransport и сертификатом шлюза.
	Client *http.Client
	// Server — адрес внутреннего API (https://хост:8445).
	Server  *url.URL
	Version string
	// BundleETag — текущий пакет конфигурации (задача 2.13); nil — пусто.
	BundleETag func() string
	// Reports — итоги самотеста и целостности для сервера (задача 2.20); nil — не передаются.
	Reports *Reports
	// Verify — проверка целостности по запросу из консоли (Н38 ревью 2.r4):
	// итог записывается в Reports. nil — запросы не выполняются.
	Verify func(ctx context.Context)
	// StartedAt — время запуска процесса шлюза: по нему сервер пишет запуск
	// и остановку в журнал аудита (В27 ревью 2.r5, РСБ.2). Нулевое — не
	// передаётся, heartbeat остановки не отправляется.
	StartedAt time.Time
	// Reissue — перевыпуск сертификата шлюза по признаку из ответа
	// heartbeat (ADR-0018, п. 6.3); nil — не выполняется.
	Reissue func(ctx context.Context) error
	// Budget — счётчики расхода для сервера и расход остальных процессов из
	// ответа (задача 3.18); nil — не передаются. Только вместе с StartedAt.
	Budget *Budget
	// ServerTime — часы сроков исключений по времени сервера из ответа
	// (3Н40 ревью 3.r3); nil — не ведутся.
	ServerTime *ServerClock
	// TLSFingerprint — отпечаток действующего сертификата адреса приложений
	// (TLSSwitch.Current); nil — не передаётся.
	TLSFingerprint func() string
	// PendingApprovals — ID ожидающих подтверждения запросов
	// (ApprovalClient.Pending, задача 4.10): по списку сервер закрывает
	// запросы, которых шлюз уже не ждёт; nil — не передаётся.
	PendingApprovals func() []string
	// QuotaAutonomous — шлюз пропускал запросы на автономной доле квот
	// (LeaseClient.Autonomous, задача 4.29); nil — не передаётся.
	QuotaAutonomous func() bool
	Logger          *slog.Logger
	Clock           func() time.Time
	// Sleep ждёт d или отмены ctx (тесты подменяют его).
	Sleep func(ctx context.Context, d time.Duration) bool
}

// stopHeartbeatTimeout — срок heartbeat остановки: остановку шлюза он не
// задерживает дольше.
const stopHeartbeatTimeout = 3 * time.Second

// RunHeartbeat отправляет heartbeat до отмены ctx. Ошибки не останавливают
// шлюз (он работает автономно, ТЗ 4.2): пауза растёт до heartbeatBackoffMax.
// После отмены отправляется heartbeat остановки (stopping).
func RunHeartbeat(ctx context.Context, c HeartbeatConfig) {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = sleepCtx
	}
	u := c.Server.JoinPath("/internal/v1/heartbeat").String()
	defer c.stopping(ctx, u)
	interval, backoff := minHeartbeatInterval*3, time.Duration(0)
	// clockTLS — сервер принимает поля time и tls_fingerprint (сообщил в
	// ответе): шлюз обновляют раньше сервера, а сервер прежней версии
	// отклоняет неизвестные поля heartbeat.
	clockTLS := false
	// approvals — сервер ведёт очередь подтверждений и принимает поле
	// approvals_pending (сообщил в ответе).
	approvals := false
	// quotaLeases — сервер выдаёт аренду квот и принимает quota_autonomous.
	quotaLeases := false
	for {
		wait, ok := c.beat(ctx, u, &interval, &backoff, &clockTLS, &approvals, &quotaLeases)
		if !ok {
			return
		}
		if !c.Sleep(ctx, wait) {
			return
		}
	}
}

// stopping сообщает серверу о корректной остановке; неудача только в
// технический журнал: сервер увидит новый запуск без записи об остановке.
func (c HeartbeatConfig) stopping(ctx context.Context, u string) {
	if c.StartedAt.IsZero() {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopHeartbeatTimeout)
	defer cancel()
	etag := ""
	if c.BundleETag != nil {
		etag = c.BundleETag()
	}
	at := c.StartedAt
	body := heartbeatBody{Version: c.Version, BundleETag: etag, StartedAt: &at, Stopping: true}
	if c.Budget != nil {
		// Расход с последнего heartbeat не теряется при остановке.
		body.Budget = c.Budget.report()
	}
	if err := postControl(ctx, c.Client, u, body, nil, http.StatusOK); err != nil {
		c.Logger.Warn("остановка не сообщена серверу управления", "error", err)
	}
}

// beat отправляет один heartbeat и возвращает паузу до следующего.
func (c HeartbeatConfig) beat(ctx context.Context, u string, interval, backoff *time.Duration, clockTLS, approvals, quotaLeases *bool) (time.Duration, bool) {
	if ctx.Err() != nil {
		return 0, false
	}
	etag := ""
	if c.BundleETag != nil {
		etag = c.BundleETag()
	}
	var resp struct {
		ServerTime      time.Time `json:"server_time"`
		IntervalSeconds int       `json:"interval_seconds"`
		// VerifyRequestedAt — администратор запросил проверку шлюза.
		VerifyRequestedAt *time.Time `json:"verify_requested_at"`
		// Reissue — сертификат шлюза нужно перевыпустить.
		Reissue bool `json:"reissue"`
		// Budget — расход остальных процессов (задача 3.18).
		Budget *budgetState `json:"budget"`
		// ClockTLS — сервер принимает time и tls_fingerprint (3Н40, 3Н43).
		ClockTLS bool `json:"clock_tls"`
		// Approvals — сервер принимает approvals_pending (задача 4.10).
		Approvals bool `json:"approvals"`
		// QuotaLeases — сервер принимает quota_autonomous (задача 4.29).
		QuotaLeases bool `json:"quota_leases"`
	}
	sent := c.Clock()
	body := heartbeatBody{Version: c.Version, BundleETag: etag}
	if *clockTLS {
		body.Time = &sent
		if c.TLSFingerprint != nil {
			fp := c.TLSFingerprint()
			body.TLSFingerprint = &fp
		}
	}
	if !c.StartedAt.IsZero() {
		at := c.StartedAt
		body.StartedAt = &at
	}
	if *approvals && c.PendingApprovals != nil {
		pending := c.PendingApprovals()
		body.ApprovalsPending = &pending
	}
	if *quotaLeases && c.QuotaAutonomous != nil {
		auto := c.QuotaAutonomous()
		body.QuotaAutonomous = &auto
	}
	body.Selftest, body.Integrity, body.BundleKeys, body.VerifyRequest = c.Reports.snapshot()
	if c.Budget != nil && body.StartedAt != nil {
		body.Budget = c.Budget.report()
	}
	err := postControlLimit(ctx, c.Client, u, body, &resp, http.StatusOK, maxHeartbeatResponse)
	if ctx.Err() != nil {
		return 0, false
	}
	if err != nil {
		*backoff = min(max(2**backoff, minHeartbeatInterval), heartbeatBackoffMax)
		wait := *backoff
		var ce *controlError
		switch {
		case errors.As(err, &ce) && ce.Status == http.StatusUnauthorized:
			c.Logger.Error("сервер отклонил сертификат шлюза: шлюз отозван или сертификат заменён; нужна повторная регистрация",
				"status", ce.Status)
			wait = heartbeatBackoffMax
		case errors.As(err, &ce) && ce.RetryAfter > 0:
			wait = max(wait, ce.RetryAfter)
			c.Logger.Warn("heartbeat отклонён сервером", "status", ce.Status)
		default:
			c.Logger.Warn("heartbeat не отправлен", "error", err)
		}
		return wait, true
	}
	*backoff = 0
	*clockTLS, *approvals, *quotaLeases = resp.ClockTLS, resp.Approvals, resp.QuotaLeases
	if c.Budget != nil {
		c.Budget.apply(body.Budget, resp.Budget)
	}
	if resp.IntervalSeconds > 0 {
		*interval = min(max(time.Duration(resp.IntervalSeconds)*time.Second, minHeartbeatInterval), maxHeartbeatInterval)
	}
	c.ServerTime.Observe(resp.ServerTime, time.Now())
	if skew := resp.ServerTime.Sub(sent); !resp.ServerTime.IsZero() && (skew > clockSkewWarn || skew < -clockSkewWarn) {
		c.Logger.Warn("часы шлюза расходятся с сервером управления", "skew_seconds", int(skew/time.Second))
	}
	if resp.Reissue && c.Reissue != nil {
		if err := c.Reissue(ctx); err != nil {
			c.Logger.Warn("сертификат шлюза не перевыпущен; повтор при следующем heartbeat", "error", err)
		}
	}
	// Проверка по запросу из консоли — один раз на запрос; итог уйдёт со
	// следующим heartbeat вместе с временем запроса (Н38 ревью 2.r4).
	if at := resp.VerifyRequestedAt; at != nil && c.Verify != nil && c.Reports != nil && !c.Reports.verified(*at) {
		c.Logger.Info("проверка целостности по запросу из консоли", "class", "integrity")
		c.Verify(ctx)
		c.Reports.setVerified(*at)
		return minHeartbeatInterval, true
	}
	return *interval, true
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ValidVersion — версия шлюза для heartbeat: «dev» и сборочные версии.
func ValidVersion(v string) bool {
	return v != "" && len(v) <= 64 && strings.Trim(v, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.+_-") == ""
}
