package gateway

import (
	"bytes"
	"context"
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
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: controlTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       cfg,
		TLSHandshakeTimeout:   controlTimeout,
		ResponseHeaderTimeout: controlTimeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}, nil
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

// postControl отправляет JSON и разбирает ответ с кодом want в out.
func postControl(ctx context.Context, client *http.Client, u string, in, out any, want int) error {
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxControlResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxControlResponse {
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
// (POST /api/v1/gateways/register на порту консоли). Токен в журнал не пишется.
func Register(ctx context.Context, client *http.Client, console *url.URL, token string) (Registration, error) {
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
	if err := postControl(ctx, client, u, map[string]string{"token": token, "csr": string(csrPEM)}, &resp, http.StatusCreated); err != nil {
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
	Logger     *slog.Logger
	Clock      func() time.Time
	// Sleep ждёт d или отмены ctx (тесты подменяют его).
	Sleep func(ctx context.Context, d time.Duration) bool
}

// RunHeartbeat отправляет heartbeat до отмены ctx. Ошибки не останавливают
// шлюз (он работает автономно, ТЗ 4.2): пауза растёт до heartbeatBackoffMax.
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
	interval, backoff := minHeartbeatInterval*3, time.Duration(0)
	for {
		wait, ok := c.beat(ctx, u, &interval, &backoff)
		if !ok {
			return
		}
		if !c.Sleep(ctx, wait) {
			return
		}
	}
}

// beat отправляет один heartbeat и возвращает паузу до следующего.
func (c HeartbeatConfig) beat(ctx context.Context, u string, interval, backoff *time.Duration) (time.Duration, bool) {
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
	}
	sent := c.Clock()
	err := postControl(ctx, c.Client, u, map[string]string{"version": c.Version, "bundle_etag": etag}, &resp, http.StatusOK)
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
	if resp.IntervalSeconds > 0 {
		*interval = min(max(time.Duration(resp.IntervalSeconds)*time.Second, minHeartbeatInterval), maxHeartbeatInterval)
	}
	if skew := resp.ServerTime.Sub(sent); !resp.ServerTime.IsZero() && (skew > clockSkewWarn || skew < -clockSkewWarn) {
		c.Logger.Warn("часы шлюза расходятся с сервером управления", "skew_seconds", int(skew/time.Second))
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
