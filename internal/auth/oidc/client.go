// Пакет oidc — клиент внешнего IdP по OpenID Connect (ТЗ 5.14, ИАФ.7;
// ADR-0025, раздел 3): discovery, JWKS и обмен кода авторизации. Ходит
// только к издателю, которого настроил администратор безопасности; это
// единственный пакет сервера в NET_CLIENT_ALLOWED. Криптография — только
// через internal/crypto: TLS — ClientConfig профиля, проверка ID-токена —
// Provider.JWT.
package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Пределы обмена с IdP (ADR-0025, 3.2).
const (
	// DefaultTimeout — срок одного запроса к IdP.
	DefaultTimeout = 10 * time.Second
	// MaxResponse — предел тела ответа discovery, JWKS и обмена кода.
	MaxResponse = 64 << 10
	// MetadataTTL — сколько живут discovery и JWKS в кэше.
	MetadataTTL = time.Hour
	// RefreshInterval — не чаще этого JWKS обновляется вне очереди
	// (неизвестный kid).
	RefreshInterval = time.Minute
	// maxURL — длина адресов в discovery.
	maxURL = 512
	// maxCode — длина кода авторизации из адреса возврата.
	maxCode = 2048
)

// Коды ошибок клиента для журнала аудита (наружу не выдаются).
const (
	CodeConfig   = "config"    // настройка неверна: адрес, корневые сертификаты
	CodeBlocked  = "blocked"   // адрес IdP запрещён (loopback, метаданные облака)
	CodeNetwork  = "network"   // соединение не установлено или прервано
	CodeTimeout  = "timeout"   // истёк срок запроса
	CodeTLS      = "tls"       // сертификат IdP не прошёл проверку
	CodeStatus   = "status"    // IdP ответил не 200
	CodeResponse = "response"  // ответ IdP не разобран или нарушает правила
	CodeGrant    = "grant"     // IdP отказал в обмене кода (invalid_grant и т. п.)
	CodeJWKS     = "jwks"      // набор ключей не разобран
	CodeIDToken  = "id_token"  // ID-токен не прошёл проверку (причина — JWTReason)
	CodeTooLarge = "too_large" // ответ больше MaxResponse
	CodeRedirect = "redirect"  // IdP ответил перенаправлением (не следуем)
	CodeOther    = "internal"
)

// Error — отказ при обмене с IdP. Code — один из Code*, Detail — короткое
// уточнение без данных IdP (для технического журнала).
type Error struct {
	Code   string
	Detail string
	err    error
}

func (e *Error) Error() string {
	s := "IdP: " + e.Code
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

func (e *Error) Unwrap() error { return e.err }

func fail(code, detail string) error { return &Error{Code: code, Detail: detail} }

func failErr(code, detail string, err error) error {
	return &Error{Code: code, Detail: detail, err: err}
}

// ErrorCode — код ошибки клиента; CodeOther — ошибка не *Error.
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeOther
}

// Config — настройки IdP из БД (секрет клиента уже расшифрован).
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// RootsPEM — корневые сертификаты IdP; системное хранилище не используется.
	RootsPEM []byte
	// RedirectURI — адрес возврата: адрес консоли + CallbackPath.
	RedirectURI string
	Scopes      []string
	ACRValues   []string
}

// CallbackPath — путь возврата от IdP на сервере.
const CallbackPath = "/api/v1/auth/oidc/callback"

// key — идентичность настройки для кэша: другой издатель, клиент или
// корни — другой кэш.
func (c Config) key() string {
	return c.Issuer + "\x00" + c.ClientID + "\x00" + string(c.RootsPEM)
}

// Metadata — конечные точки IdP из discovery.
type Metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Client — клиент IdP. Безопасен для одновременного использования.
type Client struct {
	tls     aisecCrypto.TLSProvider
	jwt     aisecCrypto.JWTVerifier
	timeout time.Duration
	now     func() time.Time

	mu      sync.Mutex
	allowed []netip.Prefix
	cache   *cacheEntry
	// failKey, failAt, failErr — последний сетевой отказ IdP: в течение
	// FailBackoff входы получают его сразу, не занимая очередь к IdP.
	failKey string
	failAt  time.Time
	failErr error
	// fetch сериализует обращения за discovery и JWKS (ёмкость 1):
	// параллельные входы после истечения кэша не порождают параллельных
	// запросов к IdP, а ожидание очереди ограничено контекстом запроса.
	fetch chan struct{}
}

// FailBackoff — сколько помнить сетевой отказ IdP (недоступен, таймаут).
const FailBackoff = 5 * time.Second

// lockFetch занимает очередь к IdP с учётом контекста.
func (c *Client) lockFetch(ctx context.Context) error {
	select {
	case c.fetch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return failErr(CodeTimeout, "очередь к IdP", ctx.Err())
	}
}

func (c *Client) unlockFetch() { <-c.fetch }

type cacheEntry struct {
	key       string
	meta      Metadata
	metaAt    time.Time
	keys      *aisecCrypto.JWKS
	keysAt    time.Time
	refreshAt time.Time // последнее обновление JWKS вне очереди
}

// Option настраивает Client.
type Option func(*Client)

// WithClock подменяет часы (тесты).
func WithClock(now func() time.Time) Option { return func(c *Client) { c.now = now } }

// WithTimeout задаёт срок одного запроса.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }

// New создаёт клиент на криптопрофиле p. В профиле без проверки JWT
// (gost до этапа 6) — aisecCrypto.ErrNotImplemented.
func New(p aisecCrypto.Provider, opts ...Option) (*Client, error) {
	if p == nil {
		return nil, errors.New("OIDC: не задан криптопрофиль")
	}
	t, err := p.TLS()
	if err != nil {
		return nil, err
	}
	j, err := p.JWT()
	if err != nil {
		return nil, err
	}
	c := &Client{tls: t, jwt: j, timeout: DefaultTimeout, now: time.Now, fetch: make(chan struct{}, 1)}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// AllowNetworks разрешает сети, которые иначе запрещены (например, IdP на
// 127.0.0.1 в тестах). Вызывается до первого запроса.
func (c *Client) AllowNetworks(nets []netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowed = slices.Clone(nets)
}

// ValidateIssuer проверяет адрес издателя: https, без учётных данных,
// запроса и фрагмента, с именем узла, не длиннее 512 символов.
func ValidateIssuer(s string) error {
	u, err := parseHTTPS(s)
	if err != nil {
		return err
	}
	if u.RawQuery != "" {
		return errors.New("адрес издателя не должен содержать параметров запроса")
	}
	return nil
}

func parseHTTPS(s string) (*url.URL, error) {
	if s == "" || len(s) > maxURL {
		return nil, errors.New("адрес пуст или длиннее 512 символов")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("адрес не разобран")
	}
	switch {
	case u.Scheme != "https":
		return nil, errors.New("адрес должен начинаться с https://")
	case u.Host == "" || u.Hostname() == "":
		return nil, errors.New("в адресе нет имени узла")
	case u.User != nil:
		return nil, errors.New("адрес не должен содержать имя пользователя или пароль")
	case u.Fragment != "" || u.RawFragment != "":
		return nil, errors.New("адрес не должен содержать фрагмент (#)")
	case u.Opaque != "":
		return nil, errors.New("адрес не разобран")
	}
	return u, nil
}

// sameOrigin — u на том же узле и порту, что издатель (ADR-0025, 3.2).
func sameOrigin(issuer, u *url.URL) bool {
	return strings.EqualFold(issuer.Hostname(), u.Hostname()) && port(issuer) == port(u)
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return "443"
}

// Discover возвращает конечные точки IdP из кэша или discovery.
func (c *Client) Discover(ctx context.Context, cfg Config) (Metadata, error) {
	e, err := c.entry(ctx, cfg, false)
	if err != nil {
		return Metadata{}, err
	}
	return e.meta, nil
}

// Check — проверка настройки перед сохранением: discovery и JWKS без кэша.
func (c *Client) Check(ctx context.Context, cfg Config) error {
	if err := c.lockFetch(ctx); err != nil {
		return err
	}
	defer c.unlockFetch()
	meta, err := c.fetchMetadata(ctx, cfg)
	if err != nil {
		return err
	}
	_, err = c.fetchJWKS(ctx, cfg, meta)
	return err
}

// entry — кэш для cfg; force — обновить JWKS вне очереди (не чаще
// RefreshInterval).
func (c *Client) entry(ctx context.Context, cfg Config, force bool) (cacheEntry, error) {
	if err := c.lockFetch(ctx); err != nil {
		return cacheEntry{}, err
	}
	defer c.unlockFetch()
	now := c.now()
	c.mu.Lock()
	var e cacheEntry
	if c.cache != nil && c.cache.key == cfg.key() {
		e = *c.cache
	}
	failed := c.failKey == cfg.key() && now.Sub(c.failAt) < FailBackoff && now.Sub(c.failAt) >= 0
	lastErr := c.failErr
	c.mu.Unlock()
	needMeta := e.key == "" || now.Sub(e.metaAt) >= MetadataTTL
	if failed && (needMeta || e.keys == nil) {
		return cacheEntry{}, lastErr
	}
	e, err := c.refreshEntry(ctx, cfg, e, now, force)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		if code := ErrorCode(err); code == CodeNetwork || code == CodeTimeout {
			c.failKey, c.failAt, c.failErr = cfg.key(), now, err
		}
		return cacheEntry{}, err
	}
	c.failKey = ""
	c.cache = &e
	return e, nil
}

// refreshEntry обновляет устаревшие метаданные и JWKS записи e.
func (c *Client) refreshEntry(ctx context.Context, cfg Config, e cacheEntry, now time.Time, force bool) (cacheEntry, error) {
	if e.key == "" || now.Sub(e.metaAt) >= MetadataTTL {
		meta, err := c.fetchMetadata(ctx, cfg)
		if err != nil {
			return cacheEntry{}, err
		}
		e = cacheEntry{key: cfg.key(), meta: meta, metaAt: now}
	}
	refresh := e.keys == nil || now.Sub(e.keysAt) >= MetadataTTL
	if force && !refresh && now.Sub(e.refreshAt) >= RefreshInterval {
		refresh = true
		e.refreshAt = now
	}
	if refresh {
		keys, err := c.fetchJWKS(ctx, cfg, e.meta)
		if err != nil {
			return cacheEntry{}, err
		}
		e.keys, e.keysAt = keys, now
	}
	return e, nil
}

func (c *Client) fetchMetadata(ctx context.Context, cfg Config) (Metadata, error) {
	iss, err := parseHTTPS(cfg.Issuer)
	if err != nil {
		return Metadata{}, failErr(CodeConfig, "адрес издателя", err)
	}
	body, err := c.get(ctx, cfg, strings.TrimSuffix(cfg.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return Metadata{}, err
	}
	var m Metadata
	if err := json.Unmarshal(body, &m); err != nil {
		return Metadata{}, fail(CodeResponse, "discovery не разобран")
	}
	// issuer из discovery совпадает с настроенным побайтно (OpenID
	// Connect Discovery 1.0, 4.3): иначе это не тот IdP.
	if m.Issuer != cfg.Issuer {
		return Metadata{}, fail(CodeResponse, "issuer в discovery не совпадает с настроенным")
	}
	for _, ep := range []string{m.AuthorizationEndpoint, m.TokenEndpoint, m.JWKSURI} {
		u, err := parseHTTPS(ep)
		if err != nil {
			return Metadata{}, failErr(CodeResponse, "конечная точка discovery", err)
		}
		if !sameOrigin(iss, u) {
			return Metadata{}, fail(CodeResponse, "конечная точка discovery на другом узле")
		}
	}
	return m, nil
}

func (c *Client) fetchJWKS(ctx context.Context, cfg Config, m Metadata) (*aisecCrypto.JWKS, error) {
	body, err := c.get(ctx, cfg, m.JWKSURI)
	if err != nil {
		return nil, err
	}
	keys, err := c.jwt.ParseJWKS(body)
	if err != nil {
		return nil, failErr(CodeJWKS, "", err)
	}
	return keys, nil
}

// AuthParams — параметры запроса авторизации.
type AuthParams struct {
	State, Nonce string
	// Challenge — code_challenge метода S256.
	Challenge string
}

// AuthURL — адрес authorization_endpoint с параметрами входа по коду с PKCE.
func (c *Client) AuthURL(ctx context.Context, cfg Config, p AuthParams) (string, error) {
	m, err := c.Discover(ctx, cfg)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(m.AuthorizationEndpoint)
	if err != nil {
		return "", fail(CodeResponse, "authorization_endpoint")
	}
	q := u.Query()
	scopes := append([]string{"openid"}, cfg.Scopes...)
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("scope", strings.Join(slices.Compact(scopes), " "))
	q.Set("state", p.State)
	q.Set("nonce", p.Nonce)
	q.Set("code_challenge", p.Challenge)
	q.Set("code_challenge_method", "S256")
	if len(cfg.ACRValues) > 0 {
		q.Set("acr_values", strings.Join(cfg.ACRValues, " "))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// tokenResponse — ответ token_endpoint (RFC 6749, 5.1; OpenID Connect Core 1.0, 3.1.3.3).
type tokenResponse struct {
	IDToken   string `json:"id_token"`
	TokenType string `json:"token_type"`
}

// Exchange меняет код авторизации на ID-токен (client_secret_basic, PKCE).
// Токены доступа и обновления, если IdP их выдал, отбрасываются.
func (c *Client) Exchange(ctx context.Context, cfg Config, code, verifier string) (string, error) {
	if code == "" || len(code) > maxCode {
		return "", fail(CodeResponse, "код авторизации пуст или слишком длинный")
	}
	m, err := c.Discover(ctx, cfg)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", cfg.RedirectURI)
	form.Set("code_verifier", verifier)
	body, status, err := c.do(ctx, cfg, http.MethodPost, m.TokenEndpoint, []byte(form.Encode()), func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// RFC 6749, 2.3.1: идентификатор и секрет кодируются как форма до Basic.
		r.SetBasicAuth(url.QueryEscape(cfg.ClientID), url.QueryEscape(cfg.ClientSecret))
	})
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		if status == http.StatusBadRequest || status == http.StatusUnauthorized {
			return "", fail(CodeGrant, grantError(body))
		}
		return "", fail(CodeStatus, fmt.Sprintf("код ответа %d", status))
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.IDToken == "" {
		return "", fail(CodeResponse, "в ответе нет id_token")
	}
	if !strings.EqualFold(tr.TokenType, "Bearer") && tr.TokenType != "" {
		return "", fail(CodeResponse, "token_type не Bearer")
	}
	if len(tr.IDToken) > aisecCrypto.MaxJWTSize {
		return "", fail(CodeResponse, "id_token длиннее предела")
	}
	return tr.IDToken, nil
}

// grantError — код ошибки OAuth из ответа (RFC 6749, 5.2), только если он
// из латиницы и «_»; описание ошибки IdP не берётся.
func grantError(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil || !SafeCode(e.Error) {
		return "отказ без кода"
	}
	return e.Error
}

// SafeCode — код ошибки OAuth пригоден для журнала: 1–64 символа a–z и «_».
func SafeCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && c != '_' {
			return false
		}
	}
	return true
}

// VerifyIDToken проверяет ID-токен ключами издателя. Неизвестный kid —
// одно обновление JWKS вне очереди (не чаще RefreshInterval) и повтор.
func (c *Client) VerifyIDToken(ctx context.Context, cfg Config, token, nonce string) (aisecCrypto.IDTokenClaims, error) {
	e, err := c.entry(ctx, cfg, false)
	if err != nil {
		return aisecCrypto.IDTokenClaims{}, err
	}
	want := aisecCrypto.IDTokenExpect{Issuer: cfg.Issuer, Audience: cfg.ClientID, Nonce: nonce, Now: c.now()}
	claims, err := c.jwt.VerifyIDToken(token, e.keys, want)
	if aisecCrypto.JWTReason(err) == aisecCrypto.JWTReasonUnknownKey {
		if e, err = c.entry(ctx, cfg, true); err != nil {
			return aisecCrypto.IDTokenClaims{}, err
		}
		claims, err = c.jwt.VerifyIDToken(token, e.keys, want)
	}
	if err != nil {
		return aisecCrypto.IDTokenClaims{}, failErr(CodeIDToken, aisecCrypto.JWTReason(err), err)
	}
	return claims, nil
}

func (c *Client) get(ctx context.Context, cfg Config, u string) ([]byte, error) {
	body, status, err := c.do(ctx, cfg, http.MethodGet, u, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fail(CodeStatus, fmt.Sprintf("код ответа %d", status))
	}
	return body, nil
}

// do — один запрос к IdP со сроком c.timeout: без прокси, без
// перенаправлений, только на разрешённые адреса, тело — до MaxResponse.
func (c *Client) do(ctx context.Context, cfg Config, method, u string, body []byte, prep func(*http.Request)) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	tlsCfg, err := c.tls.ClientConfig(cfg.RootsPEM)
	if err != nil {
		return nil, 0, failErr(CodeConfig, "корневые сертификаты IdP", err)
	}
	c.mu.Lock()
	allowed := slices.Clone(c.allowed)
	c.mu.Unlock()
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer(allowed, c.timeout),
		TLSClientConfig:        tlsCfg,
		TLSHandshakeTimeout:    c.timeout,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 16 << 10,
		ResponseHeaderTimeout:  c.timeout,
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, 0, failErr(CodeConfig, "адрес запроса", err)
	}
	req.Header.Set("Accept", "application/json")
	if prep != nil {
		prep(req)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, netError(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:gosec // G104: ошибка закрытия тела после чтения не важна
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, resp.StatusCode, fail(CodeRedirect, "")
	}
	if resp.StatusCode == http.StatusOK && !jsonType(resp.Header.Get("Content-Type")) {
		return nil, resp.StatusCode, fail(CodeResponse, "ответ не JSON")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		return nil, resp.StatusCode, netError(ctx, err)
	}
	if len(data) > MaxResponse {
		return nil, resp.StatusCode, fail(CodeTooLarge, "")
	}
	return data, resp.StatusCode, nil
}

// jsonType — тип содержимого JSON (application/json, application/jwk-set+json …).
func jsonType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && (mt == "application/json" || strings.HasSuffix(mt, "+json"))
}

func netError(ctx context.Context, err error) error {
	var ne net.Error
	switch {
	case errors.Is(err, errBlockedAddr):
		return failErr(CodeBlocked, "", err)
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return failErr(CodeTimeout, "", err)
	case aisecCrypto.IsTLSError(err):
		return failErr(CodeTLS, "", err)
	}
	return failErr(CodeNetwork, "", err)
}
