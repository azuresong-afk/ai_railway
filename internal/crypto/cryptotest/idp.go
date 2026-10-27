package cryptotest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

// IdPRealm — путь издателя на синтетическом IdP (как realm у Keycloak).
const IdPRealm = "/realms/aisec"

// IdP — синтетический IdP OpenID Connect для тестов входа через OIDC
// (ADR-0025): HTTPS на 127.0.0.1 с собственной цепочкой сертификатов,
// discovery, JWKS, авторизация по коду с PKCE S256 и обмен кода. Внешних
// адресов нет.
type IdP struct {
	// Issuer — адрес издателя; RootPEM — корень цепочки сертификата IdP.
	Issuer  string
	RootPEM []byte
	Signer  *JWTSigner

	ClientID, ClientSecret string

	srv *httptest.Server

	mu     sync.Mutex
	codes  map[string]idpGrant
	claims map[string]any
	// Now — часы IdP для iat и exp (по умолчанию time.Now).
	now func() time.Time
	// Хуки подмены ответов (тесты отказов).
	discovery func(m map[string]any)
	token     func(c map[string]any)
	tokenBody []byte
	jwksBody  []byte
	deny      string
	jwksHits  int
}

type idpGrant struct {
	nonce, challenge, redirect string
}

// NewIdP запускает IdP с ключом подписи signer (nil — ES256 с kid «k1»).
func NewIdP(clientID, clientSecret string, signer *JWTSigner) (*IdP, error) {
	if signer == nil {
		var err error
		if signer, err = NewJWTSigner("ES256", "k1", 0); err != nil {
			return nil, err
		}
	}
	chain, err := NewChain(ChainOptions{Hosts: []string{"127.0.0.1"}})
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(append(append([]byte{}, chain.Leaf...), chain.Intermediate...), chain.Key)
	if err != nil {
		return nil, err
	}
	p := &IdP{Signer: signer, ClientID: clientID, ClientSecret: clientSecret, RootPEM: chain.Root,
		codes: map[string]idpGrant{}, now: time.Now,
		claims: map[string]any{"sub": "idp-user-1", "preferred_username": "ivanov", "name": "Иванов Иван",
			"groups": []string{"aisec-analysts"}}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+IdPRealm+"/.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("GET "+IdPRealm+"/jwks", p.handleJWKS)
	mux.HandleFunc("GET "+IdPRealm+"/auth", p.handleAuth)
	mux.HandleFunc("POST "+IdPRealm+"/token", p.handleToken)
	p.srv = httptest.NewUnstartedServer(mux)
	// Отказы рукопожатия (тесты чужого корня) не засоряют вывод тестов.
	p.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	p.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	p.srv.StartTLS()
	p.Issuer = p.srv.URL + IdPRealm
	return p, nil
}

// Close останавливает IdP.
func (p *IdP) Close() { p.srv.Close() }

// SetClaims задаёт утверждения следующих токенов (кроме iss, aud, exp,
// iat и nonce, которые ставит IdP).
func (p *IdP) SetClaims(c map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.claims = c
}

// SetClock подменяет часы IdP.
func (p *IdP) SetClock(now func() time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.now = now
}

// OnDiscovery, OnToken — правка документа discovery и утверждений токена
// перед подписью (подмена издателя, адресов, aud).
func (p *IdP) OnDiscovery(f func(m map[string]any)) { p.mu.Lock(); p.discovery = f; p.mu.Unlock() }

// OnToken — правка утверждений токена перед подписью.
func (p *IdP) OnToken(f func(c map[string]any)) { p.mu.Lock(); p.token = f; p.mu.Unlock() }

// SetTokenBody — ответ token_endpoint как есть (nil — обычный).
func (p *IdP) SetTokenBody(b []byte) { p.mu.Lock(); p.tokenBody = b; p.mu.Unlock() }

// SetJWKS — ответ jwks_uri как есть (nil — набор из Signer).
func (p *IdP) SetJWKS(b []byte) { p.mu.Lock(); p.jwksBody = b; p.mu.Unlock() }

// SetSigner меняет ключ подписи (смена ключей у IdP).
func (p *IdP) SetSigner(s *JWTSigner) { p.mu.Lock(); p.Signer = s; p.mu.Unlock() }

// Deny — следующий вход IdP отклоняет с ошибкой code (пусто — пускает).
func (p *IdP) Deny(code string) { p.mu.Lock(); p.deny = code; p.mu.Unlock() }

// JWKSHits — сколько раз запрашивали JWKS.
func (p *IdP) JWKSHits() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.jwksHits
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) //nolint:gosec // G104: тестовый сервер, ошибка записи клиенту не важна
}

func (p *IdP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	m := map[string]any{"issuer": p.Issuer, "authorization_endpoint": p.Issuer + "/auth",
		"token_endpoint": p.Issuer + "/token", "jwks_uri": p.Issuer + "/jwks",
		"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}}
	p.mu.Lock()
	if p.discovery != nil {
		p.discovery(m)
	}
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, m)
}

func (p *IdP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	p.jwksHits++
	body := p.jwksBody
	if body == nil {
		body = JWKS(p.Signer)
	}
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body) //nolint:gosec // G104: тестовый сервер
}

func (p *IdP) handleAuth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	back := redirect.Query()
	back.Set("state", q.Get("state"))
	p.mu.Lock()
	deny := p.deny
	p.mu.Unlock()
	if deny != "" {
		back.Set("error", deny)
	} else {
		code := randomHex()
		p.mu.Lock()
		p.codes[code] = idpGrant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
		p.mu.Unlock()
		back.Set("code", code)
	}
	redirect.RawQuery = back.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusSeeOther) //nolint:gosec // G710: синтетический IdP только для тестов, адрес возврата задаёт тестовый клиент
}

func (p *IdP) handleToken(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	id, _ := url.QueryUnescape(user)     //nolint:gosec // G104: тест, неверное значение не совпадёт с ожидаемым
	secret, _ := url.QueryUnescape(pass) //nolint:gosec // G104: тест, неверное значение не совпадёт с ожидаемым
	if !ok || id != p.ClientID || secret != p.ClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	p.mu.Lock()
	g, found := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	body := p.tokenBody
	p.mu.Unlock()
	if body != nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:gosec // G104: тестовый сервер
		return
	}
	if !found || g.redirect != r.PostForm.Get("redirect_uri") || PKCES256(r.PostForm.Get("code_verifier")) != g.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "секрет <script>"})
		return
	}
	p.mu.Lock()
	now := p.now()
	c := map[string]any{"iss": p.Issuer, "aud": p.ClientID, "exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(), "nonce": g.nonce}
	for k, v := range p.claims {
		c[k] = v
	}
	if p.token != nil {
		p.token(c)
	}
	signer := p.Signer
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"id_token": signer.Sign(c), "token_type": "Bearer",
		"access_token": "at-" + randomHex(), "expires_in": 300})
}

// Authorize проходит авторизацию у IdP как браузер: GET адреса
// авторизации и ответ 303 на адрес возврата; возвращает его параметры
// (code и state или error и state). Запрос обрабатывается в процессе,
// без сетевого клиента (сетевые клиенты — только в разрешённых пакетах).
func (p *IdP) Authorize(ctx context.Context, authURL string) (url.Values, error) {
	if !strings.HasPrefix(authURL, p.Issuer+"/") {
		return nil, errors.New("IdP: чужой адрес авторизации")
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	p.srv.Config.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		return nil, fmt.Errorf("IdP: статус %d", w.Code)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		return nil, err
	}
	return loc.Query(), nil
}

// PKCES256 — code_challenge метода S256 (RFC 7636, 4.2): независимая от
// internal/crypto реализация для синтетического IdP.
func PKCES256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) //nolint:gosec // G104: crypto/rand.Read не возвращает ошибок
	return hex.EncodeToString(b)
}
