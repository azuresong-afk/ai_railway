package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/mcp"
	"github.com/azuresong-afk/ai_railway/internal/netguard"
	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Клиент вышестоящего MCP-сервера (ADR-0023, раздел 6; задача 4.11).
// Адрес, корневые сертификаты и учётные данные — только из пакета
// конфигурации (ЗИ.3): прокси из окружения и перенаправления не
// используются, адрес проверяется правилом internal/netguard после
// разрешения имени при каждом соединении (DNS rebinding), TLS — из
// internal/crypto. Заголовки клиента дальше не передаются: шлюз ставит
// только свои (раздел 6, «Заголовки к вышестоящему серверу»).

// Сроки и пределы вышестоящего сервера (ADR-0023, раздел 6).
const (
	mcpConnectTimeout = 10 * time.Second
	mcpListTimeout    = 30 * time.Second
	// mcpCallTimeout — tools/call без call_timeout в карточке сервера.
	mcpCallTimeout = 120 * time.Second
	// mcpListenTimeout — поток subscriptions/listen.
	mcpListenTimeout = time.Hour
	// mcpConcurrency — одновременных запросов к одному серверу.
	mcpConcurrency = 64
	// maxMCPErrorBody — тело ответа с ошибкой HTTP читается не дальше.
	maxMCPErrorBody = 4 << 10
)

// errMCPBusy — у сервера уже mcpConcurrency запросов в работе.
var errMCPBusy = errors.New("MCP-сервер: слишком много одновременных запросов")

// errMCPBlockedAddr — адрес сервера запрещён правилом адресов.
var errMCPBlockedAddr = errors.New("MCP-сервер: адрес запрещён правилом адресов")

// mcpUpstream — вышестоящий MCP-сервер из пакета конфигурации.
type mcpUpstream struct {
	srv  bundle.MCPServer
	url  string
	cred string // учётные данные из секретов пакета; пусто — без них
	// authHeader — заголовок учётных данных (Authorization: Bearer по
	// умолчанию).
	authHeader  string
	callTimeout time.Duration
	client      *http.Client
	sem         chan struct{}
}

// MCPServers — клиенты MCP-серверов пакета по slug.
type MCPServers map[string]*mcpUpstream

// NewMCPServers готовит клиентов серверов раздела mcp_servers пакета:
// учётные данные — из Bundle.MCPSecrets по slug. Неверный адрес, корневой
// сертификат или учётные данные — ошибка, и пакет отклоняется.
func NewMCPServers(servers []bundle.MCPServer, secrets bundle.Secrets, tp aisecCrypto.TLSProvider) (MCPServers, error) {
	out := make(MCPServers, len(servers))
	for _, s := range servers {
		up, err := newMCPUpstream(s, secrets[s.ID], tp, nil)
		if err != nil {
			return nil, err
		}
		out[s.ID] = up
	}
	return out, nil
}

// newMCPUpstream готовит клиента сервера s. allowed — сети сверх правила
// адресов: шлюз передаёт nil (то же правило, что у реестра на сервере),
// тесты — loopback для httptest.
func newMCPUpstream(s bundle.MCPServer, cred string, tp aisecCrypto.TLSProvider, allowed []netip.Prefix) (*mcpUpstream, error) {
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !s.InsecureHTTP)) {
		return nil, fmt.Errorf("MCP-сервер %s: неверный адрес", s.ID)
	}
	if err := netguard.CheckHost(u.Hostname(), allowed); err != nil {
		return nil, fmt.Errorf("MCP-сервер %s: %w", s.ID, err)
	}
	if strings.ContainsAny(cred, "\r\n\x00") {
		return nil, fmt.Errorf("MCP-сервер %s: учётные данные содержат недопустимые символы", s.ID)
	}
	tlsCfg, err := tp.ClientConfig([]byte(s.CAPEM))
	if err != nil {
		return nil, fmt.Errorf("MCP-сервер %s: TLS: %w", s.ID, err)
	}
	g := mcpDialer{allowed: allowed}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            g.dial,
		TLSClientConfig:        tlsCfg,
		TLSHandshakeTimeout:    mcpConnectTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxIdleConns:           mcpConcurrency,
		MaxIdleConnsPerHost:    mcpConcurrency,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        90 * time.Second,
		ForceAttemptHTTP2:      true,
	}
	up := &mcpUpstream{srv: s, url: s.URL, cred: cred, authHeader: s.AuthHeader, callTimeout: mcpCallTimeout,
		sem: make(chan struct{}, mcpConcurrency),
		client: &http.Client{Transport: tr,
			// Перенаправления не выполняются (ADR-0023, раздел 6): ответ 3xx —
			// ошибка вышестоящего сервера.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if s.CallTimeout > 0 {
		up.callTimeout = time.Duration(s.CallTimeout) * time.Second
	}
	return up, nil
}

// close закрывает простаивающие соединения (смена пакета).
func (u *mcpUpstream) close() { u.client.CloseIdleConnections() }

// mcpDialer — соединение TCP только с адресами, разрешёнными правилом
// адресов: имя разрешается здесь, и соединение идёт на проверенный адрес.
type mcpDialer struct {
	allowed []netip.Prefix
	// lookup — разрешение имени; nil — системный резолвер (тесты подменяют).
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

func (g mcpDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, errors.New("MCP-сервер: неверный порт")
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip.WithZone("")}
	} else {
		lookup := g.lookup
		if lookup == nil {
			lookup = net.DefaultResolver.LookupNetIP
		}
		if ips, err = lookup(ctx, "ip", host); err != nil {
			return nil, err
		}
	}
	// Хотя бы один запрещённый адрес среди ответов — отказ: иначе выбор
	// адреса зависел бы от порядка ответов DNS.
	for i, ip := range ips {
		ips[i] = ip.WithZone("")
		if !netguard.Permitted(ips[i], g.allowed) {
			return nil, errMCPBlockedAddr
		}
	}
	d := net.Dialer{Timeout: mcpConnectTimeout, KeepAlive: 30 * time.Second}
	var conn net.Conn
	for _, ip := range ips {
		if conn, err = d.DialContext(ctx, network, netip.AddrPortFrom(ip, uint16(p)).String()); err == nil {
			return conn, nil
		}
	}
	if err == nil {
		err = errors.New("MCP-сервер: имя не разрешилось")
	}
	return nil, err
}

// mcpOutgoing — запрос к вышестоящему серверу.
type mcpOutgoing struct {
	Msg     *mcp.Message
	Version string
	// Session — Mcp-Session-Id вышестоящего сервера (2025-11-25).
	Session string
	// Params — заголовки Mcp-Param-* по одобренной inputSchema (2026-07-28).
	Params http.Header
	// Traceparent — W3C traceparent клиента, если он верный.
	Traceparent string
}

// mcpReply — ответ вышестоящего сервера: JSON-сообщение или поток SSE.
type mcpReply struct {
	Status  int
	Session string
	// Msg — ответ JSON (application/json); Stream — поток SSE.
	Msg     *mcp.Message
	Stream  *mcp.SSEReader
	body    io.ReadCloser
	release func()
}

// Close освобождает соединение и место в пределе одновременных запросов.
func (r *mcpReply) Close() {
	if r.body != nil {
		_ = r.body.Close() //nolint:gosec // G104: ошибка закрытия тела ответа не меняет результат
	}
	if r.release != nil {
		r.release()
		r.release = nil
	}
}

// mcpUpstreamError — вышестоящий сервер ответил ошибкой HTTP или не
// по протоколу: клиенту — обобщённая ошибка, в событие — статус.
type mcpUpstreamError struct {
	Status int
	Msg    string
}

func (e *mcpUpstreamError) Error() string { return e.Msg }

// send отправляет сообщение. Тело собирается из проверенного документа
// (mcp.AppendJSON), заголовки — только свои. Ответ уведомлению — 202 без
// тела (Msg и Stream пустые). ctx задаёт срок запроса.
func (u *mcpUpstream) send(ctx context.Context, out mcpOutgoing) (*mcpReply, error) {
	select {
	case u.sem <- struct{}{}:
	default:
		return nil, errMCPBusy
	}
	release := func() { <-u.sem }
	body := out.Msg.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(body))
	if err != nil {
		release()
		return nil, err
	}
	h := req.Header
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json, text/event-stream")
	h.Set("User-Agent", "aisec-gateway")
	if out.Version != "" && out.Msg.Method != "initialize" {
		h.Set(mcp.HeaderProtocolVersion, out.Version)
	}
	if out.Version == mcp.Version20260728 && out.Msg.Method != "" {
		h.Set(mcp.HeaderMethod, mcp.EncodeHeaderValue(out.Msg.Method))
		if f := mcp.NameField(out.Msg.Method); f != "" {
			if name, ok := mcp.GetString(out.Msg.Params, f); ok {
				h.Set(mcp.HeaderName, mcp.EncodeHeaderValue(name))
			}
		}
		for k, vs := range out.Params {
			h[k] = vs
		}
	}
	if out.Session != "" {
		h.Set(mcp.HeaderSessionID, out.Session)
	}
	if out.Traceparent != "" {
		h.Set("traceparent", out.Traceparent)
	}
	if u.cred != "" {
		if u.authHeader != "" {
			h.Set(u.authHeader, u.cred)
		} else {
			h.Set("Authorization", "Bearer "+u.cred)
		}
	}
	resp, err := u.client.Do(req) //nolint:bodyclose // тело закрывает mcpReply.Close у вызывающего
	if err != nil {
		release()
		return nil, err
	}
	r := &mcpReply{Status: resp.StatusCode, body: resp.Body, release: release}
	if sid := resp.Header.Get(mcp.HeaderSessionID); sid != "" {
		if !mcp.ValidSessionID(sid) {
			r.Close()
			return nil, &mcpUpstreamError{Status: resp.StatusCode, Msg: "MCP-сервер: неверный Mcp-Session-Id"}
		}
		r.Session = sid
	}
	if resp.StatusCode == http.StatusAccepted && out.Msg.Kind == mcp.KindNotification {
		return r, nil
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		r.Close()
		return nil, &mcpUpstreamError{Status: resp.StatusCode, Msg: "MCP-сервер ответил перенаправлением"}
	case ct == "text/event-stream" && resp.StatusCode == http.StatusOK:
		r.Stream = mcp.NewSSEReader(resp.Body, mcp.MaxEvents, mcp.MaxStream)
		return r, nil
	case ct == "application/json":
		// Ошибка JSON-RPC приходит и с кодом 4xx (2026-07-28: -32020,
		// -32022 с 400, неизвестный метод — 404).
		data, err := io.ReadAll(io.LimitReader(resp.Body, mcp.MaxMessage+1))
		if err != nil || len(data) > mcp.MaxMessage {
			r.Close()
			return nil, &mcpUpstreamError{Status: resp.StatusCode, Msg: "MCP-сервер: ответ больше предела или оборван"}
		}
		m, err := mcp.Parse(data, mcp.Limits(mcp.MaxMessage))
		if err != nil || (m.Kind != mcp.KindResult && m.Kind != mcp.KindError) ||
			(resp.StatusCode != http.StatusOK && m.Kind != mcp.KindError) {
			r.Close()
			return nil, &mcpUpstreamError{Status: resp.StatusCode, Msg: "MCP-сервер: ответ не по протоколу"}
		}
		r.Msg = m
		return r, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxMCPErrorBody)) //nolint:gosec // G104: тело ошибки не нужно
	r.Close()
	return nil, &mcpUpstreamError{Status: resp.StatusCode, Msg: "MCP-сервер ответил ошибкой HTTP " + strconv.Itoa(resp.StatusCode)}
}

// await читает ответ на запрос id: сообщение JSON или поток SSE до ответа
// с тем же id. onServer получает сообщения сервера из потока до ответа
// (уведомления, запросы к клиенту); false из onServer прерывает чтение.
func (r *mcpReply) await(id argschema.Value, onServer func(*mcp.Message) bool) (*mcp.Message, error) {
	if r.Msg != nil {
		if !mcp.SameID(r.Msg.ID, id) && (r.Msg.Kind != mcp.KindError || r.Msg.ID.Kind != argschema.Null) {
			return nil, &mcpUpstreamError{Status: r.Status, Msg: "MCP-сервер: ответ с чужим id"}
		}
		return r.Msg, nil
	}
	if r.Stream == nil {
		return nil, &mcpUpstreamError{Status: r.Status, Msg: "MCP-сервер не ответил на запрос"}
	}
	for {
		m, err := r.Stream.Next()
		if errors.Is(err, io.EOF) {
			return nil, &mcpUpstreamError{Status: r.Status, Msg: "MCP-сервер закрыл поток без ответа"}
		}
		if err != nil {
			return nil, &mcpUpstreamError{Status: r.Status, Msg: "MCP-сервер: поток SSE не по протоколу или больше пределов"}
		}
		if (m.Kind == mcp.KindResult || m.Kind == mcp.KindError) && mcp.SameID(m.ID, id) {
			return m, nil
		}
		if onServer != nil && !onServer(m) {
			return nil, context.Canceled
		}
	}
}
