package agents

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/netguard"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// ServerInput — создание и изменение MCP-сервера. Признаки external и
// insecure_http и учётные данные задаются отдельными действиями.
type ServerInput struct {
	Slug        string // только при создании
	Name        string
	URL         string
	CAPEM       string
	AuthHeader  string
	CallTimeout int
	Versions    []string
}

// forbiddenHeaders — заголовки, которые нельзя занять учётными данными:
// их ставит шлюз (транспорт, MCP, сведения AISec).
var forbiddenHeaders = []string{"host", "content-length", "content-type", "transfer-encoding", "connection", "keep-alive",
	"upgrade", "te", "trailer", "cookie", "origin", "accept", "accept-encoding", "expect", "forwarded", "via"}

// forbiddenPrefixes — префиксы запрещённых заголовков.
var forbiddenPrefixes = []string{"mcp-", "x-aisec-", "proxy-", "x-forwarded-", "sec-"}

// validHeaderName — имя заголовка: token RFC 9110 без запрещённых.
func validHeaderName(h string) bool {
	if h == "" || len(h) > maxHeaderName {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	l := strings.ToLower(h)
	if slices.Contains(forbiddenHeaders, l) {
		return false
	}
	for _, p := range forbiddenPrefixes {
		if strings.HasPrefix(l, p) {
			return false
		}
	}
	return true
}

// checkURL — адрес MCP-сервера: https:// (http:// — только с insecure),
// без userinfo, запроса и фрагмента; узел не запрещён правилом адресов.
func (s *Service) checkURL(raw string, insecure bool) []error {
	if raw == "" || len(raw) > maxURL {
		return []error{errors.New("url — от 1 до 2048 байт")}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return []error{errors.New("url — адрес вида https://mcp.example.ru/mcp")}
	}
	var errs []error
	switch u.Scheme {
	case "https":
	case "http":
		if !insecure {
			errs = append(errs, errors.New("url — только https://; http:// разрешает администратор безопасности признаком insecure_http"))
		}
	default:
		errs = append(errs, errors.New("url — только https://"))
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		errs = append(errs, errors.New("url — без имени пользователя, параметров запроса и фрагмента"))
	}
	if err := netguard.CheckHost(u.Hostname(), s.allowed); err != nil {
		errs = append(errs, errors.New("url — адрес запрещён: loopback, link-local, multicast и службы метаданных недоступны"))
	}
	return errs
}

func (s *Service) checkServer(in ServerInput, insecure bool) error {
	errs := text("name", in.Name, 1, maxName)
	errs = append(errs, s.checkURL(in.URL, insecure)...)
	if in.AuthHeader != "" && !validHeaderName(in.AuthHeader) {
		errs = append(errs, errors.New("auth_header — имя заголовка из латиницы, цифр и дефиса до 64 символов; "+
			"заголовки транспорта, MCP и AISec заняты"))
	}
	if in.CallTimeout < 0 || in.CallTimeout > MaxCallTimeout {
		errs = append(errs, errors.New("call_timeout — от 0 до 600 секунд (0 — 120)"))
	}
	if len(in.Versions) == 0 || len(in.Versions) > len(MCPVersions) {
		errs = append(errs, errors.New("versions — одна или обе версии MCP: 2026-07-28, 2025-11-25"))
	}
	for i, v := range in.Versions {
		if !slices.Contains(MCPVersions, v) || slices.Contains(in.Versions[:i], v) {
			errs = append(errs, errors.New("versions — только 2026-07-28 и 2025-11-25, без повторов"))
			break
		}
	}
	// Корневые сертификаты разбирает криптопрофиль (crypto/x509 — только в
	// internal/crypto).
	switch {
	case in.CAPEM == "":
		errs = append(errs, errors.New("ca_pem — корневые сертификаты MCP-сервера в PEM обязательны"))
	case len(in.CAPEM) > MaxCAPEM:
		errs = append(errs, errors.New("ca_pem — не больше 256 КиБ"))
	default:
		if _, err := s.tls.ClientConfig([]byte(in.CAPEM)); err != nil {
			errs = append(errs, errors.New("ca_pem — не найдено ни одного корректного сертификата PEM"))
		}
	}
	if len(errs) > 0 {
		return invalid(errs...)
	}
	return nil
}

func (in ServerInput) apply(m *MCPServer) {
	m.Name, m.URL, m.CAPEM, m.AuthHeader, m.CallTimeout = in.Name, in.URL, in.CAPEM, in.AuthHeader, in.CallTimeout
	m.Versions = slices.Clone(in.Versions)
	slices.Sort(m.Versions)
}

// serverDetails — сведения о сервере для аудита: без учётных данных и
// сертификатов (только размер).
func serverDetails(m MCPServer) map[string]any {
	return map[string]any{"slug": m.Slug, "name": m.Name, "url": m.URL, "ca_pem_bytes": len(m.CAPEM),
		"auth_header": m.AuthHeader, "external": m.External, "insecure_http": m.InsecureHTTP,
		"call_timeout": m.CallTimeout, "versions": m.Versions, "has_credential": m.Credential != nil}
}

// CreateServer создаёт MCP-сервер. Новый сервер внешний, http:// не
// разрешён (insecure_http — отдельным действием администратора
// безопасности).
func (s *Service) CreateServer(ctx context.Context, by By, in ServerInput) (MCPServer, error) {
	var errs []error
	if !slugRe.MatchString(in.Slug) || in.Slug == policy.FunctionServer {
		errs = append(errs, errors.New("slug — строчные латинские буквы, цифры и дефис, до 64 символов; slug function занят"))
	}
	if err := s.checkServer(in, false); err != nil {
		var ie *InputError
		if errors.As(err, &ie) {
			errs = append(errs, ie.Errs...)
		}
	}
	if len(errs) > 0 {
		return MCPServer{}, invalid(errs...)
	}
	id, err := s.newID()
	if err != nil {
		return MCPServer{}, err
	}
	now := s.now()
	m := MCPServer{ID: id, OrgID: s.orgID, Slug: in.Slug, External: true,
		CreatedAt: now, CreatedBy: by.ref(), UpdatedAt: now, UpdatedBy: by.ref()}
	in.apply(&m)
	if err := s.store.CreateServer(ctx, m, by.entry("mcp_server.create", "mcp_server", id, serverDetails(m))); err != nil {
		return MCPServer{}, err
	}
	return m, nil
}

// UpdateServer меняет параметры MCP-сервера, кроме slug, признаков и
// учётных данных. Смена адресата (схема, узел, порт адреса, корневые
// сертификаты) сбрасывает учётные данные и возвращает признак external:
// agents.manage — не право безопасности, и без сброса чужой секрет ушёл
// бы на новый адрес. Адрес http:// у сервера с insecure_http меняет
// только администратор безопасности с повторной проверкой (DM-40).
func (s *Service) UpdateServer(ctx context.Context, by By, id string, in ServerInput) (MCPServer, error) {
	return s.store.UpdateServer(ctx, s.orgID, id, func(m *MCPServer) (audit.Entry, error) {
		if err := s.checkServer(in, m.InsecureHTTP); err != nil {
			return audit.Entry{}, err
		}
		before := serverDetails(*m)
		old := *m
		in.apply(m)
		d := map[string]any{"before": before}
		if origin(old.URL) != origin(m.URL) || old.CAPEM != m.CAPEM {
			d["credential_reset"] = m.Credential != nil
			d["external_reset"] = !m.External
			m.Credential, m.External = nil, true
			if strings.HasPrefix(m.URL, "http:") {
				if !by.Security {
					return audit.Entry{}, ErrSecurityRequired
				}
				if err := by.confirm(ctx); err != nil {
					return audit.Entry{}, err
				}
				d["weakening"], d["weakening_reasons"] = true, []string{"mcp_insecure_http"}
			}
		}
		d["after"] = serverDetails(*m)
		m.UpdatedAt, m.UpdatedBy = s.now(), by.ref()
		return by.entry("mcp_server.update", "mcp_server", id, d), nil
	})
}

// origin — схема, узел и порт адреса в каноническом виде.
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	scheme, port := strings.ToLower(u.Scheme), u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[scheme]
	}
	return scheme + "://" + strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")) + ":" + port
}

// DeleteServer удаляет MCP-сервер, которого нет в списках агентов, вместе
// с его инструментами.
func (s *Service) DeleteServer(ctx context.Context, by By, id string) (MCPServer, error) {
	return s.store.DeleteServer(ctx, s.orgID, id, func(m MCPServer) (audit.Entry, error) {
		return by.entry("mcp_server.delete", "mcp_server", id, serverDetails(m)), nil
	})
}

// Server — MCP-сервер по ID.
func (s *Service) Server(ctx context.Context, id string) (MCPServer, error) {
	return s.store.Server(ctx, s.orgID, id)
}

// Servers — MCP-серверы организации по slug.
func (s *Service) Servers(ctx context.Context) ([]MCPServer, error) {
	return s.store.Servers(ctx, s.orgID)
}

// SetServerCredential шифрует и сохраняет учётные данные MCP-сервера (ЗИ.1):
// ключ данных, AAD mcp_servers|credential|<id>. Значение не попадает ни в
// ответ, ни в журнал.
func (s *Service) SetServerCredential(ctx context.Context, by By, id string, credential []byte) (MCPServer, error) {
	if s.box == nil {
		return MCPServer{}, ErrNoDataKey
	}
	if len(credential) == 0 || len(credential) > MaxCredential {
		return MCPServer{}, invalidf("credential — от 1 байта до 16 КиБ")
	}
	if strings.TrimSpace(string(credential)) == "" {
		return MCPServer{}, invalidf("credential — не может состоять из пробелов")
	}
	// Учётные данные уходят в заголовок: только видимые символы ASCII и
	// пробел, иначе возможна подмена заголовков (CR, LF).
	for _, b := range credential {
		if b < 0x20 || b > 0x7e {
			return MCPServer{}, invalidf("credential — только латиница, цифры и знаки ASCII без управляющих символов")
		}
	}
	cur, err := s.store.Server(ctx, s.orgID, id)
	if err != nil {
		return MCPServer{}, err
	}
	keyID, sealed, err := s.box.SealKey(ctx, credential, "mcp_servers", "credential", id)
	if err != nil {
		return MCPServer{}, err
	}
	return s.store.UpdateServer(ctx, s.orgID, id, func(m *MCPServer) (audit.Entry, error) {
		// Адрес или корни сменили параллельно: секрет вводили для прежнего
		// узла (4Н2 ревью 4.r1).
		if origin(m.URL) != origin(cur.URL) || m.CAPEM != cur.CAPEM {
			return audit.Entry{}, ErrServerChanged
		}
		now := s.now()
		replaced := m.Credential != nil
		m.Credential = &Sealed{Data: sealed, KeyID: keyID, Alg: s.box.Alg(), SetAt: now}
		m.UpdatedAt, m.UpdatedBy = now, by.ref()
		return by.entry("mcp_server.credentials_set", "mcp_server", id, map[string]any{"slug": m.Slug, "replaced": replaced}), nil
	})
}

// OpenServerCredential расшифровывает учётные данные MCP-сервера: только
// для пакета конфигурации шлюзу. Вызывающий затирает результат; nil —
// учётные данные не заданы.
func (s *Service) OpenServerCredential(ctx context.Context, m MCPServer) ([]byte, error) {
	if m.Credential == nil {
		return nil, nil
	}
	if s.box == nil {
		return nil, ErrNoDataKey
	}
	return s.box.OpenContext(ctx, m.Credential.KeyID, m.Credential.Data, "mcp_servers", "credential", m.ID)
}

// SecurityInput — признаки MCP-сервера, которые меняет только
// администратор безопасности (ADR-0023, разделы 1 и 9).
type SecurityInput struct {
	External     *bool
	InsecureHTTP *bool
	Reason       string
}

// SetServerSecurity меняет признаки external и insecure_http. Снятие
// external и разрешение http:// — ослабление защиты (DM-40) с повторной
// проверкой. insecure_http не снимается, пока адрес — http://.
func (s *Service) SetServerSecurity(ctx context.Context, by By, id string, in SecurityInput) (MCPServer, error) {
	reason := strings.TrimSpace(in.Reason)
	if errs := text("reason", reason, 1, maxComment); len(errs) > 0 {
		return MCPServer{}, invalid(errs...)
	}
	if in.External == nil && in.InsecureHTTP == nil {
		return MCPServer{}, invalidf("external — укажите external или insecure_http")
	}
	if !by.Security {
		return MCPServer{}, ErrSecurityRequired
	}
	m, err := s.store.UpdateServer(ctx, s.orgID, id, func(m *MCPServer) (audit.Entry, error) {
		before := serverDetails(*m)
		var reasons []string
		if in.External != nil && *in.External != m.External {
			if !*in.External {
				reasons = append(reasons, "mcp_external_removed")
			}
			m.External = *in.External
		}
		if in.InsecureHTTP != nil && *in.InsecureHTTP != m.InsecureHTTP {
			if *in.InsecureHTTP {
				reasons = append(reasons, "mcp_insecure_http")
			} else if strings.HasPrefix(m.URL, "http:") {
				return audit.Entry{}, invalidf("insecure_http — сначала смените адрес сервера на https://")
			}
			m.InsecureHTTP = *in.InsecureHTTP
		}
		after := serverDetails(*m)
		if before["external"] == after["external"] && before["insecure_http"] == after["insecure_http"] {
			return audit.Entry{}, errUnchanged
		}
		if len(reasons) > 0 {
			if err := by.confirm(ctx); err != nil {
				return audit.Entry{}, err
			}
		}
		m.UpdatedAt, m.UpdatedBy = s.now(), by.ref()
		return by.entry("mcp_server.security_changed", "mcp_server", id, map[string]any{"slug": m.Slug,
			"before": map[string]any{"external": before["external"], "insecure_http": before["insecure_http"]},
			"after":  map[string]any{"external": m.External, "insecure_http": m.InsecureHTTP},
			"reason": reason, "weakening": len(reasons) > 0, "weakening_reasons": reasons}), nil
	})
	if errors.Is(err, errUnchanged) {
		return s.store.Server(ctx, s.orgID, id)
	}
	return m, err
}
