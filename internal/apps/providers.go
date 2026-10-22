package apps

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"unicode"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/config"
)

// ProviderInput — создание и изменение провайдера. Признак «внешний» и
// учётные данные задаются отдельными действиями.
type ProviderInput struct {
	Slug              string // только при создании
	Name              string
	Type              string
	BaseURL           string
	CAPEM             string
	AuthURL           string
	Scope             string
	FolderID          string
	ConnectTimeout    int
	HeaderTimeout     int
	ResponseTimeout   int
	StreamIdleTimeout int
}

// noControl — в строке нет управляющих символов (переводы строк в
// названиях ломают журналы и интерфейс).
func noControl(field, v string) error {
	if strings.IndexFunc(v, unicode.IsControl) >= 0 {
		return errors.New(field + " — без управляющих символов")
	}
	return nil
}

func (s *Service) checkProvider(in ProviderInput) error {
	var errs []error
	if err := textLen("name", in.Name, 1, maxName); err != nil {
		errs = append(errs, err)
	}
	if err := noControl("name", in.Name); err != nil {
		errs = append(errs, err)
	}
	for _, u := range []struct{ name, v string }{{"base_url", in.BaseURL}, {"auth_url", in.AuthURL}} {
		if len(u.v) > maxURL {
			errs = append(errs, errors.New(u.name+" — не длиннее 2048 байт"))
		}
	}
	p := config.ProviderParams{Type: in.Type, BaseURL: in.BaseURL, AuthURL: in.AuthURL, Scope: in.Scope, FolderID: in.FolderID}
	for _, t := range []struct {
		name string
		v    int
	}{{"connect_timeout", in.ConnectTimeout}, {"header_timeout", in.HeaderTimeout},
		{"response_timeout", in.ResponseTimeout}, {"stream_idle_timeout", in.StreamIdleTimeout}} {
		if t.v < 0 || t.v > MaxTimeoutSeconds {
			errs = append(errs, errors.New(t.name+" — от 0 до 600 секунд (0 — по умолчанию)"))
		}
	}
	errs = append(errs, p.Check()...)
	switch in.Type {
	case config.ProviderGigaChat:
		if in.Scope == "" {
			errs = append(errs, errors.New("для GigaChat нужен scope"))
		}
	case config.ProviderYandexGPT:
		if in.FolderID == "" {
			errs = append(errs, errors.New("для YandexGPT нужен folder_id"))
		}
	}
	if in.Type != config.ProviderGigaChat && (in.Scope != "" || in.AuthURL != "") {
		errs = append(errs, errors.New("scope и auth_url задаются только для GigaChat"))
	}
	if in.Type != config.ProviderYandexGPT && in.FolderID != "" {
		errs = append(errs, errors.New("folder_id задаётся только для YandexGPT"))
	}
	// Корневые сертификаты разбирает криптопрофиль (crypto/x509 — только в
	// internal/crypto): не разобрался ни один — отказ.
	switch {
	case in.CAPEM == "":
		errs = append(errs, errors.New("ca_pem — корневые сертификаты провайдера в PEM обязательны"))
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

func (in ProviderInput) apply(p *Provider) {
	p.Name, p.Type, p.BaseURL, p.CAPEM = in.Name, in.Type, strings.TrimSuffix(in.BaseURL, "/"), in.CAPEM
	p.AuthURL, p.Scope, p.FolderID = in.AuthURL, in.Scope, in.FolderID
	p.ConnectTimeout, p.HeaderTimeout, p.ResponseTimeout, p.StreamIdleTimeout =
		in.ConnectTimeout, in.HeaderTimeout, in.ResponseTimeout, in.StreamIdleTimeout
}

// providerDetails — сведения о провайдере для аудита: без учётных данных и
// без сертификатов (только их размер).
func providerDetails(p Provider) map[string]any {
	return map[string]any{
		"slug": p.Slug, "name": p.Name, "type": p.Type, "base_url": p.BaseURL, "auth_url": p.AuthURL,
		"scope": p.Scope, "folder_id": p.FolderID, "ca_pem_bytes": len(p.CAPEM), "external": p.External,
		"connect_timeout": p.ConnectTimeout, "header_timeout": p.HeaderTimeout,
		"response_timeout": p.ResponseTimeout, "stream_idle_timeout": p.StreamIdleTimeout,
	}
}

// CreateProvider создаёт провайдера. Новый провайдер всегда внешний (ТЗ 5.4).
func (s *Service) CreateProvider(ctx context.Context, by By, in ProviderInput) (Provider, error) {
	errs := []error{}
	if !config.ValidID(in.Slug) {
		errs = append(errs, errors.New("slug — строчные латинские буквы, цифры и дефис, до 63 символов"))
	}
	if err := s.checkProvider(in); err != nil {
		var ie *InputError
		if errors.As(err, &ie) {
			errs = append(errs, ie.Errs...)
		}
	}
	if len(errs) > 0 {
		return Provider{}, invalid(errs...)
	}
	n, err := s.store.CountProviders(ctx, s.orgID)
	if err != nil {
		return Provider{}, err
	}
	if n >= MaxProviders {
		return Provider{}, ErrTooMany
	}
	id, err := s.newID()
	if err != nil {
		return Provider{}, err
	}
	now := s.now()
	p := Provider{ID: id, OrgID: s.orgID, Slug: in.Slug, External: true,
		CreatedAt: now, CreatedBy: by.ref(), UpdatedAt: now, UpdatedBy: by.ref()}
	in.apply(&p)
	if err := s.store.CreateProvider(ctx, p, by.entry("provider.create", "provider", id, providerDetails(p))); err != nil {
		return Provider{}, err
	}
	return p, nil
}

// UpdateProvider меняет параметры провайдера, кроме slug, признака
// «внешний» и учётных данных. Смена адресата — узла (схема, хост, порт)
// base_url или auth_url, корневых сертификатов или типа — сбрасывает
// учётные данные и возвращает признак «внешний» (В14 ревью 2.r3b):
// providers.manage — не право безопасности, и без сброса оно отправило бы
// незамаскированные данные и чужой секрет на новый адрес.
func (s *Service) UpdateProvider(ctx context.Context, by By, id string, in ProviderInput) (Provider, error) {
	if err := s.checkProvider(in); err != nil {
		return Provider{}, err
	}
	return s.store.UpdateProvider(ctx, s.orgID, id, func(p *Provider) (audit.Entry, error) {
		before := providerDetails(*p)
		old := *p
		in.apply(p)
		d := map[string]any{"before": before, "after": providerDetails(*p)}
		if retargeted(old, *p) {
			d["credential_reset"] = p.Credential != nil
			d["external_reset"] = !p.External
			p.Credential, p.External = nil, true
			d["after"] = providerDetails(*p)
		}
		p.UpdatedAt, p.UpdatedBy = s.now(), by.ref()
		return by.entry("provider.update", "provider", id, d), nil
	})
}

// retargeted — у провайдера сменился адресат: тип, корневые сертификаты
// или узел base_url либо auth_url.
func retargeted(a, b Provider) bool {
	return a.Type != b.Type || a.CAPEM != b.CAPEM || origin(a.BaseURL) != origin(b.BaseURL) || origin(a.AuthURL) != origin(b.AuthURL)
}

// origin — схема, хост и порт адреса в каноническом виде (порт https по
// умолчанию — 443). Неразбираемый адрес сравнивается как есть.
func origin(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	scheme, port := strings.ToLower(u.Scheme), u.Port()
	if port == "" && scheme == "https" {
		port = "443"
	}
	return scheme + "://" + strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")) + ":" + port
}

// DeleteProvider удаляет провайдера без приложений (в том числе архивных).
func (s *Service) DeleteProvider(ctx context.Context, by By, id string) (Provider, error) {
	return s.store.DeleteProvider(ctx, s.orgID, id, func(p Provider) (audit.Entry, error) {
		return by.entry("provider.delete", "provider", id, providerDetails(p)), nil
	})
}

// Provider — провайдер по ID.
func (s *Service) Provider(ctx context.Context, id string) (Provider, error) {
	return s.store.Provider(ctx, s.orgID, id)
}

// Providers — провайдеры организации по slug.
func (s *Service) Providers(ctx context.Context) ([]Provider, error) {
	return s.store.Providers(ctx, s.orgID)
}

// SetCredential шифрует и сохраняет учётные данные провайдера (ЗИ.1):
// ключ данных, AAD providers|credential|<id> (Р4). Значение не попадает ни
// в ответ, ни в журнал.
func (s *Service) SetCredential(ctx context.Context, by By, id string, credential []byte) (Provider, error) {
	if s.box == nil {
		return Provider{}, ErrNoDataKey
	}
	if len(credential) == 0 || len(credential) > MaxCredential {
		return Provider{}, invalidf("credential — от 1 байта до 16 КиБ")
	}
	if strings.TrimSpace(string(credential)) == "" {
		return Provider{}, invalidf("credential — не может состоять из пробелов")
	}
	// Учётные данные уходят в заголовок Authorization: только видимые
	// символы ASCII и пробел, иначе возможна подмена заголовков (CR, LF).
	for _, b := range credential {
		if b < 0x20 || b > 0x7e {
			return Provider{}, invalidf("credential — только латиница, цифры и знаки ASCII без управляющих символов")
		}
	}
	if _, err := s.store.Provider(ctx, s.orgID, id); err != nil {
		return Provider{}, err
	}
	keyID, sealed, err := s.box.SealKey(ctx, credential, "providers", "credential", id)
	if err != nil {
		return Provider{}, err
	}
	return s.store.UpdateProvider(ctx, s.orgID, id, func(p *Provider) (audit.Entry, error) {
		now := s.now()
		replaced := p.Credential != nil
		p.Credential = &Sealed{Data: sealed, KeyID: keyID, Alg: s.box.Alg(), SetAt: now}
		p.UpdatedAt, p.UpdatedBy = now, by.ref()
		return by.entry("provider.credentials_set", "provider", id, map[string]any{"slug": p.Slug, "replaced": replaced}), nil
	})
}

// OpenCredential расшифровывает учётные данные провайдера: только для
// пакета конфигурации шлюзу (задача 2.13). Вызывающий затирает результат.
func (s *Service) OpenCredential(ctx context.Context, id string) ([]byte, error) {
	if s.box == nil {
		return nil, ErrNoDataKey
	}
	p, err := s.store.Provider(ctx, s.orgID, id)
	if err != nil {
		return nil, err
	}
	if p.Credential == nil {
		return nil, ErrNoCredential
	}
	return s.box.OpenContext(ctx, p.Credential.KeyID, p.Credential.Data, "providers", "credential", p.ID)
}

// SetExternal ставит или снимает признак «внешний» (ТЗ 5.4). Снятие —
// ослабление защиты (DM-40): в режиме monitor данные к провайдеру больше не
// маскируются, поэтому оно требует повторной проверки (Н32 ревью 2.r3b).
// Право на маршрут — только у администратора безопасности.
func (s *Service) SetExternal(ctx context.Context, by By, id string, external bool, reason string) (Provider, error) {
	reason = strings.TrimSpace(reason)
	if err := textLen("reason", reason, 1, maxReason); err != nil {
		return Provider{}, invalid(err)
	}
	if err := noControl("reason", reason); err != nil {
		return Provider{}, invalid(err)
	}
	p, err := s.store.UpdateProvider(ctx, s.orgID, id, func(p *Provider) (audit.Entry, error) {
		if p.External == external {
			return audit.Entry{}, errUnchanged
		}
		if !external {
			if err := by.confirm(ctx); err != nil {
				return audit.Entry{}, err
			}
		}
		p.External = external
		p.UpdatedAt, p.UpdatedBy = s.now(), by.ref()
		return by.entry("provider.external_changed", "provider", id, map[string]any{
			"slug": p.Slug, "before": !external, "after": external, "reason": reason, "weakening": !external}), nil
	})
	if errors.Is(err, errUnchanged) {
		return s.store.Provider(ctx, s.orgID, id)
	}
	return p, err
}

// errUnchanged — fn отказалась от изменения: хранилище откатывает
// транзакцию без записи аудита.
var errUnchanged = errors.New("без изменений")
