package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth/oidc"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Настройки входа через внешний IdP по OpenID Connect (ТЗ 5.14, ИАФ.7;
// ADR-0025, задача 4.17).

const (
	// Место хранения шифротекста секрета клиента (AAD: таблица, столбец, ID организации).
	idpTable        = "oidc_settings"
	idpSecretColumn = "client_secret"
	// externalPassword — заглушка хеша пароля внешней записи (миграция
	// 0051): её не принимает разборщик PHC, и она не попадает в проверку пароля.
	externalPassword = "!external"
	// Пределы настроек; те же — в CHECK миграции 0051.
	maxIdPName       = 64
	maxIdPURL        = 512
	maxClientID      = 256
	maxClientSecret  = 1024
	maxIdPCAPEM      = 64 << 10
	maxIdPList       = 16
	maxIdPListItem   = 256
	maxScopeLen      = 64
	maxClaimNameLen  = 64
	maxGroupRoles    = 200
	maxGroupNameLen  = 256
	defaultGroupsKey = "groups"
)

var (
	// ErrIdPNotConfigured — вход через IdP не настроен или отключён.
	ErrIdPNotConfigured = errors.New("вход через IdP не настроен")
	// ErrIdPUnavailable — на сервере нет клиента IdP или ключа данных.
	ErrIdPUnavailable = errors.New("вход через IdP недоступен на сервере")
	// ErrExternalUser — действие недоступно внешней учётной записи: у неё
	// нет пароля и TOTP консоли (ADR-0025, 1.2, 3.10).
	ErrExternalUser = errors.New("действие недоступно учётной записи внешнего IdP")
	// ErrTooManyLogins — незавершённых входов через IdP больше предела.
	ErrTooManyLogins = errors.New("слишком много незавершённых входов через IdP")
	// ErrIdPChanged — настройки IdP изменились или удалены, пока шёл вход.
	ErrIdPChanged = errors.New("настройки IdP изменились во время входа")
)

// GroupRole — строка таблицы «группа IdP → роль» (ADR-0025, 1.4).
type GroupRole struct {
	Group string
	Role  Role
}

// IdPSettings — настройки IdP организации. Секрет клиента — только
// шифротекстом под ключом данных.
type IdPSettings struct {
	Enabled     bool
	DisplayName string
	Issuer      string
	ClientID    string
	// ConsoleURL — адрес консоли без пути: из него строится адрес возврата.
	ConsoleURL  string
	CAPEM       string
	Scopes      []string
	GroupsClaim string
	RequiredACR []string
	RequiredAMR []string
	GroupRoles  []GroupRole
	Version     int
	UpdatedAt   time.Time
	UpdatedBy   string
	// SecretKeyID и Secret — шифротекст секрета клиента и версия ключа данных.
	SecretKeyID string
	Secret      []byte
}

// MFARequirement — в настройке задано требование второго фактора (acr/amr).
func (s IdPSettings) MFARequirement() bool { return len(s.RequiredACR)+len(s.RequiredAMR) > 0 }

// IdPInput — новые настройки IdP. Пустой ClientSecret — оставить прежний.
type IdPInput struct {
	Enabled      bool
	DisplayName  string
	Issuer       string
	ClientID     string
	ClientSecret string
	ConsoleURL   string
	CAPEM        string
	Scopes       []string
	GroupsClaim  string
	RequiredACR  []string
	RequiredAMR  []string
	GroupRoles   []GroupRole
}

// IdPStore — настройки IdP, незавершённые входы и внешние пользователи.
type IdPStore interface {
	// IdPSettings — настройки организации; нет — ErrIdPNotConfigured.
	IdPSettings(ctx context.Context, orgID string) (IdPSettings, error)
	// SaveIdPSettings сохраняет настройки с таблицей групп, увеличивает
	// версию и в той же транзакции завершает сессии внешних пользователей
	// (RevokeIdPChanged; их число — revoked_sessions в rec) и пишет rec.
	SaveIdPSettings(ctx context.Context, orgID string, st IdPSettings, now time.Time, rec audit.Entry) error
	// DeleteIdPSettings удаляет настройки (нет — ErrIdPNotConfigured) и
	// завершает сессии внешних пользователей так же.
	DeleteIdPSettings(ctx context.Context, orgID string, now time.Time, rec audit.Entry) error
	// StartOIDCLogin сохраняет хеш незавершённого входа, удаляя истёкшие;
	// незавершённых больше max — ErrTooManyLogins.
	StartOIDCLogin(ctx context.Context, orgID string, idHash []byte, now, expires time.Time, max int) error
	// TakeOIDCLogin удаляет незавершённый вход (одноразовость); нет или
	// истёк — ErrNotFound.
	TakeOIDCLogin(ctx context.Context, orgID string, idHash []byte, now time.Time) error
	// UserByIdentity — внешняя учётная запись по издателю и sub; нет — ErrNotFound.
	UserByIdentity(ctx context.Context, orgID, issuer, subject string) (User, error)
	// ExternalLogin создаёт или обновляет внешнюю учётную запись и открывает
	// сессию одной транзакцией (ExternalLoginTx).
	ExternalLogin(ctx context.Context, in ExternalLoginTx) (User, error)
}

// ExternalLoginTx — вход внешнего пользователя. Хранилище под блокировкой
// строки: находит запись по (Issuer, Subject) или создаёт её (логин Login,
// если свободен, иначе FallbackLogin; ID — NewUserID); деактивированная —
// ErrDeactivated; роль меняет на Role, если она другая (последнего
// активного администратора безопасности — ErrLastAdmin; прежние сессии
// завершаются с RevokeIdPRoleChanged), отмечает вход и сохраняет Session
// с лимитом SessionLimit. Записи аудита — Records(u, created, prevRole).
type ExternalLoginTx struct {
	OrgID string
	// SettingsVersion — версия настроек IdP, по которым проверен вход:
	// хранилище сверяет её под блокировкой строки настроек, иначе
	// ErrIdPChanged (настройки сменили или удалили, пока шёл обмен кода).
	SettingsVersion int
	Source          AuthSource
	Issuer          string
	Subject         string
	Login           string
	FallbackLogin   string
	DisplayName     string
	Role            Role
	NewUserID       string
	Session         Session
	SessionLimit    int
	Now             time.Time
	Records         func(u User, created bool, prevRole Role) []audit.Entry
}

// WithOIDC подключает вход через IdP: хранилище настроек и клиент. Без
// него эндпоинты IdP отвечают «не настроено».
func WithOIDC(st IdPStore, c *oidc.Client) Option {
	return func(s *Service) { s.idp, s.oidc = st, c }
}

// IdPConfigured — подключён ли вход через IdP на сервере.
func (s *Service) IdPConfigured() bool { return s.idp != nil && s.oidc != nil }

// IdP — настройки IdP (без секрета клиента).
func (s *Service) IdP(ctx context.Context) (IdPSettings, error) {
	if !s.IdPConfigured() {
		return IdPSettings{}, ErrIdPUnavailable
	}
	st, err := s.idp.IdPSettings(ctx, s.orgID)
	if err != nil {
		return IdPSettings{}, err
	}
	st.Secret, st.SecretKeyID = nil, ""
	return st, nil
}

// LoginOption — способ входа через IdP для экрана входа (без аутентификации).
type LoginOption struct {
	Enabled     bool
	DisplayName string
}

// IdPLoginOption — показывать ли кнопку «Войти через …».
func (s *Service) IdPLoginOption(ctx context.Context) (LoginOption, error) {
	if !s.IdPConfigured() {
		return LoginOption{}, nil
	}
	st, err := s.idp.IdPSettings(ctx, s.orgID)
	if errors.Is(err, ErrIdPNotConfigured) {
		return LoginOption{}, nil
	}
	if err != nil {
		return LoginOption{}, err
	}
	return LoginOption{Enabled: st.Enabled, DisplayName: st.DisplayName}, nil
}

// requireLocal — повторная проверка действия над входом возможна только
// локальной записью (ADR-0025, 1.6): внешний IdP не меняет свои же настройки.
func requireLocal(c Caller) error {
	if c.User.External() {
		return ErrExternalUser
	}
	return nil
}

// SetIdP сохраняет настройки IdP (изменение доступа, ADR-0025, 1.6):
// повторная проверка паролем или кодом TOTP локальной записи, проверка
// роли каждой группы, при включении — проверка IdP (discovery и JWKS).
// Сессии внешних пользователей завершаются: роли пересчитаются при входе.
// Аудит — auth.idp_changed со значениями до и после, без секрета;
// расширение доступа отмечается weakening (DM-40).
func (s *Service) SetIdP(ctx context.Context, by Caller, in IdPInput, password, code string) (IdPSettings, error) {
	if !s.IdPConfigured() || s.box == nil {
		return IdPSettings{}, ErrIdPUnavailable
	}
	if err := requireLocal(by); err != nil {
		return IdPSettings{}, err
	}
	next, err := s.cleanIdP(ctx, in)
	if err != nil {
		return IdPSettings{}, err
	}
	// Роль по группам не шире прав того, кто её назначает (УПД.2): иначе
	// держатель своей роли с auth_idp.manage выдал бы себе через IdP роль
	// администратора безопасности.
	if err := s.idpRolesCovered(ctx, by, next.GroupRoles); err != nil {
		return IdPSettings{}, err
	}
	before, err := s.idp.IdPSettings(ctx, s.orgID)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrIdPNotConfigured) {
		return IdPSettings{}, err
	}
	if in.ClientSecret == "" && !exists {
		return IdPSettings{}, &InputError{"client_secret", "Укажите секрет клиента, выданный IdP."}
	}
	// Сохранённый секрет не уходит на другой узел: при смене издателя или
	// корней доверия его нужно ввести заново (ревью 4.16, замечание 2).
	if in.ClientSecret == "" && (before.Issuer != next.Issuer || before.CAPEM != next.CAPEM) {
		return IdPSettings{}, &InputError{"client_secret", "Издатель или корневые сертификаты изменились: введите секрет клиента заново."}
	}
	if err := s.reauthenticate(ctx, by, password, code, "auth.idp_changed"); err != nil {
		return IdPSettings{}, err
	}
	secret := in.ClientSecret
	if secret == "" {
		plain, err := s.box.Open(before.SecretKeyID, before.Secret, idpTable, idpSecretColumn, s.orgID)
		if err != nil {
			return IdPSettings{}, err
		}
		secret = string(plain)
		next.SecretKeyID, next.Secret = before.SecretKeyID, before.Secret
	} else {
		if next.SecretKeyID, next.Secret, err = s.box.SealKey(ctx, []byte(in.ClientSecret), idpTable, idpSecretColumn, s.orgID); err != nil {
			return IdPSettings{}, err
		}
	}
	if next.Enabled {
		if err := s.oidc.Check(ctx, s.oidcConfig(next, secret)); err != nil {
			return IdPSettings{}, &InputError{"issuer", idpCheckReason(err)}
		}
	}
	now := s.clock()
	next.UpdatedAt, next.UpdatedBy = now, by.User.ID
	next.Version = before.Version + 1
	details := map[string]any{"after": s.idpDetails(next), "client_auth_changed": in.ClientSecret != "",
		"ca_pem_changed": exists && before.CAPEM != next.CAPEM}
	if exists {
		details["before"] = s.idpDetails(before)
	}
	if reasons := idpWeakened(before, exists, next); len(reasons) > 0 {
		details["weakening"], details["weakening_reasons"] = true, reasons
	}
	rec := s.entry(by.actor(), by.SourceIP, "auth.idp_changed", audit.Object{Type: "idp", ID: s.orgID}, audit.ResultSuccess, details)
	if err := s.idp.SaveIdPSettings(ctx, s.orgID, next, now, rec); err != nil {
		return IdPSettings{}, err
	}
	next.Secret, next.SecretKeyID = nil, ""
	return next, nil
}

// DeleteIdP отключает вход через IdP и удаляет его настройки; сессии
// внешних пользователей завершаются, их записи и аудит остаются.
func (s *Service) DeleteIdP(ctx context.Context, by Caller, password, code string) error {
	if !s.IdPConfigured() {
		return ErrIdPUnavailable
	}
	if err := requireLocal(by); err != nil {
		return err
	}
	before, err := s.idp.IdPSettings(ctx, s.orgID)
	if err != nil {
		return err
	}
	if err := s.reauthenticate(ctx, by, password, code, "auth.idp_disabled"); err != nil {
		return err
	}
	rec := s.entry(by.actor(), by.SourceIP, "auth.idp_disabled", audit.Object{Type: "idp", ID: s.orgID}, audit.ResultSuccess,
		map[string]any{"before": s.idpDetails(before)})
	return s.idp.DeleteIdPSettings(ctx, s.orgID, s.clock(), rec)
}

// idpCheckReason — текст причины неудачной проверки IdP для администратора.
func idpCheckReason(err error) string {
	switch oidc.ErrorCode(err) {
	case oidc.CodeBlocked:
		return "Адрес IdP запрещён: loopback, link-local и адреса метаданных облака недоступны."
	case oidc.CodeTLS:
		return "Сертификат IdP не прошёл проверку: проверьте корневые сертификаты и имя узла."
	case oidc.CodeTimeout, oidc.CodeNetwork:
		return "IdP недоступен с сервера: проверьте адрес и сетевой доступ."
	case oidc.CodeConfig:
		return "Корневые сертификаты IdP не разобраны: нужен PEM с сертификатом УЦ."
	case oidc.CodeJWKS:
		return "IdP не отдал ключи подписи (JWKS) RS256, ES256 или EdDSA."
	case oidc.CodeRedirect, oidc.CodeStatus, oidc.CodeTooLarge, oidc.CodeResponse:
		return "IdP ответил не по OpenID Connect: issuer в discovery должен совпадать с адресом, конечные точки — https на том же узле."
	}
	return "Проверка IdP не пройдена."
}

func (s *Service) oidcConfig(st IdPSettings, secret string) oidc.Config {
	return oidc.Config{Issuer: st.Issuer, ClientID: st.ClientID, ClientSecret: secret, RootsPEM: []byte(st.CAPEM),
		RedirectURI: st.ConsoleURL + oidc.CallbackPath, Scopes: st.Scopes, ACRValues: st.RequiredACR}
}

// singleFactorAMR — значения amr (RFC 8176), которые сами по себе не второй
// фактор: пароль, PIN, контрольные вопросы, вход Windows, местоположение,
// присутствие пользователя.
var singleFactorAMR = []string{"pwd", "pin", "kba", "wia", "geo", "user"}

// cleanIdP проверяет и нормализует настройки.
func (s *Service) cleanIdP(ctx context.Context, in IdPInput) (IdPSettings, error) {
	out := IdPSettings{Enabled: in.Enabled}
	name, ok := CleanDisplayName(in.DisplayName)
	if !ok || utf8.RuneCountInString(name) > maxIdPName {
		return out, &InputError{"display_name", "Название для кнопки входа — от 1 до 64 символов."}
	}
	out.DisplayName = name
	if err := oidc.ValidateIssuer(in.Issuer); err != nil {
		return out, &InputError{"issuer", "Адрес издателя: " + err.Error() + "."}
	}
	out.Issuer = in.Issuer
	if in.ClientID == "" || len(in.ClientID) > maxClientID || !printable(in.ClientID) {
		return out, &InputError{"client_id", "Идентификатор клиента — от 1 до 256 печатных символов ASCII."}
	}
	out.ClientID = in.ClientID
	if len(in.ClientSecret) > maxClientSecret || !printable(in.ClientSecret) {
		return out, &InputError{"client_secret", "Секрет клиента — до 1024 печатных символов ASCII."}
	}
	cu, err := cleanConsoleURL(in.ConsoleURL)
	if err != nil {
		return out, &InputError{"console_url", "Адрес консоли — https://имя[:порт] без пути, как его открывают пользователи."}
	}
	out.ConsoleURL = cu
	if in.CAPEM == "" || len(in.CAPEM) > maxIdPCAPEM {
		return out, &InputError{"ca_pem", "Укажите корневые сертификаты IdP в PEM (до 64 КиБ)."}
	}
	tp, err := s.provider.TLS()
	if err != nil {
		return out, err
	}
	if _, err := tp.ClientConfig([]byte(in.CAPEM)); err != nil {
		return out, &InputError{"ca_pem", "Корневые сертификаты не разобраны: нужен PEM с сертификатом УЦ."}
	}
	out.CAPEM = in.CAPEM
	if out.Scopes, err = cleanList(in.Scopes, maxScopeLen, scopeToken); err != nil {
		return out, &InputError{"scopes", "Области — до 16 значений без пробелов и кавычек, до 64 символов."}
	}
	out.Scopes = slices.DeleteFunc(out.Scopes, func(v string) bool { return v == "openid" })
	out.GroupsClaim = in.GroupsClaim
	if out.GroupsClaim == "" {
		out.GroupsClaim = defaultGroupsKey
	}
	if len(out.GroupsClaim) > maxClaimNameLen || !claimName(out.GroupsClaim) {
		return out, &InputError{"groups_claim", "Имя утверждения с группами — латиница, цифры, «_», «-», «.», «:», «/», до 64 символов."}
	}
	if out.RequiredACR, err = cleanList(in.RequiredACR, maxIdPListItem, printable); err != nil {
		return out, &InputError{"required_acr", "Значения acr — до 16 строк печатных символов ASCII до 256 символов."}
	}
	if out.RequiredAMR, err = cleanList(in.RequiredAMR, maxIdPListItem, printable); err != nil {
		return out, &InputError{"required_amr", "Значения amr — до 16 строк печатных символов ASCII до 256 символов."}
	}
	// Однофакторные значения RFC 8176 (4Н18 ревью 4.r2): достаточно одного
	// совпадения, поэтому «pwd» в списке засчитал бы вход по одному паролю
	// как второй фактор.
	if v := slices.IndexFunc(out.RequiredAMR, func(v string) bool { return slices.Contains(singleFactorAMR, v) }); v >= 0 {
		return out, &InputError{"required_amr", "Значение amr «" + out.RequiredAMR[v] + "» означает один фактор: укажите значения второго " +
			"фактора, например «otp», «hwk» или «mfa»."}
	}
	if len(in.GroupRoles) > maxGroupRoles {
		return out, &InputError{"group_roles", "Не больше 200 строк сопоставления групп."}
	}
	if in.Enabled && len(in.GroupRoles) == 0 {
		return out, &InputError{"group_roles", "Сопоставьте с ролью хотя бы одну группу: без этого никто не войдёт."}
	}
	seen := map[string]bool{}
	for _, gr := range in.GroupRoles {
		if gr.Group == "" || len(gr.Group) > maxGroupNameLen || !utf8.ValidString(gr.Group) || hasControl(gr.Group) {
			return out, &InputError{"group_roles", "Имя группы — от 1 до 256 символов без управляющих."}
		}
		if seen[gr.Group] {
			return out, &InputError{"group_roles", "Группа «" + gr.Group + "» указана дважды: у группы одна роль."}
		}
		seen[gr.Group] = true
		if _, err := s.RoleDef(ctx, gr.Role); errors.Is(err, ErrRoleNotFound) {
			return out, &InputError{"group_roles", "Роли «" + string(gr.Role) + "» нет."}
		} else if err != nil {
			return out, err
		}
		out.GroupRoles = append(out.GroupRoles, gr)
	}
	return out, nil
}

// cleanConsoleURL — адрес консоли: https, без пути, параметров и учётных данных.
func cleanConsoleURL(s string) (string, error) {
	errText := errors.New("адрес консоли — https://имя[:порт] без пути, как его открывают пользователи")
	if s == "" || len(s) > maxIdPURL {
		return "", errText
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return "", errText
	}
	return "https://" + u.Host, nil
}

// cleanList — список до maxIdPList значений длиной 1–maxLen, каждое
// проходит ok; повторы удаляются с сохранением порядка.
func cleanList(in []string, maxLen int, ok func(string) bool) ([]string, error) {
	if len(in) > maxIdPList {
		return nil, errors.New("слишком много значений")
	}
	out := []string{}
	for _, v := range in {
		if v == "" || len(v) > maxLen || !ok(v) {
			return nil, errors.New("неверное значение")
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

// printable — только печатные символы ASCII.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// scopeToken — значение scope (RFC 6749, 3.3): печатные ASCII без пробела, «"» и «\».
func scopeToken(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func claimName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_-.:/", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return true
		}
	}
	return false
}

// idpDetails — настройки для подробностей аудита: без секрета; вместо PEM
// корней — его хеш профиля (замена корней видна в записи).
func (s *Service) idpDetails(st IdPSettings) map[string]any {
	groups := make([]any, 0, len(st.GroupRoles))
	for _, g := range st.GroupRoles {
		groups = append(groups, map[string]any{"group": g.Group, "role": string(g.Role)})
	}
	return map[string]any{"enabled": st.Enabled, "display_name": st.DisplayName, "issuer": st.Issuer,
		"client_id": st.ClientID, "console_url": st.ConsoleURL, "scopes": st.Scopes, "groups_claim": st.GroupsClaim,
		"required_acr": st.RequiredACR, "required_amr": st.RequiredAMR, "group_roles": groups,
		"ca_pem_digest": hex.EncodeToString(s.hasher.Sum([]byte(st.CAPEM)))}
}

// idpRolesCovered — каждая роль таблицы групп не шире прав вызывающего
// (УПД.2); иначе отказ с записью в аудит.
func (s *Service) idpRolesCovered(ctx context.Context, by Caller, groups []GroupRole) error {
	return s.groupRolesCovered(ctx, by, groups, "auth.idp_changed", "idp")
}

// idpWeakened — изменения, расширяющие доступ (DM-40): вход через IdP
// включён, требование второго фактора ослаблено, группам дана роль,
// сменился издатель или клиент, заменены корни доверия к IdP или
// утверждение с группами.
func idpWeakened(before IdPSettings, exists bool, after IdPSettings) []any {
	var reasons []any
	if after.Enabled && (!exists || !before.Enabled) {
		reasons = append(reasons, "idp_enabled")
	}
	if exists && before.MFARequirement() && (!after.MFARequirement() ||
		!subset(after.RequiredACR, before.RequiredACR) || !subset(after.RequiredAMR, before.RequiredAMR)) {
		reasons = append(reasons, "idp_mfa_relaxed")
	}
	for _, g := range after.GroupRoles {
		if !exists || !slices.Contains(before.GroupRoles, g) {
			reasons = append(reasons, "idp_group_roles_added")
			break
		}
	}
	if exists && (before.Issuer != after.Issuer || before.ClientID != after.ClientID) {
		reasons = append(reasons, "idp_issuer_changed")
	}
	if exists && before.CAPEM != after.CAPEM {
		reasons = append(reasons, "idp_trust_changed")
	}
	if exists && before.GroupsClaim != after.GroupsClaim {
		reasons = append(reasons, "idp_groups_claim_changed")
	}
	return reasons
}

// subset — каждое значение a есть в b.
func subset(a, b []string) bool {
	for _, v := range a {
		if !slices.Contains(b, v) {
			return false
		}
	}
	return true
}

// IdPKeys — издатель настроенного IdP и его ключи подписи для пакета
// конфигурации шлюзов (задача 4.21, ADR-0025, 4.1): шлюз проверяет JWT
// пользователей приложений по ним и в IdP не ходит. Ключи нужны шлюзам и
// при выключенном входе в консоль через IdP; нет настроек или вход через
// IdP не подключён на сервере — пустой издатель без ошибки.
func (s *Service) IdPKeys(ctx context.Context) (string, *aisecCrypto.JWKS, error) {
	if !s.IdPConfigured() {
		return "", nil, nil
	}
	st, err := s.idp.IdPSettings(ctx, s.orgID)
	if errors.Is(err, ErrIdPNotConfigured) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	keys, err := s.oidc.KeysForBundle(ctx, s.oidcConfig(st, ""))
	if err != nil {
		return "", nil, err
	}
	return st.Issuer, keys, nil
}
