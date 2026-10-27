package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth/ldap"
)

// Настройки входа по учётной записи каталога LDAP (ТЗ 5.14, ИАФ.7;
// ADR-0025, раздел 2; задача 4.16).

const (
	// Место хранения шифротекста пароля сервисной учётной записи (AAD:
	// таблица, столбец, ID организации).
	ldapTable        = "ldap_settings"
	ldapSecretColumn = "bind_password"
	// LDAPIssuer — «издатель» записей каталога в паре (издатель,
	// идентификатор): один каталог на установку, идентификаторы
	// (entryUUID, objectGUID и т. п.) уникальны.
	LDAPIssuer = "ldap"
	// Пределы настроек; те же — в CHECK миграции 0055.
	maxBindPassword    = 1024
	maxLDAPGroupDN     = 1024
	defaultLDAPDisplay = "displayName"
)

var (
	// ErrLDAPNotConfigured — вход через каталог не настроен или отключён.
	ErrLDAPNotConfigured = errors.New("вход через каталог LDAP не настроен")
	// ErrLDAPUnavailable — на сервере нет клиента каталога или ключа данных.
	ErrLDAPUnavailable = errors.New("вход через каталог LDAP недоступен на сервере")
)

// LDAPSettings — настройки каталога организации. Пароль сервисной учётной
// записи — только шифротекстом под ключом данных.
type LDAPSettings struct {
	Enabled bool
	// URL — ldaps://узел[:порт] или ldap://узел[:порт] со StartTLS.
	URL              string
	CAPEM            string
	BindDN           string
	UserBaseDN       string
	UserFilter       string
	IDAttribute      string
	DisplayAttribute string
	GroupMode        string
	GroupBaseDN      string
	// GroupRoles — DN группы → роль (Group — DN).
	GroupRoles []GroupRole
	Version    int
	UpdatedAt  time.Time
	UpdatedBy  string
	// SecretKeyID и Secret — шифротекст пароля сервисной учётной записи.
	SecretKeyID string
	Secret      []byte
}

// LDAPInput — новые настройки каталога. Пустой BindPassword — оставить прежний.
type LDAPInput struct {
	Enabled          bool
	URL              string
	CAPEM            string
	BindDN           string
	BindPassword     string
	UserBaseDN       string
	UserFilter       string
	IDAttribute      string
	DisplayAttribute string
	GroupMode        string
	GroupBaseDN      string
	GroupRoles       []GroupRole
}

// LDAPStore — настройки каталога и внешние пользователи.
type LDAPStore interface {
	// LDAPSettings — настройки организации; нет — ErrLDAPNotConfigured.
	LDAPSettings(ctx context.Context, orgID string) (LDAPSettings, error)
	// SaveLDAPSettings сохраняет настройки с таблицей групп, увеличивает
	// версию и в той же транзакции завершает сессии пользователей каталога
	// (RevokeLDAPChanged; их число — revoked_sessions в rec) и пишет rec.
	SaveLDAPSettings(ctx context.Context, orgID string, st LDAPSettings, now time.Time, rec audit.Entry) error
	// DeleteLDAPSettings удаляет настройки (нет — ErrLDAPNotConfigured) и
	// завершает сессии пользователей каталога так же.
	DeleteLDAPSettings(ctx context.Context, orgID string, now time.Time, rec audit.Entry) error
	// UserByIdentity и ExternalLogin — как у IdPStore (Source — SourceLDAP).
	UserByIdentity(ctx context.Context, orgID, issuer, subject string) (User, error)
	ExternalLogin(ctx context.Context, in ExternalLoginTx) (User, error)
}

// WithLDAP подключает вход через каталог: хранилище настроек и клиент.
// Без него вход только локальный, эндпоинты LDAP отвечают «недоступно».
func WithLDAP(st LDAPStore, c *ldap.Client) Option {
	return func(s *Service) { s.ldapStore, s.ldap = st, c }
}

// LDAPConfigured — подключён ли вход через каталог на сервере.
func (s *Service) LDAPConfigured() bool { return s.ldapStore != nil && s.ldap != nil }

// LDAP — настройки каталога (без пароля сервисной учётной записи).
func (s *Service) LDAP(ctx context.Context) (LDAPSettings, error) {
	if !s.LDAPConfigured() {
		return LDAPSettings{}, ErrLDAPUnavailable
	}
	st, err := s.ldapStore.LDAPSettings(ctx, s.orgID)
	if err != nil {
		return LDAPSettings{}, err
	}
	st.Secret, st.SecretKeyID = nil, ""
	return st, nil
}

// SetLDAP сохраняет настройки каталога (изменение доступа, ADR-0025, 1.6):
// повторная проверка паролем или кодом TOTP локальной записи, роли групп не
// шире прав изменяющего, при включении — проверка каталога (TLS, bind
// сервисной учётной записью, ветки). Сессии пользователей каталога
// завершаются: роли пересчитаются при входе. Аудит — auth.ldap_changed со
// значениями до и после, без пароля; расширение доступа — weakening (DM-40).
func (s *Service) SetLDAP(ctx context.Context, by Caller, in LDAPInput, password, code string) (LDAPSettings, error) {
	if !s.LDAPConfigured() || s.box == nil {
		return LDAPSettings{}, ErrLDAPUnavailable
	}
	if err := requireLocal(by); err != nil {
		return LDAPSettings{}, err
	}
	next, err := s.cleanLDAP(ctx, in)
	if err != nil {
		return LDAPSettings{}, err
	}
	if err := s.groupRolesCovered(ctx, by, next.GroupRoles, "auth.ldap_changed", "ldap"); err != nil {
		return LDAPSettings{}, err
	}
	before, err := s.ldapStore.LDAPSettings(ctx, s.orgID)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrLDAPNotConfigured) {
		return LDAPSettings{}, err
	}
	if in.BindPassword == "" && !exists {
		return LDAPSettings{}, &InputError{"bind_password", "Укажите пароль сервисной учётной записи каталога."}
	}
	// Сохранённый пароль не уходит на другой узел или от имени другой
	// записи: при смене адреса, корней доверия или DN его нужно ввести заново
	// (ревью 4.16, замечание 2).
	if in.BindPassword == "" && (before.URL != next.URL || before.CAPEM != next.CAPEM || !ldap.SameDN(before.BindDN, next.BindDN)) {
		return LDAPSettings{}, &InputError{"bind_password", "Адрес каталога, корневые сертификаты или DN сервисной учётной записи изменились: введите её пароль заново."}
	}
	if err := s.reauthenticate(ctx, by, password, code, "auth.ldap_changed"); err != nil {
		return LDAPSettings{}, err
	}
	secret := in.BindPassword
	if secret == "" {
		plain, err := s.box.Open(before.SecretKeyID, before.Secret, ldapTable, ldapSecretColumn, s.orgID)
		if err != nil {
			return LDAPSettings{}, err
		}
		secret = string(plain)
		next.SecretKeyID, next.Secret = before.SecretKeyID, before.Secret
	} else if next.SecretKeyID, next.Secret, err = s.box.SealKey(ctx, []byte(in.BindPassword), ldapTable, ldapSecretColumn, s.orgID); err != nil {
		return LDAPSettings{}, err
	}
	if next.Enabled {
		if err := s.ldap.Check(ctx, ldapConfig(next, secret)); err != nil {
			return LDAPSettings{}, &InputError{"url", ldapCheckReason(err)}
		}
	}
	now := s.clock()
	next.UpdatedAt, next.UpdatedBy = now, by.User.ID
	next.Version = before.Version + 1
	details := map[string]any{"after": s.ldapDetails(next), "service_credential_changed": in.BindPassword != "",
		"ca_pem_changed": exists && before.CAPEM != next.CAPEM}
	if exists {
		details["before"] = s.ldapDetails(before)
	}
	if reasons := ldapWeakened(before, exists, next); len(reasons) > 0 {
		details["weakening"], details["weakening_reasons"] = true, reasons
	}
	rec := s.entry(by.actor(), by.SourceIP, "auth.ldap_changed", audit.Object{Type: "ldap", ID: s.orgID}, audit.ResultSuccess, details)
	if err := s.ldapStore.SaveLDAPSettings(ctx, s.orgID, next, now, rec); err != nil {
		return LDAPSettings{}, err
	}
	next.Secret, next.SecretKeyID = nil, ""
	return next, nil
}

// DeleteLDAP отключает вход через каталог и удаляет его настройки; сессии
// пользователей каталога завершаются, их записи и аудит остаются.
func (s *Service) DeleteLDAP(ctx context.Context, by Caller, password, code string) error {
	if !s.LDAPConfigured() {
		return ErrLDAPUnavailable
	}
	if err := requireLocal(by); err != nil {
		return err
	}
	before, err := s.ldapStore.LDAPSettings(ctx, s.orgID)
	if err != nil {
		return err
	}
	if err := s.reauthenticate(ctx, by, password, code, "auth.ldap_disabled"); err != nil {
		return err
	}
	rec := s.entry(by.actor(), by.SourceIP, "auth.ldap_disabled", audit.Object{Type: "ldap", ID: s.orgID}, audit.ResultSuccess,
		map[string]any{"before": s.ldapDetails(before)})
	return s.ldapStore.DeleteLDAPSettings(ctx, s.orgID, s.clock(), rec)
}

// ldapConfig — настройки клиента каталога с расшифрованным паролем.
func ldapConfig(st LDAPSettings, secret string) ldap.Config {
	return ldap.Config{URL: st.URL, RootsPEM: []byte(st.CAPEM), BindDN: st.BindDN, BindPassword: secret,
		UserBaseDN: st.UserBaseDN, UserFilter: st.UserFilter, IDAttribute: st.IDAttribute,
		DisplayAttribute: st.DisplayAttribute, GroupMode: st.GroupMode, GroupBaseDN: st.GroupBaseDN}
}

// ldapCheckReason — текст причины неудачной проверки каталога для администратора.
func ldapCheckReason(err error) string {
	switch ldap.ErrorCode(err) {
	case ldap.CodeBlocked:
		return "Адрес каталога запрещён: loopback, link-local и адреса метаданных облака недоступны."
	case ldap.CodeTLS:
		return "TLS с каталогом не установлен: проверьте корневые сертификаты, имя узла и поддержку LDAPS или StartTLS."
	case ldap.CodeTimeout, ldap.CodeNetwork, ldap.CodeBusy:
		return "Каталог недоступен с сервера: проверьте адрес, порт и сетевой доступ."
	case ldap.CodeConfig:
		return "Корневые сертификаты каталога не разобраны: нужен PEM с сертификатом УЦ."
	case ldap.CodeServiceBind:
		return "Сервисная учётная запись не вошла в каталог: проверьте DN и пароль."
	case ldap.CodeResponse:
		return "Каталог не нашёл ветку пользователей или групп: проверьте DN веток и права сервисной учётной записи на чтение."
	case ldap.CodeTooLarge:
		return "Каталог прислал слишком большой ответ."
	}
	return "Проверка каталога не пройдена."
}

// cleanLDAP проверяет и нормализует настройки.
func (s *Service) cleanLDAP(ctx context.Context, in LDAPInput) (LDAPSettings, error) {
	out := LDAPSettings{Enabled: in.Enabled, URL: in.URL, BindDN: in.BindDN, UserBaseDN: in.UserBaseDN,
		UserFilter: in.UserFilter, IDAttribute: in.IDAttribute, DisplayAttribute: in.DisplayAttribute,
		GroupMode: in.GroupMode, GroupBaseDN: in.GroupBaseDN}
	if out.DisplayAttribute == "" {
		out.DisplayAttribute = defaultLDAPDisplay
	}
	if out.GroupMode == ldap.GroupsMemberOf {
		out.GroupBaseDN = ""
	}
	err := ldap.ValidateConfig(ldapConfig(out, ""))
	var ce *ldap.ConfigError
	if errors.As(err, &ce) {
		return out, &InputError{ce.Field, ldapFieldReason(ce.Field)}
	}
	if err != nil {
		return out, err
	}
	if len(in.BindPassword) > maxBindPassword || !utf8.ValidString(in.BindPassword) || hasControl(in.BindPassword) {
		return out, &InputError{"bind_password", "Пароль сервисной учётной записи — до 1024 символов без управляющих."}
	}
	if in.CAPEM == "" || len(in.CAPEM) > maxIdPCAPEM {
		return out, &InputError{"ca_pem", "Укажите корневые сертификаты каталога в PEM (до 64 КиБ)."}
	}
	tp, err := s.provider.TLS()
	if err != nil {
		return out, err
	}
	if _, err := tp.ClientConfig([]byte(in.CAPEM)); err != nil {
		return out, &InputError{"ca_pem", "Корневые сертификаты не разобраны: нужен PEM с сертификатом УЦ."}
	}
	out.CAPEM = in.CAPEM
	if len(in.GroupRoles) > maxGroupRoles {
		return out, &InputError{"group_roles", "Не больше 200 строк сопоставления групп."}
	}
	if in.Enabled && len(in.GroupRoles) == 0 {
		return out, &InputError{"group_roles", "Сопоставьте с ролью хотя бы одну группу: без этого никто не войдёт."}
	}
	for _, gr := range in.GroupRoles {
		if len(gr.Group) > maxLDAPGroupDN || !ldap.ValidDN(gr.Group) || hasControl(gr.Group) {
			return out, &InputError{"group_roles", "DN группы «" + truncate(gr.Group, 64) + "» не разобран: нужен полный DN, например cn=aisec-admins,cn=groups,dc=example,dc=ru."}
		}
		if slices.ContainsFunc(out.GroupRoles, func(x GroupRole) bool { return ldap.SameDN(x.Group, gr.Group) }) {
			return out, &InputError{"group_roles", "Группа «" + gr.Group + "» указана дважды: у группы одна роль."}
		}
		if _, err := s.RoleDef(ctx, gr.Role); errors.Is(err, ErrRoleNotFound) {
			return out, &InputError{"group_roles", "Роли «" + string(gr.Role) + "» нет."}
		} else if err != nil {
			return out, err
		}
		out.GroupRoles = append(out.GroupRoles, gr)
	}
	return out, nil
}

// ldapFieldReason — текст ошибки поля настроек каталога.
func ldapFieldReason(field string) string {
	switch field {
	case "url":
		return "Адрес каталога — ldaps://имя[:порт] или ldap://имя[:порт] (тогда StartTLS), без DN и параметров."
	case "bind_dn":
		return "DN сервисной учётной записи не разобран."
	case "user_base_dn":
		return "DN ветки пользователей не разобран."
	case "user_filter":
		return "Фильтр поиска пользователя — фильтр LDAP до 512 символов с " + ldap.LoginPlaceholder +
			" в значении, например (&(objectClass=person)(uid=" + ldap.LoginPlaceholder + "))."
	case "id_attribute":
		return "Атрибут идентификатора — один из: " + strings.Join(ldap.IDAttributes, ", ") + "."
	case "display_attribute":
		return "Атрибут отображаемого имени — латиница, цифры и «-», до 64 символов."
	case "group_mode":
		return "Способ получения групп — memberOf, поиск по member/uniqueMember или вложенные группы AD."
	case "group_base_dn":
		return "Укажите DN ветки групп: он нужен для поиска групп."
	}
	return "Неверное значение."
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// ldapDetails — настройки для подробностей аудита: без пароля; вместо PEM
// корней — его хеш профиля.
func (s *Service) ldapDetails(st LDAPSettings) map[string]any {
	groups := make([]any, 0, len(st.GroupRoles))
	for _, g := range st.GroupRoles {
		groups = append(groups, map[string]any{"group": g.Group, "role": string(g.Role)})
	}
	return map[string]any{"enabled": st.Enabled, "url": st.URL, "bind_dn": st.BindDN, "user_base_dn": st.UserBaseDN,
		"user_filter": st.UserFilter, "id_attribute": st.IDAttribute, "display_attribute": st.DisplayAttribute,
		"group_mode": st.GroupMode, "group_base_dn": st.GroupBaseDN, "group_roles": groups,
		"ca_pem_digest": hex.EncodeToString(s.hasher.Sum([]byte(st.CAPEM)))}
}

// groupRolesCovered — каждая роль таблицы групп не шире прав вызывающего
// (УПД.2); иначе отказ с записью в аудит.
func (s *Service) groupRolesCovered(ctx context.Context, by Caller, groups []GroupRole, action, objType string) error {
	for _, g := range groups {
		if err := s.canManage(ctx, by, g.Role, action, audit.Object{Type: objType, ID: s.orgID}); err != nil {
			return err
		}
	}
	return nil
}

// ldapWeakened — изменения, расширяющие доступ (DM-40): вход через каталог
// включён, группам дана роль, сменились каталог, учётная запись поиска,
// ветка или фильтр пользователей, атрибут идентификатора, корни доверия
// или способ получения групп.
func ldapWeakened(before LDAPSettings, exists bool, after LDAPSettings) []any {
	var reasons []any
	if after.Enabled && (!exists || !before.Enabled) {
		reasons = append(reasons, "ldap_enabled")
	}
	for _, g := range after.GroupRoles {
		if !exists || !slices.ContainsFunc(before.GroupRoles, func(b GroupRole) bool {
			return b.Role == g.Role && ldap.SameDN(b.Group, g.Group)
		}) {
			reasons = append(reasons, "ldap_group_roles_added")
			break
		}
	}
	if exists && (before.URL != after.URL || before.BindDN != after.BindDN || before.UserBaseDN != after.UserBaseDN ||
		before.UserFilter != after.UserFilter || before.IDAttribute != after.IDAttribute) {
		reasons = append(reasons, "ldap_directory_changed")
	}
	if exists && before.CAPEM != after.CAPEM {
		reasons = append(reasons, "ldap_trust_changed")
	}
	if exists && (before.GroupMode != after.GroupMode || before.GroupBaseDN != after.GroupBaseDN) {
		reasons = append(reasons, "ldap_groups_changed")
	}
	return reasons
}
