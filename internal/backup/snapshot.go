package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Состав копии (H-Р2): политики со всеми версиями, приложения с хешами
// ключей, провайдеры, пользователи (хеши паролей, история паролей, второй
// фактор, хеши кодов восстановления), токены API (хеши), свои роли,
// настройки и ключ HMAC псевдонимов. Секреты (учётные данные провайдеров,
// секреты TOTP, ключ HMAC) лежат шифротекстами ключа секретов копии.
// События, журнал аудита, сессии, шлюзы и ключи установки в копию не входят.

// Snapshot — содержимое копии.
type Snapshot struct {
	Version int    `json:"version"`
	OrgID   string `json:"org_id"`
	OrgName string `json:"org_name"`
	// SchemaVersion — последняя миграция БД, с которой снята копия.
	// Восстановление в БД со схемой старше копии отклоняется.
	SchemaVersion int           `json:"schema_version"`
	TakenAt       time.Time     `json:"taken_at"`
	Settings      Settings      `json:"settings"`
	Roles         []Role        `json:"roles"`
	Users         []User        `json:"users"`
	APITokens     []APIToken    `json:"api_tokens"`
	Providers     []Provider    `json:"providers"`
	Applications  []Application `json:"applications"`
	Policies      []Policy      `json:"policies"`
	// UserHMACKey — ключ псевдонимов пользователей (шифротекст ключа
	// секретов); нет — администратор явно отказался его включать.
	UserHMACKey []byte `json:"user_hmac_key"`
}

// Settings — настройки организации и установки. nil — строки нет, действуют
// значения по умолчанию.
type Settings struct {
	Auth    *AuthSettings    `json:"auth"`
	Audit   *AuditSettings   `json:"audit"`
	Events  *EventSettings   `json:"events"`
	Install *InstallSettings `json:"install"`
}

// InstallSettings — настройки первичной настройки (задача 2.24b, H-Р4):
// часовой пояс показа времени и режим хранения по умолчанию.
type InstallSettings struct {
	Timezone      string    `json:"timezone"`
	RetentionMode string    `json:"retention_mode"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// AuthSettings — строка auth_settings.
type AuthSettings struct {
	PasswordMinLength  int       `json:"password_min_length"`
	PasswordMinClasses int       `json:"password_min_classes"`
	PasswordHistory    int       `json:"password_history"`
	PasswordMaxAgeDays int       `json:"password_max_age_days"`
	PasswordWarnDays   int       `json:"password_warn_days"`
	LockoutThreshold   int       `json:"lockout_threshold"`
	LockoutMinutes     int       `json:"lockout_minutes"`
	SessionIdleMinutes int       `json:"session_idle_minutes"`
	SessionMaxPerUser  int       `json:"session_max_per_user"`
	TempPasswordHours  int       `json:"temp_password_hours"`
	MFARequiredAll     bool      `json:"mfa_required_all"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// AuditSettings — строка audit_settings.
type AuditSettings struct {
	DisabledActions []string  `json:"disabled_actions"`
	RetentionDays   int       `json:"retention_days"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// EventSettings — сроки хранения событий (одна строка на установку).
type EventSettings struct {
	MetadataDays int       `json:"metadata_days"`
	ContentDays  int       `json:"content_days"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Role — своя роль организации; предустановленные задаются кодом.
type Role struct {
	ID          string           `json:"id"`
	DisplayName string           `json:"display_name"`
	Description string           `json:"description"`
	MFARequired bool             `json:"mfa_required"`
	CreatedAt   time.Time        `json:"created_at"`
	CreatedBy   string           `json:"created_by"`
	UpdatedAt   time.Time        `json:"updated_at"`
	Permissions []RolePermission `json:"permissions"`
}

// RolePermission — разрешение своей роли.
type RolePermission struct {
	Permission string `json:"permission"`
	Scope      string `json:"scope"`
}

// User — учётная запись консоли.
type User struct {
	ID                    string     `json:"id"`
	Login                 string     `json:"login"`
	DisplayName           string     `json:"display_name"`
	Role                  string     `json:"role"`
	Status                string     `json:"status"`
	PasswordHash          string     `json:"password_hash"`
	PasswordChangedAt     time.Time  `json:"password_changed_at"`
	MustChangePassword    bool       `json:"must_change_password"`
	TempPasswordExpiresAt *time.Time `json:"temp_password_expires_at"`
	FailedAttempts        int        `json:"failed_attempts"`
	LockedAt              *time.Time `json:"locked_at"`
	LockedUntil           *time.Time `json:"locked_until"`
	CreatedAt             time.Time  `json:"created_at"`
	CreatedBy             string     `json:"created_by"`
	DeactivatedAt         *time.Time `json:"deactivated_at"`
	LastLoginAt           *time.Time `json:"last_login_at"`
	// AuthSource, IdPIssuer, IdPSubject — источник учётной записи (ADR-0025):
	// у внешней записи нет пароля, она привязана к издателю и sub. В копиях
	// до задачи 4.17 полей нет — запись локальная.
	AuthSource      string            `json:"auth_source,omitempty"`
	IdPIssuer       *string           `json:"idp_issuer,omitempty"`
	IdPSubject      *string           `json:"idp_subject,omitempty"`
	PasswordHistory []PasswordHistory `json:"password_history"`
	MFA             *MFA              `json:"mfa"`
	RecoveryCodes   []RecoveryCode    `json:"recovery_codes"`
}

// source — источник учётной записи; пустой (копия до задачи 4.17) — local.
func (u User) source() string {
	if u.AuthSource == "" {
		return "local"
	}
	return u.AuthSource
}

// PasswordHistory — прежний хеш пароля (ИАФ.2).
type PasswordHistory struct {
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

// MFA — второй фактор; Secret — шифротекст ключа секретов копии.
type MFA struct {
	State     string     `json:"state"`
	Secret    []byte     `json:"secret"`
	Alg       string     `json:"alg"`
	LastStep  int64      `json:"last_step"`
	CreatedAt time.Time  `json:"created_at"`
	EnabledAt *time.Time `json:"enabled_at"`
}

// RecoveryCode — хеш кода восстановления.
type RecoveryCode struct {
	CodeHash  []byte     `json:"code_hash"`
	CreatedAt time.Time  `json:"created_at"`
	UsedAt    *time.Time `json:"used_at"`
}

// APIToken — токен API (хранится только хеш).
type APIToken struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	Name         string     `json:"name"`
	Prefix       string     `json:"prefix"`
	TokenHash    []byte     `json:"token_hash"`
	HashAlg      string     `json:"hash_alg"`
	Permissions  []string   `json:"permissions"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	LastUsedIP   *string    `json:"last_used_ip"`
	RevokedAt    *time.Time `json:"revoked_at"`
	RevokedBy    *string    `json:"revoked_by"`
	RevokeReason *string    `json:"revoke_reason"`
}

// Provider — провайдер LLM; Credential — шифротекст ключа секретов копии.
type Provider struct {
	ID                 string     `json:"id"`
	Slug               string     `json:"slug"`
	Name               string     `json:"name"`
	Type               string     `json:"type"`
	BaseURL            string     `json:"base_url"`
	CAPEM              string     `json:"ca_pem"`
	AuthURL            *string    `json:"auth_url"`
	Scope              *string    `json:"scope"`
	FolderID           *string    `json:"folder_id"`
	ConnectTimeoutS    int        `json:"connect_timeout_s"`
	HeaderTimeoutS     int        `json:"header_timeout_s"`
	ResponseTimeoutS   int        `json:"response_timeout_s"`
	StreamIdleTimeoutS int        `json:"stream_idle_timeout_s"`
	External           bool       `json:"external"`
	Credential         []byte     `json:"credential"`
	CredentialSetAt    *time.Time `json:"credential_set_at"`
	CreatedAt          time.Time  `json:"created_at"`
	CreatedBy          string     `json:"created_by"`
	UpdatedAt          time.Time  `json:"updated_at"`
	UpdatedBy          string     `json:"updated_by"`
}

// Application — приложение с ключами.
type Application struct {
	ID                string          `json:"id"`
	Slug              string          `json:"slug"`
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	Department        string          `json:"department"`
	OwnerID           string          `json:"owner_id"`
	Env               string          `json:"env"`
	ProviderID        string          `json:"provider_id"`
	Models            []string        `json:"models"`
	Aliases           json.RawMessage `json:"aliases"`
	Policy            string          `json:"policy"`
	PolicyMode        string          `json:"policy_mode"`
	Storage           string          `json:"storage"`
	FailMode          string          `json:"fail_mode"`
	UserFrom          string          `json:"user_from"`
	Quotas            json.RawMessage `json:"quotas"`
	Lists             json.RawMessage `json:"lists"`
	ExfilAllowDomains []string        `json:"exfil_allow_domains"`
	CreatedAt         time.Time       `json:"created_at"`
	CreatedBy         string          `json:"created_by"`
	UpdatedAt         time.Time       `json:"updated_at"`
	UpdatedBy         string          `json:"updated_by"`
	ArchivedAt        *time.Time      `json:"archived_at"`
	Keys              []AppKey        `json:"keys"`
}

// AppKey — ключ приложения (хранится только хеш).
type AppKey struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Prefix       string     `json:"prefix"`
	KeyHash      []byte     `json:"key_hash"`
	HashAlg      string     `json:"hash_alg"`
	AllowedCIDRs []string   `json:"allowed_cidrs"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	CreatedBy    string     `json:"created_by"`
	RotatedFrom  *string    `json:"rotated_from"`
	RevokedAt    *time.Time `json:"revoked_at"`
	RevokedBy    *string    `json:"revoked_by"`
}

// Policy — политика организации со всеми версиями.
type Policy struct {
	ID             string          `json:"id"`
	Slug           string          `json:"slug"`
	Name           string          `json:"name"`
	Mode           string          `json:"mode"`
	CurrentVersion int             `json:"current_version"`
	CreatedAt      time.Time       `json:"created_at"`
	CreatedBy      string          `json:"created_by"`
	UpdatedAt      time.Time       `json:"updated_at"`
	UpdatedBy      string          `json:"updated_by"`
	Versions       []PolicyVersion `json:"versions"`
}

// PolicyVersion — неизменяемая версия политики.
type PolicyVersion struct {
	Version        int       `json:"version"`
	SpecYAML       string    `json:"spec_yaml"`
	SpecHash       []byte    `json:"spec_hash"`
	HashAlg        string    `json:"hash_alg"`
	Source         string    `json:"source"`
	Comment        string    `json:"comment"`
	RolledBackFrom *int      `json:"rolled_back_from"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
}

// Пределы числа объектов в копии: защита от раздутого (но подписанного
// фразой) файла; значения с запасом выше разумной установки.
const (
	maxRoles        = 1000
	maxUsers        = 100_000
	maxTokens       = 100_000
	maxProviders    = 1000
	maxApplications = 10_000
	maxKeysPerApp   = 1000
	maxPolicies     = 1000
	maxVersions     = 10_000
	maxPerUserRows  = 64
	maxSecret       = 32 << 10
)

// Секреты копии: вид секрета входит в AAD шифротекста.
const (
	secretProviderCredential = "providers.credential"
	secretMFA                = "user_mfa.secret"
	secretUserHMACKey        = "user_hmac_key"
	userHMACKeyID            = "installation"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// decodeSnapshot — строгий разбор содержимого: неизвестные поля, лишние
// данные после объекта, превышение пределов и нарушение ссылочной
// целостности — отказ. Значения полей дополнительно проверяют ограничения
// схемы БД при восстановлении.
func decodeSnapshot(payload []byte) (*Snapshot, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var s Snapshot
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: данные после содержимого", ErrFormat)
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	return &s, nil
}

// ids — проверка уникальности значений одного вида.
type ids map[string]struct{}

func (m ids) add(kind, v string) error {
	if _, ok := m[v]; ok {
		return fmt.Errorf("%s %q повторяется", kind, v)
	}
	m[v] = struct{}{}
	return nil
}

func checkUUID(kind, v string) error {
	if !uuidRe.MatchString(v) {
		return fmt.Errorf("%s: неверный ID %q", kind, truncate(v))
	}
	return nil
}

func truncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

func (s *Snapshot) validate() error {
	if s.Version != FormatVersion {
		return fmt.Errorf("версия содержимого %d", s.Version)
	}
	if err := checkUUID("организация", s.OrgID); err != nil {
		return err
	}
	if s.SchemaVersion < 1 {
		return errors.New("нет версии схемы БД")
	}
	switch {
	case len(s.Roles) > maxRoles, len(s.Users) > maxUsers, len(s.APITokens) > maxTokens,
		len(s.Providers) > maxProviders, len(s.Applications) > maxApplications, len(s.Policies) > maxPolicies:
		return errors.New("объектов больше предела")
	}
	if s.UserHMACKey != nil && (len(s.UserHMACKey) == 0 || len(s.UserHMACKey) > maxSecret) {
		return errors.New("ключ HMAC: неверная длина шифротекста")
	}
	roles := ids{}
	for _, r := range s.Roles {
		if auth.Role(r.ID).Builtin() {
			return fmt.Errorf("роль %q — предустановленная, в копию не входит", r.ID)
		}
		if err := roles.add("роль", r.ID); err != nil {
			return err
		}
		if len(r.Permissions) > 256 {
			return fmt.Errorf("роль %q: разрешений больше предела", r.ID)
		}
		perms := ids{}
		for _, p := range r.Permissions {
			if err := perms.add("разрешение роли "+r.ID, p.Permission); err != nil {
				return err
			}
		}
	}
	users, logins := ids{}, ids{}
	for _, u := range s.Users {
		if err := checkUUID("пользователь", u.ID); err != nil {
			return err
		}
		if err := users.add("пользователь", u.ID); err != nil {
			return err
		}
		if err := logins.add("логин", u.Login); err != nil {
			return err
		}
		if _, ok := roles[u.Role]; !ok && !auth.Role(u.Role).Builtin() {
			return fmt.Errorf("пользователь %s: роли %q нет", u.Login, u.Role)
		}
		if len(u.PasswordHistory) > maxPerUserRows || len(u.RecoveryCodes) > maxPerUserRows {
			return fmt.Errorf("пользователь %s: строк истории или кодов больше предела", u.Login)
		}
		if u.MFA != nil && (len(u.MFA.Secret) == 0 || len(u.MFA.Secret) > maxSecret) {
			return fmt.Errorf("пользователь %s: нет секрета второго фактора", u.Login)
		}
	}
	tokens, prefixes, keyPrefixes := ids{}, ids{}, ids{}
	for _, t := range s.APITokens {
		if err := checkUUID("токен API", t.ID); err != nil {
			return err
		}
		if err := tokens.add("токен API", t.ID); err != nil {
			return err
		}
		if err := prefixes.add("префикс токена", t.Prefix); err != nil {
			return err
		}
		if _, ok := users[t.UserID]; !ok {
			return fmt.Errorf("токен %s: владельца нет в копии", t.Prefix)
		}
	}
	providers, pslugs := ids{}, ids{}
	for _, p := range s.Providers {
		if err := checkUUID("провайдер", p.ID); err != nil {
			return err
		}
		if err := providers.add("провайдер", p.ID); err != nil {
			return err
		}
		if err := pslugs.add("slug провайдера", p.Slug); err != nil {
			return err
		}
		if (p.Credential == nil) != (p.CredentialSetAt == nil) || len(p.Credential) > maxSecret {
			return fmt.Errorf("провайдер %s: учётные данные без отметки времени или наоборот", p.Slug)
		}
	}
	apps, aslugs, keys := ids{}, ids{}, ids{}
	for _, a := range s.Applications {
		if err := checkUUID("приложение", a.ID); err != nil {
			return err
		}
		if err := apps.add("приложение", a.ID); err != nil {
			return err
		}
		if err := aslugs.add("slug приложения", a.Slug); err != nil {
			return err
		}
		if _, ok := users[a.OwnerID]; !ok {
			return fmt.Errorf("приложение %s: владельца нет в копии", a.Slug)
		}
		if _, ok := providers[a.ProviderID]; !ok {
			return fmt.Errorf("приложение %s: провайдера нет в копии", a.Slug)
		}
		if len(a.Keys) > maxKeysPerApp {
			return fmt.Errorf("приложение %s: ключей больше предела", a.Slug)
		}
		for _, k := range a.Keys {
			if err := checkUUID("ключ приложения", k.ID); err != nil {
				return err
			}
			if err := keys.add("ключ приложения", k.ID); err != nil {
				return err
			}
			if err := keyPrefixes.add("префикс ключа", k.Prefix); err != nil {
				return err
			}
		}
		// Ротация ссылается на ключ того же приложения; порядок вставки
		// строит restore (ключ-предшественник раньше).
		local := ids{}
		for _, k := range a.Keys {
			local[k.ID] = struct{}{}
		}
		for _, k := range a.Keys {
			if k.RotatedFrom != nil {
				if _, ok := local[*k.RotatedFrom]; !ok || *k.RotatedFrom == k.ID {
					return fmt.Errorf("ключ %s: предшественника нет в приложении", k.Prefix)
				}
			}
		}
	}
	policies, polslugs := ids{}, ids{}
	for _, p := range s.Policies {
		if err := checkUUID("политика", p.ID); err != nil {
			return err
		}
		if err := policies.add("политика", p.ID); err != nil {
			return err
		}
		if err := polslugs.add("slug политики", p.Slug); err != nil {
			return err
		}
		if len(p.Versions) == 0 || len(p.Versions) > maxVersions {
			return fmt.Errorf("политика %s: число версий вне границ", p.Slug)
		}
		for i, v := range p.Versions {
			if v.Version != i+1 {
				return fmt.Errorf("политика %s: версии идут не подряд с 1", p.Slug)
			}
		}
		if p.CurrentVersion < 1 || p.CurrentVersion > len(p.Versions) {
			return fmt.Errorf("политика %s: текущей версии нет в копии", p.Slug)
		}
	}
	return nil
}

// verifyHashes сверяет хеши версий политик с их текстом: пакет для шлюзов
// (2.13) собирается из версии, а хеш показывает, что текст не менялся.
func (s *Snapshot) verifyHashes(h crypto.Hasher) error {
	for _, p := range s.Policies {
		for _, v := range p.Versions {
			if v.HashAlg != h.Name() || !crypto.Equal(h.Sum([]byte(v.SpecYAML)), v.SpecHash) {
				return fmt.Errorf("%w: политика %s, версия %d: хеш не совпадает с текстом", ErrFormat, p.Slug, v.Version)
			}
		}
	}
	return nil
}

// SettingsDetails — значения настроек копии для записи аудита: изменение
// настроек входа, аудита и сроков хранения должно быть видно в журнале.
func (s *Snapshot) SettingsDetails() map[string]any {
	out := map[string]any{"org_name": s.OrgName}
	if a := s.Settings.Auth; a != nil {
		// Те же имена, что в auth.policy_changed: слово password в ключе
		// журнал отклоняет как похожее на секрет.
		out["auth"] = map[string]any{
			"min_length": a.PasswordMinLength, "min_classes": a.PasswordMinClasses,
			"history": a.PasswordHistory, "max_age_days": a.PasswordMaxAgeDays, "warn_days": a.PasswordWarnDays,
			"lockout_threshold": a.LockoutThreshold, "lockout_minutes": a.LockoutMinutes,
			"idle_minutes": a.SessionIdleMinutes, "max_sessions": a.SessionMaxPerUser,
			"temp_hours": a.TempPasswordHours, "mfa_all": a.MFARequiredAll,
		}
	}
	if a := s.Settings.Audit; a != nil {
		actions := make([]any, len(a.DisabledActions))
		for i, x := range a.DisabledActions {
			actions[i] = x
		}
		out["audit"] = map[string]any{"disabled_actions": actions, "retention_days": a.RetentionDays}
	}
	if e := s.Settings.Events; e != nil {
		out["events"] = map[string]any{"metadata_days": e.MetadataDays, "content_days": e.ContentDays}
	}
	if i := s.Settings.Install; i != nil {
		out["install"] = map[string]any{"timezone": i.Timezone, "retention_mode": i.RetentionMode}
	}
	return out
}

// Counts — число объектов копии для отчёта и записи аудита.
func (s *Snapshot) Counts() map[string]any {
	var keys, versions int
	for _, a := range s.Applications {
		keys += len(a.Keys)
	}
	for _, p := range s.Policies {
		versions += len(p.Versions)
	}
	return map[string]any{
		"roles": len(s.Roles), "users": len(s.Users), "api_tokens": len(s.APITokens),
		"providers": len(s.Providers), "applications": len(s.Applications), "app_keys": keys,
		"policies": len(s.Policies), "policy_versions": versions, "user_hmac_included": s.UserHMACKey != nil,
	}
}
