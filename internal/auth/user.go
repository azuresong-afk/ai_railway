package auth

import (
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Ошибки учётных записей и сессий консоли. Тексты — для журнала и тестов;
// пользователю API показывает свои формулировки.
var (
	// ErrInvalidCredentials — любой отказ при входе: нет учётной записи,
	// неверный пароль, запись заблокирована или деактивирована. Причины
	// наружу не различаются (перебор логинов), они — в журнале аудита.
	ErrInvalidCredentials = errors.New("неверный логин или пароль")
	// ErrUnauthenticated — сессии нет, она завершена или истекла.
	ErrUnauthenticated = errors.New("сессия недействительна")
	ErrNotFound        = errors.New("учётная запись не найдена")
	ErrLoginTaken      = errors.New("логин уже занят")
	// ErrLastAdmin — действие оставило бы систему без активного администратора безопасности.
	ErrLastAdmin = errors.New("нельзя оставить систему без активного администратора безопасности")
	// ErrLocked — запись заблокирована, пока шла проверка пароля (параллельные неудачи).
	ErrLocked = errors.New("учётная запись заблокирована")
	// ErrSelf — администратор не может деактивировать сам себя.
	ErrSelf = errors.New("действие над своей учётной записью запрещено")
	// ErrWrongPassword — неверный текущий пароль при смене пароля.
	ErrWrongPassword = errors.New("текущий пароль неверен")
	// ErrSetupUnavailable — первичная настройка уже выполнена или токен недействителен.
	ErrSetupUnavailable = errors.New("первичная настройка недоступна")
	// ErrDeactivated — учётная запись деактивирована (сброс пароля невозможен).
	ErrDeactivated = errors.New("учётная запись деактивирована")
)

// Role — ID роли: предустановленной (ТЗ, 1.3) или своей из набора
// разрешений (УПД.1). Права ролей — permissions.go и rbac.go.
type Role string

// Предустановленные роли; ID совпадают во всех установках.
const (
	RoleSecurityAdmin Role = "security_admin"
	RoleSystemAdmin   Role = "system_admin"
	RoleAnalyst       Role = "analyst"
	RoleAuditor       Role = "auditor"
	RoleAppOwner      Role = "app_owner"
)

// Valid — ID роли допустим: латиница в нижнем регистре, цифры и «_»,
// начинается с буквы, от 3 до 48 символов (тот же CHECK в миграции).
// Существует ли такая роль, проверяет сервис.
func (r Role) Valid() bool {
	s := string(r)
	if len(s) < 3 || len(s) > MaxRoleIDLen || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// Status — состояние учётной записи (УПД.5). Записи не удаляются.
type Status string

// Состояния учётной записи.
const (
	StatusActive      Status = "active"
	StatusDeactivated Status = "deactivated"
)

// User — учётная запись консоли.
type User struct {
	ID          string
	OrgID       string
	Login       string
	DisplayName string
	Role        Role
	Status      Status
	// PasswordHash — хеш PHC из PasswordHasher профиля; наружу не выдаётся.
	PasswordHash      string
	PasswordChangedAt time.Time
	// MustChangePassword — пароль временный (ИАФ.3): после входа доступна только его смена.
	MustChangePassword bool
	// TempPasswordExpires — срок временного пароля; нулевое — пароль не временный.
	TempPasswordExpires time.Time
	FailedAttempts      int
	// LockedAt — момент блокировки после неудач (ИАФ.4); нулевое — не заблокирована.
	LockedAt time.Time
	// LockedUntil — конец блокировки; нулевое при ненулевом LockedAt — до
	// разблокировки администратором.
	LockedUntil   time.Time
	CreatedAt     time.Time
	CreatedBy     string
	DeactivatedAt time.Time
	LastLoginAt   time.Time
	// Source — источник учётной записи (ADR-0025): local или oidc. У
	// внешней записи нет пароля, она привязана к (IdPIssuer, IdPSubject).
	Source     AuthSource
	IdPIssuer  string
	IdPSubject string
}

// AuthSource — источник учётной записи.
type AuthSource string

// Источники учётных записей. Пустое значение — local (записи до 4.17).
const (
	SourceLocal AuthSource = "local"
	SourceOIDC  AuthSource = "oidc"
)

// External — внешняя учётная запись (IdP): пароля и TOTP консоли у неё нет.
func (u *User) External() bool { return u.Source != "" && u.Source != SourceLocal }

// Locked — запись заблокирована на момент now.
func (u *User) Locked(now time.Time) bool {
	if u.LockedAt.IsZero() {
		return false
	}
	return u.LockedUntil.IsZero() || now.Before(u.LockedUntil)
}

// PasswordExpires — момент истечения пароля по политике; нулевое — бессрочный.
func (u *User) PasswordExpires(p Policy) time.Time {
	if p.PasswordMaxAgeDays == 0 || u.External() {
		return time.Time{}
	}
	return u.PasswordChangedAt.AddDate(0, 0, p.PasswordMaxAgeDays)
}

// SessionState — что разрешено сессии.
type SessionState string

// Состояния сессии.
const (
	// SessionActive — полный доступ по правам роли.
	SessionActive SessionState = "active"
	// SessionPasswordChange — пароль временный или истёк: доступны только
	// свои данные, смена пароля и выход (ИАФ.2, ИАФ.3).
	SessionPasswordChange SessionState = "password_change"
	// SessionMFAPending — пароль верен, нужен код второго фактора (ИАФ.5):
	// доступны только ввод кода, свои данные и выход.
	SessionMFAPending SessionState = "mfa_pending"
	// SessionMFASetup — второй фактор обязателен, но не подключён: доступны
	// только его подключение, свои данные и выход.
	SessionMFASetup SessionState = "mfa_setup"
)

// Причины завершения сессии (столбец sessions.revoke_reason).
const (
	RevokeLogout          = "logout"
	RevokeIdle            = "idle"
	RevokeExpired         = "expired"
	RevokeLimit           = "limit"
	RevokeAdmin           = "admin"
	RevokePasswordChanged = "password_changed"
	RevokePasswordReset   = "password_reset"
	RevokeDeactivated     = "deactivated"
	RevokeLocked          = "locked"
	RevokeMFAReset        = "mfa_reset"
	// RevokeMFAPassed — сессия до второго фактора заменена полной с новыми токенами.
	RevokeMFAPassed = "mfa_passed"
	// RevokeMFARequired — полной сессии без второго фактора он стал обязателен.
	RevokeMFARequired = "mfa_required"
	// RevokeBackupRestore — сессия из восстановленной полной копии
	// (aisec-cli restore-finish).
	RevokeBackupRestore = "backup_restore"
	// RevokeIdPChanged — изменены или отключены настройки IdP: роли
	// внешних пользователей пересчитываются при следующем входе (ADR-0025).
	RevokeIdPChanged = "idp_changed"
	// RevokeIdPRoleChanged — роль внешнего пользователя по группам IdP
	// изменилась при входе: прежние сессии с прежней ролью завершаются.
	RevokeIdPRoleChanged = "idp_role_changed"
)

// Session — сессия консоли (решение Р6). Токен и CSRF-токен хранятся только хешами.
type Session struct {
	ID         string
	UserID     string
	TokenHash  []byte
	CSRFHash   []byte
	State      SessionState
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
	SourceIP   netip.Addr
	UserAgent  string
	// MFAVerified — в сессии принят код второго фактора (В6 ревью 2.r2).
	MFAVerified bool
}

// Пределы полей учётной записи и сессии; те же — в CHECK миграции.
const (
	MaxLoginLen       = 64
	MaxDisplayNameLen = 200
	MaxUserAgentLen   = 256
)

// NormalizeLogin приводит логин к хранимой форме: латиница в нижнем
// регистре, цифры, «.», «_», «-», первый символ — буква или цифра, до 64
// символов. ok = false — логин недопустим (такой учётной записи быть не может).
func NormalizeLogin(s string) (string, bool) {
	if s == "" || len(s) > MaxLoginLen {
		return "", false
	}
	// Регистр приводится побайтно только для ASCII: strings.ToLower превратил
	// бы «İ» и знак кельвина в латинские i и k, и чужой логин совпал бы с нашим.
	l := []byte(s)
	for i, c := range l {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
			l[i] = c
		}
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '.' || c == '_' || c == '-') && i > 0:
		default:
			return "", false
		}
	}
	return string(l), true
}

// CleanDisplayName проверяет имя для показа: UTF-8, без управляющих и
// форматирующих символов (направление текста, нулевая ширина: ими подделывают
// имя в консоли и выгрузке аудита) и разделителей строк и абзацев, от 1 до
// 200 символов после обрезки пробелов по краям.
func CleanDisplayName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxDisplayNameLen {
		return "", false
	}
	for _, r := range s {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return "", false
		}
	}
	return s, true
}

// cleanUserAgent обрезает заголовок User-Agent для хранения: только
// печатные ASCII, не длиннее MaxUserAgentLen.
func cleanUserAgent(s string) string {
	b := make([]byte, 0, min(len(s), MaxUserAgentLen))
	for i := 0; i < len(s) && len(b) < MaxUserAgentLen; i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b = append(b, c)
		}
	}
	return string(b)
}
