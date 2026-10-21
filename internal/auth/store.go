package auth

import (
	"context"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Store — хранилище учётных записей, сессий и настроек входа. Рабочая
// реализация — PGStore; для тестов без PostgreSQL — authtest.Memory.
//
// Методы, которые меняют данные по действию человека, принимают запись
// аудита rec и фиксируют её в той же транзакции: изменение без записи
// в журнале невозможно (РСБ.1).
type Store interface {
	Policy(ctx context.Context, orgID string) (Policy, error)
	SetPolicy(ctx context.Context, orgID string, p Policy, rec audit.Entry) error

	HasUsers(ctx context.Context, orgID string) (bool, error)
	UserByLogin(ctx context.Context, orgID, login string) (User, error)
	UserByID(ctx context.Context, orgID, id string) (User, error)
	// ListUsers — пользователи по (CreatedAt, ID) строго после курсора.
	ListUsers(ctx context.Context, orgID string, after *UserCursor, limit int) ([]User, error)
	// CreateUser добавляет пользователя; занятый логин — ErrLoginTaken.
	CreateUser(ctx context.Context, u User, rec audit.Entry) error

	// RecordFailure атомарно увеличивает счётчик неудач и, когда он достиг
	// threshold, блокирует запись до lockUntil (нулевое — до разблокировки
	// администратором). Истёкшая блокировка перед этим снимается со
	// сбросом счётчика. lockedNow — блокировка наступила этим вызовом.
	// Записи аудита recs(attempts, lockedNow) пишутся в той же транзакции.
	RecordFailure(ctx context.Context, userID string, now time.Time, threshold int, lockUntil time.Time,
		recs func(attempts int, lockedNow bool) []audit.Entry) (attempts int, lockedNow bool, err error)

	// PasswordHistory — до n последних прежних хешей пароля, новые первыми.
	PasswordHistory(ctx context.Context, userID string, n int) ([]string, error)
	// SetPassword меняет пароль: прежний хеш уходит в историю (хранится не
	// больше Keep), сессии пользователя, кроме KeepSession, завершаются, а
	// KeepSession получает полный доступ (SessionActive).
	SetPassword(ctx context.Context, ch PasswordChange, rec audit.Entry) error
	// SetStatus деактивирует или активирует запись (УПД.5). Деактивация
	// завершает сессии и отказывает с ErrLastAdmin, если не останется
	// активного администратора безопасности; активация снимает блокировку.
	// В подробности rec добавляется прежнее состояние (previous_status).
	SetStatus(ctx context.Context, orgID, userID string, s Status, now time.Time, rec audit.Entry) error
	// SetupFirstUser гасит одноразовый токен первичной настройки (ЗИ.4) и
	// создаёт первую учётную запись — только если в организации ещё нет
	// пользователей. Неизвестный, истёкший или погашенный токен, токен другого
	// алгоритма или уже выполненная настройка — ErrSetupUnavailable.
	SetupFirstUser(ctx context.Context, tokenHash []byte, hashAlg string, u User, rec audit.Entry) error

	// CreateSession сохраняет сессию; если незавершённых сессий пользователя
	// того же рода (до второго фактора или полных) станет больше limit, самые
	// старые из них завершаются (RevokeLimit): вход по одному паролю не
	// вытесняет полные сессии. Их ID
	// добавляются в подробности rec (evicted_sessions). При входе (login != nil)
	// в той же транзакции под блокировкой строки проверяется, что запись всё
	// ещё активна, не заблокирована и пароль не сменился с момента проверки
	// (иначе ErrLocked или ErrInvalidCredentials), и сбрасывается счётчик неудач.
	CreateSession(ctx context.Context, s Session, limit int, login *LoginCheck, rec audit.Entry) error
	// SessionByToken — незавершённая сессия по хешу токена и её пользователь.
	SessionByToken(ctx context.Context, tokenHash []byte) (Session, User, error)
	// TouchSession отмечает активность сессии.
	TouchSession(ctx context.Context, id string, now time.Time) error
	// SetSessionState меняет состояние сессии.
	SetSessionState(ctx context.Context, id string, st SessionState) error
	// RevokeSession завершает сессию с записью аудита; уже завершённая
	// сессия не меняется и записи не даёт.
	RevokeSession(ctx context.Context, id, reason string, now time.Time, rec audit.Entry) error
	// RevokeUserSessions завершает все сессии пользователя.
	RevokeUserSessions(ctx context.Context, userID, reason string, now time.Time, rec audit.Entry) (int, error)
	// ListSessions — незавершённые сессии пользователя, новые первыми.
	ListSessions(ctx context.Context, userID string) ([]Session, error)

	// MFA — второй фактор пользователя; нет — ErrNotFound.
	MFA(ctx context.Context, userID string) (MFA, error)
	// SaveMFAPending сохраняет новый неподтверждённый секрет с записью
	// аудита, заменяя прежний неподтверждённый; шаг последнего кода не
	// уменьшается. Подключённый фактор — ErrMFAEnabled.
	SaveMFAPending(ctx context.Context, m MFA, rec audit.Entry) error
	// MFAStep проверяет код второго фактора и выполняет действие st.Kind в
	// одной транзакции под блокировкой строки пользователя: параллельные
	// попытки сериализуются, и кодов проверяется не больше порога блокировки
	// (ИАФ.4). Запись заблокирована — ErrLocked, деактивирована или сессия
	// завершена — ErrUnauthenticated, сессия не в FromState — ErrSessionState,
	// фактор не в нужном состоянии — ErrMFANotEnabled или ErrMFAEnabled.
	// Неверный код: счётчик неудач растёт (на пороге — блокировка и
	// завершение всех сессий пользователя), записи st.Failed фиксируются,
	// возвращается ErrInvalidCode. Принятый код: шаг сохраняется, фактор
	// подключается (MFAStepConfirm), коды восстановления заменяются
	// (RecoveryHashes), сессия заменяется NewSession (прежняя завершается с
	// RevokeMFAPassed, лишние полные сессии сверх SessionLimit — с
	// RevokeLimit), при входе (MFAStepVerify) сбрасывается счётчик неудач;
	// rec пишется с подробностями evicted_sessions и recovery_codes_left.
	MFAStep(ctx context.Context, st MFAStep, rec audit.Entry) error
	// ResetMFA удаляет второй фактор (нет — ErrMFANotEnabled), гасит коды
	// восстановления и завершает сессии пользователя (RevokeMFAReset).
	// В подробности rec добавляются previous_state и revoked_sessions.
	ResetMFA(ctx context.Context, userID string, now time.Time, rec audit.Entry) error
}

// Auditor — журнал аудита для событий без изменения данных (вход, неудача).
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) error
}

// UserCursor — позиция в списке пользователей.
type UserCursor struct {
	CreatedAt time.Time
	ID        string
}

// LoginCheck — условия входа, которые CreateSession перепроверяет в своей транзакции.
type LoginCheck struct {
	// VerifiedHash — хеш, с которым совпал введённый пароль.
	VerifiedHash string
	// Rehash — новый хеш того же пароля (параметры хеширования обновились); пусто — не менять.
	Rehash string
	Now    time.Time
	// KeepFailures — не сбрасывать счётчик неудач: вход завершит второй
	// фактор (ИАФ.4, ИАФ.5), счётчик сбросит принятый код.
	KeepFailures bool
}

// PasswordChange — смена или сброс пароля.
type PasswordChange struct {
	UserID  string
	NewHash string
	// ExpectHash — текущий хеш, с которым сверялся пароль; пусто — без
	// сверки (сброс администратором). Не совпал — ErrWrongPassword.
	ExpectHash string
	// ExpectRole — роль, по которой проверялись права администратора
	// (УПД.2); пусто — без сверки. Роль сменилась — ErrRoleChanged.
	ExpectRole Role
	// Temporary — пароль выдан администратором (ИАФ.3): после входа его нужно сменить.
	Temporary   bool
	TempExpires time.Time
	Now         time.Time
	// Keep — сколько прежних хешей хранить в истории (ИАФ.2).
	Keep int
	// KeepSession — сессия, которая остаётся (смена своего пароля); пусто —
	// завершаются все. Уже завершённая KeepSession — ErrUnauthenticated.
	KeepSession  string
	RevokeReason string
	// Unlock — снять блокировку и сбросить счётчик неудач (сброс администратором).
	Unlock bool
	// RequireActive — запись должна быть активна на момент изменения, иначе
	// ErrDeactivated: временный пароль не ложится на параллельно
	// деактивированную запись.
	RequireActive bool
}

// AddDetail добавляет поле в подробности записи аудита (хранилища дописывают
// то, что узнают только внутри транзакции: вытесненные сессии, прежнее состояние).
func AddDetail(rec *audit.Entry, key string, v any) {
	m, ok := rec.Details.(map[string]any)
	if !ok || m == nil {
		m = map[string]any{}
	}
	m[key] = v
	rec.Details = m
}
