package auth

import (
	"context"
	"errors"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// NewUser — данные для создания учётной записи администратором.
type NewUser struct {
	Login       string
	DisplayName string
	Role        Role
}

// InputError — неверные данные запроса; Field — имя поля API.
type InputError struct {
	Field  string
	Reason string
}

func (e *InputError) Error() string { return e.Field + ": " + e.Reason }

// errResetDeactivated — сброс пароля деактивированной записи.
var errResetDeactivated = &InputError{"id", "Учётная запись деактивирована: сначала активируйте её."}

// Правила для полей учётной записи (тексты для пользователя).
const (
	loginRule       = "Логин: от 1 до 64 символов — латинские буквы, цифры, «.», «_», «-»; начинается с буквы или цифры."
	displayNameRule = "Имя: от 1 до 200 символов без управляющих символов."
)

// CreateUser создаёт учётную запись с временным паролем (ИАФ.1, ИАФ.3).
// Временный пароль возвращается один раз и нигде не хранится открыто.
func (s *Service) CreateUser(ctx context.Context, by Caller, nu NewUser) (User, string, error) {
	login, ok := NormalizeLogin(nu.Login)
	if !ok {
		return User{}, "", &InputError{"login", loginRule}
	}
	name, ok := CleanDisplayName(nu.DisplayName)
	if !ok {
		return User{}, "", &InputError{"display_name", displayNameRule}
	}
	if _, err := s.RoleDef(ctx, nu.Role); errors.Is(err, ErrRoleNotFound) {
		return User{}, "", &InputError{"role", "Неизвестная роль."}
	} else if err != nil {
		return User{}, "", err
	}
	// Создатель узнаёт временный пароль: учётная запись сильнее его — путь
	// к повышению своих прав (УПД.2).
	if err := s.canManage(ctx, by, nu.Role, "user.create", audit.Object{Type: "user"}); err != nil {
		return User{}, "", err
	}
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return User{}, "", err
	}
	temp, err := GenerateTempPassword(s.random, pol)
	if err != nil {
		return User{}, "", err
	}
	h, err := s.pw.Hash(ctx, []byte(temp))
	if err != nil {
		return User{}, "", err
	}
	now := s.clock()
	id, err := store.NewUUIDv7(now, s.random)
	if err != nil {
		return User{}, "", err
	}
	u := User{
		ID: string(id), OrgID: s.orgID, Login: login, DisplayName: name, Role: nu.Role, Status: StatusActive,
		PasswordHash: h, PasswordChangedAt: now, MustChangePassword: true,
		TempPasswordExpires: now.Add(time.Duration(pol.TempPasswordHours) * time.Hour),
		CreatedAt:           now, CreatedBy: by.User.ID,
	}
	rec := s.entry(by.actor(), by.SourceIP, "user.create", userObject(u.ID), audit.ResultSuccess,
		map[string]any{"login": login, "role": string(nu.Role)})
	if err := s.store.CreateUser(ctx, u, rec); err != nil {
		return User{}, "", err
	}
	return u, temp, nil
}

// User возвращает учётную запись организации.
func (s *Service) User(ctx context.Context, id string) (User, error) {
	return s.store.UserByID(ctx, s.orgID, id)
}

// Users — страница списка пользователей.
func (s *Service) Users(ctx context.Context, after *UserCursor, limit int) ([]User, error) {
	return s.store.ListUsers(ctx, s.orgID, after, limit)
}

// SetStatus деактивирует или повторно активирует учётную запись (УПД.5).
// Себя деактивировать нельзя; последнего активного администратора
// безопасности — тоже (проверяет хранилище в той же транзакции).
func (s *Service) SetStatus(ctx context.Context, by Caller, userID string, st Status) error {
	if by.User.ID == userID {
		return ErrSelf
	}
	action := "user.activate"
	if st == StatusDeactivated {
		action = "user.deactivate"
	}
	u, err := s.store.UserByID(ctx, s.orgID, userID)
	if err != nil {
		return err
	}
	if err := s.canManage(ctx, by, u.Role, action, userObject(userID)); err != nil {
		return err
	}
	rec := s.entry(by.actor(), by.SourceIP, action, userObject(userID), audit.ResultSuccess, nil)
	return s.store.SetStatus(ctx, s.orgID, userID, st, s.clock(), rec)
}

// ResetPassword выдаёт новый временный пароль (ИАФ.3), снимает блокировку и
// завершает сессии пользователя. Свой пароль меняется через ChangePassword.
func (s *Service) ResetPassword(ctx context.Context, by Caller, userID string) (string, error) {
	if by.User.ID == userID {
		return "", ErrSelf
	}
	u, err := s.store.UserByID(ctx, s.orgID, userID)
	if err != nil {
		return "", err
	}
	if err := s.canManage(ctx, by, u.Role, "user.password_reset", userObject(userID)); err != nil {
		return "", err
	}
	if u.Status != StatusActive {
		return "", errResetDeactivated
	}
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return "", err
	}
	temp, err := GenerateTempPassword(s.random, pol)
	if err != nil {
		return "", err
	}
	h, err := s.pw.Hash(ctx, []byte(temp))
	if err != nil {
		return "", err
	}
	now := s.clock()
	rec := s.entry(by.actor(), by.SourceIP, "user.password_reset", userObject(userID), audit.ResultSuccess, nil)
	err = s.store.SetPassword(ctx, PasswordChange{
		UserID: userID, NewHash: h, Temporary: true,
		TempExpires: now.Add(time.Duration(pol.TempPasswordHours) * time.Hour),
		Now:         now, Keep: pol.PasswordHistory, RevokeReason: RevokePasswordReset, Unlock: true, RequireActive: true,
		ExpectRole: u.Role,
	}, rec)
	if errors.Is(err, ErrDeactivated) {
		return "", errResetDeactivated
	}
	if err != nil {
		return "", err
	}
	return temp, nil
}

// Sessions — незавершённые сессии пользователя.
func (s *Service) Sessions(ctx context.Context, userID string) ([]Session, error) {
	if _, err := s.store.UserByID(ctx, s.orgID, userID); err != nil {
		return nil, err
	}
	return s.store.ListSessions(ctx, userID)
}

// RevokeSessions принудительно завершает сессии пользователя (УПД.4).
func (s *Service) RevokeSessions(ctx context.Context, by Caller, userID string) (int, error) {
	u, err := s.store.UserByID(ctx, s.orgID, userID)
	if err != nil {
		return 0, err
	}
	if err := s.canManage(ctx, by, u.Role, "auth.sessions_revoked", userObject(userID)); err != nil {
		return 0, err
	}
	rec := s.entry(by.actor(), by.SourceIP, "auth.sessions_revoked", userObject(userID), audit.ResultSuccess, nil)
	return s.store.RevokeUserSessions(ctx, userID, RevokeAdmin, s.clock(), rec)
}

// Policy — настройки входа организации.
func (s *Service) Policy(ctx context.Context) (Policy, error) {
	return s.store.Policy(ctx, s.orgID)
}

// SetPolicy меняет настройки входа (ИАФ.2, ИАФ.4, УПД.4) с записью
// auth.policy_changed со значениями до и после.
func (s *Service) SetPolicy(ctx context.Context, by Caller, p Policy) error {
	if err := p.Validate(); err != nil {
		return &InputError{"policy", err.Error()}
	}
	before, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return err
	}
	rec := s.entry(by.actor(), by.SourceIP, "auth.policy_changed", audit.Object{Type: "auth_policy", ID: s.orgID},
		audit.ResultSuccess, map[string]any{"before": policyDetails(before), "after": policyDetails(p)})
	return s.store.SetPolicy(ctx, s.orgID, p, rec)
}

// policyDetails — настройки для подробностей аудита. Ключи без «password»:
// журнал отклоняет такие ключи как похожие на секрет.
func policyDetails(p Policy) map[string]any {
	return map[string]any{
		"min_length": p.PasswordMinLength, "min_classes": p.PasswordMinClasses,
		"history": p.PasswordHistory, "max_age_days": p.PasswordMaxAgeDays, "warn_days": p.PasswordWarnDays,
		"lockout_threshold": p.LockoutThreshold, "lockout_minutes": p.LockoutMinutes,
		"idle_minutes": p.SessionIdleMinutes, "max_sessions": p.SessionMaxPerUser,
		"temp_hours": p.TempPasswordHours, "mfa_all": p.MFARequiredAll,
	}
}

// PasswordExpiresIn — сколько осталось до истечения пароля, если пора
// предупреждать (ИАФ.2); ok = false — предупреждать рано или пароль бессрочный.
func (s *Service) PasswordExpiresIn(ctx context.Context, u User) (left time.Duration, ok bool, err error) {
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return 0, false, err
	}
	exp := u.PasswordExpires(pol)
	if exp.IsZero() || u.MustChangePassword {
		return 0, false, nil
	}
	left = exp.Sub(s.clock())
	if left > time.Duration(pol.PasswordWarnDays)*24*time.Hour {
		return 0, false, nil
	}
	return max(left, 0), true, nil
}
