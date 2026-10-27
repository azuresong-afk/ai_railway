package auth

import (
	"context"
	"errors"
	"net/netip"
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
	// Учётная запись IdP не заводит локальные записи с паролем: иначе
	// IdP получил бы локальный вход и через него — свои же настройки
	// (ADR-0025, 1.6).
	if err := requireLocal(by); err != nil {
		return User{}, "", err
	}
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

// SetEmail задаёт или убирает (пустой) e-mail учётной записи: администратор —
// чужой записи, чья роль не сильнее его (УПД.2), пользователь — своей через
// SetOwnEmail. В журнал аудита адрес не пишется, только факт изменения.
func (s *Service) SetEmail(ctx context.Context, by Caller, userID, email string) error {
	if err := requireLocal(by); err != nil {
		return err
	}
	addr, ok := NormalizeEmail(email)
	if !ok {
		return &InputError{"email", emailRule}
	}
	u, err := s.store.UserByID(ctx, s.orgID, userID)
	if err != nil {
		return err
	}
	if err := s.canManage(ctx, by, u.Role, "user.email_set", userObject(userID)); err != nil {
		return err
	}
	rec := s.entry(by.actor(), by.SourceIP, "user.email_set", userObject(userID), audit.ResultSuccess,
		map[string]any{"self": by.User.ID == userID, "cleared": addr == ""})
	return s.store.SetEmail(ctx, s.orgID, userID, addr, rec)
}

// SetOwnEmail — пользователь задаёт или убирает свой e-mail в профиле.
// Сессия и право self проверены на маршруте; запись своя, поэтому canManage не нужен.
func (s *Service) SetOwnEmail(ctx context.Context, by Caller, email string) error {
	addr, ok := NormalizeEmail(email)
	if !ok {
		return &InputError{"email", emailRule}
	}
	rec := s.entry(by.actor(), by.SourceIP, "user.email_set", userObject(by.User.ID), audit.ResultSuccess,
		map[string]any{"self": true, "cleared": addr == ""})
	return s.store.SetEmail(ctx, s.orgID, by.User.ID, addr, rec)
}

// ResetPassword выдаёт новый временный пароль (ИАФ.3), снимает блокировку,
// завершает сессии и отзывает токены API пользователя (решение владельца
// по В8 ревью 2.r2: сброс — реакция на компрометацию). Свой пароль
// меняется через ChangePassword.
func (s *Service) ResetPassword(ctx context.Context, by Caller, userID string) (string, error) {
	if by.User.ID == userID {
		return "", ErrSelf
	}
	// Временный пароль локальной записи учётной записи IdP не выдаётся (ADR-0025, 1.6).
	if err := requireLocal(by); err != nil {
		return "", err
	}
	u, err := s.store.UserByID(ctx, s.orgID, userID)
	if err != nil {
		return "", err
	}
	if err := s.canManage(ctx, by, u.Role, "user.password_reset", userObject(userID)); err != nil {
		return "", err
	}
	return s.resetPassword(ctx, by.actor(), by.SourceIP, u, by.User.ID)
}

// resetPassword — общая часть сброса пароля администратором и aisec-cli;
// revokedBy — ID администратора консоли, пусто — aisec-cli.
func (s *Service) resetPassword(ctx context.Context, actor audit.Actor, ip netip.Addr, u User, revokedBy string) (string, error) {
	userID := u.ID
	if u.External() {
		return "", ErrExternalUser
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
	rec := s.entry(actor, ip, "user.password_reset", userObject(userID), audit.ResultSuccess, nil)
	err = s.store.SetPassword(ctx, PasswordChange{
		UserID: userID, NewHash: h, Temporary: true,
		TempExpires: now.Add(time.Duration(pol.TempPasswordHours) * time.Hour),
		Now:         now, Keep: pol.PasswordHistory, RevokeReason: RevokePasswordReset, Unlock: true, RequireActive: true,
		ExpectRole:   u.Role,
		RevokeTokens: &TokenRevocation{Reason: APITokenRevokedByPasswordReset, By: revokedBy},
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

// RevokeSessions принудительно завершает сессии пользователя (УПД.4);
// revokeTokens — отозвать и его токены API (В8 ревью 2.r2, в консоли
// включено по умолчанию).
func (s *Service) RevokeSessions(ctx context.Context, by Caller, userID string, revokeTokens bool) (int, error) {
	u, err := s.store.UserByID(ctx, s.orgID, userID)
	if err != nil {
		return 0, err
	}
	if err := s.canManage(ctx, by, u.Role, "auth.sessions_revoked", userObject(userID)); err != nil {
		return 0, err
	}
	var tokens *TokenRevocation
	if revokeTokens {
		tokens = &TokenRevocation{Reason: APITokenRevokedBySessions, By: by.User.ID}
	}
	rec := s.entry(by.actor(), by.SourceIP, "auth.sessions_revoked", userObject(userID), audit.ResultSuccess,
		map[string]any{"revoke_api_tokens": revokeTokens})
	return s.store.RevokeUserSessions(ctx, userID, RevokeAdmin, s.clock(), tokens, rec)
}

// Policy — настройки входа организации.
func (s *Service) Policy(ctx context.Context) (Policy, error) {
	return s.store.Policy(ctx, s.orgID)
}

// SetPolicy меняет настройки входа (ИАФ.2, ИАФ.4, УПД.4) с записью
// auth.policy_changed со значениями до и после. Ослабление (WeakenedFields)
// требует повторной проверки текущим паролем или кодом TOTP и отмечается
// weakening (В24 ревью 2.r5): иначе украденная сессия снимает защиту от
// перебора (DM-39) одним запросом.
func (s *Service) SetPolicy(ctx context.Context, by Caller, p Policy, password, code string) error {
	if err := p.Validate(); err != nil {
		return &InputError{"policy", err.Error()}
	}
	before, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return err
	}
	weakened := WeakenedFields(before, p)
	if len(weakened) > 0 {
		if err := s.reauthenticate(ctx, by, password, code, "auth.policy_changed"); err != nil {
			return err
		}
	}
	details := map[string]any{"before": policyDetails(before), "after": policyDetails(p), "weakening": len(weakened) > 0}
	if len(weakened) > 0 {
		details["weakened"] = weakened
	}
	rec := s.entry(by.actor(), by.SourceIP, "auth.policy_changed", audit.Object{Type: "auth_policy", ID: s.orgID},
		audit.ResultSuccess, details)
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
