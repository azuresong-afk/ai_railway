package auth

import (
	"context"
	"errors"
	"net/netip"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Аварийные действия aisec-cli (В7 ревью 2.r2). Снять блокировку, сбросить
// пароль или второй фактор в консоли может только тот, чьи права покрывают
// права цели, и не себе: единственный администратор безопасности,
// заблокированный подбором пароля или потерявший фактор, иначе остался бы
// без входа. Команды выполняются локально с доступом к БД (строка
// подключения администратора СУБД) — это уже полный доступ к данным,
// поэтому права консоли не проверяются. Субъект записи — пользователь ОС
// (audit.ActorCLI), логин СУБД журнал дописывает сам (Н5 ревью 2.r1).

// errLocalActor — действие aisec-cli вызвано не от имени aisec-cli.
var errLocalActor = errors.New("аварийное действие: субъект — не aisec-cli")

// localUser — активная или деактивированная запись по логину для
// аварийного действия.
func (s *Service) localUser(ctx context.Context, by audit.Actor, login string) (User, error) {
	if by.Type != audit.ActorCLI || by.ID == "" {
		return User{}, errLocalActor
	}
	l, ok := NormalizeLogin(login)
	if !ok {
		return User{}, ErrNotFound
	}
	return s.store.UserByLogin(ctx, s.orgID, l)
}

// LocalUnlock снимает блокировку учётной записи (auth.unlocked).
// Деактивированная запись — ErrDeactivated: её возвращают в консоли.
func (s *Service) LocalUnlock(ctx context.Context, by audit.Actor, login string) error {
	u, err := s.localUser(ctx, by, login)
	if err != nil {
		return err
	}
	rec := s.entry(by, netip.Addr{}, "auth.unlocked", userObject(u.ID), audit.ResultSuccess, nil)
	return s.store.Unlock(ctx, s.orgID, u.ID, s.clock(), rec)
}

// LocalResetPassword выдаёт временный пароль, как сброс в консоли:
// блокировка снимается, сессии завершаются, токены API отзываются.
func (s *Service) LocalResetPassword(ctx context.Context, by audit.Actor, login string) (string, error) {
	u, err := s.localUser(ctx, by, login)
	if err != nil {
		return "", err
	}
	return s.resetPassword(ctx, by, netip.Addr{}, u, "")
}

// LocalResetMFA удаляет второй фактор и завершает сессии пользователя;
// при следующем входе фактор подключается заново.
func (s *Service) LocalResetMFA(ctx context.Context, by audit.Actor, login string) error {
	u, err := s.localUser(ctx, by, login)
	if err != nil {
		return err
	}
	return s.resetMFA(ctx, by, netip.Addr{}, u.ID)
}
