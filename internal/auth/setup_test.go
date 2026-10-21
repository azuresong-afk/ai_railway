package auth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
)

// shortPhrase — пароль короче политики.
const shortPhrase = "короткий"

// newSetupEnv — установка сразу после aisec-cli init: пользователей нет,
// есть токен первичной настройки. Возвращает токен.
func newSetupEnv(t *testing.T) (*env, string) {
	t.Helper()
	e := &env{mem: authtest.NewMemory(), hash: &authtest.Hasher{}, clock: &clock{t: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}}
	p := provider(t)
	svc, err := auth.NewService(context.Background(), e.mem, e.mem, p, auth.WithClock(e.clock.now), auth.WithPasswordHasher(e.hash),
		auth.WithSecretBox(testBox(t)))
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	e.mfa = newMFAKeys(svc, e.mem, e.clock)
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	token := setupToken(0x5a)
	e.mem.AddSetupToken(audit.DefaultOrgID, h.Name(), h.Sum([]byte(token)), e.clock.now().Add(24*time.Hour))
	t.Cleanup(func() { checkRecords(t, e.mem.Records()) })
	return e, token
}

// setupToken — токен в формате aisec-cli init с детерминированной случайной частью.
func setupToken(b byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b + byte(i)
	}
	return "aisec_setup_" + base64.RawURLEncoding.EncodeToString(raw)
}

func (e *env) setup(token, login, password string) (auth.User, error) {
	return e.svc.Setup(context.Background(), auth.SetupInput{
		Token: token, Login: login, DisplayName: "Первый администратор", Password: password, SourceIP: testIP,
	})
}

// ЗИ.4: первый администратор безопасности создаётся по одноразовому токену;
// после этого настройка недоступна, а администратор входит обычным путём.
func TestSetupCreatesFirstAdmin(t *testing.T) {
	e, token := newSetupEnv(t)
	ctx := context.Background()
	need, err := e.svc.SetupRequired(ctx)
	if err != nil || !need {
		t.Fatalf("настройка нужна: %v %v", need, err)
	}
	u, err := e.setup(token, "Admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	if u.Login != "admin" || u.Role != auth.RoleSecurityAdmin || u.Status != auth.StatusActive || u.MustChangePassword {
		t.Fatalf("учётная запись: %+v", u)
	}
	rec := lastRecord(t, e.mem, "setup.completed")
	d, _ := rec.Details.(map[string]any)
	if rec.Result != audit.ResultSuccess || rec.Actor.Type != audit.ActorSystem || d["setup_record_id"] == nil {
		t.Fatalf("аудит: %+v", rec)
	}
	if need, err := e.svc.SetupRequired(ctx); err != nil || need {
		t.Fatalf("настройка после выполнения: %v %v", need, err)
	}
	// Токен одноразовый, а повторная настройка невозможна и с другим,
	// ещё не погашенным токеном (второй запуск aisec-cli init).
	if _, err := e.setup(token, "admin2", phrase); !errors.Is(err, auth.ErrSetupUnavailable) {
		t.Fatalf("повтор: %v", err)
	}
	h, err := provider(t).Hasher()
	if err != nil {
		t.Fatal(err)
	}
	other := setupToken(0x33)
	e.mem.AddSetupToken(audit.DefaultOrgID, h.Name(), h.Sum([]byte(other)), e.clock.now().Add(time.Hour))
	if _, err := e.setup(other, "admin3", phrase); !errors.Is(err, auth.ErrSetupUnavailable) {
		t.Fatalf("другой токен: %v", err)
	}
	if rec := lastRecord(t, e.mem, "setup.completed"); rec.Result != audit.ResultFailure {
		t.Fatalf("аудит отказа: %+v", rec)
	}
	// После настройки отказ — до проверки пароля по политике и хеширования.
	if _, err := e.setup(other, "admin3", shortPhrase); !errors.Is(err, auth.ErrSetupUnavailable) {
		t.Fatalf("слабый пароль после настройки: %v", err)
	}
	// Первый вход администратора — сразу к подключению второго фактора (ИАФ.5).
	if res := e.mustLogin(t, "admin", phrase); res.Caller.Session.State != auth.SessionMFASetup {
		t.Fatalf("первый вход администратора: %s", res.Caller.Session.State)
	}
}

func TestSetupRejects(t *testing.T) {
	cases := map[string]struct {
		token, login, password string
		advance                time.Duration
		want                   func(error) bool
	}{
		"чужой токен":        {token: setupToken(0x01), login: "admin", password: phrase, want: unavailable},
		"без префикса":       {token: strings.TrimPrefix(setupToken(0x5a), "aisec_setup_"), login: "admin", password: phrase, want: unavailable},
		"не base64url":       {token: "aisec_setup_" + strings.Repeat("!", 43), login: "admin", password: phrase, want: unavailable},
		"лишний символ":      {token: setupToken(0x5a) + "A", login: "admin", password: phrase, want: unavailable},
		"истёк":              {token: setupToken(0x5a), login: "admin", password: phrase, advance: 24 * time.Hour, want: unavailable},
		"пароль по политике": {token: setupToken(0x5a), login: "admin", password: shortPhrase, want: passwordErr},
		"логин":              {token: setupToken(0x5a), login: "плохой логин", password: phrase, want: inputErr("login")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e, token := newSetupEnv(t)
			e.clock.add(tc.advance)
			if _, err := e.setup(tc.token, tc.login, tc.password); !tc.want(err) {
				t.Fatalf("ошибка: %v", err)
			}
			// Отказ не гасит токен: настройка остаётся доступной.
			if tc.advance == 0 {
				if _, err := e.setup(token, "admin", phrase); err != nil {
					t.Fatalf("настройка после отказа: %v", err)
				}
			}
			for _, r := range e.mem.Records() {
				if strings.Contains(r.Actor.Name+r.Actor.ID, "aisec_setup_") {
					t.Fatalf("токен в аудите: %+v", r)
				}
			}
		})
	}
}

func unavailable(err error) bool { return errors.Is(err, auth.ErrSetupUnavailable) }

func passwordErr(err error) bool {
	var pe *auth.PasswordError
	return errors.As(err, &pe)
}

func inputErr(field string) func(error) bool {
	return func(err error) bool {
		var ie *auth.InputError
		return errors.As(err, &ie) && ie.Field == field
	}
}

// Отказ из-за токена пишется в аудит с причиной, без токена.
func TestSetupFailureAudited(t *testing.T) {
	e, _ := newSetupEnv(t)
	if _, err := e.setup(setupToken(0x01), "admin", phrase); !unavailable(err) {
		t.Fatal(err)
	}
	rec := lastRecord(t, e.mem, "setup.completed")
	if rec.Result != audit.ResultFailure || rec.Details.(map[string]any)["reason"] != "unavailable" {
		t.Fatalf("аудит отказа: %+v", rec)
	}
}
