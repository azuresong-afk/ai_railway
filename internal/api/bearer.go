package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// tokenAuditTimeout — предел записи api_token.used после ответа.
const tokenAuditTimeout = 5 * time.Second

// BearerAuthorizer проверяет запросы по токену API (ИАФ.9, задача 2.10).
// Есть заголовок Authorization со схемой Bearer — проверяется только он: в
// cookie не откатываемся, CSRF не нужен (заголовок браузер сам не
// подставляет). Заголовка Bearer нет — решает Next (сессия консоли):
// Basic от обратного прокси консоль не ломает (Н10 ревью 2.r2). Права
// токена — пересечение его области с текущими правами роли владельца
// (auth.TokenGrants).
type BearerAuthorizer struct {
	Auth   *auth.Service
	Logger *slog.Logger
	// Next — проверка без заголовка Bearer; nil — DenyAll.
	Next Authorizer
	// Limiter — неудачи проверки токена по адресу клиента (В9 ревью 2.r2):
	// после порога — 429 без записей в аудит до конца блокировки, о начале
	// блокировки — одна запись. nil — без ограничения.
	Limiter *auth.FailureLimiter
	// Malformed — счётчик заголовков Bearer неверного формата (в аудит они
	// не пишутся: подделать формат может любой, журнал не раздувается).
	Malformed *atomic.Uint64
	// Now — часы ограничителя; nil — time.Now.
	Now func() time.Time
}

// hasBearer — среди заголовков Authorization есть схема Bearer.
func hasBearer(values []string) bool {
	for _, v := range values {
		if scheme, _, _ := strings.Cut(strings.TrimLeft(v, " \t"), " "); strings.EqualFold(scheme, "bearer") {
			return true
		}
	}
	return false
}

// Authorize — Authorizer.
func (a BearerAuthorizer) Authorize(r *http.Request, permission string) (Principal, Decision) {
	values := r.Header.Values("Authorization")
	if !hasBearer(values) {
		if a.Next == nil {
			return DenyAll{}.Authorize(r, permission)
		}
		return a.Next.Authorize(r, permission)
	}
	ip := clientAddr(r)
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	if a.Limiter != nil {
		if blocked, until := a.Limiter.Blocked(ip, now); blocked {
			return Principal{RetryAfter: until.Sub(now)}, RateLimited
		}
	}
	// Несколько заголовков или неверный формат — отказ без записи в аудит,
	// счётчиком в технический журнал (без значения заголовка).
	raw, err := auth.BearerToken(values)
	if err == nil {
		_, err = auth.ParseAPIToken(raw)
	}
	if err != nil {
		n := uint64(0)
		if a.Malformed != nil {
			n = a.Malformed.Add(1)
		}
		if a.Logger != nil {
			a.Logger.Info("заголовок Bearer неверного формата", "client", ip.String(), "total", n)
		}
		a.failed(r.Context(), ip, now)
		return Principal{}, Unauthenticated
	}
	c, err := a.Auth.AuthenticateAPIToken(r.Context(), raw, ip)
	if err != nil {
		if !errors.Is(err, auth.ErrUnauthenticated) && a.Logger != nil {
			// Сбой хранилища или журнала: отказ, причина — в техническом журнале (без токена).
			a.Logger.Error("проверка токена API не выполнена", "error", err)
		}
		if errors.Is(err, auth.ErrUnauthenticated) {
			a.failed(r.Context(), ip, now)
		}
		return Principal{}, Unauthenticated
	}
	g, err := a.Auth.CallerGrants(r.Context(), c)
	if err != nil {
		if a.Logger != nil {
			a.Logger.Error("права владельца токена API не получены", "error", err)
		}
		return Principal{}, Unavailable
	}
	// Отдельная область ключей повторяемости: запрос по токену не
	// повторяет ответ, сохранённый для сессии того же пользователя.
	p := Principal{ID: "api_token:" + c.Token.ID, Caller: &c, Grants: g}
	if !g.Allows(permission) {
		return p, Forbidden
	}
	return p, Allow
}

// failed учитывает неудачу адреса ip; на пороге — одна запись о блокировке.
func (a BearerAuthorizer) failed(ctx context.Context, ip netip.Addr, now time.Time) {
	if a.Limiter == nil || !a.Limiter.Fail(ip, now) {
		return
	}
	_, until := a.Limiter.Blocked(ip, now)
	if err := a.Auth.APITokenRateLimited(ctx, ip, until); err != nil && a.Logger != nil {
		a.Logger.Error("блокировка адреса по неудачам токена API не записана в журнал аудита", "error", err)
	}
}

// statusRecorder запоминает код ответа обработчика (аудит api_token.used).
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status, s.wrote = http.StatusOK, true
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap — для http.ResponseController.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// auditTokenUsed — запись каждого пропущенного запроса по токену в журнал
// аудита (РСБ.1): метод, шаблон пути, код ответа.
func auditTokenUsed(svc *auth.Service, logger *slog.Logger) func(*http.Request, Principal, string, string, int) {
	return func(r *http.Request, p Principal, method, path string, status int) {
		if p.Caller == nil || p.Caller.Token == nil {
			return
		}
		// Клиент мог уже отключиться: запись не должна пропасть вместе с его контекстом.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), tokenAuditTimeout)
		defer cancel()
		if err := svc.APITokenUsed(ctx, *p.Caller, method, path, status); err != nil {
			logger.Error("запрос по токену API не записан в журнал аудита", "error", err)
		}
	}
}
