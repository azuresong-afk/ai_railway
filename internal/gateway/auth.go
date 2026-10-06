package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// EventSink — куда шлюз отдаёт события (events.Queue).
type EventSink interface {
	Enqueue(events.Event) error
}

// AuthConfig — зависимости аутентификации приложений.
type AuthConfig struct {
	Authenticator *auth.Authenticator
	Limiter       *auth.FailureLimiter
	Events        EventSink
	IDs           *ids.Generator
	Logger        *slog.Logger
	Now           func() time.Time // для тестов; по умолчанию time.Now
}

type identityKey struct{}

// IdentityFrom возвращает приложение, от имени которого пришёл запрос.
func IdentityFrom(ctx context.Context) (*auth.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(*auth.Identity)
	return id, ok && id != nil
}

// RequireAppKey пропускает запрос к next только с действующим ключом
// приложения (ТЗ, 5.1, 5.4). Отказ — 401 без подробностей, причина — только
// в событии auth_failure; неудачи с адреса, с которого их слишком много,
// получают 429 без событий (DM-38).
func RequireAppKey(cfg AuthConfig, next http.Handler) (http.Handler, error) {
	if cfg.Authenticator == nil || cfg.Limiter == nil || cfg.Events == nil || cfg.IDs == nil {
		return nil, errors.New("аутентификация: не заданы зависимости")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := cfg.Now()
		remote := remoteAddr(r)
		var f *auth.Failure
		var id *auth.Identity
		if vals := r.Header.Values("Authorization"); len(vals) == 0 {
			f = &auth.Failure{Reason: auth.ReasonMissing}
		} else if key, err := auth.BearerToken(vals); err != nil {
			f = &auth.Failure{Reason: auth.ReasonMalformed}
		} else {
			id, f = cfg.Authenticator.Authenticate(key, remote, now)
		}
		if f == nil {
			// Действующий ключ проходит и с заблокированного адреса: иначе
			// одно приложение с отозванным ключом в цикле повторов отключило
			// бы соседей за тем же NAT. Подбор это не облегчает: секрет —
			// 256 случайных бит.
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
			return
		}
		if blocked, until := cfg.Limiter.Blocked(remote, now); blocked {
			// Неудачи с заблокированного адреса событий не создают: о начале
			// блокировки уже есть одно событие rate_limited.
			// Секунды до снятия блокировки с округлением вверх.
			w.Header().Set("Retry-After", strconv.FormatInt(int64((until.Sub(now)+time.Second-1)/time.Second), 10))
			WriteError(w, http.StatusTooManyRequests, "слишком много неудачных попыток аутентификации, повторите позже",
				"rate_limit_error", "auth_rate_limited")
			return
		}
		cfg.emit(remote, f, now)
		if cfg.Limiter.Fail(remote, now) {
			// Адрес — только в событии: в техническом журнале его не нужно.
			cfg.Logger.Warn("адрес заблокирован после неудачных попыток аутентификации, подробности — в событии auth_failure")
			cfg.emit(remote, &auth.Failure{Reason: auth.ReasonRateLimited}, now)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="aisec"`)
		WriteError(w, http.StatusUnauthorized, "ключ приложения не принят", "invalid_request_error", "invalid_api_key")
	}), nil
}

// emit создаёт событие auth_failure. Сам ключ в событие не попадает.
func (cfg AuthConfig) emit(remote netip.Addr, f *auth.Failure, now time.Time) {
	u, err := cfg.IDs.New()
	if err != nil {
		cfg.Logger.Error("идентификатор события", "error", err)
		return
	}
	e := events.Event{
		ID: u.String(), Time: now.UTC(), Type: events.TypeAuthFailure, App: f.AppID, Env: f.Env,
		Threats:     []string{"DM-38"},
		AuthFailure: &events.AuthFailure{RemoteAddr: addrString(remote), KeyPrefix: f.KeyPrefix, Reason: f.Reason},
	}
	if err := cfg.Events.Enqueue(e); err != nil {
		cfg.Logger.Error("событие auth_failure не принято", "error", err)
	}
}

// remoteAddr — адрес клиента из соединения. Заголовки X-Forwarded-For не
// учитываются: доверенных обратных прокси перед шлюзом на этапе 1 нет, а
// иначе клиент мог бы подставить любой адрес и обойти allowed_cidrs.
func remoteAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return "unknown"
	}
	return a.String()
}

// KeyRecords переводит ключи приложений из файла конфигурации в записи для
// аутентификации. Срок expires — дата: ключ действует до 00:00 UTC этой даты
// (03:00 МСК), сама дата в срок не входит. Раньше — безопаснее, чем позже.
func KeyRecords(apps []config.Application) ([]auth.KeyRecord, error) {
	var out []auth.KeyRecord
	for _, a := range apps {
		for _, k := range a.Keys {
			rec := auth.KeyRecord{AppID: a.ID, Env: a.Env, Prefix: k.Prefix, SHA256: k.SHA256, Revoked: k.Revoked}
			if k.Expires != "" {
				t, err := time.Parse(time.DateOnly, k.Expires)
				if err != nil {
					return nil, fmt.Errorf("ключ %s: expires: %w", k.Prefix, err)
				}
				rec.Expires = t
			}
			for _, c := range k.AllowedCIDRs {
				p, err := netip.ParsePrefix(c)
				if err != nil {
					return nil, fmt.Errorf("ключ %s: allowed_cidrs: %w", k.Prefix, err)
				}
				rec.AllowedCIDRs = append(rec.AllowedCIDRs, p.Masked())
			}
			out = append(out, rec)
		}
	}
	return out, nil
}
