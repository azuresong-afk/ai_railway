package gateway

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// JWT пользователя приложения и доступ к моделям по группам (ТЗ 4.3, 7.3
// УПД.9, 5.16 DM-33; ADR-0025, раздел 4 и дополнение 1; задача 4.21
// этапа 4).
//
// Приложение передаёт JWT корпоративного IdP в заголовке
// X-AISec-User-Token, отдельно от своего ключа в Authorization. Шлюз
// проверяет подпись ключами издателя из подписанного пакета конфигурации
// (в IdP не ходит), iss и aud — точно, exp и nbf — с допуском часов из
// карточки приложения. Пользователь для псевдонима — sub проверенного JWT,
// группы — из утверждения карточки. Режимы:
//   - optional — JWT, если он есть; без него пользователь по user_from;
//   - required — без действительного JWT отказ 401 до провайдера.
//
// Недействительный JWT — 401 и событие auth_failure с причиной (DM-38);
// модель, закрытая для групп пользователя, — 403 без списка групп и
// событие с правилом model_group_denied (DM-33).

// HeaderUserToken — JWT пользователя приложения (дополнение 1 к ADR-0025).
const HeaderUserToken = "X-AISec-User-Token" //nolint:gosec // G101: имя заголовка, а не секрет

// Режимы пользователя приложения в шлюзе.
const (
	UserTokenOptional = "optional"
	UserTokenRequired = "required"
)

// Пределы JWT пользователя: проверяются до разбора токена и утверждений.
const (
	// maxUserGroups — групп в утверждении: больше — отказ (groups).
	maxUserGroups = 256
	// maxUserGroupLen — длина имени группы.
	maxUserGroupLen = 256
)

// Служебные имена и причины.
const (
	ruleModelGroup = "model_group_denied"
	// userTokenReasonPrefix — причина auth_failure: user_token_<причина>.
	userTokenReasonPrefix = "user_token_"
	userTokenMissing      = "missing"
	userTokenDuplicate    = "duplicate"
	userTokenGroups       = "groups"
	userTokenNoKeys       = "no_keys"
	userTokenUnavailable  = "unavailable"
)

// UserToken — настройка приложения из пакета.
type UserToken struct {
	Mode        string
	Issuer      string
	Audience    string
	GroupsClaim string
	Leeway      time.Duration
	// ModelGroups — модель или псевдоним → группы, которым она доступна.
	ModelGroups map[string][]string
}

// userTokenCheck — проверка JWT пользователя приложения.
type userTokenCheck struct {
	UserToken
	// keys — ключи издателя из пакета; nil — их нет, любой JWT отклоняется.
	keys *aisecCrypto.JWKS
	// jwt — проверка JWT криптопрофиля; nil — профиль без неё (gost).
	jwt aisecCrypto.JWTVerifier
}

// SetUserTokens задаёт ключи издателей (issuer → каноничный JWKS) и
// проверку JWT приложений (ID → настройка). Неверный JWKS или режим —
// ошибка: пакет не применяется. v = nil — профиль без проверки JWT: JWT
// отклоняются, режим optional принимает X-AISec-User. Вызывается до
// начала обслуживания запросов.
func (rt *Router) SetUserTokens(v aisecCrypto.JWTVerifier, keys map[string][]byte, tokens map[string]UserToken) error {
	parsed := map[string]*aisecCrypto.JWKS{}
	if v != nil {
		for iss, raw := range keys {
			k, err := v.ParseJWKS(raw)
			if err != nil {
				return fmt.Errorf("ключи издателя JWT пользователей: %w", err)
			}
			parsed[iss] = k
		}
	}
	for id, t := range tokens {
		a, ok := rt.apps[id]
		if !ok {
			continue
		}
		if t.Mode != UserTokenOptional && t.Mode != UserTokenRequired {
			return fmt.Errorf("приложение %s: режим JWT пользователя %q", id, t.Mode)
		}
		if t.Issuer == "" || t.Audience == "" || t.GroupsClaim == "" || t.Leeway < 0 || t.Leeway > aisecCrypto.MaxUserTokenLeeway {
			return fmt.Errorf("приложение %s: настройка JWT пользователя неполна", id)
		}
		a.userToken = &userTokenCheck{UserToken: t, keys: parsed[t.Issuer], jwt: v}
	}
	return nil
}

// endUser — конечный пользователь запроса.
type endUser struct {
	// ID — псевдоним; пусто — пользователь не указан.
	ID string
	// groups — группы из проверенного JWT; token — пользователь из JWT.
	groups []string
	token  bool
}

// verify проверяет JWT и извлекает sub и группы; reason — причина отказа.
func (c *userTokenCheck) verify(token string, now time.Time) (sub string, groups []string, reason string) {
	if len(token) > aisecCrypto.MaxJWTSize {
		return "", nil, aisecCrypto.JWTReasonMalformed
	}
	if c.jwt == nil {
		return "", nil, userTokenUnavailable
	}
	if c.keys == nil {
		return "", nil, userTokenNoKeys
	}
	claims, err := c.jwt.VerifyUserToken(token, c.keys, aisecCrypto.UserTokenExpect{Issuer: c.Issuer, Audience: c.Audience,
		Now: now, Leeway: c.Leeway})
	if err != nil {
		if r := aisecCrypto.JWTReason(err); r != "" {
			return "", nil, r
		}
		return "", nil, aisecCrypto.JWTReasonMalformed
	}
	groups, err = userGroups(claims, c.GroupsClaim)
	if err != nil {
		return "", nil, userTokenGroups
	}
	return claims.Subject, groups, ""
}

// userGroups — группы из утверждения claim: строка или массив строк, не
// больше maxUserGroups по maxUserGroupLen байт; нет утверждения — нет групп.
func userGroups(claims aisecCrypto.IDTokenClaims, claim string) ([]string, error) {
	groups, err := claims.Strings(claim, maxUserGroups, maxUserGroupLen)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g == "" {
			return nil, errors.New("пустое имя группы")
		}
	}
	return groups, nil
}

// userFromToken — пользователь по JWT, если приложение его проверяет.
// handled = false — JWT не проверяется или его нет в режиме optional:
// пользователь по user_from. При отказе ответ уже записан.
func (h *ChatHandler) userFromToken(w http.ResponseWriter, r *http.Request, app *App) (u endUser, handled, ok bool) {
	c := app.userToken
	if c == nil {
		return endUser{}, false, true
	}
	vals := r.Header.Values(HeaderUserToken)
	switch {
	case len(vals) > 1:
		h.userTokenFailure(w, r, app, userTokenDuplicate)
		return endUser{}, true, false
	case len(vals) == 0 && c.Mode == UserTokenRequired:
		h.userTokenFailure(w, r, app, userTokenMissing)
		return endUser{}, true, false
	case len(vals) == 0:
		return endUser{}, false, true
	}
	sub, groups, reason := c.verify(vals[0], h.cfg.Now())
	if reason != "" {
		h.userTokenFailure(w, r, app, reason)
		return endUser{}, true, false
	}
	u = endUser{groups: groups, token: true}
	if h.cfg.UserMAC != nil {
		// Разделитель назначения: X-AISec-User с тем же значением не даёт
		// псевдоним пользователя из JWT.
		u.ID = hex.EncodeToString(h.cfg.UserMAC.Sum([]byte("jwt\x00" + c.Issuer + "\x00" + sub))[:16])
	}
	return u, true, true
}

// userTokenFailure — отказ 401 и событие auth_failure (DM-38): ключ
// приложения верный, JWT пользователя — нет. Адрес не блокируется: один
// пользователь с просроченным токеном не должен отключать всё приложение.
// Причина — только в событии.
func (h *ChatHandler) userTokenFailure(w http.ResponseWriter, r *http.Request, app *App, reason string) {
	if h.cfg.Events != nil && h.cfg.IDs != nil {
		f := events.AuthFailure{RemoteAddr: addrString(remoteAddr(r)), Reason: userTokenReasonPrefix + reason}
		if id, ok := IdentityFrom(r.Context()); ok {
			f.KeyPrefix = id.KeyPrefix
		}
		if u, err := h.cfg.IDs.New(); err != nil {
			h.logger.Error("идентификатор события", "error", err)
		} else if err := h.cfg.Events.Enqueue(events.Event{ID: u.String(), Time: h.cfg.Now().UTC(), Type: events.TypeAuthFailure,
			App: app.ID, Env: app.Env, Threats: []string{"DM-38"}, AuthFailure: &f}); err != nil {
			h.logger.Error("событие auth_failure не принято", "error", err)
		}
	}
	w.Header().Set(HeaderDecision, string(policy.Block))
	WriteError(w, http.StatusUnauthorized, "JWT пользователя не принят", "invalid_request_error", "invalid_user_token")
}

// modelAllowed — модель доступна пользователю (DM-33): у каждого имени
// модели провайдера, для которого заданы группы, — у самой модели и у всех
// её псевдонимов — должна быть общая группа с JWT. Так запрет на псевдоним
// не обходится прямым именем модели, а запрет на модель — псевдонимом.
// Без JWT такие модели недоступны.
func (a *App) modelAllowed(requested, model string, u endUser) bool {
	c := a.userToken
	if c == nil || len(c.ModelGroups) == 0 {
		return true
	}
	for name, groups := range c.ModelGroups {
		if name != requested && name != model && a.aliases[name] != model {
			continue
		}
		if !slices.ContainsFunc(u.groups, func(g string) bool { return slices.Contains(groups, g) }) {
			return false
		}
	}
	return true
}

// denyModelGroup — отказ 403 по группам без списка групп в ответе.
func denyModelGroup(w http.ResponseWriter, rec *record) {
	rec.reject(ruleModelGroup, "DM-33")
	w.Header().Set(HeaderDecision, string(policy.Block))
	WriteError(w, http.StatusForbidden, "модель недоступна пользователю", "invalid_request_error", "model_access_denied")
}
