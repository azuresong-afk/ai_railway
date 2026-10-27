package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"
)

// JWT пользователя приложения и доступ к моделям по группам (ТЗ 4.3, 7.3
// УПД.9, 5.16 DM-33; ADR-0025, раздел 4; задача 4.21 этапа 4).
//
// Раздел user_token_keys — открытые ключи подписи издателя в каноничном
// JWKS: их забирает сервер (шлюз в IdP не ходит), смена ключей у IdP —
// новая версия пакета. Раздел user_tokens — настройки приложений, у
// которых проверка JWT включена: режим, издатель, аудитория, утверждение с
// группами, допуск часов и группы, которым доступны модели. Приложения с
// режимом «только X-AISec-User» в раздел не входят: без них байты пакета
// прежние.

// Режимы пользователя приложения в пакете.
const (
	// UserTokenOptional — JWT, если он есть; иначе пользователь по user_from.
	UserTokenOptional = "optional"
	// UserTokenRequired — без действительного JWT запрос отклоняется 401.
	UserTokenRequired = "required"
)

// Пределы раздела user_tokens: проверяются сервером при сохранении и
// шлюзом при разборе пакета.
const (
	// MaxUserTokenIssuers — издателей с ключами (сейчас один IdP на
	// установку, ADR-0025, 3.1; запас — на смену издателя).
	MaxUserTokenIssuers = 4
	// MaxJWKSBytes — каноничный JWKS одного издателя.
	MaxJWKSBytes = 64 << 10
	// MaxIssuerLen — адрес издателя.
	MaxIssuerLen = 512
	// MaxAudienceLen — аудитория (client_id или имя ресурса у IdP).
	MaxAudienceLen = 256
	// MaxClaimNameLen — имя утверждения с группами.
	MaxClaimNameLen = 64
	// MaxGroupsPerModel — групп, которым открыта одна модель.
	MaxGroupsPerModel = 64
	// MaxGroupLen — имя группы.
	MaxGroupLen = 256
	// MaxUserTokenLeeway — допуск часов, секунд.
	MaxUserTokenLeeway = 300
)

// IssuerKeys — ключи подписи издателя.
type IssuerKeys struct {
	Issuer string `json:"issuer"`
	// JWKS — каноничный набор ключей (crypto.JWTVerifier.MarshalJWKS);
	// шлюз разбирает его тем же разборщиком, что и сервер.
	JWKS json.RawMessage `json:"jwks"`
}

// UserToken — проверка JWT пользователя приложения.
type UserToken struct {
	App      string `json:"app"`
	Mode     string `json:"mode"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// GroupsClaim — утверждение со списком групп.
	GroupsClaim string `json:"groups_claim"`
	// Leeway — допуск часов для exp, nbf и iat, секунд.
	Leeway int `json:"leeway"`
	// ModelGroups — модель или псевдоним приложения → группы, которым она
	// доступна (DM-33). Модели вне списка доступны всем пользователям
	// приложения; модель из списка — только с одной из групп JWT.
	ModelGroups map[string][]string `json:"model_groups,omitempty"`
}

// validateUserTokens — ключи по издателю без повторов, настройки только у
// приложений пакета и не больше одной на приложение, модели — из моделей
// и псевдонимов приложения.
func (c *Content) validateUserTokens(apps map[string]Application) []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if len(c.UserTokenKeys) > MaxUserTokenIssuers {
		add("user_token_keys: больше %d издателей", MaxUserTokenIssuers)
	}
	issuers := map[string]bool{}
	for i, k := range c.UserTokenKeys {
		at := fmt.Sprintf("user_token_keys[%d] (%s)", i, short(k.Issuer))
		if err := CheckIssuer(k.Issuer); err != nil || issuers[k.Issuer] {
			add("%s: неверный или повторный issuer", at)
		}
		issuers[k.Issuer] = true
		if len(k.JWKS) == 0 || len(k.JWKS) > MaxJWKSBytes || !json.Valid(k.JWKS) || k.JWKS[0] != '{' {
			add("%s: jwks — объект JSON до %d байт", at, MaxJWKSBytes)
		}
	}
	if len(c.UserTokens) > MaxApplications {
		return append(errs, fmt.Errorf("user_tokens: больше %d приложений", MaxApplications))
	}
	seen := map[string]bool{}
	for i, u := range c.UserTokens {
		at := fmt.Sprintf("user_tokens[%d] (%s)", i, short(u.App))
		app, ok := apps[u.App]
		if !ok || seen[u.App] {
			add("%s: приложения нет в пакете или настройка указана дважды", at)
		}
		seen[u.App] = true
		if u.Mode != UserTokenOptional && u.Mode != UserTokenRequired {
			add("%s: mode — optional или required", at)
		}
		if err := CheckIssuer(u.Issuer); err != nil {
			add("%s: issuer: %v", at, err)
		}
		if u.Audience == "" || len(u.Audience) > MaxAudienceLen || !printable(u.Audience) {
			add("%s: audience — от 1 до %d печатных символов", at, MaxAudienceLen)
		}
		if !ClaimName(u.GroupsClaim) {
			add("%s: groups_claim — от 1 до %d символов A–Z, a–z, 0–9, _-.:/", at, MaxClaimNameLen)
		}
		if u.Leeway < 0 || u.Leeway > MaxUserTokenLeeway {
			add("%s: leeway — от 0 до %d секунд", at, MaxUserTokenLeeway)
		}
		errs = append(errs, checkModelGroups(at, u.ModelGroups, app)...)
	}
	return errs
}

func checkModelGroups(at string, mg map[string][]string, app Application) []error {
	var errs []error
	if len(mg) > MaxModels*2 {
		return []error{fmt.Errorf("%s: model_groups — больше %d моделей", at, MaxModels*2)}
	}
	for m, groups := range mg {
		_, alias := app.Aliases[m]
		if !alias && !slices.Contains(app.Models, m) {
			errs = append(errs, fmt.Errorf("%s: model_groups: %q — не модель и не псевдоним приложения", at, short(m)))
		}
		if len(groups) == 0 || len(groups) > MaxGroupsPerModel {
			errs = append(errs, fmt.Errorf("%s: model_groups[%s]: от 1 до %d групп", at, short(m), MaxGroupsPerModel))
		}
		for _, g := range groups {
			if !ValidGroup(g) {
				errs = append(errs, fmt.Errorf("%s: model_groups[%s]: группа — от 1 до %d байт UTF-8 без управляющих символов",
					at, short(m), MaxGroupLen))
				break
			}
		}
	}
	return errs
}

// CheckIssuer — адрес издателя: https с именем узла, без учётных данных,
// запроса и фрагмента, до MaxIssuerLen символов (как настройка IdP).
func CheckIssuer(s string) error {
	if s == "" || len(s) > MaxIssuerLen {
		return fmt.Errorf("адрес пуст или длиннее %d символов", MaxIssuerLen)
	}
	u, err := url.Parse(s)
	switch {
	case err != nil || u.Opaque != "":
		return errors.New("адрес не разобран")
	case u.Scheme != "https" || u.Hostname() == "":
		return errors.New("адрес должен начинаться с https:// и содержать имя узла")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "":
		return errors.New("адрес без имени пользователя, параметров запроса и фрагмента")
	}
	return nil
}

// ClaimName — имя утверждения: 1–MaxClaimNameLen символов A–Z, a–z, 0–9 и
// _-.:/ (как имя утверждения с группами в настройке IdP).
func ClaimName(s string) bool {
	if s == "" || len(s) > MaxClaimNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && !strings.ContainsRune("_-.:/", rune(c)) {
			return false
		}
	}
	return true
}

// ValidGroup — имя группы: 1–MaxGroupLen байт UTF-8 без управляющих
// символов.
func ValidGroup(g string) bool {
	if g == "" || len(g) > MaxGroupLen || !utf8.ValidString(g) {
		return false
	}
	for _, r := range g {
		if r < 0x20 || r >= 0x7f && r < 0xa0 {
			return false
		}
	}
	return true
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
