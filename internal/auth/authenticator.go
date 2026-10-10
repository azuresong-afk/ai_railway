package auth

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Причины неудачной аутентификации на шлюзе (ТЗ, 5.1; DM-38). Попадают в
// событие auth_failure; приложению не сообщаются — ответ всегда один и тот же.
const (
	ReasonMissing     = "missing"      // нет заголовка Authorization
	ReasonMalformed   = "malformed"    // заголовок или ключ неверного формата
	ReasonInvalid     = "invalid"      // префикс неизвестен или секрет не совпал
	ReasonRevoked     = "revoked"      // ключ отозван
	ReasonExpired     = "expired"      // срок действия истёк
	ReasonAddress     = "address"      // адрес клиента вне allowed_cidrs
	ReasonRateLimited = "rate_limited" // с адреса слишком много неудач подряд
)

// KeyRecord — сохранённый ключ приложения: только префикс и SHA-256.
type KeyRecord struct {
	AppID  string
	Env    string
	Prefix string
	SHA256 string
	// Expires — момент, с которого ключ недействителен; нулевое — бессрочный.
	Expires time.Time
	Revoked bool
	// AllowedCIDRs — разрешённые адреса клиента; пусто — любые.
	AllowedCIDRs []netip.Prefix
}

// Identity — результат успешной аутентификации.
type Identity struct {
	AppID     string
	Env       string
	KeyPrefix string
}

// Failure — подробности отказа для события auth_failure. Сам ключ не
// сохраняется; AppID заполняется, только если префикс известен.
type Failure struct {
	Reason    string
	KeyPrefix string
	AppID     string
	Env       string
}

// Authenticator проверяет ключи приложений. Неизменяем после создания и
// безопасен для одновременного использования.
type Authenticator struct {
	h     aisecCrypto.Hasher
	keys  map[string]KeyRecord
	dummy string // хеш для неизвестного префикса: время ответа не зависит от того, известен ли префикс
}

// NewAuthenticator проверяет записи и строит индекс по префиксу.
func NewAuthenticator(h aisecCrypto.Hasher, records []KeyRecord) (*Authenticator, error) {
	a := &Authenticator{h: h, keys: make(map[string]KeyRecord, len(records))}
	for _, r := range records {
		if r.AppID == "" || !ValidPrefix(r.Prefix) || !ValidHash(r.SHA256) {
			return nil, fmt.Errorf("ключ %q приложения %q: неверная запись", r.Prefix, r.AppID)
		}
		if _, dup := a.keys[r.Prefix]; dup {
			return nil, fmt.Errorf("префикс %s указан дважды", r.Prefix)
		}
		a.keys[r.Prefix] = r
	}
	a.dummy = strings.Repeat("0", 64)
	return a, nil
}

// ErrNoBearer — заголовок Authorization не содержит ключ в схеме Bearer.
var ErrNoBearer = errors.New("ожидается Authorization: Bearer <ключ>")

// BearerToken извлекает ключ из значения заголовка Authorization. Схема
// сравнивается без учёта регистра (RFC 9110, 11.1), лишние пробелы и
// несколько значений не допускаются.
func BearerToken(values []string) (string, error) {
	if len(values) != 1 {
		return "", ErrNoBearer
	}
	v := values[0]
	const scheme = "bearer "
	if len(v) <= len(scheme) || len(v) > len(scheme)+MaxKeyLen || !strings.EqualFold(v[:len(scheme)], scheme) {
		return "", ErrNoBearer
	}
	return v[len(scheme):], nil
}

// Authenticate проверяет предъявленный ключ для клиента с адресом remote в
// момент now. Сначала сравнивается секрет и только потом — отзыв, срок и
// адрес: иначе по причине отказа можно было бы узнать, что префикс
// существует и отозван, не зная секрета.
func (a *Authenticator) Authenticate(key string, remote netip.Addr, now time.Time) (*Identity, *Failure) {
	prefix, err := ParseAppKey(key)
	if err != nil {
		return nil, &Failure{Reason: ReasonMalformed}
	}
	rec, known := a.keys[prefix]
	stored := a.dummy
	if known {
		stored = rec.SHA256
	}
	match := KeyMatches(a.h, key, stored)
	f := &Failure{KeyPrefix: prefix}
	if known {
		f.AppID, f.Env = rec.AppID, rec.Env
	}
	switch {
	case !known || !match:
		f.Reason = ReasonInvalid
	case rec.Revoked:
		f.Reason = ReasonRevoked
	case !rec.Expires.IsZero() && !now.Before(rec.Expires):
		f.Reason = ReasonExpired
	case !addressAllowed(rec.AllowedCIDRs, remote):
		f.Reason = ReasonAddress
	default:
		return &Identity{AppID: rec.AppID, Env: rec.Env, KeyPrefix: prefix}, nil
	}
	return nil, f
}

func addressAllowed(cidrs []netip.Prefix, remote netip.Addr) bool {
	if len(cidrs) == 0 {
		return true
	}
	remote = remote.Unmap()
	for _, p := range cidrs {
		if p.Contains(remote) {
			return true
		}
	}
	return false
}
