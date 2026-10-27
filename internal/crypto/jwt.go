package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"
)

// Алгоритмы подписи ID-токенов OIDC (ADR-0025, раздел 3, п. 5). Остальные,
// включая none и HS*, отклоняются.
const (
	JWTAlgRS256 = "RS256"
	JWTAlgES256 = "ES256"
	JWTAlgEdDSA = "EdDSA"
)

// Пределы разбора JWT и JWKS (ADR-0025): недоверенный ввод от IdP и браузера.
const (
	// MaxJWTSize — длина ID-токена в компактной форме.
	MaxJWTSize = 16 << 10
	// maxJWTPart — заголовок и утверждения после декодирования base64url.
	maxJWTPart = 8 << 10
	// maxJWTSig — подпись после декодирования (RSA 8 192 бит — 1 024 байта).
	maxJWTSig = 1 << 10
	// MaxJWKSSize — набор ключей издателя.
	MaxJWKSSize = 64 << 10
	// MaxJWKSKeys — ключей в наборе.
	MaxJWKSKeys = 32
	// maxJSONDepth — вложенность объектов и массивов JSON.
	maxJSONDepth = 16
	// JWTLeeway — допуск расхождения часов для exp, iat и nbf.
	JWTLeeway = time.Minute
	// DefaultIDTokenMaxAge — насколько старым может быть iat ID-токена на
	// момент проверки: токен проверяется сразу после обмена кода.
	DefaultIDTokenMaxAge = 10 * time.Minute
	// maxKIDLen, maxClaimString — длина kid и строковых утверждений.
	maxKIDLen      = 256
	maxSubjectLen  = 255
	maxClaimString = 1024
	maxAudiences   = 16
	// maxNumericDate — 2^53: целые за ним в JSON теряют точность.
	maxNumericDate = 1 << 53
)

// Причины отказа в проверке JWT для журнала аудита (наружу не выдаются).
const (
	JWTReasonMalformed  = "malformed"
	JWTReasonAlg        = "alg"
	JWTReasonUnknownKey = "unknown_kid"
	JWTReasonSignature  = "signature"
	JWTReasonIssuer     = "issuer"
	JWTReasonAudience   = "audience"
	JWTReasonAZP        = "azp"
	JWTReasonExpired    = "expired"
	JWTReasonIssuedAt   = "iat"
	JWTReasonNotBefore  = "nbf"
	JWTReasonNonce      = "nonce"
	JWTReasonSubject    = "subject"
)

// JWTError — отказ в проверке JWT; Reason — одна из JWTReason*.
type JWTError struct {
	Reason string
	detail string
}

func (e *JWTError) Error() string {
	if e.detail == "" {
		return "JWT: " + e.Reason
	}
	return "JWT: " + e.Reason + ": " + e.detail
}

func jwtErr(reason, detail string) error { return &JWTError{Reason: reason, detail: detail} }

// JWTReason — причина отказа из ошибки проверки; пусто — ошибка не JWTError.
func JWTReason(err error) string {
	var je *JWTError
	if errors.As(err, &je) {
		return je.Reason
	}
	return ""
}

// ErrJWKS — набор ключей издателя не прошёл разбор.
var ErrJWKS = errors.New("JWKS: неверный набор ключей")

// JWTVerifier — проверка ID-токенов внешнего IdP (OIDC, ADR-0025). Ключи —
// только из JWKS настроенного издателя; jku, jwk, x5u, x5c заголовка не
// используются.
type JWTVerifier interface {
	// ParseJWKS разбирает набор ключей издателя (RFC 7517): до MaxJWKSSize
	// байт и MaxJWKSKeys ключей. Ключи не для подписи и неподдерживаемых
	// типов пропускаются, ключ с ошибкой отклоняет весь набор.
	ParseJWKS(data []byte) (*JWKS, error)
	// VerifyIDToken проверяет подпись и утверждения ID-токена. Ошибка —
	// *JWTError с причиной; JWTReasonUnknownKey — повод обновить JWKS.
	VerifyIDToken(token string, keys *JWKS, want IDTokenExpect) (IDTokenClaims, error)
}

// IDTokenExpect — ожидаемые значения утверждений.
type IDTokenExpect struct {
	Issuer   string
	Audience string // client_id
	Nonce    string // пусто — nonce не проверяется
	Now      time.Time
	// MaxAge — предельный возраст iat; ноль — DefaultIDTokenMaxAge.
	MaxAge time.Duration
}

// IDTokenClaims — проверенные утверждения ID-токена.
type IDTokenClaims struct {
	Issuer    string
	Subject   string
	Audience  []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	raw       map[string]json.RawMessage
}

// String — строковое утверждение name; ok = false — его нет или это не строка.
func (c IDTokenClaims) String(name string) (string, bool) {
	raw, ok := c.raw[name]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || len(s) > maxClaimString {
		return "", false
	}
	return s, true
}

// Strings — утверждение name как список строк: массив строк или одна
// строка. Нет утверждения — nil без ошибки; другой тип, больше maxItems
// значений или значение длиннее maxLen байт — ошибка.
func (c IDTokenClaims) Strings(name string, maxItems, maxLen int) ([]string, error) {
	raw, ok := c.raw[name]
	if !ok || string(raw) == "null" {
		return nil, nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if len(one) > maxLen {
			return nil, errors.New("значение утверждения слишком длинное")
		}
		return []string{one}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, errors.New("утверждение не строка и не массив строк")
	}
	if len(list) > maxItems {
		return nil, errors.New("в утверждении слишком много значений")
	}
	for _, s := range list {
		if len(s) > maxLen {
			return nil, errors.New("значение утверждения слишком длинное")
		}
	}
	return list, nil
}

// JWKS — разобранный набор открытых ключей подписи издателя.
type JWKS struct {
	keys []jwk
}

// Len — число ключей подписи в наборе.
func (s *JWKS) Len() int {
	if s == nil {
		return 0
	}
	return len(s.keys)
}

// Has — есть ли ключ с идентификатором kid.
func (s *JWKS) Has(kid string) bool {
	if s == nil {
		return false
	}
	for _, k := range s.keys {
		if k.kid == kid {
			return true
		}
	}
	return false
}

type jwk struct {
	kid string
	alg string // из набора; пусто — не задан
	// Ровно одно из трёх.
	rsa *rsa.PublicKey
	ec  *ecdsa.PublicKey
	ed  ed25519.PublicKey
}

// fits — ключ подходит алгоритму: тип ключа соответствует алгоритму, и
// заданный в наборе alg совпадает. Так открытый ключ нельзя использовать с
// другим алгоритмом (подмена алгоритма).
func (k jwk) fits(alg string) bool {
	if k.alg != "" && k.alg != alg {
		return false
	}
	switch alg {
	case JWTAlgRS256:
		return k.rsa != nil
	case JWTAlgES256:
		return k.ec != nil
	case JWTAlgEdDSA:
		return k.ed != nil
	}
	return false
}

// standardJWT — проверка JWT средствами стандартной библиотеки Go.
type standardJWT struct{}

var b64 = base64.RawURLEncoding.Strict()

func (standardJWT) ParseJWKS(data []byte) (*JWKS, error) {
	if len(data) > MaxJWKSSize {
		return nil, errors.Join(ErrJWKS, errors.New("набор больше предела"))
	}
	top, err := jsonObject(data)
	if err != nil {
		return nil, errors.Join(ErrJWKS, err)
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(top["keys"], &raws); err != nil || raws == nil {
		return nil, errors.Join(ErrJWKS, errors.New("нет массива keys"))
	}
	if len(raws) > MaxJWKSKeys {
		return nil, errors.Join(ErrJWKS, errors.New("слишком много ключей"))
	}
	set := &JWKS{}
	seen := map[string]bool{}
	for _, raw := range raws {
		k, ok, err := parseJWK(raw)
		if err != nil {
			return nil, errors.Join(ErrJWKS, err)
		}
		if !ok {
			continue
		}
		// Два ключа подписи с одним kid — неоднозначность: отказ всего набора.
		if k.kid != "" {
			if seen[k.kid] {
				return nil, errors.Join(ErrJWKS, errors.New("повторяющийся kid"))
			}
			seen[k.kid] = true
		}
		set.keys = append(set.keys, k)
	}
	if len(set.keys) == 0 {
		return nil, errors.Join(ErrJWKS, errors.New("нет ключей подписи"))
	}
	return set, nil
}

// parseJWK — один ключ набора; ok = false — ключ пропускается (не для
// подписи или неподдерживаемого типа).
func parseJWK(raw json.RawMessage) (jwk, bool, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return jwk{}, false, errors.New("ключ — не объект")
	}
	field := func(name string) (string, error) {
		v, ok := m[name]
		if !ok {
			return "", nil
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return "", errors.New("поле " + name + " — не строка")
		}
		return s, nil
	}
	var f [9]string
	for i, name := range []string{"kty", "use", "alg", "kid", "n", "e", "crv", "x", "y"} {
		s, err := field(name)
		if err != nil {
			return jwk{}, false, err
		}
		f[i] = s
	}
	kty, use, alg, kid := f[0], f[1], f[2], f[3]
	if use != "" && use != "sig" {
		return jwk{}, false, nil
	}
	if len(kid) > maxKIDLen || !printableASCII(kid) {
		return jwk{}, false, errors.New("недопустимый kid")
	}
	k := jwk{kid: kid, alg: alg}
	switch kty {
	case "RSA":
		if alg != "" && alg != JWTAlgRS256 {
			return jwk{}, false, nil
		}
		pub, err := parseRSAKey(f[4], f[5])
		if err != nil {
			return jwk{}, false, err
		}
		k.rsa = pub
	case "EC":
		if f[6] != "P-256" || (alg != "" && alg != JWTAlgES256) {
			return jwk{}, false, nil
		}
		pub, err := parseP256Key(f[7], f[8])
		if err != nil {
			return jwk{}, false, err
		}
		k.ec = pub
	case "OKP":
		if f[6] != "Ed25519" || (alg != "" && alg != JWTAlgEdDSA) {
			return jwk{}, false, nil
		}
		x, err := b64.DecodeString(f[7])
		if err != nil || len(x) != ed25519.PublicKeySize {
			return jwk{}, false, errors.New("неверный ключ Ed25519")
		}
		k.ed = ed25519.PublicKey(x)
	default:
		// oct (симметричные ключи) и неизвестные типы не принимаются никогда.
		return jwk{}, false, nil
	}
	return k, true, nil
}

// parseRSAKey — ключ RSA с модулем minRSABits–maxRSABits (как у
// сертификатов, ТЗ 10.3): короче — слабый, длиннее — дорогая проверка
// подписи на каждый вход.
func parseRSAKey(n64, e64 string) (*rsa.PublicKey, error) {
	n, err := b64.DecodeString(n64)
	if err != nil || len(n) == 0 || len(n) > maxRSABits/8+1 {
		return nil, errors.New("неверный модуль RSA")
	}
	e, err := b64.DecodeString(e64)
	if err != nil || len(e) == 0 || len(e) > 4 {
		return nil, errors.New("неверная экспонента RSA")
	}
	nb := new(big.Int).SetBytes(n)
	if bits := nb.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, errors.New("длина модуля RSA вне 2048–8192 бит")
	}
	eb := new(big.Int).SetBytes(e)
	if !eb.IsInt64() || eb.Int64() < 3 || eb.Int64() > math.MaxInt32 || eb.Bit(0) == 0 {
		return nil, errors.New("недопустимая экспонента RSA")
	}
	return &rsa.PublicKey{N: nb, E: int(eb.Int64())}, nil
}

func parseP256Key(x64, y64 string) (*ecdsa.PublicKey, error) {
	x, errX := b64.DecodeString(x64)
	y, errY := b64.DecodeString(y64)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("неверные координаты ключа P-256")
	}
	pt := make([]byte, 0, 65)
	pt = append(append(append(pt, 4), x...), y...)
	// Разбор проверяет, что точка лежит на кривой.
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
	if err != nil {
		return nil, errors.New("точка не на кривой P-256")
	}
	return pub, nil
}

func (standardJWT) VerifyIDToken(token string, keys *JWKS, want IDTokenExpect) (IDTokenClaims, error) {
	if want.Issuer == "" || want.Audience == "" || want.Now.IsZero() {
		return IDTokenClaims{}, errors.New("JWT: не заданы издатель, клиент или время проверки")
	}
	if len(token) > MaxJWTSize || strings.Count(token, ".") != 2 {
		return IDTokenClaims{}, jwtErr(JWTReasonMalformed, "не компактная форма JWS")
	}
	h64, rest, _ := strings.Cut(token, ".")
	p64, s64, _ := strings.Cut(rest, ".")
	if h64 == "" || p64 == "" || s64 == "" || len(h64) > b64.EncodedLen(maxJWTPart) ||
		len(p64) > b64.EncodedLen(maxJWTPart) || len(s64) > b64.EncodedLen(maxJWTSig) {
		return IDTokenClaims{}, jwtErr(JWTReasonMalformed, "пустая или слишком длинная часть")
	}
	hdrJSON, err := b64.DecodeString(h64)
	if err != nil {
		return IDTokenClaims{}, jwtErr(JWTReasonMalformed, "заголовок не base64url")
	}
	hdr, err := jsonObject(hdrJSON)
	if err != nil {
		return IDTokenClaims{}, jwtErr(JWTReasonMalformed, "заголовок: "+err.Error())
	}
	alg, ok := rawString(hdr, "alg")
	if !ok {
		return IDTokenClaims{}, jwtErr(JWTReasonAlg, "нет alg")
	}
	if alg != JWTAlgRS256 && alg != JWTAlgES256 && alg != JWTAlgEdDSA {
		return IDTokenClaims{}, jwtErr(JWTReasonAlg, "алгоритм не допускается")
	}
	// Расширения, которые надо понимать (RFC 7515, 4.1.11), не поддерживаются.
	if _, ok := hdr["crit"]; ok {
		return IDTokenClaims{}, jwtErr(JWTReasonMalformed, "заголовок crit")
	}
	if typ, ok := hdr["typ"]; ok {
		// Токен доступа (typ at+jwt) за ID-токен не принимается.
		var t string
		if json.Unmarshal(typ, &t) != nil || !strings.EqualFold(t, "JWT") {
			return IDTokenClaims{}, jwtErr(JWTReasonMalformed, "typ не JWT")
		}
	}
	kid := ""
	if raw, ok := hdr["kid"]; ok {
		if json.Unmarshal(raw, &kid) != nil || len(kid) > maxKIDLen {
			return IDTokenClaims{}, jwtErr(JWTReasonMalformed, "неверный kid")
		}
	}
	key, err := pickKey(keys, kid, alg)
	if err != nil {
		return IDTokenClaims{}, err
	}
	sig, err := b64.DecodeString(s64)
	if err != nil {
		return IDTokenClaims{}, jwtErr(JWTReasonMalformed, "подпись не base64url")
	}
	signed := token[:len(h64)+1+len(p64)]
	if !verifyJWS(key, alg, []byte(signed), sig) {
		return IDTokenClaims{}, jwtErr(JWTReasonSignature, "")
	}
	payload, err := b64.DecodeString(p64)
	if err != nil {
		return IDTokenClaims{}, jwtErr(JWTReasonMalformed, "утверждения не base64url")
	}
	claims, err := jsonObject(payload)
	if err != nil {
		return IDTokenClaims{}, jwtErr(JWTReasonMalformed, "утверждения: "+err.Error())
	}
	return checkClaims(claims, want)
}

// pickKey — ключ по kid; без kid — единственный ключ нужного типа.
func pickKey(keys *JWKS, kid, alg string) (jwk, error) {
	if keys == nil {
		return jwk{}, jwtErr(JWTReasonUnknownKey, "нет набора ключей")
	}
	if kid != "" {
		for _, k := range keys.keys {
			if k.kid == kid {
				if !k.fits(alg) {
					return jwk{}, jwtErr(JWTReasonAlg, "тип ключа не соответствует алгоритму")
				}
				return k, nil
			}
		}
		return jwk{}, jwtErr(JWTReasonUnknownKey, "")
	}
	var found []jwk
	for _, k := range keys.keys {
		if k.fits(alg) {
			found = append(found, k)
		}
	}
	if len(found) != 1 {
		return jwk{}, jwtErr(JWTReasonUnknownKey, "без kid ключ неоднозначен")
	}
	return found[0], nil
}

func verifyJWS(k jwk, alg string, signed, sig []byte) bool {
	switch alg {
	case JWTAlgRS256:
		h := sha256.Sum256(signed)
		return rsa.VerifyPKCS1v15(k.rsa, crypto.SHA256, h[:], sig) == nil
	case JWTAlgES256:
		// JWS хранит подпись ECDSA как r‖s фиксированной длины (RFC 7518, 3.4).
		if len(sig) != 64 {
			return false
		}
		h := sha256.Sum256(signed)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(k.ec, h[:], r, s)
	case JWTAlgEdDSA:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(k.ed, signed, sig)
	}
	return false
}

func checkClaims(c map[string]json.RawMessage, want IDTokenExpect) (IDTokenClaims, error) {
	out := IDTokenClaims{raw: c}
	iss, ok := rawString(c, "iss")
	if !ok || iss != want.Issuer {
		return IDTokenClaims{}, jwtErr(JWTReasonIssuer, "")
	}
	out.Issuer = iss
	sub, ok := rawString(c, "sub")
	if !ok || sub == "" || len(sub) > maxSubjectLen || !utf8.ValidString(sub) || hasControlRune(sub) {
		return IDTokenClaims{}, jwtErr(JWTReasonSubject, "")
	}
	out.Subject = sub
	aud, err := audiences(c["aud"])
	if err != nil || !containsString(aud, want.Audience) {
		return IDTokenClaims{}, jwtErr(JWTReasonAudience, "")
	}
	out.Audience = aud
	// azp обязателен при нескольких получателях и тогда должен быть нашим
	// клиентом (OpenID Connect Core 1.0, 3.1.3.7, п. 4–5).
	azp, hasAZP := rawString(c, "azp")
	if _, present := c["azp"]; present && !hasAZP {
		return IDTokenClaims{}, jwtErr(JWTReasonAZP, "")
	}
	if (len(aud) > 1 && !hasAZP) || (hasAZP && azp != want.Audience) {
		return IDTokenClaims{}, jwtErr(JWTReasonAZP, "")
	}
	now := want.Now
	exp, ok := numericDate(c, "exp")
	if !ok {
		return IDTokenClaims{}, jwtErr(JWTReasonExpired, "нет exp")
	}
	if !now.Before(exp.Add(JWTLeeway)) {
		return IDTokenClaims{}, jwtErr(JWTReasonExpired, "")
	}
	out.ExpiresAt = exp
	iat, ok := numericDate(c, "iat")
	if !ok {
		return IDTokenClaims{}, jwtErr(JWTReasonIssuedAt, "нет iat")
	}
	maxAge := want.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultIDTokenMaxAge
	}
	if iat.After(now.Add(JWTLeeway)) || now.Sub(iat) > maxAge {
		return IDTokenClaims{}, jwtErr(JWTReasonIssuedAt, "")
	}
	out.IssuedAt = iat
	if _, present := c["nbf"]; present {
		nbf, ok := numericDate(c, "nbf")
		if !ok || nbf.After(now.Add(JWTLeeway)) {
			return IDTokenClaims{}, jwtErr(JWTReasonNotBefore, "")
		}
	}
	if want.Nonce != "" {
		nonce, ok := rawString(c, "nonce")
		if !ok || !Equal([]byte(nonce), []byte(want.Nonce)) {
			return IDTokenClaims{}, jwtErr(JWTReasonNonce, "")
		}
	}
	return out, nil
}

func audiences(raw json.RawMessage) ([]string, error) {
	if raw == nil {
		return nil, errors.New("нет aud")
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" || len(one) > maxClaimString {
			return nil, errors.New("неверный aud")
		}
		return []string{one}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 || len(list) > maxAudiences {
		return nil, errors.New("неверный aud")
	}
	for _, s := range list {
		if s == "" || len(s) > maxClaimString {
			return nil, errors.New("неверный aud")
		}
	}
	return list, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// numericDate — утверждение-время (RFC 7519, 2): число секунд от эпохи в
// пределах ±2^53; дробная часть отбрасывается.
func numericDate(c map[string]json.RawMessage, name string) (time.Time, bool) {
	raw, ok := c[name]
	if !ok {
		return time.Time{}, false
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > maxNumericDate {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0).UTC(), true
}

// rawString — строковое поле объекта; ok = false — нет или не строка.
func rawString(m map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := m[name]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || len(s) > maxClaimString {
		return "", false
	}
	return s, true
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// errJSON* — нарушения строгого JSON недоверенных объектов.
var (
	errJSONDuplicate = errors.New("повторяющийся ключ JSON")
	errJSONDepth     = errors.New("слишком глубокая вложенность JSON")
	errJSONNotObject = errors.New("не объект JSON")
)

// jsonObject разбирает объект JSON верхнего уровня строго: без
// повторяющихся ключей на любом уровне (encoding/json молча берёт последнее
// значение, и два разборщика по-разному прочли бы один токен), без
// данных после объекта и с ограничением вложенности. Ключи сравниваются
// точно, без учёта регистра encoding/json для структур.
func jsonObject(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	t, err := dec.Token()
	if err != nil {
		return nil, errJSONNotObject
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, errJSONNotObject
	}
	if err := walkObject(dec, 1); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("данные после объекта JSON")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, errJSONNotObject
	}
	return m, nil
}

// walkObject проходит объект после «{» до закрывающей «}».
func walkObject(dec *json.Decoder, depth int) error {
	seen := map[string]struct{}{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		k, ok := t.(string)
		if !ok {
			return errJSONNotObject
		}
		if _, dup := seen[k]; dup {
			return errJSONDuplicate
		}
		seen[k] = struct{}{}
		if err := walkValue(dec, depth); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

func walkValue(dec *json.Decoder, depth int) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxJSONDepth {
		return errJSONDepth
	}
	switch d {
	case '{':
		return walkObject(dec, depth+1)
	case '[':
		for dec.More() {
			if err := walkValue(dec, depth+1); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	}
	return errJSONNotObject
}

// PKCEChallengeS256 — code_challenge метода S256 для code_verifier (RFC
// 7636, 4.2). SHA-256 задан протоколом, а не профилем.
func PKCEChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// hasControlRune — в строке есть управляющий символ (C0, DEL, C1): sub
// хранится в БД и журнале аудита, NUL туда не записать.
func hasControlRune(s string) bool {
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return true
		}
	}
	return false
}
