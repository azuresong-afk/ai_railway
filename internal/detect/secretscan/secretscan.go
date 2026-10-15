// Пакет secretscan — детектор secrets: ключи API, приватные ключи, пароли в
// явном виде, JWT, строки подключения, высокоэнтропийные токены (ТЗ, 5.2;
// DM-32 — в запросе к модели, DM-10 — в ответе). Пакет назван не по ID
// детектора, чтобы не совпадать с каталогом secrets/ для секретов разработки.
//
// Позиции находок охватывают само секретное значение (пароль в URL, значение
// после «password=»): по ним маскирование, контекст вокруг остаётся модели.
// Правила применяются по приоритету — от самых точных (приватный ключ, ключ
// с префиксом поставщика) к энтропийному анализу; находка правила ниже не
// принимается, если пересекается с уже принятой.
package secretscan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// ID и версия детектора.
const (
	ID      = "secrets"
	Version = "1.0.0"
)

// Категории находок.
const (
	CatPrivateKey = "secret.private_key"
	CatAPIKey     = "secret.api_key"
	CatJWT        = "secret.jwt"
	CatConnString = "secret.connection_string"
	CatPassword   = "secret.password"
	CatToken      = "secret.token"
)

// Оценка заглушек из документации («AKIA…EXAMPLE», «<token>»): видны в
// событии, но ниже порога 0,5.
const placeholderScore = 0.3

// Detector — детектор secrets. Без состояния, безопасен для одновременного
// вызова.
type Detector struct{}

// New создаёт детектор.
func New() Detector { return Detector{} }

// ID — идентификатор детектора.
func (Detector) ID() string { return ID }

// Version — версия детектора.
func (Detector) Version() string { return Version }

// Directions — запрос и ответ.
func (Detector) Directions() []detect.Direction {
	return []detect.Direction{detect.Input, detect.Output}
}

// Detect находит секреты в тексте.
func (Detector) Detect(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	threat := "DM-32"
	if t.Direction == detect.Output {
		threat = "DM-10"
	}
	text := t.Text
	low, err := fold(ctx, text)
	if err != nil {
		return nil, err
	}
	c := &collector{}
	steps := []func() error{
		func() error { return privateKeys(ctx, text, c) },
		func() error { return publicBlocks(ctx, text, c) },
		func() error { return prefixedKeys(ctx, text, c) },
		func() error { return telegramTokens(ctx, text, c) },
		func() error { return jwts(ctx, text, c) },
		func() error { return connStrings(ctx, text, c) },
		func() error { return assignments(ctx, text, low, c) },
		func() error { return authHeaders(ctx, text, low, c) },
		func() error { return highEntropy(ctx, text, low, c) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
		c.commit()
	}
	out := c.done[:0]
	for _, f := range c.done {
		if f.Category == "" {
			continue // исключённый фрагмент: открытый ключ, сертификат
		}
		f.Detector, f.Version, f.Threat = ID, Version, threat
		out = append(out, f)
	}
	return out, nil
}

// collector — принятые находки: не пересекаются, по возрастанию начала.
// Находки текущего правила копятся в pending и после правила сливаются с
// принятыми: время — O(n log n) и на текстах с множеством находок.
type collector struct {
	done, pending []detect.Finding
}

func (c *collector) add(cat, rule string, s, e int, score float64) {
	if s >= e || c.overlaps(s, e) {
		return
	}
	if n := len(c.pending); n > 0 && c.pending[n-1].End > s {
		return // правило уже нашло значение на этом месте
	}
	c.pending = append(c.pending, detect.Finding{Category: cat, Rule: rule, Start: s, End: e, Score: score})
}

// exclude закрывает фрагмент [s, e) для правил ниже по приоритету, не
// создавая находки: открытый ключ и сертификат — не секреты, но их тело
// похоже на случайную строку.
func (c *collector) exclude(s, e int) { c.add("", "", s, e, 0) }

func (c *collector) overlaps(s, e int) bool {
	i := sort.Search(len(c.done), func(i int) bool { return c.done[i].End > s })
	return i < len(c.done) && c.done[i].Start < e
}

// commit сливает находки правила с принятыми.
func (c *collector) commit() {
	if len(c.pending) == 0 {
		return
	}
	sort.SliceStable(c.pending, func(i, j int) bool { return c.pending[i].Start < c.pending[j].Start })
	merged := make([]detect.Finding, 0, len(c.done)+len(c.pending))
	i, j := 0, 0
	for i < len(c.done) || j < len(c.pending) {
		if j == len(c.pending) || i < len(c.done) && c.done[i].Start < c.pending[j].Start {
			merged = append(merged, c.done[i])
			i++
		} else {
			merged = append(merged, c.pending[j])
			j++
		}
	}
	c.done, c.pending = merged, c.pending[:0]
}

// --- Приватные ключи ---

var pemHeadRe = regexp.MustCompile(`^-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP|ED25519|SSH2 ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----`)

// maxPEM — наибольший размер блока ключа: RSA-8192 в PEM — около 6,5 КиБ.
const maxPEM = 32 << 10

// privateKeys — блоки PEM с приватным ключом, от BEGIN до END включительно;
// обрезанный блок — до конца тела. Публичные ключи и сертификаты — не
// секреты. Блок без тела («-----BEGIN PRIVATE KEY-----\n...\n-----END…») —
// пример из документации.
func privateKeys(ctx context.Context, text string, c *collector) error {
	return indexAll(ctx, text, "-----BEGIN ", func(i int) {
		m := pemHeadRe.FindStringIndex(text[i:min(i+64, len(text))])
		if m == nil {
			return
		}
		body := i + m[1]
		limit := min(body+maxPEM, len(text))
		end := -1
		if j := strings.Index(text[body:limit], "-----END "); j >= 0 {
			k := body + j + len("-----END ")
			if l := strings.Index(text[k:min(k+64, len(text))], "-----"); l >= 0 {
				end = k + l + len("-----")
			}
		}
		if end < 0 {
			end = body
			for end < limit && isPEMByte(text[end]) {
				end++
			}
		}
		if base64Chars(text[body:end]) < 64 {
			c.add(CatPrivateKey, "pem.empty", i, end, placeholderScore)
			return
		}
		c.add(CatPrivateKey, "pem", i, end, 0.99)
	})
}

var pemPublicRe = regexp.MustCompile(`^-----BEGIN (?:(?:RSA|EC|DSA|PGP|SSH2) )?(?:PUBLIC KEY(?: BLOCK)?|CERTIFICATE(?: REQUEST)?|TRUSTED CERTIFICATE|NEW CERTIFICATE REQUEST|X509 CRL)-----`)

// publicBlocks исключает из проверки блоки PEM с открытым ключом,
// сертификатом, запросом на сертификат и списком отзыва.
func publicBlocks(ctx context.Context, text string, c *collector) error {
	return indexAll(ctx, text, "-----BEGIN ", func(i int) {
		m := pemPublicRe.FindStringIndex(text[i:min(i+64, len(text))])
		if m == nil {
			return
		}
		body := i + m[1]
		limit := min(body+maxPEM, len(text))
		end := body
		if j := strings.Index(text[body:limit], "-----END "); j >= 0 {
			end = body + j + len("-----END ")
			if l := strings.Index(text[end:min(end+64, len(text))], "-----"); l >= 0 {
				end += l + len("-----")
			}
		} else {
			for end < limit && isPEMByte(text[end]) {
				end++
			}
		}
		c.exclude(i, end)
	})
}

// isPEMByte — символ тела PEM: base64, пробелы и переводы строк, заголовки
// («Proc-Type: 4,ENCRYPTED»), «\» из экранированного «\n» в JSON.
func isPEMByte(b byte) bool {
	return isTokenByte(b) || strings.IndexByte("+/= \t\r\n:,\\", b) >= 0
}

func base64Chars(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if b := s[i]; isTokenByte(b) && b != '_' && b != '-' || b == '+' || b == '/' {
			n++
		}
	}
	return n
}

// --- Ключи с префиксом поставщика ---

// prefixRule — ключ с известным префиксом и форматом. Выражение
// применяется к окну у найденного префикса, а не ко всему тексту.
type prefixRule struct {
	prefix string
	re     *regexp.Regexp
	rule   string
	score  float64
}

func pr(prefix, expr, rule string, score float64) prefixRule {
	return prefixRule{prefix, regexp.MustCompile("^" + expr), rule, score}
}

// prefixRules — по приоритету: «sk-ant-» раньше «sk-».
var prefixRules = []prefixRule{
	pr("aisec_", `aisec_[a-z0-9]{8}_[A-Za-z0-9_-]{43}`, "aisec", 0.99),
	pr("github_pat_", `github_pat_[A-Za-z0-9_]{50,255}`, "github", 0.97),
	pr("ghp_", `ghp_[A-Za-z0-9]{36}`, "github", 0.97),
	pr("gho_", `gho_[A-Za-z0-9]{36}`, "github", 0.97),
	pr("ghu_", `ghu_[A-Za-z0-9]{36}`, "github", 0.97),
	pr("ghs_", `ghs_[A-Za-z0-9]{36}`, "github", 0.97),
	pr("ghr_", `ghr_[A-Za-z0-9]{36}`, "github", 0.97),
	pr("glpat-", `glpat-[A-Za-z0-9_-]{20,64}`, "gitlab", 0.97),
	pr("xox", `xox[abeoprs]-[A-Za-z0-9-]{10,250}`, "slack", 0.95),
	pr("xapp-", `xapp-\d-[A-Za-z0-9-]{10,250}`, "slack", 0.95),
	pr("sk-ant-", `sk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_-]{32,255}`, "anthropic", 0.97),
	pr("sk-", `sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,255}`, "openai", 0.9),
	pr("sk_live_", `sk_live_[A-Za-z0-9]{16,255}`, "stripe", 0.97),
	pr("rk_live_", `rk_live_[A-Za-z0-9]{16,255}`, "stripe", 0.97),
	pr("sk_test_", `sk_test_[A-Za-z0-9]{16,255}`, "stripe", 0.9),
	pr("rk_test_", `rk_test_[A-Za-z0-9]{16,255}`, "stripe", 0.9),
	pr("AKIA", `AKIA[A-Z0-9]{16}`, "aws", 0.9),
	pr("ASIA", `ASIA[A-Z0-9]{16}`, "aws", 0.9),
	pr("AIza", `AIza[0-9A-Za-z_-]{35}`, "google", 0.95),
	pr("AQVN", `AQVN[A-Za-z0-9_-]{30,64}`, "yandex", 0.95),
	pr("t1.", `t1\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{40,}`, "yandex.iam", 0.95),
	pr("y0_", `y0_[A-Za-z0-9_-]{40,128}`, "yandex.oauth", 0.95),
	pr("npm_", `npm_[A-Za-z0-9]{36}`, "npm", 0.95),
	pr("hf_", `hf_[A-Za-z]{34}`, "huggingface", 0.9),
}

// maxToken — окно для выражения ключа: самый длинный формат — IAM-токен
// (длину остальных задают выражения).
const maxToken = 2048

// prefixedKeys — ключи с префиксом поставщика. Значение должно стоять
// отдельно (не продолжать более длинный токен); заглушки — ниже порога.
func prefixedKeys(ctx context.Context, text string, c *collector) error {
	for _, r := range prefixRules {
		err := indexAll(ctx, text, r.prefix, func(s int) {
			if s > 0 && isTokenByte(text[s-1]) {
				return
			}
			m := r.re.FindStringIndex(text[s:min(s+maxToken, len(text))])
			if m == nil {
				return
			}
			e := s + m[1]
			if e < len(text) && isTokenByte(text[e]) {
				return
			}
			if isPlaceholder(text[s+len(r.prefix) : e]) {
				c.add(CatAPIKey, r.rule+".example", s, e, placeholderScore)
				return
			}
			c.add(CatAPIKey, r.rule, s, e, r.score)
		})
		if err != nil {
			return err
		}
		c.commit()
	}
	return nil
}

// telegramTokens — токен бота Telegram: 8–10 цифр, «:», 35 символов.
func telegramTokens(ctx context.Context, text string, c *collector) error {
	return indexAll(ctx, text, ":", func(i int) {
		s := i
		for s > 0 && i-s <= 10 && text[s-1] >= '0' && text[s-1] <= '9' {
			s--
		}
		if i-s < 8 || i-s > 10 || s > 0 && isTokenByte(text[s-1]) {
			return
		}
		e := i + 1
		for e < len(text) && e-i-1 <= 35 && isTokenByte(text[e]) {
			e++
		}
		if e-i-1 != 35 || charClasses(text[i+1:e]) < 3 {
			return
		}
		c.add(CatAPIKey, "telegram", s, e, 0.9)
	})
}

// --- JWT ---

// jwtRe — три части base64url; длину ограничивает окно maxJWT.
var jwtRe = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)

// maxJWT — окно для JWT: токены с большим набором утверждений — до десятков КиБ.
const maxJWT = 32 << 10

// jwts — JWT: заголовок декодируется в объект JSON с полем «alg».
func jwts(ctx context.Context, text string, c *collector) error {
	return indexAll(ctx, text, "eyJ", func(s int) {
		if s > 0 && (isTokenByte(text[s-1]) || text[s-1] == '.') {
			return
		}
		m := jwtRe.FindStringIndex(text[s:min(s+maxJWT, len(text))])
		if m == nil {
			return
		}
		e := s + m[1]
		if e < len(text) && (isTokenByte(text[e]) || text[e] == '.') {
			return
		}
		v := text[s:e]
		dot := strings.IndexByte(v, '.')
		if !jwtHeader(v[:dot]) {
			return
		}
		if sig := v[strings.LastIndexByte(v, '.')+1:]; len(sig) < 16 {
			c.add(CatJWT, "jwt.unsigned", s, e, 0.85)
			return
		}
		c.add(CatJWT, "jwt", s, e, 0.95)
	})
}

// jwtHeader — заголовок JWT: base64url без выравнивания, объект JSON с «alg».
func jwtHeader(h string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(h)
	if err != nil {
		return false
	}
	var hdr map[string]json.RawMessage
	if json.Unmarshal(raw, &hdr) != nil {
		return false
	}
	_, ok := hdr["alg"]
	return ok
}

// --- Строки подключения ---

// connStrings — пароль в URL: «scheme://user:password@host». Находка — сам
// пароль: хост и имя пользователя остаются модели.
func connStrings(ctx context.Context, text string, c *collector) error {
	return indexAll(ctx, text, "://", func(i int) {
		j := i
		for j > 0 && i-j < 32 && isSchemeByte(text[j-1]) {
			j--
		}
		if i-j < 2 || !isLetterByte(text[j]) {
			return
		}
		k := i + 3
		end := k
		for end < len(text) && end-k < 512 && !isAuthorityEnd(text[end]) {
			end++
		}
		at := strings.LastIndexByte(text[k:end], '@')
		if at < 0 {
			return
		}
		colon := strings.IndexByte(text[k:k+at], ':')
		if colon < 0 {
			return
		}
		ps, pe := k+colon+1, k+at
		if pe <= ps {
			return
		}
		if isPlaceholder(text[ps:pe]) {
			c.add(CatConnString, "url.example", ps, pe, placeholderScore)
			return
		}
		c.add(CatConnString, "url.password", ps, pe, 0.95)
	})
}

func isLetterByte(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }

func isSchemeByte(b byte) bool {
	return isLetterByte(b) || b >= '0' && b <= '9' || b == '+' || b == '.' || b == '-'
}

// isAuthorityEnd — конец части URL до пути: «/», «?», «#», пробел, кавычки,
// угловые скобки.
func isAuthorityEnd(b byte) bool {
	return strings.IndexByte("/?#\"'<>` \t\r\n", b) >= 0
}
