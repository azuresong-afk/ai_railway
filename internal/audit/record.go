package audit

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// DefaultOrgID — организация по умолчанию из migrations/0001_init.sql.
const DefaultOrgID = "00000000-0000-7000-8000-000000000001"

// Лимиты полей записи; в БД те же значения стоят в CHECK.
const (
	maxActorID      = 128
	maxActorName    = 256
	maxObjectType   = 64
	maxObjectID     = 256
	maxDetailsSize  = 16 << 10
	maxDetailsDepth = 8
	// formatVersion — версия канонической формы; меняется только вместе
	// с проверкой, которая умеет читать все прежние версии.
	formatVersion = 1
	tsLayout      = "2006-01-02T15:04:05.000000Z"
)

// ActorType — кто совершил действие.
type ActorType string

const (
	ActorUser     ActorType = "user"
	ActorAPIToken ActorType = "api_token"
	ActorSystem   ActorType = "system"
	ActorGateway  ActorType = "gateway"
	ActorCLI      ActorType = "cli"
)

// Result — итог действия.
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
	ResultDenied  Result = "denied"
)

// Actor — субъект действия: пользователь, токен API, компонент или CLI.
type Actor struct {
	Type ActorType
	ID   string // ID пользователя, токена, шлюза; для system — имя компонента
	Name string // логин или имя для показа; не секрет
}

// Object — объект действия.
type Object struct {
	Type string // например, «policy», «user»; пусто — действие без объекта
	ID   string
}

// Entry — запись, которую передаёт вызывающий код (РСБ.1): кто, откуда,
// что сделал, с каким объектом и каким результатом.
type Entry struct {
	OrgID    string     // пусто — организация по умолчанию
	Actor    Actor      // кто
	SourceIP netip.Addr // откуда; нулевое значение — адреса нет (системные события)
	Action   string     // код из перечня (catalog.go)
	Object   Object
	Result   Result
	// Details — подробности, сериализуемые в JSON-объект; для изменений
	// конфигурации — {"before": …, "after": …}. Секреты сюда не передаются:
	// ключи вида password, secret, token отклоняются.
	Details any
}

// Record — сохранённая запись журнала.
type Record struct {
	Seq      int64
	ID       string
	OrgID    string
	TS       time.Time
	Actor    Actor
	SourceIP netip.Addr
	Action   string
	Object   Object
	Result   Result
	Details  json.RawMessage // каноническая форма
	HashAlg  string
	PrevHash []byte
	Hash     []byte
	// unreadable — запись прочитана из БД не полностью (время не конечное,
	// адрес не разбирается): проверка считает её нарушением.
	unreadable bool
}

// canonicalRecord — каноническая форма записи: порядок полей фиксирован
// объявлением, encoding/json сериализует его детерминированно.
type canonicalRecord struct {
	V       int             `json:"v"`
	Seq     int64           `json:"seq"`
	ID      string          `json:"id"`
	OrgID   string          `json:"org_id"`
	TS      string          `json:"ts"`
	Actor   canonicalActor  `json:"actor"`
	IP      string          `json:"ip"`
	Action  string          `json:"action"`
	Object  canonicalObject `json:"object"`
	Result  string          `json:"result"`
	Details json.RawMessage `json:"details"`
	Alg     string          `json:"alg"`
	Prev    string          `json:"prev"`
}

type canonicalActor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

type canonicalObject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Canonical возвращает каноническую форму записи — то, что хешируется.
func (r *Record) Canonical() ([]byte, error) {
	ip := ""
	if r.SourceIP.IsValid() {
		ip = r.SourceIP.String()
	}
	return json.Marshal(canonicalRecord{
		V:       formatVersion,
		Seq:     r.Seq,
		ID:      r.ID,
		OrgID:   r.OrgID,
		TS:      r.TS.UTC().Format(tsLayout),
		Actor:   canonicalActor{Type: string(r.Actor.Type), ID: r.Actor.ID, Name: r.Actor.Name},
		IP:      ip,
		Action:  r.Action,
		Object:  canonicalObject{Type: r.Object.Type, ID: r.Object.ID},
		Result:  string(r.Result),
		Details: r.Details,
		Alg:     r.HashAlg,
		Prev:    hex.EncodeToString(r.PrevHash),
	})
}

// ComputeHash считает хеш записи: H(каноническая форма), где prev входит
// в форму, — так каждая запись зависит от всех предыдущих.
func (r *Record) ComputeHash(h crypto.Hasher) ([]byte, error) {
	c, err := r.Canonical()
	if err != nil {
		return nil, fmt.Errorf("каноническая форма записи %d: %w", r.Seq, err)
	}
	return h.Sum(c), nil
}

// genesis — prev первой записи журнала: нули длины хеша профиля.
func genesis(h crypto.Hasher) []byte { return make([]byte, h.New().Size()) }

// cleanText приводит текст к виду, который принимает БД, не отклоняя запись:
// значения вроде логина при неудачном входе задаёт нарушитель, а
// обязательное событие должно записаться (РСБ.2). Неверные байты UTF-8 и
// NUL заменяются на U+FFFD, длинное обрезается до limit символов с «…» в
// конце.
func cleanText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.ReplaceAll(s, "\x00", "\uFFFD")
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	r := []rune(s)
	return string(r[:limit-1]) + "…"
}

// normalize проверяет запись вызывающего кода и возвращает тип события.
// Отклоняются только ошибки программиста (код действия, тип субъекта,
// результат, ID организации); поля, которые может задать нарушитель,
// нормализуются.
func (e *Entry) normalize() (Event, error) {
	ev, ok := Lookup(e.Action)
	if !ok {
		return Event{}, fmt.Errorf("код события %q не из перечня", e.Action)
	}
	switch e.Actor.Type {
	case ActorUser, ActorAPIToken, ActorSystem, ActorGateway, ActorCLI:
	default:
		return Event{}, errors.New("неизвестный тип субъекта")
	}
	if e.Actor.ID == "" {
		return Event{}, errors.New("субъект без ID")
	}
	switch e.Result {
	case ResultSuccess, ResultFailure, ResultDenied:
	default:
		return Event{}, errors.New("неизвестный результат действия")
	}
	if e.OrgID != "" {
		if _, err := store.ParseUUID(e.OrgID); err != nil {
			return Event{}, fmt.Errorf("ID организации: %w", err)
		}
	}
	e.Actor.ID = cleanText(e.Actor.ID, maxActorID)
	e.Actor.Name = cleanText(e.Actor.Name, maxActorName)
	e.Object.Type = cleanText(e.Object.Type, maxObjectType)
	e.Object.ID = cleanText(e.Object.ID, maxObjectID)
	// Зона IPv6 (fe80::1%eth0) — свойство интерфейса сервера, а не клиента.
	e.SourceIP = e.SourceIP.WithZone("").Unmap()
	return ev, nil
}

// CanonicalDetails сериализует подробности в каноническую форму: объект
// JSON, ключи по алфавиту, без пробелов, числа без пересчёта.
func CanonicalDetails(v any) (json.RawMessage, error) {
	if v == nil {
		return json.RawMessage("{}"), nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("подробности не сериализуются в JSON: %w", err)
	}
	return CanonicalJSON(raw)
}

// CanonicalJSON приводит JSON-объект к канонической форме и проверяет
// лимиты и отсутствие ключей с секретами. Повторное применение не меняет
// результат.
func CanonicalJSON(raw []byte) (json.RawMessage, error) {
	if len(raw) > maxDetailsSize {
		return nil, fmt.Errorf("подробности больше %d байт", maxDetailsSize)
	}
	obj, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	clean, err := sanitizeValue(obj, 1)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(clean)
	if err != nil {
		return nil, errors.New("подробности: сериализация")
	}
	if len(out) > maxDetailsSize {
		return nil, fmt.Errorf("подробности больше %d байт", maxDetailsSize)
	}
	return out, nil
}

// isCanonical — хранимые подробности совпадают со своей канонической
// формой. Проверяется только форма, без лимитов и фильтра секретов: их
// изменение в новых версиях не должно делать старые записи «нарушенными».
func isCanonical(raw []byte) bool {
	obj, err := decodeObject(raw)
	if err != nil {
		return false
	}
	out, err := json.Marshal(obj)
	return err == nil && bytes.Equal(out, raw)
}

func decodeObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("подробности: неверный JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("подробности: лишние данные после объекта")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("подробности: ожидается JSON-объект")
	}
	return obj, nil
}

// sanitizeValue проверяет вложенность и ключи и маскирует строки, похожие
// на секрет. Ключ, похожий на секрет, — ошибка программиста: запись
// отклоняется. Значение задаёт пользователь (причина просмотра содержимого,
// название), поэтому подозрительный фрагмент заменяется на «[скрыто]», а
// запись пишется: обязательное событие не теряется, секрет в журнал не
// попадает (замечание В4 ревью 2.r1).
func sanitizeValue(v any, depth int) (any, error) {
	if depth > maxDetailsDepth {
		return nil, fmt.Errorf("подробности: вложенность больше %d", maxDetailsDepth)
	}
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if secretKey(k) {
				return nil, fmt.Errorf("подробности: ключ %q похож на секрет — секреты в журнал не пишутся", k)
			}
			clean, err := sanitizeValue(val, depth+1)
			if err != nil {
				return nil, err
			}
			x[k] = clean
		}
	case []any:
		for i, val := range x {
			clean, err := sanitizeValue(val, depth+1)
			if err != nil {
				return nil, err
			}
			x[i] = clean
		}
	case string:
		return maskSecrets(x), nil
	}
	return v, nil
}

// Ключи подробностей, которые выглядят как секреты (после приведения к
// нижнему регистру и удаления «_», «-», «.» и пробелов). Это вторая линия:
// не передавать секреты — обязанность вызывающего кода.
var (
	secretExact = map[string]bool{
		"otp": true, "totp": true, "seed": true, "pass": true, "pwd": true, "dsn": true,
		"authorization": true, "bearer": true, "credential": true, "session": true, "sessionid": true,
	}
	// Вхождение в любом месте ключа: password_hash, new_password, client_secret.
	secretParts = []string{"password", "passwd", "passphrase", "secret", "credentials", "cookie"}
	// Окончание ключа: api_token, access_key, private_key.
	secretSuffixes = []string{"token", "key"}
	// Окончания на key и token, которые не секрет. requests_per_minute_per_key —
	// числовой лимит запросов на ключ приложения в квотах (ТЗ 5.2).
	notSecret = map[string]bool{"publickey": true, "keyid": true, "tokenid": true, "requestsperminuteperkey": true}
)

func secretKey(k string) bool {
	n := strings.Map(func(r rune) rune {
		switch r {
		case '_', '-', '.', ' ':
			return -1
		}
		return r
	}, strings.ToLower(k))
	if notSecret[n] {
		return false
	}
	if secretExact[n] {
		return true
	}
	for _, p := range secretParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	for _, s := range secretSuffixes {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// Masked — замена фрагмента, похожего на секрет, в подробностях аудита.
const Masked = "[скрыто]"

// maskSecrets заменяет фрагменты, похожие на секрет при любом ключе:
// учётные данные после схемы авторизации («Bearer …», «Basic …») в любом
// месте строки и пароль в URL (строка подключения к БД). Повторное
// применение строку не меняет.
func maskSecrets(v string) string {
	v = maskAuthSchemes(v)
	return maskURLPasswords(v)
}

// authSchemes — схемы заголовка Authorization (в нижнем регистре).
var authSchemes = []string{"bearer", "basic"}

// maskAuthSchemes заменяет слово после «Bearer» или «Basic» (без учёта
// регистра, после пробелов) на Masked.
func maskAuthSchemes(v string) string {
	var b strings.Builder
	rest := v
	for {
		i, n := nextScheme(rest)
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		// Схема и пробелы после неё остаются; слово учётных данных — нет.
		j := i + n
		for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t') {
			j++
		}
		k := j
		for k < len(rest) && !isSpace(rest[k]) {
			k++
		}
		b.WriteString(rest[:j])
		if k > j {
			b.WriteString(Masked)
		}
		rest = rest[k:]
	}
}

// nextScheme — позиция и длина первой схемы авторизации, за которой идёт
// пробел; -1 — нет.
func nextScheme(s string) (int, int) {
	l := strings.ToLower(s)
	best, n := -1, 0
	for _, sc := range authSchemes {
		from := 0
		for {
			i := strings.Index(l[from:], sc)
			if i < 0 {
				break
			}
			i += from
			end := i + len(sc)
			// Отдельное слово: слева начало строки или не буква, справа пробел.
			if (i == 0 || !isLetter(l[i-1])) && end < len(l) && (l[end] == ' ' || l[end] == '\t') {
				if best < 0 || i < best {
					best, n = i, len(sc)
				}
				break
			}
			from = end
		}
	}
	return best, n
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// isLetter — латинская буква или байт многобайтового символа UTF-8.
func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80 }

// maskURLPasswords заменяет пароль в URL вида схема://пользователь:пароль@хост.
func maskURLPasswords(v string) string {
	var b strings.Builder
	rest := v
	for {
		i := strings.Index(rest, "://")
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		start := i + 3
		// Учётные данные — до первого '@' в пределах полномочий URL.
		end := strings.IndexAny(rest[start:], "/?# \t\n")
		auth := rest[start:]
		if end >= 0 {
			auth = rest[start : start+end]
		}
		at := strings.LastIndexByte(auth, '@')
		colon := strings.IndexByte(auth, ':')
		if at > 0 && colon >= 0 && colon < at && auth[colon+1:at] != Masked {
			b.WriteString(rest[:start+colon+1])
			b.WriteString(Masked)
			rest = rest[start+at:]
			continue
		}
		b.WriteString(rest[:start])
		rest = rest[start:]
	}
}
