package pseudonym

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Limits — пределы словаря одного запроса.
type Limits struct {
	// MaxEntries — сколько разных значений можно псевдонимизировать; сверх
	// предела фрагмент маскируется необратимо (безопасный исход). Он же —
	// предел разных псевдонимов, которые NewVault резервирует из текста
	// запроса: если их больше, словарь не выдаёт псевдонимов совсем.
	MaxEntries int
	// MaxRestoreBytes — суммарный объём значений, которые обратная
	// подстановка вставит в ответ. Защищает память шлюза и приложения от
	// ответа из тысяч повторов псевдонима длинного значения; сверх предела
	// псевдонимы остаются в ответе как есть.
	MaxRestoreBytes int
}

// Пределы по умолчанию.
const (
	DefaultMaxEntries      = 4096
	DefaultMaxRestoreBytes = 4 << 20
)

func (l Limits) withDefaults() Limits {
	if l.MaxEntries <= 0 {
		l.MaxEntries = DefaultMaxEntries
	}
	if l.MaxRestoreBytes <= 0 {
		l.MaxRestoreBytes = DefaultMaxRestoreBytes
	}
	return l
}

// Stats — счётчики словаря для события и метрик. Значений не содержат.
type Stats struct {
	// Issued — выдано псевдонимов (разных значений).
	Issued int
	// Pseudonymized и Redacted — сколько фрагментов заменено псевдонимом и
	// маскировано необратимо.
	Pseudonymized int
	Redacted      int
	// Fallback — псевдоним не выдан (предел словаря или номеров, в запросе
	// больше MaxEntries псевдонимов), фрагмент маскирован необратимо;
	// входит в Redacted.
	Fallback int
	// Restored — псевдонимов в ответе заменено исходными значениями.
	Restored int
	// Unknown — в ответе псевдоним выданного в запросе типа с номером,
	// которого нет в словаре и который не взят из запроса: модель исказила
	// номер.
	Unknown int
	// Mangled — псевдоним искажён сильнее допустимого: тип переведён
	// ([[ТЕЛЕФОН_1]]) или скобки потеряны и заменены (PHONE_1, <PHONE_1>).
	Mangled int
	// Unsafe — не восстановлен из-за места: возможный адрес или, в JSON,
	// не значение строки (ADR-0005).
	Unsafe int
	// Limited — не восстановлен: исчерпан MaxRestoreBytes.
	Limited int
}

// Failed — неудачные подстановки (ТЗ, 5.1): значение осталось
// замаскированным, хотя модель, вероятно, ссылалась на него.
func (s Stats) Failed() int { return s.Unknown + s.Mangled + s.Unsafe + s.Limited }

// key — тип и номер псевдонима.
type key struct {
	typ string
	n   int
}

// Vault — словарь «значение ↔ псевдоним» одного запроса. Безопасен для
// одновременного использования. Значения не печатаются (String, LogValue).
type Vault struct {
	mu       sync.Mutex
	lim      Limits
	byValue  map[string]string // ТИП + "\x00" + значение → псевдоним
	values   map[key]string    // псевдоним → значение
	next     map[string]int    // ТИП → последний выданный номер
	reserved map[key]bool      // псевдонимы, которые уже были в тексте запроса
	full     bool              // резерв переполнен: псевдонимы не выдаются
	cleared  bool              // запрос завершён (Clear)
	restored int               // байт значений, вставленных в ответ
	stats    Stats
}

// NewVault создаёт словарь запроса. request — все текстовые фрагменты
// запроса (chat.Request.Segments): псевдонимы, которые в них уже есть (их
// мог написать пользователь или документ RAG), не выдаются, иначе в ответе
// их было бы не различить. Фрагменты передаются при создании, чтобы
// резервирование нельзя было забыть или сделать после выдачи.
//
// Резерв ограничен lim.MaxEntries разными псевдонимами: запрос из
// «[A_1][A_2]…» иначе занял бы около 9 байт кучи на байт тела. Если в
// запросе их больше, резерв не хранится, а каждый Pseudonymize маскируется
// необратимо (Stats.Fallback): выдать номер, не зная всех занятых, нельзя.
func NewVault(lim Limits, request ...string) *Vault {
	v := &Vault{
		lim:      lim.withDefaults(),
		byValue:  map[string]string{},
		values:   map[key]string{},
		next:     map[string]int{},
		reserved: map[key]bool{},
	}
	for _, s := range request {
		for i := 0; i < len(s) && !v.full; i++ {
			if s[i] != '[' && s[i] != '\\' {
				continue
			}
			if t, r := parseToken(s, i, true, true); r == scanMatch {
				k := key{t.typ, t.n}
				if !v.reserved[k] && len(v.reserved) >= v.lim.MaxEntries {
					v.full = true
					clear(v.reserved)
					break
				}
				v.reserved[k] = true
				i = t.end - 1
			}
		}
	}
	return v
}

// Span — фрагмент текста под защитой данных: позиции находки, её
// категория и действие решения политики (policy.Match.Apply).
type Span struct {
	Start, End int
	Category   string
	Action     policy.Action
}

// Protect заменяет фрагменты text: Pseudonymize — псевдонимом, Redact —
// маркером [[ТИП]]. Пересекающиеся фрагменты объединяются; если среди них
// есть Redact, объединение маскируется необратимо (сильнее по таблице
// приоритетов). Тип объединения — по фрагменту, который начинается раньше.
// Неверные позиции или действие — ошибка вызывающего кода: текст не
// возвращается, и конвейер не должен отправлять запрос.
func (v *Vault) Protect(text string, spans []Span) (string, error) {
	if len(spans) == 0 {
		return text, nil
	}
	for _, s := range spans {
		switch {
		case s.Action != policy.Redact && s.Action != policy.Pseudonymize:
			return "", fmt.Errorf("фрагмент [%d, %d): действие %q не защищает данные", s.Start, s.End, s.Action)
		case s.Start < 0 || s.End <= s.Start || s.End > len(text):
			return "", fmt.Errorf("фрагмент [%d, %d) вне текста длиной %d", s.Start, s.End, len(text))
		case !detect.OnRuneBoundary(text, s.Start) || !detect.OnRuneBoundary(text, s.End):
			return "", fmt.Errorf("фрагмент [%d, %d) разрезает символ UTF-8", s.Start, s.End)
		}
	}
	sorted := slices.Clone(spans)
	slices.SortStableFunc(sorted, func(a, b Span) int {
		return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(b.End, a.End))
	})
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cleared {
		return "", errCleared
	}
	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for i := 0; i < len(sorted); {
		cur := sorted[i]
		for i++; i < len(sorted) && sorted[i].Start < cur.End; i++ {
			cur.End = max(cur.End, sorted[i].End)
			if sorted[i].Action == policy.Redact {
				cur.Action = policy.Redact
			}
		}
		b.WriteString(text[pos:cur.Start])
		pos = cur.End
		typ := TypeOf(cur.Category)
		if cur.Action == policy.Pseudonymize {
			if tok, ok := v.issue(typ, text[cur.Start:cur.End]); ok {
				b.WriteString(tok)
				v.stats.Pseudonymized++
				continue
			}
			v.stats.Fallback++
		}
		b.WriteString(redactMarker(typ))
		v.stats.Redacted++
	}
	b.WriteString(text[pos:])
	return b.String(), nil
}

// errCleared — Protect после Clear: запрос уже завершён, словарь не должен
// пополняться значениями, которые никто не очистит.
var errCleared = errors.New("словарь псевдонимов очищен: запрос завершён")

// issue — псевдоним значения: прежний для повторного значения или новый
// с наименьшим свободным номером типа. false — предел словаря или номеров.
func (v *Vault) issue(typ, value string) (string, bool) {
	vk := typ + "\x00" + value
	if tok, ok := v.byValue[vk]; ok {
		return tok, true
	}
	if v.full || len(v.values) >= v.lim.MaxEntries {
		return "", false
	}
	n := v.next[typ] + 1
	for n <= MaxNumber && v.reserved[key{typ, n}] {
		n++
	}
	if n > MaxNumber {
		return "", false
	}
	v.next[typ] = n
	tok := formatToken(typ, n)
	v.byValue[vk] = tok
	v.values[key{typ, n}] = value
	v.stats.Issued++
	return tok, true
}

// Restore возвращает значения на место псевдонимов в законченном тексте
// ответа (content, refusal). Что восстанавливается и что нет — в описании
// пакета.
func (v *Vault) Restore(text string) string {
	r := restorer{v: v}
	return r.run(text, true)
}

// RestoreJSON — Restore для content в формате JSON (response_format
// json_object, json_schema): значение вставляется только в значение строки
// и экранируется, чтобы не изменить структуру (значение с кавычкой не
// добавит поле). Равен склейке NewJSONStream.
func (v *Vault) RestoreJSON(text string) string {
	r := restorer{v: v, ctx: ctxState{json: true}}
	return r.run(text, true)
}

// RestoreToolArgs — Restore для собранных аргументов одного вызова
// инструмента (tool_calls): как RestoreJSON, но если признак адреса есть
// где угодно в аргументах, в том числе после псевдонима, не
// восстанавливается ничего: внедрённая инструкция могла попросить модель
// вызвать HTTP-инструмент с чужим адресом в одном поле и псевдонимом в
// другом (DM-13). В потоке аргументы вызова собираются целиком (их и так
// проверяют выходные детекторы) и восстанавливаются этой функцией. Если в
// ответе несколько вызовов, нужен RestoreToolCalls.
func (v *Vault) RestoreToolArgs(args string) string {
	return v.RestoreToolCalls([]string{args})[0]
}

// RestoreToolCalls — RestoreToolArgs для собранных аргументов всех вызовов
// инструментов одного ответа (tool_calls всех choices) с общим признаком
// адреса: если он есть в аргументах любого вызова, не восстанавливается
// ничего ни в одном. Иначе адрес в одном параллельном вызове и псевдоним в
// другом не связались бы (DM-13). Результат — в том же порядке.
func (v *Vault) RestoreToolCalls(args []string) []string {
	addr := false
	for _, a := range args {
		pre := ctxState{json: true}
		for i := 0; i < len(a); i++ {
			pre.observe(a[i])
		}
		pre.observeEnd()
		if addr = pre.urlSeen || pre.broken; addr {
			break
		}
	}
	out := make([]string, len(args))
	for i, a := range args {
		r := restorer{v: v, ctx: ctxState{json: true, urlSeen: addr}}
		out[i] = r.run(a, true)
	}
	return out
}

// Stats — счётчики словаря.
func (v *Vault) Stats() Stats {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.stats
}

// Len — число значений в словаре.
func (v *Vault) Len() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.values)
}

// Clear удаляет значения из словаря по завершении запроса, чтобы они не
// жили дольше него через забытую ссылку. Строки Go неизменяемы, поэтому
// память освобождает сборщик мусора, а не затирание. После Clear Protect
// возвращает ошибку, а Restore, RestoreJSON, RestoreToolCalls и Stream
// отдают текст как есть, не меняя Stats: обрыв потока после завершения
// запроса не портит метрику Failed(). Stats сохраняются для события.
func (v *Vault) Clear() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.cleared = true
	clear(v.byValue)
	clear(v.values)
	clear(v.next)
	clear(v.reserved)
}

// String не раскрывает значений.
func (v *Vault) String() string { return fmt.Sprintf("pseudonym.Vault{entries: %d}", v.Len()) }

// GoString не раскрывает значений (%#v).
func (v *Vault) GoString() string { return v.String() }

// LogValue не раскрывает значений (slog).
func (v *Vault) LogValue() slog.Value { return slog.IntValue(v.Len()) }

// issuedType — тип выдавался в этом запросе. Вызывается под v.mu.
func (v *Vault) issuedType(typ string) bool { return v.next[typ] > 0 }

// typePrefix — p — начало выданного типа. Вызывается под v.mu.
func (v *Vault) typePrefix(p string) bool {
	for typ := range v.next {
		if strings.HasPrefix(typ, p) {
			return true
		}
	}
	return false
}

// lookup — значение псевдонима для подстановки и учёт исхода. Вызывается
// под v.mu.
func (v *Vault) lookup(t token, unsafe bool) (string, bool) {
	k := key{t.typ, t.n}
	value, ok := v.values[k]
	switch {
	case !ok:
		// Псевдоним из самого запроса модель просто повторила — не неудача.
		if v.next[t.typ] > 0 && !v.reserved[k] {
			v.stats.Unknown++
		}
		return "", false
	case unsafe:
		v.stats.Unsafe++
		return "", false
	case v.restored+len(value) > v.lim.MaxRestoreBytes:
		v.stats.Limited++
		return "", false
	}
	v.restored += len(value)
	v.stats.Restored++
	return value, true
}
