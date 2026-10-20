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
	// предела фрагмент маскируется необратимо (безопасный исход).
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
	// Fallback — псевдоним не выдан (предел словаря или номеров), фрагмент
	// маскирован необратимо; входит в Redacted.
	Fallback int
	// Restored — псевдонимов в ответе заменено исходными значениями.
	Restored int
	// Unknown — в ответе псевдоним выданного в запросе типа с номером,
	// которого нет в словаре: модель его исказила.
	Unknown int
	// Unsafe — не восстановлен из-за места: внутри адреса или, в JSON,
	// вне строки.
	Unsafe int
	// Limited — не восстановлен: исчерпан MaxRestoreBytes.
	Limited int
}

// Failed — неудачные подстановки (ТЗ, 5.1): значение осталось
// замаскированным, хотя модель, вероятно, ссылалась на него.
func (s Stats) Failed() int { return s.Unknown + s.Unsafe + s.Limited }

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
	restored int               // байт значений, вставленных в ответ
	stats    Stats
}

// NewVault создаёт пустой словарь.
func NewVault(lim Limits) *Vault {
	return &Vault{
		lim:      lim.withDefaults(),
		byValue:  map[string]string{},
		values:   map[key]string{},
		next:     map[string]int{},
		reserved: map[key]bool{},
	}
}

// ErrReserveAfterIssue — Reserve вызван после выдачи псевдонимов.
var ErrReserveAfterIssue = errors.New("псевдонимы уже выдавались: Reserve вызывается до Protect")

// Reserve отмечает псевдонимы, которые уже встречаются в тексте запроса
// (их мог написать пользователь или документ RAG), чтобы не выдать такой же:
// иначе в ответе их было бы не различить. Вызывается для всех фрагментов
// запроса до первого Protect.
func (v *Vault) Reserve(texts ...string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.values) > 0 {
		return ErrReserveAfterIssue
	}
	for _, s := range texts {
		for i := 0; i < len(s); i++ {
			if s[i] != '[' && s[i] != '\\' {
				continue
			}
			if t, r := parseToken(s, i, true, true); r == scanMatch {
				v.reserved[key{t.typ, t.n}] = true
				i = t.end - 1
			}
		}
	}
	return nil
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

// issue — псевдоним значения: прежний для повторного значения или новый
// с наименьшим свободным номером типа. false — предел словаря или номеров.
func (v *Vault) issue(typ, value string) (string, bool) {
	vk := typ + "\x00" + value
	if tok, ok := v.byValue[vk]; ok {
		return tok, true
	}
	if len(v.values) >= v.lim.MaxEntries {
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

// RestoreJSON — Restore для аргументов вызова инструмента (tool_calls):
// текст — JSON, значение вставляется экранированным для строки JSON, чтобы
// не изменить структуру аргументов (значение с кавычкой не добавит поле).
func (v *Vault) RestoreJSON(text string) string {
	r := restorer{v: v, url: urlState{json: true}}
	return r.run(text, true)
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
// память освобождает сборщик мусора, а не затирание.
func (v *Vault) Clear() {
	v.mu.Lock()
	defer v.mu.Unlock()
	clear(v.byValue)
	clear(v.values)
}

// String не раскрывает значений.
func (v *Vault) String() string { return fmt.Sprintf("pseudonym.Vault{entries: %d}", v.Len()) }

// GoString не раскрывает значений (%#v).
func (v *Vault) GoString() string { return v.String() }

// LogValue не раскрывает значений (slog).
func (v *Vault) LogValue() slog.Value { return slog.IntValue(v.Len()) }

// lookup — значение псевдонима для подстановки и учёт исхода. Вызывается
// под v.mu.
func (v *Vault) lookup(t token, unsafe bool) (string, bool) {
	value, ok := v.values[key{t.typ, t.n}]
	switch {
	case !ok:
		if v.next[t.typ] > 0 {
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
