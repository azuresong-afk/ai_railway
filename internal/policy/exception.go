package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/canary"
)

// Исключения (ТЗ 5.3; решение Р8 этапа 3, задача 3.22) — часть версии
// политики (ADR-0016): находка детектора, совпавшая с действующим
// исключением, не участвует в решении. Исключение ограничено детектором и
// хотя бы одним сужающим условием — шаблоном детектора, хешем фрагмента,
// приложением или пользователем: детектор целиком для всех приложений
// одним исключением не отключается. Срок действия обязателен: истёкшее
// исключение шлюз не применяет по своим часам, без нового пакета.

// Пределы исключений.
const (
	// MaxExceptions — исключений в политике.
	MaxExceptions = 1000
	// MaxExceptionTTL — наибольший срок действия от created_at.
	MaxExceptionTTL = 365 * 24 * time.Hour
	// MaxCanaryExceptionTTL — наибольший срок нового или продлённого
	// исключения для канарейки (3Н49 ревью 3.r4): маркер постоянный, и
	// исключение по хешу фрагмента почти отключает DM-08 в приложении.
	// Проверяется при сохранении сервером, а не при разборе: сохранённые
	// версии с прежними сроками остаются действительными до истечения.
	MaxCanaryExceptionTTL = 7 * 24 * time.Hour
	// DefaultExceptionTTL — срок по умолчанию при создании.
	DefaultExceptionTTL = 30 * 24 * time.Hour
	// MaxExceptionReason — символов в причине.
	MaxExceptionReason = 500
	// MaxExceptionAuthor — символов в ссылке на автора.
	MaxExceptionAuthor = 128
	// Границы лет: запись RFC 3339 однозначна только для четырёхзначного года.
	minExceptionYear = 2000
	maxExceptionYear = 9999
)

var (
	// patternRe — правило детектора (detect.Finding.Rule): печатные ASCII
	// без пробелов, как их выдают встроенные детекторы (persona_removal,
	// list.<id>.word).
	patternRe = regexp.MustCompile(`^[\x21-\x7e]{1,128}$`)
	// aliasRe — хеш фрагмента и псевдоним пользователя: 16 байт HMAC в hex,
	// как в событиях (ТЗ 5.5).
	aliasRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// eventRe — ID события-основания (UUID в каноничной записи).
	eventRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ErrExceptionTooBroad — исключение без сужающего условия отключило бы
// детектор для всех приложений.
var ErrExceptionTooBroad = errors.New("слишком широкое исключение: укажите шаблон, хеш фрагмента, приложение или пользователя — " +
	"детектор целиком для всех приложений не отключается")

// ErrExceptionCanaryFragment — исключение для канарейки без хеша фрагмента.
// У канарейки два-три правила и постоянный маркер приложения: исключение по
// правилу и приложению выключило бы обнаружение утечки системного промпта
// (DM-08) для приложения целиком, а ложное срабатывание бывает только на
// конкретном тексте (3Н42 ревью 3.r3).
var ErrExceptionCanaryFragment = errors.New("исключение для канарейки — только с хешем фрагмента из события: " +
	"по правилу или приложению обнаружение утечки системного промпта не отключается")

// ExceptionSpec — исключение в YAML политики. Условия соединяются «и»;
// пустое условие — любое значение.
type ExceptionSpec struct {
	ID       string `yaml:"id"`
	Detector string `yaml:"detector"`
	// Category — категория находки (pii.card).
	Category string `yaml:"category,omitempty"`
	// Pattern — правило детектора, давшее находку (шаблон, ТЗ 5.3).
	Pattern string `yaml:"pattern,omitempty"`
	// Fragment — хеш фрагмента: HMAC текста находки на ключе шлюза (поле
	// fragment находки в событии). Сам текст в политику не попадает.
	Fragment string `yaml:"fragment,omitempty"`
	// App — ID приложения.
	App string `yaml:"app,omitempty"`
	// User — псевдоним пользователя (HMAC), как в событии.
	User string `yaml:"user,omitempty"`
	// Source — источник текста: user, rag, tool, output.
	Source detect.Source `yaml:"source,omitempty"`
	Reason string        `yaml:"reason"`
	// Author — кто создал или последним изменил исключение (тип:ID).
	Author string `yaml:"author"`
	// CreatedAt — время создания или последнего изменения; ExpiresAt — конец
	// действия, не дальше MaxExceptionTTL от CreatedAt. Секунды, UTC.
	CreatedAt time.Time `yaml:"created_at"`
	ExpiresAt time.Time `yaml:"expires_at"`
	// Event — событие, из отметки «ложное срабатывание» которого создано
	// исключение; пусто — создано вручную.
	Event string `yaml:"event,omitempty"`
}

// Narrowed — у исключения есть условие, сужающее его меньше чем до
// «детектор во всех приложениях».
func (e *ExceptionSpec) Narrowed() bool {
	return e.Pattern != "" || e.Fragment != "" || e.App != "" || e.User != ""
}

// Active — исключение действует в момент now.
func (e *ExceptionSpec) Active(now time.Time) bool { return now.Before(e.ExpiresAt) }

// Condition — условие без причины, автора и сроков: по нему сравниваются
// версии (изменение условия — новое исключение).
func (e *ExceptionSpec) Condition() ExceptionSpec {
	return ExceptionSpec{ID: e.ID, Detector: e.Detector, Category: e.Category, Pattern: e.Pattern, Fragment: e.Fragment,
		App: e.App, User: e.User, Source: e.Source}
}

// validate — ошибки полей исключения без номера.
func (e *ExceptionSpec) validate() []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !idRe.MatchString(e.ID) {
		add("id — строчные латинские буквы, цифры и дефис, до 63 символов")
	}
	if !detectorRe.MatchString(e.Detector) {
		add("detector — ID детектора, например injection.heuristic")
	}
	if e.Category != "" && !categoryRe.MatchString(e.Category) {
		add("category — категория вида pii.card")
	}
	if e.Pattern != "" && !patternRe.MatchString(e.Pattern) {
		add("pattern — правило детектора до 128 печатных символов ASCII без пробелов")
	}
	if e.Fragment != "" && !aliasRe.MatchString(e.Fragment) {
		add("fragment — хеш фрагмента из события: 32 шестнадцатеричные цифры")
	}
	if e.App != "" && !idRe.MatchString(e.App) {
		add("app — ID приложения")
	}
	if e.User != "" && !aliasRe.MatchString(e.User) {
		add("user — псевдоним пользователя из события: 32 шестнадцатеричные цифры")
	}
	if e.Source != "" && !sources[e.Source] {
		add("source — user, rag, tool или output")
	}
	if !e.Narrowed() {
		add("%v", ErrExceptionTooBroad)
	}
	if e.Detector == canary.ID && e.Fragment == "" {
		add("%v", ErrExceptionCanaryFragment)
	}
	if err := checkText(e.Reason, MaxExceptionReason); err != nil || strings.TrimSpace(e.Reason) == "" {
		add("reason — обязательная причина до %d символов без управляющих символов", MaxExceptionReason)
	}
	if err := checkText(e.Author, MaxExceptionAuthor); err != nil || e.Author == "" {
		add("author — обязательная ссылка на автора до %d символов", MaxExceptionAuthor)
	}
	switch {
	case e.CreatedAt.IsZero() || e.ExpiresAt.IsZero():
		add("created_at и expires_at обязательны")
	case e.CreatedAt.Nanosecond() != 0 || e.ExpiresAt.Nanosecond() != 0:
		add("created_at и expires_at — с точностью до секунды")
	case e.CreatedAt.Year() < minExceptionYear || e.ExpiresAt.Year() > maxExceptionYear:
		add("created_at и expires_at — между %d и %d годом", minExceptionYear, maxExceptionYear)
	case !e.ExpiresAt.After(e.CreatedAt):
		add("expires_at — позже created_at")
	case e.ExpiresAt.Sub(e.CreatedAt) > MaxExceptionTTL:
		add("expires_at — не дальше %d суток от created_at", int(MaxExceptionTTL.Hours()/24))
	}
	if e.Event != "" && !eventRe.MatchString(e.Event) {
		add("event — ID события")
	}
	return errs
}

// ExceptionTTLLimit — наибольший срок нового или продлённого исключения
// для детектора.
func ExceptionTTLLimit(detector string) time.Duration {
	if detector == canary.ID {
		return MaxCanaryExceptionTTL
	}
	return MaxExceptionTTL
}

// validateExceptions — ошибки раздела exceptions спецификации.
func (s *Spec) validateExceptions(add func(format string, a ...any)) {
	if len(s.Exceptions) > MaxExceptions {
		add("не больше %d исключений", MaxExceptions)
	}
	seen := map[string]bool{}
	for i, e := range s.Exceptions {
		if i >= MaxExceptions {
			break
		}
		for _, err := range e.validate() {
			add("exceptions[%d] (%s): %v", i, e.ID, err)
		}
		if seen[e.ID] {
			add("exceptions[%d]: исключение %s указано дважды", i, e.ID)
		}
		seen[e.ID] = true
	}
}

// normalizeExceptions приводит время к UTC: YAML может записать смещение,
// а каноничная запись версии — одна.
func (s *Spec) normalizeExceptions() {
	if len(s.Exceptions) == 0 {
		s.Exceptions = nil
		return
	}
	for i := range s.Exceptions {
		e := &s.Exceptions[i]
		e.CreatedAt, e.ExpiresAt = e.CreatedAt.UTC(), e.ExpiresAt.UTC()
	}
}

// Excepted — находка, пропущенная по исключению.
type Excepted struct {
	// Hit — номер находки в Request.Hits.
	Hit int
	// Exception — ID исключения.
	Exception string
}

// exceptionFor — ID первого действующего исключения, под которое попадает
// находка; пусто — ни одного.
func (p *Policy) exceptionFor(h Hit, req Request, now time.Time) string {
	f := h.Finding
	for i := range p.exceptions {
		e := &p.exceptions[i]
		if !e.Active(now) || e.Detector != f.Detector ||
			e.Category != "" && e.Category != f.Category ||
			e.Pattern != "" && e.Pattern != f.Rule ||
			e.Fragment != "" && e.Fragment != h.Fragment ||
			e.App != "" && e.App != req.App ||
			e.User != "" && e.User != req.User ||
			e.Source != "" && e.Source != h.Source {
			continue
		}
		return e.ID
	}
	return ""
}

// ValidPattern — строка годится как шаблон исключения (правило детектора).
func ValidPattern(s string) bool { return patternRe.MatchString(s) }

// Exceptions — число исключений политики (действующих и истёкших).
func (p *Policy) Exceptions() int { return len(p.exceptions) }
