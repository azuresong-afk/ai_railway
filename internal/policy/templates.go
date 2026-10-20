package policy

import (
	"fmt"
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// Шаблоны политик (ТЗ, 5.3). Шаблон ссылается на детекторы по ID из
// таблицы ТЗ, 5.2, и не зависит от того, какие из них уже встроены: правила
// для детекторов, которых нет в реестре, при компиляции шаблона опускаются
// (TemplatePolicy). Политика заказчика проверяется строго: неизвестный
// детектор — ошибка (Compile).

// ID шаблонов.
const (
	TemplateBase        = "base"            // «Базовая защита»
	TemplatePIIStrict   = "pii-strict"      // «ПДн — строго»
	TemplateExternalPII = "external-no-pii" // «Внешний провайдер: ПДн не передавать»
	TemplateMonitorOnly = "monitor-only"    // «Только мониторинг»
	// DefaultTemplate — политика приложения по умолчанию (решение Р7):
	// «Базовая защита» в режиме monitor.
	DefaultTemplate = TemplateBase
)

// ID детекторов из таблицы ТЗ, 5.2.
const (
	detPII       = "pii.ru"
	detSecrets   = "secrets"
	detInjection = "injection.heuristic"
	detUnicode   = "unicode.hidden"
	detCanary    = "canary"
	detExfil     = "output.exfil"
	detLists     = "lists"
)

var (
	in     = []detect.Direction{detect.Input}
	out    = []detect.Direction{detect.Output}
	hidden = []string{"unicode.invisible", "unicode.tag", "unicode.bidi"}
)

// TemplateIDs — шаблоны в порядке показа.
func TemplateIDs() []string {
	return []string{TemplateBase, TemplatePIIStrict, TemplateExternalPII, TemplateMonitorOnly}
}

// IsTemplate — id — шаблон.
func IsTemplate(id string) bool { return slices.Contains(TemplateIDs(), id) }

// Template возвращает копию шаблона: изменение копии шаблон не меняет.
func Template(id string) (*Spec, bool) {
	var s *Spec
	switch id {
	case TemplateBase:
		s = &Spec{Name: "Базовая защита", Mode: Monitor, NonText: NonTextAllowUnchecked, Rules: []RuleSpec{
			{ID: "unicode-hidden", Detector: detUnicode, Directions: in, Categories: hidden, Action: Redact, Severity: Medium},
			{ID: "unicode-homoglyph", Detector: detUnicode, Directions: in, Categories: []string{"unicode.homoglyph"}, Action: Log, Severity: Low},
			{ID: "injection", Detector: detInjection, Directions: in, Action: Block, Severity: High},
			{ID: "pii-input", Detector: detPII, Directions: in, Action: Pseudonymize, Severity: Medium},
			{ID: "pii-output", Detector: detPII, Directions: out, Action: Redact, Severity: Medium},
			{ID: "secrets", Detector: detSecrets, Action: Redact, Severity: High},
			{ID: "canary", Detector: detCanary, Directions: out, Action: Block, Severity: Critical},
			{ID: "exfil", Detector: detExfil, Directions: out, Action: Redact, Severity: High},
			{ID: "lists", Detector: detLists, Action: Log, Severity: Medium},
		}}
	case TemplatePIIStrict:
		// Правила *-protect — защита данных, если приложение переведено в
		// monitor: там block только журналируется (ТЗ, 5.3).
		s = &Spec{Name: "ПДн — строго", Mode: Enforce, NonText: NonTextBlock, Rules: []RuleSpec{
			{ID: "unicode-hidden", Detector: detUnicode, Directions: in, Categories: hidden, Action: Block, Severity: High},
			{ID: "unicode-hidden-protect", Detector: detUnicode, Directions: in, Categories: hidden, Action: Redact, Severity: High},
			{ID: "unicode-homoglyph", Detector: detUnicode, Directions: in, Categories: []string{"unicode.homoglyph"}, Action: Log, Severity: Low},
			{ID: "injection", Detector: detInjection, Directions: in, Action: Block, Severity: High},
			{ID: "pii-input", Detector: detPII, Directions: in, Action: Block, Severity: High},
			{ID: "pii-input-protect", Detector: detPII, Directions: in, Action: Redact, Severity: High},
			{ID: "pii-output", Detector: detPII, Directions: out, Action: Redact, Severity: High},
			{ID: "secrets-input", Detector: detSecrets, Directions: in, Action: Block, Severity: Critical},
			{ID: "secrets-input-protect", Detector: detSecrets, Directions: in, Action: Redact, Severity: Critical},
			{ID: "secrets-output", Detector: detSecrets, Directions: out, Action: Redact, Severity: Critical},
			{ID: "canary", Detector: detCanary, Directions: out, Action: Block, Severity: Critical},
			{ID: "exfil", Detector: detExfil, Directions: out, Action: Block, Severity: High},
			{ID: "lists", Detector: detLists, Action: Log, Severity: Medium},
		}}
	case TemplateExternalPII:
		s = &Spec{Name: "Внешний провайдер: ПДн не передавать", Mode: Enforce, NonText: NonTextBlock, Rules: []RuleSpec{
			{ID: "unicode-hidden", Detector: detUnicode, Directions: in, Categories: hidden, Action: Redact, Severity: Medium},
			{ID: "unicode-homoglyph", Detector: detUnicode, Directions: in, Categories: []string{"unicode.homoglyph"}, Action: Log, Severity: Low},
			{ID: "injection", Detector: detInjection, Directions: in, Action: Block, Severity: High},
			{ID: "pii-input", Detector: detPII, Directions: in, Action: Pseudonymize, Severity: High},
			{ID: "pii-output", Detector: detPII, Directions: out, Action: Redact, Severity: Medium},
			{ID: "secrets", Detector: detSecrets, Action: Redact, Severity: Critical},
			{ID: "canary", Detector: detCanary, Directions: out, Action: Block, Severity: Critical},
			{ID: "exfil", Detector: detExfil, Directions: out, Action: Redact, Severity: High},
			{ID: "lists", Detector: detLists, Action: Log, Severity: Medium},
		}}
	case TemplateMonitorOnly:
		// Только журнал: ПДн уходят внешнему провайдеру как есть. Для
		// внешнего провайдера — «Базовая защита» в monitor.
		s = &Spec{Name: "Только мониторинг", Mode: Monitor, NonText: NonTextAllowUnchecked}
		for _, det := range []string{detUnicode, detInjection, detPII, detSecrets, detCanary, detExfil, detLists} {
			s.Rules = append(s.Rules, RuleSpec{ID: "log-" + slug(det), Detector: det, Action: Log, Severity: Info})
		}
	default:
		return nil, false
	}
	s.ID, s.Version = id, 1
	for i := range s.Rules {
		s.Rules[i].Directions = slices.Clone(s.Rules[i].Directions)
		s.Rules[i].Categories = slices.Clone(s.Rules[i].Categories)
	}
	return s, true
}

func slug(det string) string {
	b := []byte(det)
	for i, c := range b {
		if c == '.' {
			b[i] = '-'
		}
	}
	return string(b)
}

// TemplatePolicy компилирует шаблон для реестра: правила детекторов, которых
// в реестре нет, опускаются, направления — только те, что детектор
// проверяет.
func TemplatePolicy(id string, c Catalog) (*Policy, error) {
	s, ok := Template(id)
	if !ok {
		return nil, fmt.Errorf("шаблон политики %q не существует", id)
	}
	rules := s.Rules[:0]
	for _, r := range s.Rules {
		d, ok := c.Get(r.Detector)
		if !ok {
			continue
		}
		if len(r.Directions) > 0 {
			r.Directions = slices.DeleteFunc(slices.Clone(r.Directions), func(dir detect.Direction) bool {
				return !slices.Contains(d.Directions(), dir)
			})
			if len(r.Directions) == 0 {
				continue
			}
		}
		rules = append(rules, r)
	}
	s.Rules = rules
	return Compile(s, c)
}

// Resolve находит политику приложения: политику заказчика из specs
// (строгая компиляция) или шаблон. Пустой id — DefaultTemplate (Р7).
// Политика заказчика с ID шаблона отвергается при проверке конфигурации.
func Resolve(id string, specs []Spec, c Catalog) (*Policy, error) {
	if id == "" {
		id = DefaultTemplate
	}
	for i := range specs {
		if specs[i].ID == id {
			return Compile(&specs[i], c)
		}
	}
	return TemplatePolicy(id, c)
}
