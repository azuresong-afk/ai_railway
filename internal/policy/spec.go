package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// Спецификация политики — то, что хранится в YAML: в файле конфигурации
// шлюза (этап 1, решение Р2) и при импорте и экспорте (ТЗ, 5.3). Проверка
// спецификации не зависит от реестра детекторов; наличие детекторов и их
// направления проверяет Compile.

// Пределы спецификации.
const (
	MaxSpecSize   = 1 << 20 // байт в документе YAML при импорте
	MaxRules      = 256     // правил в политике
	MaxCategories = 32      // категорий в правиле
	MaxNameLen    = 128     // символов в названии политики
	MaxMessageLen = 300     // символов в сообщении для пользователя
	// DefaultThreshold — порог по умолчанию: находки от 0,5 считаются
	// метриками качества (docs/detectors.md).
	DefaultThreshold = 0.5
)

// DefaultBlockMessage — безопасное сообщение о блокировке: какие детекторы
// сработали, пользователю не сообщается (ТЗ, 5.1).
const DefaultBlockMessage = "Запрос отклонён политикой безопасности."

// Spec — политика: имя, режим, упорядоченный список правил, версия (ТЗ, 5.3).
type Spec struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	Version int    `yaml:"version"`
	Mode    Mode   `yaml:"mode"`
	// NonText — пусто означает allow_unchecked.
	NonText NonText `yaml:"non_text,omitempty"`
	// ResponseCheck — пусто означает incremental (решение Р7).
	ResponseCheck ResponseCheck `yaml:"response_check,omitempty"`
	// BlockMessage — сообщение о блокировке; пусто — DefaultBlockMessage.
	BlockMessage string     `yaml:"block_message,omitempty"`
	Rules        []RuleSpec `yaml:"rules"`
	// Exceptions — исключения (решение Р8 этапа 3, exception.go).
	Exceptions []ExceptionSpec `yaml:"exceptions,omitempty"`
	// Tools — политика вызовов инструментов агентами (ADR-0023, tools.go);
	// nil — умолчания совместимости (CompatTools).
	Tools *ToolsSpec `yaml:"tools,omitempty"`
}

// RuleSpec — правило: детектор, направления, условия, порог, действие,
// серьёзность, сообщение для пользователя.
type RuleSpec struct {
	ID       string `yaml:"id"`
	Detector string `yaml:"detector"`
	// Directions — пусто означает все направления детектора.
	Directions []detect.Direction `yaml:"directions,omitempty,flow"`
	// Categories — только эти категории находок (pii.card); пусто — все.
	Categories []string `yaml:"categories,omitempty,flow"`
	// Sources — только эти источники текста (user, rag, tool, tool_args, output);
	// пусто — все.
	Sources []detect.Source `yaml:"sources,omitempty,flow"`
	// Threshold — минимальная оценка находки, (0, 1]; nil — DefaultThreshold.
	Threshold *float64 `yaml:"threshold,omitempty"`
	Action    Action   `yaml:"action"`
	Severity  Severity `yaml:"severity"`
	// Message — сообщение о блокировке по этому правилу; пусто — сообщение
	// политики.
	Message string `yaml:"message,omitempty"`
}

var (
	idRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	detectorRe = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`)
	categoryRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	directions = map[detect.Direction]bool{detect.Input: true, detect.Output: true}
	sources    = map[detect.Source]bool{detect.SourceUser: true, detect.SourceRAG: true, detect.SourceTool: true,
		detect.SourceToolArgs: true, detect.SourceOutput: true}
	nonTexts   = map[NonText]bool{"": true, NonTextAllowUnchecked: true, NonTextAllowInline: true, NonTextBlock: true}
	respChecks = map[ResponseCheck]bool{"": true, ResponseBuffered: true, ResponseIncremental: true, ResponseMonitor: true}
)

// Validate проверяет спецификацию без реестра детекторов. Ошибки — по всем
// полям сразу, с номером правила.
func (s *Spec) Validate() error {
	var errs []error
	add := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("политика %s: "+format, append([]any{s.ID}, a...)...))
	}
	if !idRe.MatchString(s.ID) {
		add("id — строчные латинские буквы, цифры и дефис, до 63 символов")
	}
	if err := checkText(s.Name, MaxNameLen); err != nil || strings.TrimSpace(s.Name) == "" {
		add("name — обязательное название до %d символов без управляющих символов", MaxNameLen)
	}
	if s.Version < 1 {
		add("version — целое от 1")
	}
	if s.Mode != Monitor && s.Mode != Enforce {
		add("mode — monitor или enforce")
	}
	if !nonTexts[s.NonText] {
		add("non_text — allow_unchecked, allow_inline или block")
	}
	if !respChecks[s.ResponseCheck] {
		add("response_check — buffered, incremental или monitor")
	}
	if s.BlockMessage != "" && checkText(s.BlockMessage, MaxMessageLen) != nil {
		add("block_message — до %d символов без управляющих символов", MaxMessageLen)
	}
	if len(s.Rules) > MaxRules {
		add("не больше %d правил", MaxRules)
	}
	seen := map[string]bool{}
	for i, r := range s.Rules {
		if i >= MaxRules {
			break
		}
		for _, err := range r.validate() {
			add("rules[%d] (%s): %v", i, r.ID, err)
		}
		if seen[r.ID] {
			add("rules[%d]: правило %s указано дважды", i, r.ID)
		}
		seen[r.ID] = true
	}
	s.validateExceptions(add)
	if s.Tools != nil {
		for _, err := range s.Tools.validate() {
			add("%v", err)
		}
	}
	return errors.Join(errs...)
}

func (r *RuleSpec) validate() []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !idRe.MatchString(r.ID) {
		add("id — строчные латинские буквы, цифры и дефис")
	}
	if !detectorRe.MatchString(r.Detector) {
		add("detector — ID детектора, например pii.ru")
	}
	if !unique(r.Directions, func(d detect.Direction) bool { return directions[d] }) {
		add("directions — input и output без повторов")
	}
	if len(r.Categories) > MaxCategories || !unique(r.Categories, categoryRe.MatchString) {
		add("categories — до %d категорий вида pii.card без повторов", MaxCategories)
	}
	if !unique(r.Sources, func(s detect.Source) bool { return sources[s] }) {
		add("sources — user, rag, tool, tool_args, output без повторов")
	}
	// Отрицание сравнения отвергает и NaN (.nan в YAML).
	if r.Threshold != nil && !(*r.Threshold > 0 && *r.Threshold <= 1) {
		add("threshold — число больше 0 и не больше 1")
	}
	switch {
	case r.Action == RequireApproval:
		add("action require_approval — с этапа 4")
	case !supported(r.Action):
		add("action — allow, log, redact, pseudonymize или block")
	case r.Action == Pseudonymize && (len(r.Directions) == 0 || slices.Contains(r.Directions, detect.Output)):
		// Псевдоним в ответе модели восстановить нечем: приложение получило
		// бы псевдонимы вместо данных. Для ответа — redact.
		add("pseudonymize — только для входа: укажите directions: [input], для ответа — redact")
	}
	if severityRank[r.Severity] == 0 {
		add("severity — info, low, medium, high или critical")
	}
	if r.Message != "" && checkText(r.Message, MaxMessageLen) != nil {
		add("message — до %d символов без управляющих символов", MaxMessageLen)
	}
	return errs
}

// threshold — порог правила с учётом значения по умолчанию.
func (r *RuleSpec) threshold() float64 {
	if r.Threshold == nil {
		return DefaultThreshold
	}
	return *r.Threshold
}

// checkText — валидный UTF-8, не длиннее max символов, без управляющих
// символов и символов форматирования (скрытый текст в сообщении для
// пользователя, ТЗ, 5.2, unicode.hidden).
func checkText(s string, max int) error {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return errors.New("недопустимый текст")
	}
	if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
		return errors.New("управляющие символы")
	}
	return nil
}

func unique[T comparable](xs []T, valid func(T) bool) bool {
	seen := make(map[T]bool, len(xs))
	for _, x := range xs {
		if !valid(x) || seen[x] {
			return false
		}
		seen[x] = true
	}
	return true
}

// Parse разбирает одну политику из YAML (импорт, ТЗ, 5.3): не больше
// MaxSpecSize байт, один документ, неизвестные поля — ошибка, затем Validate.
func Parse(r io.Reader) (*Spec, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSpecSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSpecSize {
		return nil, fmt.Errorf("политика больше %d байт", MaxSpecSize)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Spec
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("разбор политики: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("разбор политики: ожидается один YAML-документ")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	// Пустой список и его отсутствие — одно и то же: импорт выгруженной
	// политики даёт ту же политику.
	if len(s.Rules) == 0 {
		s.Rules = nil
	}
	for i := range s.Rules {
		r := &s.Rules[i]
		r.Directions, r.Categories, r.Sources = nilIfEmpty(r.Directions), nilIfEmpty(r.Categories), nilIfEmpty(r.Sources)
	}
	s.normalizeExceptions()
	if s.Tools != nil {
		s.Tools.normalize()
	}
	return &s, nil
}

func nilIfEmpty[T any](xs []T) []T {
	if len(xs) == 0 {
		return nil
	}
	return xs
}

// Marshal выгружает политику в YAML (экспорт). Выгружается только
// проверенная спецификация: Parse(Marshal(s)) возвращает ту же политику.
func Marshal(s *Spec) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return yaml.Marshal(s)
}
