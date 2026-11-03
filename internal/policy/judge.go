package policy

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// Оценщик judge.llm в политике (ТЗ 5.2, DM-18 и DM-19 «LLM — 5»; задача
// 5.28 этапа 5, ADR-0030, раздел 2): раздел judge — провайдер, модель и
// бюджет оценщика; правило с detector: judge.llm и подразделом judge —
// критерий на естественном языке, вид, режим, срок и поведение при отказе.
// Критерии пишет администратор безопасности (policies.manage).

// JudgeDetector — ID детектора judge.llm (internal/detect/judge; пакет
// политики его не импортирует: judge строит запросы через провайдеров).
const JudgeDetector = "judge.llm"

// JudgeMode — режим оценки правила.
type JudgeMode string

// Режимы: async — после ответа приложению (по умолчанию), sync — до решения.
const (
	JudgeAsync JudgeMode = "async"
	JudgeSync  JudgeMode = "sync"
)

// Поведение при отказе оценщика в режиме sync.
const (
	JudgeFailAllow = "allow"
	JudgeFailBlock = "block"
)

// Виды правил: content — недопустимый контент (DM-18), business — бизнес-
// правило (DM-19). Совпадают с internal/detect/judge.
const (
	JudgeKindContent  = "content"
	JudgeKindBusiness = "business"
)

// Пределы ADR-0030.
const (
	MaxJudgeRules        = 16
	MinJudgeCriterion    = 10
	MaxJudgeCriterion    = 1000
	MinJudgeTimeoutMS    = 500
	MaxJudgeTimeoutMS    = 30000
	DefaultJudgeTimeout  = 5 * time.Second
	DefaultJudgeCalls    = 60
	MaxJudgeCalls        = 6000
	DefaultJudgeTokens   = 200000
	MinJudgeTokens       = 1000
	MaxJudgeTokens       = 100000000
	maxJudgeModelNameLen = 128
)

// JudgeSpec — раздел judge политики.
type JudgeSpec struct {
	// Provider — slug провайдера с признаком «у заказчика».
	Provider string `yaml:"provider"`
	// Model — модель оценщика у провайдера.
	Model string `yaml:"model"`
	// MaxCallsPerMinute и MaxTokensPerHour — бюджет; 0 — по умолчанию.
	MaxCallsPerMinute int `yaml:"max_calls_per_minute,omitempty"`
	MaxTokensPerHour  int `yaml:"max_tokens_per_hour,omitempty"`
}

// JudgeRuleSpec — подраздел judge правила judge.llm.
type JudgeRuleSpec struct {
	Kind      string    `yaml:"kind"`
	Criterion string    `yaml:"criterion"`
	Mode      JudgeMode `yaml:"mode,omitempty"`
	// TimeoutMS и OnFailure — только для sync; 0 и пусто — по умолчанию
	// (5000 мс, allow).
	TimeoutMS int    `yaml:"timeout_ms,omitempty"`
	OnFailure string `yaml:"on_failure,omitempty"`
}

// judgeModelRe — имя модели оценщика: без пробелов и управляющих символов.
var judgeModelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$`)

func (j *JudgeSpec) validate() []error {
	var errs []error
	if !idRe.MatchString(j.Provider) {
		errs = append(errs, errors.New("judge.provider — slug провайдера с признаком «у заказчика»"))
	}
	if len(j.Model) > maxJudgeModelNameLen || !judgeModelRe.MatchString(j.Model) {
		errs = append(errs, fmt.Errorf("judge.model — имя модели до %d символов без пробелов", maxJudgeModelNameLen))
	}
	if j.MaxCallsPerMinute < 0 || j.MaxCallsPerMinute > MaxJudgeCalls {
		errs = append(errs, fmt.Errorf("judge.max_calls_per_minute — от 1 до %d (0 — %d)", MaxJudgeCalls, DefaultJudgeCalls))
	}
	if j.MaxTokensPerHour != 0 && (j.MaxTokensPerHour < MinJudgeTokens || j.MaxTokensPerHour > MaxJudgeTokens) {
		errs = append(errs, fmt.Errorf("judge.max_tokens_per_hour — от %d до %d (0 — %d)", MinJudgeTokens, MaxJudgeTokens, DefaultJudgeTokens))
	}
	return errs
}

// validateJudgeRule — правило judge.llm и подраздел judge (вызывает
// RuleSpec.validate).
func (r *RuleSpec) validateJudgeRule(add func(format string, a ...any)) {
	if r.Detector != JudgeDetector {
		if r.Judge != nil {
			add("judge — только у правил детектора %s", JudgeDetector)
		}
		return
	}
	j := r.Judge
	if j == nil {
		add("judge — у правила %s обязателен подраздел judge (kind, criterion)", JudgeDetector)
		return
	}
	if j.Kind != JudgeKindContent && j.Kind != JudgeKindBusiness {
		add("judge.kind — content (DM-18) или business (DM-19)")
	}
	n := utf8.RuneCountInString(strings.TrimSpace(j.Criterion))
	if checkText(j.Criterion, MaxJudgeCriterion) != nil || n < MinJudgeCriterion {
		add("judge.criterion — от %d до %d символов без управляющих символов", MinJudgeCriterion, MaxJudgeCriterion)
	}
	switch j.Mode {
	case "", JudgeAsync:
		if j.TimeoutMS != 0 || j.OnFailure != "" {
			add("judge.timeout_ms и judge.on_failure — только для mode: sync")
		}
		if r.Action == Block {
			add("action block — только для judge.mode: sync (в async решение уже принято)")
		}
	case JudgeSync:
		if j.TimeoutMS != 0 && (j.TimeoutMS < MinJudgeTimeoutMS || j.TimeoutMS > MaxJudgeTimeoutMS) {
			add("judge.timeout_ms — от %d до %d", MinJudgeTimeoutMS, MaxJudgeTimeoutMS)
		}
		if j.OnFailure != "" && j.OnFailure != JudgeFailAllow && j.OnFailure != JudgeFailBlock {
			add("judge.on_failure — allow или block")
		}
	default:
		add("judge.mode — async или sync")
	}
	if len(r.Categories) > 0 || len(r.Sources) > 0 {
		add("categories и sources у правила %s не задаются: категорию даёт judge.kind", JudgeDetector)
	}
}

// validateJudge — раздел judge и число правил judge.llm.
func (s *Spec) validateJudge(add func(format string, a ...any)) {
	n := 0
	for _, r := range s.Rules {
		if r.Detector == JudgeDetector {
			n++
		}
	}
	if n > MaxJudgeRules {
		add("не больше %d правил %s", MaxJudgeRules, JudgeDetector)
	}
	if n > 0 && s.Judge == nil {
		add("правила %s требуют раздел judge (провайдер и модель оценщика)", JudgeDetector)
	}
	if s.Judge != nil {
		for _, err := range s.Judge.validate() {
			add("%v", err)
		}
	}
}

// JudgeConfig — оценщик политики.
type JudgeConfig struct {
	Provider       string
	Model          string
	CallsPerMinute int
	TokensPerHour  int
}

// JudgeRule — правило judge.llm, готовое к оценке.
type JudgeRule struct {
	ID        string
	Kind      string
	Criterion string
	Sync      bool
	// Timeout — срок оценки sync; BlockOnFailure — on_failure: block.
	Timeout        time.Duration
	BlockOnFailure bool
}

// compileJudge — оценщик политики с умолчаниями.
func compileJudge(j *JudgeSpec) *JudgeConfig {
	if j == nil {
		return nil
	}
	out := &JudgeConfig{Provider: j.Provider, Model: j.Model, CallsPerMinute: j.MaxCallsPerMinute, TokensPerHour: j.MaxTokensPerHour}
	if out.CallsPerMinute == 0 {
		out.CallsPerMinute = DefaultJudgeCalls
	}
	if out.TokensPerHour == 0 {
		out.TokensPerHour = DefaultJudgeTokens
	}
	return out
}

func compileJudgeRule(r RuleSpec) *JudgeRule {
	if r.Judge == nil {
		return nil
	}
	out := &JudgeRule{ID: r.ID, Kind: r.Judge.Kind, Criterion: strings.TrimSpace(r.Judge.Criterion), Sync: r.Judge.Mode == JudgeSync}
	if out.Sync {
		out.Timeout = DefaultJudgeTimeout
		if r.Judge.TimeoutMS != 0 {
			out.Timeout = time.Duration(r.Judge.TimeoutMS) * time.Millisecond
		}
		out.BlockOnFailure = r.Judge.OnFailure == JudgeFailBlock
	}
	return out
}

// Judge — оценщик политики; nil — раздела judge нет.
func (p *Policy) Judge() *JudgeConfig {
	if p.judge == nil {
		return nil
	}
	c := *p.judge
	return &c
}

// JudgeRules — правила judge.llm направления dir в порядке политики.
func (p *Policy) JudgeRules(dir detect.Direction) []JudgeRule {
	var out []JudgeRule
	for _, r := range p.rules {
		if r.judge != nil && slices.Contains(r.directions, dir) {
			out = append(out, *r.judge)
		}
	}
	return out
}
