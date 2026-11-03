// Пакет judge — детектор judge.llm (ТЗ 5.2, DM-18 и DM-19 «LLM — 5»,
// ADR-0030): проверка текста моделью заказчика по правилам на естественном
// языке. Пакет строит запрос к оценщику (разделители с nonce), разбирает его
// строгий JSON-ответ, держит кэш вердиктов и бюджет вызовов. Сам вызов идёт
// через адаптер провайдера (internal/providers), сетевых обращений пакет не
// делает. Когда и для какого текста вызывать оценщика, решает шлюз.
package judge

import (
	"context"
	"errors"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// Идентификатор, версия и категории детектора.
const (
	ID      = "judge.llm"
	Version = "1.0.0"
	// CategoryContent — недопустимый контент (DM-18), CategoryBusiness —
	// нарушение бизнес-правила (DM-19).
	CategoryContent  = "judge.content"
	CategoryBusiness = "judge.business"
	// KindContent и KindBusiness — вид правила в политике (judge.kind).
	KindContent  = "content"
	KindBusiness = "business"
	// ThreatContent и ThreatBusiness — строки матрицы обнаружения.
	ThreatContent  = "DM-18"
	ThreatBusiness = "DM-19"
)

// Пределы ADR-0030.
const (
	// MaxCriteria — правил judge.llm в политике и в одном вызове.
	MaxCriteria = 16
	// MaxText — байт текста, который оценивается; больше — too_large.
	MaxText = 32 << 10
	// MaxReply — байт ответа оценщика (content), который разбирается.
	MaxReply = 8 << 10
	// MaxSyncCalls — одновременных синхронных вызовов на шлюз.
	MaxSyncCalls = 32
	// AsyncWorkers и AsyncQueue — асинхронных оценок одновременно и в
	// очереди.
	AsyncWorkers = 4
	AsyncQueue   = 64
	// AsyncTimeout — срок асинхронной оценки.
	AsyncTimeout = 30 * time.Second
	// InjectionThreshold — порог находки детектора инъекций, с которого
	// текст оценщику не передаётся.
	InjectionThreshold = 0.5
)

// Reason — почему оценка не получена («не проверено»).
type Reason string

// Причины ADR-0030, раздел 7.
const (
	ReasonUnavailable Reason = "unavailable"
	ReasonTimeout     Reason = "timeout"
	ReasonOverloaded  Reason = "overloaded"
	ReasonBudget      Reason = "budget"
	ReasonInjection   Reason = "injection"
	ReasonTooLarge    Reason = "too_large"
	ReasonBadResponse Reason = "bad_response"
	ReasonError       Reason = "error"
)

// Reasons — все причины (для проверки события).
var Reasons = []Reason{ReasonUnavailable, ReasonTimeout, ReasonOverloaded, ReasonBudget, ReasonInjection,
	ReasonTooLarge, ReasonBadResponse, ReasonError}

// Detector — запись judge.llm в реестре детекторов: по ней политика
// проверяет правила (категории, действия). Отдельный текст детектор не
// проверяет (RequestLevel): оценщика вызывает шлюз по правилам политики.
type Detector struct{}

// New — запись реестра.
func New() Detector { return Detector{} }

// ID — идентификатор детектора.
func (Detector) ID() string { return ID }

// Version — версия детектора.
func (Detector) Version() string { return Version }

// Directions — вход и выход.
func (Detector) Directions() []detect.Direction { return []detect.Direction{detect.Input, detect.Output} }

// Categories — категории находок (detect.Categorizer).
func (Detector) Categories() []string { return []string{CategoryContent, CategoryBusiness} }

// Actions — допустимые действия (detect.ActionLimiter): у находки нет
// позиций, маскировать нечего.
func (Detector) Actions() []string { return []string{"allow", "log", "block"} }

// RequestLevel — Registry.Run детектор не запускает.
func (Detector) RequestLevel() bool { return true }

// Detect по отдельному тексту находок не даёт.
func (Detector) Detect(context.Context, detect.Text) ([]detect.Finding, error) { return nil, nil }

// ValidKind — вид правила известен.
func ValidKind(k string) bool { return k == KindContent || k == KindBusiness }

// Category — категория находки по виду правила.
func Category(kind string) string {
	if kind == KindContent {
		return CategoryContent
	}
	return CategoryBusiness
}

// Threat — строка матрицы по виду правила.
func Threat(kind string) string {
	if kind == KindContent {
		return ThreatContent
	}
	return ThreatBusiness
}

// Criterion — правило для оценщика: ID правила политики, вид и текст.
type Criterion struct {
	Rule string
	Kind string
	Text string
}

// Verdict — вердикт оценщика по правилу.
type Verdict struct {
	Rule       string
	Violated   bool
	Confidence float64
}

// Outcome — итог оценки.
type Outcome struct {
	// Checked — вердикты получены (от оценщика или из кэша).
	Checked bool
	// Reason — почему не получены; у Checked пусто.
	Reason Reason
	Cached bool
	// Verdicts — в порядке критериев запроса.
	Verdicts []Verdict
	// Tokens — расход оценщика (prompt и completion).
	Prompt, Completion int
	Latency            time.Duration
}

// Findings — находки по нарушенным правилам: без позиций, оценка —
// уверенность оценщика, Rule — ID правила политики. Порог применяет
// политика.
func (o Outcome) Findings(cs []Criterion) []detect.Finding {
	kinds := make(map[string]string, len(cs))
	for _, c := range cs {
		kinds[c.Rule] = c.Kind
	}
	var out []detect.Finding
	for _, v := range o.Verdicts {
		if !v.Violated {
			continue
		}
		k := kinds[v.Rule]
		out = append(out, detect.Finding{Detector: ID, Version: Version, Category: Category(k), Threat: Threat(k),
			Score: v.Confidence, Rule: v.Rule})
	}
	return out
}

// Client — модель оценщика: адаптер провайдера (providers.Provider).
type Client interface {
	Chat(ctx context.Context, req *chat.Request) (*chat.Response, providers.Meta, error)
}

// Guard — проверка текста детекторами инъекций до отправки оценщику:
// true — найдена инъекция с оценкой не ниже InjectionThreshold.
type Guard func(ctx context.Context, text string, dir detect.Direction) (bool, error)

// Limits — бюджет политики (раздел judge).
type Limits struct {
	CallsPerMinute int
	TokensPerHour  int
}

// Config — оценщик политики.
type Config struct {
	// Provider и Model — оценщик (slug провайдера и модель): входят в ключ
	// кэша.
	Provider string
	Model    string
	// Client — nil: провайдера нет в пакете или он не «у заказчика»
	// (unavailable).
	Client Client
	Hasher aisecCrypto.Hasher
	Random aisecCrypto.Random
	// Shared — кэш, бюджеты и очереди шлюза; переживают смену пакета.
	Shared *Shared
	// BudgetKey — ключ бюджета (ID политики) и его пределы.
	BudgetKey string
	Limits    Limits
}

// Engine — оценщик одной политики.
type Engine struct {
	cfg Config
}

// NewEngine проверяет параметры.
func NewEngine(cfg Config) (*Engine, error) {
	if cfg.Hasher == nil || cfg.Random == nil || cfg.Shared == nil || cfg.BudgetKey == "" {
		return nil, errors.New("judge.llm: не заданы хеш, источник случайности, общее состояние или ключ бюджета")
	}
	if cfg.Limits.CallsPerMinute <= 0 || cfg.Limits.TokensPerHour <= 0 {
		return nil, errors.New("judge.llm: пределы бюджета — положительные")
	}
	return &Engine{cfg: cfg}, nil
}

// Request — что оценить.
type Request struct {
	Direction detect.Direction
	Text      string
	Criteria  []Criterion
	// Sync — синхронная оценка (до решения): свой предел одновременных
	// вызовов. Асинхронные оценки ограничивает Shared.Async.
	Sync bool
	// Timeout — срок вызова оценщика; 0 — AsyncTimeout.
	Timeout time.Duration
	// Guard — проверка на инъекции; nil — без неё (только тесты).
	Guard Guard
}

// Available — оценщик настроен: провайдер есть и помечен «у заказчика».
func (e *Engine) Available() bool { return e != nil && e.cfg.Client != nil }

// Evaluate оценивает текст по критериям. Ошибки не возвращает: любая
// неудача — Outcome с Reason («не проверено»), текст при этом никуда не
// пишется.
func (e *Engine) Evaluate(ctx context.Context, req Request) (out Outcome) {
	start := time.Now()
	defer func() { out.Latency = time.Since(start) }()
	switch {
	case len(req.Criteria) == 0:
		return Outcome{Checked: true}
	case len(req.Criteria) > MaxCriteria:
		return Outcome{Reason: ReasonError}
	case !e.Available():
		return Outcome{Reason: ReasonUnavailable}
	case len(req.Text) > MaxText:
		return Outcome{Reason: ReasonTooLarge}
	case req.Text == "":
		// Нечего оценивать: нарушений нет, вызова нет.
		vs := make([]Verdict, len(req.Criteria))
		for i, c := range req.Criteria {
			vs[i] = Verdict{Rule: c.Rule}
		}
		return Outcome{Checked: true, Verdicts: vs}
	}
	key := e.cacheKey(req)
	if vs, ok := e.cfg.Shared.cache.get(key, time.Now()); ok {
		return Outcome{Checked: true, Cached: true, Verdicts: vs}
	}
	if req.Guard != nil {
		found, err := req.Guard(ctx, req.Text, req.Direction)
		switch {
		case err != nil:
			return Outcome{Reason: ReasonError}
		case found:
			return Outcome{Reason: ReasonInjection}
		}
	}
	if req.Sync {
		release, ok := e.cfg.Shared.acquireSync()
		if !ok {
			return Outcome{Reason: ReasonOverloaded}
		}
		defer release()
	}
	if !e.cfg.Shared.budgets.take(e.cfg.BudgetKey, e.cfg.Limits, time.Now()) {
		return Outcome{Reason: ReasonBudget}
	}
	nonce, err := newNonce(e.cfg.Random)
	if err != nil {
		return Outcome{Reason: ReasonError}
	}
	creq, err := buildRequest(e.cfg.Model, req.Direction, req.Text, req.Criteria, nonce)
	if err != nil {
		return Outcome{Reason: ReasonError}
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = AsyncTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, _, err := e.cfg.Client.Chat(cctx, creq)
	if err != nil {
		// Расход неизвестен — оценка по размеру запроса (сверху для входа).
		e.cfg.Shared.budgets.spend(e.cfg.BudgetKey, estimateTokens(creq), time.Now())
		return Outcome{Reason: callReason(cctx, err), Prompt: estimateTokens(creq)}
	}
	prompt, completion := usage(resp, creq)
	e.cfg.Shared.budgets.spend(e.cfg.BudgetKey, prompt+completion, time.Now())
	out = Outcome{Prompt: prompt, Completion: completion}
	content, ok := replyContent(resp)
	if !ok {
		out.Reason = ReasonBadResponse
		return out
	}
	vs, err := ParseVerdicts([]byte(content), req.Criteria)
	if err != nil {
		out.Reason = ReasonBadResponse
		return out
	}
	e.cfg.Shared.cache.put(key, vs, time.Now())
	out.Checked, out.Verdicts = true, vs
	return out
}

// callReason — причина по ошибке вызова провайдера.
func callReason(ctx context.Context, err error) Reason {
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, providers.ErrTimeout) || ctx.Err() != nil:
		return ReasonTimeout
	case errors.Is(err, providers.ErrBadResponse) || errors.Is(err, chat.ErrResponseTooLarge):
		return ReasonBadResponse
	}
	var pe *providers.Error
	if errors.As(err, &pe) {
		// Оценщик ответил ошибкой (например, не поддерживает response_format).
		return ReasonBadResponse
	}
	return ReasonUnavailable
}

// replyContent — content первого варианта ответа.
func replyContent(resp *chat.Response) (string, bool) {
	if resp == nil || len(resp.Choices) == 0 || resp.Choices[0].Message.Content == nil {
		return "", false
	}
	return *resp.Choices[0].Message.Content, true
}

// usage — расход по usage оценщика; без него — оценка по размеру.
func usage(resp *chat.Response, req *chat.Request) (prompt, completion int) {
	if resp.Usage != nil && resp.Usage.PromptTokens+resp.Usage.CompletionTokens > 0 {
		return max(resp.Usage.PromptTokens, 0), max(resp.Usage.CompletionTokens, 0)
	}
	c, _ := replyContent(resp)
	return estimateTokens(req), len(c)/3 + 1
}

// estimateTokens — оценка токенов запроса сверху: байт на токен не меньше
// трёх для русского и английского текста.
func estimateTokens(req *chat.Request) int {
	n := 0
	for _, m := range req.Messages {
		if m.Content.Text != nil {
			n += len(*m.Content.Text)
		}
	}
	return n/3 + 1
}
