package gateway

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Песочница политик консоли (задача 2.12, ТЗ 5.3): проверка текста тем же
// конвейером, что Check API шлюза (inspect, endpoint check), но без
// приложения шлюза: без событий, квот, псевдонимов пользователя и
// обращения к провайдеру. Сервер вызывает Sandbox с политикой (сохранённой
// версией или черновиком) и настройками приложения из консоли.

// SandboxRequest — что проверить в песочнице.
type SandboxRequest struct {
	// Spec — проверяемая политика; компилируется по детекторам App.
	Spec *policy.Spec
	// App — настройки приложения: policy_mode, fail_mode, lists,
	// exfil_allow_domains, quotas.max_messages. Нулевое значение — без
	// приложения: режим политики, fail_closed, встроенные списки.
	App config.Application
	// External — провайдер приложения внешний (ТЗ 5.4).
	External bool
	// Body — тело запроса Check API (POST /guard/v1/check) как есть: тот же
	// формат, те же проверки и пределы.
	Body []byte
	// Timeout — базовый срок детектора; 0 — DefaultDetectorTimeout.
	Timeout time.Duration
}

// SandboxFinding — находка с правилом, которое её взяло.
type SandboxFinding struct {
	Detector string
	Category string
	Score    float64
	Start    int
	End      int
	Location string
	Threat   string
	// Rule и Action — правило с самым сильным действием по находке и это
	// действие; пусто — ни одно правило не совпало (находка ниже порога или
	// вне области правила). Apply — что сделано с фрагментом.
	Rule   string
	Action policy.Action
	Apply  policy.Action
}

// SandboxText — фрагмент после проверки.
type SandboxText struct {
	Role     string // только для messages
	Location string
	Text     string
	Changed  bool
}

// SandboxResult — итог проверки: поля ответа Check API и правила находок.
type SandboxResult struct {
	Direction detect.Direction
	Mode      policy.Mode
	// Decision — что сделано с текстом; Action — решение как в enforce.
	Decision string
	Action   policy.Action
	Rule     string
	Blocked  bool
	// FailBlock — сбой детекторов при fail_closed: шлюз ответил бы 503.
	FailBlock  bool
	Message    string
	Incomplete bool
	Unchecked  bool
	// MLUnavailable — ML-детектор политики не дал результата: на сервере
	// aisec-ml нет, проверку ML песочница не показывает (ADR-0024).
	MLUnavailable bool
	Failures      []events.DetectorFailure
	Findings      []SandboxFinding
	Truncated     bool
	// Texts — фрагменты после защиты данных; при блокировке — пусто.
	Texts []SandboxText
}

// SandboxError — запрос не прошёл проверки Check API (ответ 400 шлюза).
type SandboxError struct {
	Code    string
	Message string
}

func (e *SandboxError) Error() string { return e.Message }

// ErrSandboxPolicy — политика не компилируется по детекторам приложения
// (например, правило на категорию словаря, которого у приложения нет).
var ErrSandboxPolicy = errors.New("политика не подходит к детекторам приложения")

// Sandbox проверяет текст из req.Body по политике req.Spec. Ошибка
// *SandboxError — неверный запрос; ошибка с ErrSandboxPolicy — неверная
// политика или настройки приложения; прочие — отмена контекста или
// внутренняя ошибка конвейера.
func Sandbox(ctx context.Context, req SandboxRequest) (*SandboxResult, error) {
	if req.Spec == nil {
		return nil, errors.New("песочница: нет политики")
	}
	reg, err := appDetectors(req.App, nil)
	if err != nil {
		return nil, errors.Join(ErrSandboxPolicy, err)
	}
	pol, err := policy.Compile(req.Spec, reg)
	if err != nil {
		return nil, errors.Join(ErrSandboxPolicy, err)
	}
	maxMessages := req.App.Quotas.MaxMessages
	if maxMessages <= 0 {
		maxMessages = chat.DefaultLimits.MaxMessages
	}
	r, dir, texts, cerr := parseCheck(req.Body, maxMessages)
	if cerr != nil {
		return nil, &SandboxError{Code: cerr.Code, Message: cerr.Message}
	}
	app := &App{ID: req.App.ID, Policy: pol, Detectors: reg, Mode: policy.Mode(req.App.PolicyMode), FailOpen: req.App.FailMode == failOpen}
	in, err := app.inspect(ctx, inspectRequest{
		Endpoint: policy.EndpointCheck, Direction: dir, External: req.External, Texts: texts, Timeout: req.Timeout,
	})
	if err != nil {
		return nil, err
	}
	policyIDs := pol.Detectors(dir)
	res := &SandboxResult{
		Direction: dir, Mode: in.Decision.Mode, Decision: in.headerDecision(), Action: in.Decision.Action, Rule: in.Decision.Rule,
		Blocked: in.Blocked(), FailBlock: in.FailBlock, Incomplete: len(in.Failures) > 0, Unchecked: len(policyIDs) == 0,
		Failures: in.Failures, Findings: []SandboxFinding{}, MLUnavailable: in.MLUnavailable,
	}
	if in.Decision.Block {
		res.Message = in.Decision.Message
	}
	byHit := make(map[int]policy.Match, len(in.Decision.Matches))
	for _, m := range in.Decision.Matches {
		byHit[m.Hit] = m
	}
	// Как в Check API: находки только детекторов политики.
	for i, f := range in.Findings {
		if !slices.Contains(policyIDs, f.Detector) {
			continue
		}
		if len(res.Findings) >= maxEventFindings {
			res.Truncated = true
			break
		}
		m := byHit[i]
		res.Findings = append(res.Findings, SandboxFinding{Detector: f.Detector, Category: f.Category, Score: f.Score,
			Start: f.Start, End: f.End, Location: texts[f.Text].Location, Threat: f.Threat, Rule: m.Rule, Action: m.Action, Apply: m.Apply})
	}
	if res.Blocked {
		return res, nil
	}
	res.Texts = make([]SandboxText, len(texts))
	for i, t := range texts {
		st := SandboxText{Location: t.Location, Text: t.Text}
		if i < len(in.Changed) && in.Changed[i] {
			st.Text, st.Changed = in.Texts[i], true
		}
		if r.Text == nil {
			st.Role = r.Messages[i].Role
		}
		res.Texts[i] = st
	}
	return res, nil
}
