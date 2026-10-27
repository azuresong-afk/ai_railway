package gateway

import (
	"context"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Подтверждение вызова инструмента человеком (require_approval, DM-22;
// ADR-0023, раздел 5; задача 4.10). Вызов ждёт решения в шлюзе: шлюз
// создаёт запрос в очереди сервера управления и ждёт его долгим опросом.
// Подтверждения без сервера не бывает: недоступный сервер, переполненная
// очередь и любой сбой — отказ вызова (fail-closed), режим приложения при
// отказе (ТЗ, 4.4) здесь не действует. В режиме monitor запрос не
// создаётся (ТЗ, 5.3) — это решает вызывающий по policy.ToolDecision.
//
// Approver используют путь chat (удержание tool_calls в ответе модели,
// response.go) и MCP-прокси (tools/call, задача 4.11).

// Сроки ожидания подтверждения.
const (
	// ApprovalKeepAlive — период вызова wait в Approver.Await: поток SSE
	// клиента получает комментарий `: aisec-approval-pending`, MCP — и
	// notifications/progress.
	ApprovalKeepAlive = 15 * time.Second
	// MaxChatApprovalWait — предел ожидания на пути chat: ответ модели
	// без потока удерживается целиком, дольше клиенты не ждут.
	MaxChatApprovalWait = 5 * time.Minute
	// MaxApprovalArgs — предел аргументов, показываемых дежурному.
	MaxApprovalArgs = 16 << 10
)

// ApprovalPath — откуда пришёл вызов инструмента (поле path события
// agent_tool_call).
type ApprovalPath string

// Пути вызова.
const (
	ApprovalPathMCP  ApprovalPath = "mcp"
	ApprovalPathChat ApprovalPath = "chat"
)

// ApprovalRequest — вызов, ждущий подтверждения.
type ApprovalRequest struct {
	Path ApprovalPath
	App  string
	// Agent — slug агента; пусто — путь chat без агента.
	Agent string
	// User — псевдоним пользователя; Session — сессия (пусто — неизвестна).
	User, Session string
	// Server — slug MCP-сервера или policy.FunctionServer; Tool — имя
	// инструмента.
	Server, Tool string
	// ApprovedHash — хеш одобренного описания инструмента (пусто — путь
	// chat без реестра): решение действует только для него.
	ApprovedHash string
	Risk         policy.ToolRisk
	// Rule, Message, Severity — сработавшее правило раздела tools.
	Rule     string
	Message  string
	Severity policy.Severity
	// Args — аргументы ровно в том виде, в каком они уйдут вышестоящему
	// серверу или клиенту после одобрения (каноничный JSON из
	// policy.ToolDecision.Args). Хеш считает Approver, решение связано с ним:
	// после одобрения вызывающий передаёт дальше именно эти байты.
	Args []byte
	// ShownArgs — аргументы для дежурного: ПДн и секреты замаскированы
	// (pii.ru, secrets), не длиннее MaxApprovalArgs. Готовит вызывающий
	// (App.approvalArgs); сырые аргументы на сервер не уходят.
	ShownArgs string
	// Timeout — approval_timeout политики; 0 — policy.DefaultApprovalTimeout.
	// На пути chat Approver ограничивает его MaxChatApprovalWait.
	Timeout time.Duration
	// RequestEventID — событие gateway_request (путь chat), пусто — нет.
	RequestEventID string
}

// ApprovalState — итог ожидания (поле approval.state события
// agent_tool_call).
type ApprovalState string

// Итоги ожидания. Вызов проходит только при ApprovalApproved.
const (
	ApprovalApproved    ApprovalState = "approved"
	ApprovalDenied      ApprovalState = "denied"
	ApprovalTimeout     ApprovalState = "timeout"
	ApprovalCancelled   ApprovalState = "cancelled"
	ApprovalInterrupted ApprovalState = "interrupted"
	ApprovalQueueFull   ApprovalState = "queue_full"
	ApprovalUnavailable ApprovalState = "unavailable"
)

// ApprovalResult — решение по вызову.
type ApprovalResult struct {
	// ID — запрос в очереди (UUIDv7); пусто — запрос не создан
	// (queue_full, unavailable).
	ID    string
	State ApprovalState
	// DecidedBy — логин пользователя консоли (approved, denied).
	DecidedBy string
	// Comment — комментарий к отклонению (виден в событии и агенту не
	// передаётся).
	Comment string
	// Waited — сколько вызов ждал.
	Waited time.Duration
}

// Approved — вызов подтверждён: только тогда он передаётся дальше.
func (r ApprovalResult) Approved() bool { return r.State == ApprovalApproved }

// Сообщения агенту при отказе без сообщения правила (ADR-0023, раздел 5).
const (
	approvalDeniedMessage  = "Вызов отклонён"
	approvalTimeoutMessage = "Вызов не подтверждён вовремя"
	approvalFailedMessage  = "Вызов не может быть подтверждён: очередь подтверждений недоступна"
)

// AgentMessage — текст отказа для агента: сообщение правила или
// стандартный текст по итогу. Комментарий дежурного не передаётся.
func (r ApprovalResult) AgentMessage(ruleMessage string) string {
	switch {
	case r.State == ApprovalTimeout || r.State == ApprovalInterrupted:
		return approvalTimeoutMessage
	case r.State == ApprovalQueueFull || r.State == ApprovalUnavailable:
		return approvalFailedMessage
	case ruleMessage != "":
		return ruleMessage
	default:
		return approvalDeniedMessage
	}
}

// Approver — очередь подтверждений.
type Approver interface {
	// Await создаёт запрос и ждёт решения. Возвращается всегда с итогом,
	// без ошибки: любой сбой — отказ (unavailable, queue_full). Отмена ctx
	// (клиент закрыл поток) закрывает запрос как cancelled; по сроку —
	// timeout. wait, если не nil, вызывается каждые ApprovalKeepAlive, пока
	// решения нет, в той же горутине: вызывающий пишет из него keep-alive в
	// свой поток без синхронизации.
	Await(ctx context.Context, req ApprovalRequest, wait func()) ApprovalResult
}

// ApproverFunc — функция как Approver (тестовые заглушки).
type ApproverFunc func(ctx context.Context, req ApprovalRequest, wait func()) ApprovalResult

// Await вызывает f.
func (f ApproverFunc) Await(ctx context.Context, req ApprovalRequest, wait func()) ApprovalResult {
	return f(ctx, req, wait)
}

// NoApprover — шлюз без сервера управления (локальный конфиг): каждый
// вызов с require_approval отклоняется как unavailable.
var NoApprover Approver = ApproverFunc(func(context.Context, ApprovalRequest, func()) ApprovalResult {
	return ApprovalResult{State: ApprovalUnavailable}
})
