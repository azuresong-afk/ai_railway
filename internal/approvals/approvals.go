// Пакет approvals — очередь подтверждений вызовов инструментов агентов
// (require_approval, DM-22; ТЗ 5.10; задача 4.10, ADR-0023, раздел 5).
//
// Шлюз создаёт запрос, когда политика вызовов требует подтверждения
// человеком, и ждёт решения долгим опросом. Решает пользователь консоли с
// правом approvals.decide (администратор безопасности, аналитик); токен
// API решить не может. Срок — approval_timeout политики: по его истечении
// запрос закрывается как timeout, и решение после срока отклоняется.
// Аргументы вызова (маскированные шлюзом, до 16 КиБ) шифруются ключом
// данных (keyring.Box, AAD approval_requests|args|<id>) и удаляются через
// 30 суток после закрытия; метаданные хранятся по сроку событий. Создание
// запроса, переполнение очереди и решение пишутся в журнал аудита; по
// записям поднимаются оповещения agents.approval_requested и
// agents.approval_queue_full (без аргументов).
package approvals

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/tooldesc"
)

// Пределы и сроки (ADR-0023, раздел 5).
const (
	// MaxPerGateway и MaxPerAgent — ожидающих запросов на шлюз и на
	// агента (приложение и агент) шлюза.
	MaxPerGateway = 256
	MaxPerAgent   = 16
	// MaxArgs — аргументы для дежурного, байт.
	MaxArgs = 16 << 10
	// MinTimeout, MaxTimeout — границы срока ожидания (approval_timeout).
	MinTimeout = time.Minute
	MaxTimeout = 60 * time.Minute
	// MaxWait — предел долгого опроса: ответ приходит раньше таймаута
	// клиента шлюза (35 с).
	MaxWait = 25 * time.Second
	// ArgsRetention — аргументы удаляются через этот срок после закрытия.
	ArgsRetention = 30 * 24 * time.Hour
	// InterruptGrace — запрос, которого нет в списке ожидающих из
	// heartbeat, закрывается как interrupted не раньше этого срока после
	// создания: шлюз мог ещё не получить ответ на создание.
	InterruptGrace = time.Minute
	// MaxComment — комментарий к решению, символов.
	MaxComment = 500
	maxText    = 256
	maxRule    = 128
	maxMessage = 500
)

// State — состояние запроса.
type State string

// Состояния. Ожидает только Pending; остальные окончательные.
const (
	Pending     State = "pending"
	Approved    State = "approved"
	Denied      State = "denied"
	Timeout     State = "timeout"
	Cancelled   State = "cancelled"
	Interrupted State = "interrupted"
)

// ValidState — известное состояние.
func ValidState(s State) bool {
	switch s {
	case Pending, Approved, Denied, Timeout, Cancelled, Interrupted:
		return true
	}
	return false
}

// Пути вызова (поле path события agent_tool_call).
const (
	PathMCP  = "mcp"
	PathChat = "chat"
)

// Ошибки.
var (
	ErrNotFound = errors.New("запрос подтверждения не найден")
	// ErrQueueFull — пределы ожидающих запросов шлюза или агента.
	ErrQueueFull = errors.New("очередь подтверждений переполнена")
	// ErrClosed — запрос уже закрыт другим решением, отменой или сроком.
	ErrClosed = errors.New("запрос подтверждения уже закрыт")
	// ErrExpired — срок ожидания истёк до решения (решение после срока).
	ErrExpired = errors.New("срок подтверждения истёк")
	// ErrStale — дежурному показали другие аргументы.
	ErrStale = errors.New("аргументы запроса не совпадают с показанными")
	// ErrHumanRequired — решает только пользователь консоли, не токен API.
	ErrHumanRequired = errors.New("вызов подтверждает пользователь консоли")
	// ErrConfirmRequired — одобрение вызова с риском critical без
	// повторной проверки пароля или кода.
	ErrConfirmRequired = errors.New("одобрение вызова с риском critical требует повторной проверки")
	ErrNoDataKey       = errors.New("ключ данных не подключён: аргументы вызова сохранить нельзя")
)

// InputError — неверные данные запроса; текст показывается вызывающему.
type InputError struct{ Errs []error }

func (e *InputError) Error() string { return errors.Join(e.Errs...).Error() }

// Sealed — аргументы, зашифрованные ключом данных.
type Sealed struct {
	Data  []byte
	KeyID string
	Alg   string
}

// Request — запрос подтверждения.
type Request struct {
	ID        string
	OrgID     string
	GatewayID string
	Path      string
	// App — slug приложения; Agent — slug агента (пусто — путь chat без
	// агента); User — псевдоним пользователя; Session — сессия.
	App, Agent, User, Session string
	// Server — slug MCP-сервера или policy.FunctionServer; Tool — имя.
	Server, Tool string
	// ApprovedHash — хеш одобренного описания (hex), пусто — нет в реестре.
	ApprovedHash string
	Risk         policy.ToolRisk
	Rule         string
	Message      string
	Severity     policy.Severity
	// ArgsHash — хеш аргументов, которые шлюз передаст дальше (hex).
	ArgsHash string
	// Args — маскированные аргументы; nil — удалены по сроку.
	Args           *Sealed
	RequestEventID string
	State          State
	CreatedAt      time.Time
	Deadline       time.Time
	// ClosedAt — время закрытия; нулевое — ожидает.
	ClosedAt time.Time
	// DecidedBy и DecidedByName — пользователь консоли (approved, denied).
	DecidedBy     string
	DecidedByName string
	Comment       string
}

// ToolRef — инструмент для журналов и оповещений: «сервер/имя».
func (r Request) ToolRef() string { return r.Server + "/" + r.Tool }

// Waited — сколько вызов ждал решения (до закрытия или до now).
func (r Request) Waited(now time.Time) time.Duration {
	end := r.ClosedAt
	if end.IsZero() {
		end = now
	}
	return max(end.Sub(r.CreatedAt), 0)
}

// CreateInput — запрос шлюза.
type CreateInput struct {
	Path                      string
	App, Agent, User, Session string
	Server, Tool              string
	ApprovedHash              string
	Risk                      policy.ToolRisk
	Rule, Message             string
	Severity                  policy.Severity
	ArgsHash                  string
	// Args — маскированные аргументы (JSON или текст), до MaxArgs байт.
	Args           string
	Timeout        time.Duration
	RequestEventID string
}

var (
	slugRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	agentRe = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	hashRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ValidID — ID запроса в канонической записи UUID.
func ValidID(id string) bool { return uuidRe.MatchString(id) }

// printable — строка в UTF-8 без управляющих символов, не длиннее n символов.
func printable(s string, n int) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= n && strings.IndexFunc(s, unicode.IsControl) < 0
}

// Validate проверяет запрос шлюза: поля приходят по сети и пишутся в БД,
// аудит и оповещения.
func (in *CreateInput) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if in.Path != PathMCP && in.Path != PathChat {
		add("path — mcp или chat")
	}
	if !slugRe.MatchString(in.App) {
		add("app — slug приложения")
	}
	if in.Agent != "" && !agentRe.MatchString(in.Agent) {
		add("agent — slug агента")
	}
	if in.Path == PathMCP && in.Agent == "" {
		add("agent — обязателен для пути mcp")
	}
	if !printable(in.User, maxText) || !printable(in.Session, maxText) {
		add("user и session — до %d печатных символов", maxText)
	}
	switch {
	case in.Server == policy.FunctionServer:
	case !agentRe.MatchString(in.Server):
		add("server — slug MCP-сервера или function")
	case in.Path == PathChat:
		add("server — для пути chat только function")
	}
	if !tooldesc.ValidName(in.Tool) {
		add("tool — имя инструмента")
	}
	if in.ApprovedHash != "" && !hashRe.MatchString(in.ApprovedHash) {
		add("approved_hash — 64 шестнадцатеричные цифры")
	}
	if !policy.ValidRisk(in.Risk) {
		add("risk — low, medium, high или critical")
	}
	if in.Rule == "" || !printable(in.Rule, maxRule) {
		add("rule — от 1 до %d печатных символов", maxRule)
	}
	if !printable(in.Message, maxMessage) {
		add("message — до %d печатных символов", maxMessage)
	}
	if !validSeverity(in.Severity) {
		add("severity — info, low, medium, high или critical")
	}
	if !hashRe.MatchString(in.ArgsHash) {
		add("args_hash — 64 шестнадцатеричные цифры")
	}
	if len(in.Args) > MaxArgs || !utf8.ValidString(in.Args) || strings.ContainsRune(in.Args, 0) {
		add("args — до %d байт текста в UTF-8", MaxArgs)
	}
	if in.Timeout < MinTimeout || in.Timeout > MaxTimeout {
		add("timeout — от 1 до 60 минут")
	}
	if in.RequestEventID != "" && !ValidID(in.RequestEventID) {
		add("request_event_id — UUID")
	}
	if len(errs) > 0 {
		return &InputError{Errs: errs}
	}
	return nil
}

func validSeverity(s policy.Severity) bool {
	switch s {
	case policy.Info, policy.Low, policy.Medium, policy.High, policy.Critical:
		return true
	}
	return false
}

// Filter — отбор запросов для консоли.
type Filter struct {
	// State — пусто — все; Pending — ожидающие.
	State State
	App   string
	Agent string
	// After — курсор (время создания и ID последней записи страницы).
	AfterTime time.Time
	AfterID   string
	Limit     int
}

// Store — хранилище (миграция 0056_approvals). Рабочая реализация —
// PGStore, для тестов без PostgreSQL — Memory. Записи аудита фиксируются
// той же транзакцией, что и изменение (РСБ.1).
type Store interface {
	// Create сохраняет запрос, если ожидающих запросов шлюза меньше
	// maxGateway и агента (приложение и агент) меньше maxAgent; иначе
	// ErrQueueFull (*QueueFullError).
	Create(ctx context.Context, r Request, rec audit.Entry, maxGateway, maxAgent int) error
	Get(ctx context.Context, orgID, id string) (Request, error)
	// Close блокирует запрос и передаёт его fn; fn меняет его и возвращает
	// запись аудита (nil — без записи) или ошибку (изменение отменяется).
	Close(ctx context.Context, orgID, id string, fn func(*Request) (*audit.Entry, error)) (Request, error)
	List(ctx context.Context, orgID string, f Filter) ([]Request, error)
	// Expire закрывает до limit ожидающих запросов со сроком не позже now
	// как timeout; возвращает их ID.
	Expire(ctx context.Context, orgID string, now time.Time, limit int) ([]string, error)
	// Interrupt закрывает как interrupted ожидающие запросы шлюза,
	// созданные раньше before и не входящие в keep; возвращает их ID.
	Interrupt(ctx context.Context, orgID, gatewayID string, keep []string, before, now time.Time) ([]string, error)
	// PurgeArgs удаляет аргументы до limit запросов, закрытых раньше before.
	PurgeArgs(ctx context.Context, orgID string, before time.Time, limit int) (int, error)
	// Delete удаляет до limit запросов, закрытых раньше before.
	Delete(ctx context.Context, orgID string, before time.Time, limit int) (int, error)
	// Record пишет запись аудита вне изменения (переполнение очереди).
	Record(ctx context.Context, rec audit.Entry) error
}

// QueueFullError — какой предел исчерпан: gateway или agent.
type QueueFullError struct{ Scope string }

func (e *QueueFullError) Error() string { return ErrQueueFull.Error() + ": " + e.Scope }
func (e *QueueFullError) Unwrap() error { return ErrQueueFull }

// By — кто решает (РСБ.1).
type By struct {
	Actor audit.Actor
	IP    netip.Addr
	// Confirm — повторная проверка пароля или кода перед одобрением
	// вызова с риском critical; nil — ErrConfirmRequired.
	Confirm func(ctx context.Context) error
	// NoMFA — в сессии не принят код второго фактора: любое одобрение —
	// после повторной проверки, как у critical (4В37; аналитику TOTP не
	// обязателен, а украденного пароля не должно хватать на одобрение).
	NoMFA bool
}
