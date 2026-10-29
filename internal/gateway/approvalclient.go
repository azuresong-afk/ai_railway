package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sync"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Клиент очереди подтверждений сервера управления (задача 4.10, ADR-0023,
// раздел 5): создание запроса — по управляющему каналу (таймаут 10 с),
// ожидание — долгим опросом своим клиентом с таймаутом ответа 35 с по тому
// же mTLS. Решение связано с ID запроса, хешем аргументов и одобренным
// хешем описания: ответ с другими значениями — отказ.

const (
	// approvalPollTimeout — таймаут клиента долгого опроса: сервер отвечает
	// не позже 25 с.
	approvalPollTimeout = 35 * time.Second
	// approvalPollWait — ожидание на сервере в одном опросе: между опросами
	// вызывается keep-alive, поэтому не дольше ApprovalKeepAlive.
	approvalPollWait = ApprovalKeepAlive
	// approvalRetry — пауза после сбоя опроса.
	approvalRetry = 2 * time.Second
	// approvalGrace — запас после срока запроса: решение сервера по сроку
	// (timeout) успевает прийти; дальше шлюз считает вызов не подтверждённым
	// сам.
	approvalGrace = 30 * time.Second
	// MaxPendingApprovals — ожидающих запросов на шлюз (сервер проверяет
	// тот же предел и предел агента).
	MaxPendingApprovals = 256
	maxApprovalResponse = 16 << 10
)

// argsHashPrefix — разделение области хеша аргументов вызова.
const argsHashPrefix = "aisec-tool-args-v1\n"

// ToolArgsHash — хеш аргументов вызова инструмента (hex) для признака
// зацикливания (limits.repeat): живёт только в памяти шлюза.
func ToolArgsHash(h aisecCrypto.Hasher, args []byte) string {
	return hex.EncodeToString(h.Sum(append([]byte(argsHashPrefix), args...)))
}

// bindNonceSize — байт случайного числа в хеше привязки.
const bindNonceSize = 32

// bindArgsHash — хеш привязки решения дежурного к аргументам (hex):
// хешер профиля над префиксом, случайным числом запроса и аргументами.
// Число живёт только в памяти шлюза на время Await, поэтому по хешу из
// карточки нельзя перебором восстановить замаскированные аргументы, а
// одинаковые аргументы двух запросов дают разные хеши (ревью 4.r1, 4В9).
// Защита от подмены — сверка хеша ответа сервера на шлюзе.
func bindArgsHash(h aisecCrypto.Hasher, nonce, args []byte) string {
	b := make([]byte, 0, len(argsHashPrefix)+len(nonce)+len(args))
	b = append(append(append(b, argsHashPrefix...), nonce...), args...)
	return hex.EncodeToString(h.Sum(b))
}

var approvalIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ApprovalClientConfig — параметры клиента очереди.
type ApprovalClientConfig struct {
	// Client — клиент управляющего канала (ControlTransport или
	// ControlTransportSwitch с сертификатом шлюза).
	Client *http.Client
	// Server — адрес внутреннего API (https://хост:8445).
	Server *url.URL
	Hasher aisecCrypto.Hasher
	// Random — источник случайных чисел хеша привязки (bindArgsHash).
	Random aisecCrypto.Random
	Logger *slog.Logger
	// Clock — часы сроков (тесты подменяют); nil — time.Now.
	Clock func() time.Time
	// Sleep — пауза после сбоя опроса (тесты подменяют); nil — по таймеру.
	Sleep func(ctx context.Context, d time.Duration) bool
	// PollWait — ожидание на сервере в одном опросе, целые секунды от 1 до
	// ApprovalKeepAlive (тесты сокращают); 0 — ApprovalKeepAlive.
	PollWait time.Duration
}

// ApprovalClient — Approver через сервер управления.
type ApprovalClient struct {
	create *http.Client
	poll   *http.Client
	base   *url.URL
	hasher aisecCrypto.Hasher
	random aisecCrypto.Random
	logger *slog.Logger
	clock  func() time.Time
	sleep  func(ctx context.Context, d time.Duration) bool
	wait   string

	mu      sync.Mutex
	pending map[string]struct{}
	slots   int
}

// NewApprovalClient создаёт клиент. Для долгого опроса берётся копия
// транспорта управляющего канала с таймаутом ответа 35 с.
func NewApprovalClient(c ApprovalClientConfig) (*ApprovalClient, error) {
	if c.Client == nil || c.Server == nil || c.Hasher == nil || c.Random == nil {
		return nil, errors.New("очередь подтверждений: не заданы клиент, адрес сервера, хеш или источник случайных чисел")
	}
	poll := &http.Client{Timeout: approvalPollTimeout, CheckRedirect: noRedirect}
	if t, ok := c.Client.Transport.(*http.Transport); ok {
		pt := t.Clone()
		pt.ResponseHeaderTimeout = approvalPollTimeout
		poll.Transport = pt
	} else {
		poll.Transport = c.Client.Transport
	}
	a := &ApprovalClient{create: c.Client, poll: poll, base: c.Server, hasher: c.Hasher, random: c.Random, logger: c.Logger, clock: c.Clock,
		sleep: c.Sleep, pending: map[string]struct{}{}}
	pw := c.PollWait.Truncate(time.Second)
	if pw <= 0 || pw > approvalPollWait {
		pw = approvalPollWait
	}
	a.wait = fmt.Sprintf("%ds", int(pw/time.Second))
	if a.logger == nil {
		a.logger = slog.Default()
	}
	if a.clock == nil {
		a.clock = time.Now
	}
	if a.sleep == nil {
		a.sleep = sleepCtx
	}
	return a, nil
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Pending — ID ожидающих запросов для heartbeat: пропавшие из списка
// сервер закрывает как interrupted.
func (a *ApprovalClient) Pending() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.pending))
	for id := range a.pending {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func (a *ApprovalClient) acquire() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.slots >= MaxPendingApprovals {
		return false
	}
	a.slots++
	return true
}

func (a *ApprovalClient) release(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.slots--
	delete(a.pending, id)
}

func (a *ApprovalClient) track(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pending[id] = struct{}{}
}

// approvalCreate — тело POST /internal/v1/approvals.
type approvalCreate struct {
	Path           ApprovalPath    `json:"path"`
	App            string          `json:"app"`
	Agent          string          `json:"agent,omitempty"`
	User           string          `json:"user,omitempty"`
	Session        string          `json:"session,omitempty"`
	Server         string          `json:"server"`
	Tool           string          `json:"tool"`
	ApprovedHash   string          `json:"approved_hash,omitempty"`
	Risk           policy.ToolRisk `json:"risk"`
	Rule           string          `json:"rule"`
	Message        string          `json:"message,omitempty"`
	Severity       policy.Severity `json:"severity"`
	ArgsHash       string          `json:"args_hash"`
	Args           string          `json:"args"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	RequestEventID string          `json:"request_event_id,omitempty"`
}

// approvalStatus — ответ сервера о запросе.
type approvalStatus struct {
	ID           string    `json:"id"`
	State        string    `json:"state"`
	ArgsHash     string    `json:"args_hash"`
	ApprovedHash string    `json:"approved_hash"`
	Deadline     time.Time `json:"deadline"`
	DecidedBy    string    `json:"decided_by"`
	Comment      string    `json:"comment"`
}

// approvalTimeout — срок ожидания: approval_timeout политики в границах
// 1–60 мин, на пути chat — не дольше MaxChatApprovalWait.
func approvalTimeout(req ApprovalRequest) time.Duration {
	t := req.Timeout
	if t <= 0 {
		t = policy.DefaultApprovalTimeout
	}
	t = min(max(t, time.Minute), time.Hour)
	if req.Path == ApprovalPathChat {
		t = min(t, MaxChatApprovalWait)
	}
	return t.Truncate(time.Second)
}

// Await — см. Approver.
func (a *ApprovalClient) Await(ctx context.Context, req ApprovalRequest, wait func()) (res ApprovalResult) {
	start := a.clock()
	if !a.acquire() {
		a.logger.Warn("очередь подтверждений шлюза переполнена: вызов отклонён", "app", req.App, "agent", req.Agent,
			"tool", req.Server+"/"+req.Tool)
		res.State = ApprovalQueueFull
		return res
	}
	id := ""
	defer func() { a.release(id) }()
	defer func() { res.Waited = max(a.clock().Sub(start), 0) }()
	nonce, err := aisecCrypto.RandomBytes(a.random, bindNonceSize)
	if err != nil {
		a.logger.Error("очередь подтверждений: нет случайного числа для хеша аргументов: вызов отклонён", "error", err)
		res.State = ApprovalUnavailable
		return res
	}
	argsHash := bindArgsHash(a.hasher, nonce, req.Args)
	clear(nonce)
	timeout := approvalTimeout(req)
	body := approvalCreate{Path: req.Path, App: req.App, Agent: req.Agent, User: req.User, Session: req.Session,
		Server: req.Server, Tool: req.Tool, ApprovedHash: req.ApprovedHash, Risk: req.Risk, Rule: req.Rule,
		Message: req.Message, Severity: req.Severity, ArgsHash: argsHash, Args: req.ShownArgs,
		TimeoutSeconds: int(timeout / time.Second), RequestEventID: req.RequestEventID}
	var st approvalStatus
	err = postControl(ctx, a.create, a.base.JoinPath("/internal/v1/approvals").String(), body, &st, http.StatusCreated)
	if err != nil {
		var ce *controlError
		if errors.As(err, &ce) && ce.Status == http.StatusTooManyRequests {
			res.State = ApprovalQueueFull
		} else {
			res.State = ApprovalUnavailable
		}
		a.logger.Warn("запрос подтверждения не создан: вызов отклонён", "app", req.App, "agent", req.Agent,
			"tool", req.Server+"/"+req.Tool, "error", err)
		return res
	}
	if !approvalIDRe.MatchString(st.ID) || !a.matches(st, argsHash, req.ApprovedHash) || st.State != "pending" {
		a.logger.Error("ответ очереди подтверждений не совпадает с запросом: вызов отклонён", "tool", req.Server+"/"+req.Tool)
		res.State = ApprovalUnavailable
		return res
	}
	id = st.ID
	res.ID = id
	a.track(id)
	// Срок по часам шлюза; ответ сервера по сроку приходит раньше.
	deadline := start.Add(timeout + approvalGrace)
	lastTick := a.clock()
	tick := func() {
		if wait != nil && a.clock().Sub(lastTick) >= ApprovalKeepAlive {
			lastTick = a.clock()
			wait()
		}
	}
	for {
		if ctx.Err() != nil {
			a.cancel(ctx, id)
			res.State = ApprovalCancelled
			return res
		}
		if !a.clock().Before(deadline) {
			a.cancel(ctx, id)
			res.State = ApprovalTimeout
			return res
		}
		st, err := a.poll1(ctx, id)
		switch {
		case err == nil && st.State == "pending" && st.ID == id:
			lastTick = time.Time{} // опрос отработал свой срок: keep-alive сразу
			tick()
			continue
		case err == nil:
			return a.result(res, st, argsHash, req)
		}
		if ctx.Err() != nil {
			continue
		}
		var ce *controlError
		if errors.As(err, &ce) && ce.Status == http.StatusNotFound {
			// Запрос закрыт и удалён или сервер его не знает: решения нет.
			res.State = ApprovalInterrupted
			return res
		}
		a.logger.Warn("опрос очереди подтверждений не удался; повтор", "error", err)
		tick()
		a.sleep(ctx, approvalRetry)
	}
}

// matches — ответ сервера связан с запросом шлюза.
func (a *ApprovalClient) matches(st approvalStatus, argsHash, approvedHash string) bool {
	return st.ArgsHash == argsHash && st.ApprovedHash == approvedHash
}

// result — итог по окончательному состоянию запроса.
func (a *ApprovalClient) result(res ApprovalResult, st approvalStatus, argsHash string, req ApprovalRequest) ApprovalResult {
	if st.ID != res.ID || !a.matches(st, argsHash, req.ApprovedHash) {
		a.logger.Error("решение очереди подтверждений не совпадает с запросом: вызов отклонён", "approval_id", res.ID)
		res.State = ApprovalDenied
		return res
	}
	switch ApprovalState(st.State) {
	case ApprovalApproved, ApprovalDenied:
		res.State, res.DecidedBy, res.Comment = ApprovalState(st.State), st.DecidedBy, st.Comment
	case ApprovalTimeout, ApprovalCancelled, ApprovalInterrupted:
		res.State = ApprovalState(st.State)
	default:
		res.State = ApprovalDenied
	}
	return res
}

// poll1 — один долгий опрос.
func (a *ApprovalClient) poll1(ctx context.Context, id string) (approvalStatus, error) {
	u := a.base.JoinPath("/internal/v1/approvals", id)
	u.RawQuery = url.Values{"wait": {a.wait}}.Encode()
	ctx, cancel := context.WithTimeout(ctx, approvalPollTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return approvalStatus{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aisec-gateway")
	resp, err := a.poll.Do(req)
	if err != nil {
		return approvalStatus{}, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:gosec // G104: тело прочитано; ошибка закрытия не меняет результат
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxApprovalResponse+1))
	if err != nil {
		return approvalStatus{}, err
	}
	if len(data) > maxApprovalResponse {
		return approvalStatus{}, errors.New("ответ очереди подтверждений слишком большой")
	}
	if resp.StatusCode != http.StatusOK {
		return approvalStatus{}, &controlError{Status: resp.StatusCode}
	}
	var st approvalStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return approvalStatus{}, errors.New("ответ очереди подтверждений — не ожидаемый JSON")
	}
	return st, nil
}

// cancel закрывает запрос на сервере: клиент ушёл или срок вышел. Отмена
// ctx вызова не мешает: запрос идёт со своим сроком.
func (a *ApprovalClient) cancel(ctx context.Context, id string) {
	ctx, done := context.WithTimeout(context.WithoutCancel(ctx), controlTimeout)
	defer done()
	u := a.base.JoinPath("/internal/v1/approvals", id, "cancel").String()
	if err := postControl(ctx, a.create, u, struct{}{}, nil, http.StatusOK); err != nil {
		a.logger.Warn("запрос подтверждения не отменён на сервере; закроется по сроку", "approval_id", id, "error", err)
	}
}
