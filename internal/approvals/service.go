package approvals

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Место хранения аргументов для AAD ключа данных (ADR-0007).
const (
	argsTable  = "approval_requests"
	argsColumn = "args"
)

// Фоновая очистка.
const (
	// RunInterval — период закрытия просроченных запросов и очистки.
	RunInterval = 5 * time.Second
	// recheck — повторное чтение запроса во время ожидания: решение могло
	// прийти через другой экземпляр сервера.
	recheck = 5 * time.Second
	// queueFullEvery — запись аудита о переполнении очереди не чаще раза за
	// этот срок на шлюз и агента: переполнение повторяется на каждом вызове.
	queueFullEvery = time.Minute
	batch          = 500
	// DefaultMetadataDays — срок метаданных без настройки сроков событий.
	DefaultMetadataDays = 365
)

// Options — зависимости Service.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	// Box — ключ данных для аргументов; nil — запросы с аргументами не
	// создаются (ErrNoDataKey).
	Box   *keyring.Box
	OrgID string
	Clock func() time.Time
	// MetadataDays — срок хранения метаданных (срок событий, ТЗ 5.5); nil
	// — DefaultMetadataDays.
	MetadataDays func(ctx context.Context) (int, error)
	Logger       *slog.Logger
}

// Service — очередь подтверждений.
type Service struct {
	store    Store
	box      *keyring.Box
	ids      *ids.Generator
	orgID    string
	clock    func() time.Time
	metadata func(ctx context.Context) (int, error)
	logger   *slog.Logger

	mu sync.Mutex
	// waiters — ожидающие решения долгие опросы по ID запроса.
	waiters map[string]map[chan struct{}]struct{}
	// full — последняя запись аудита о переполнении (шлюз и агент).
	full map[string]time.Time
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Provider == nil {
		return nil, errors.New("подтверждения: не заданы хранилище или криптопрофиль")
	}
	r, err := o.Provider.Random()
	if err != nil {
		return nil, err
	}
	s := &Service{store: o.Store, box: o.Box, ids: ids.NewGenerator(r), orgID: o.OrgID, clock: o.Clock, metadata: o.MetadataDays,
		logger: o.Logger, waiters: map[string]map[chan struct{}]struct{}{}, full: map[string]time.Time{}}
	if s.orgID == "" {
		s.orgID = audit.DefaultOrgID
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	return s, nil
}

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

// gatewayActor — шлюз как субъект записи аудита.
func gatewayActor(gatewayID string) audit.Actor {
	return audit.Actor{Type: audit.ActorGateway, ID: gatewayID}
}

// requestDetails — подробности записи аудита и оповещения: без аргументов,
// их хеша (ревью 4.r1, 4В9: журнал неизменяем, а хеш связывает запись с
// аргументами), сообщения правила и комментария пользователя приложения.
func requestDetails(r *Request) map[string]any {
	d := map[string]any{"app": r.App, "server": r.Server, "tool": r.Tool, "risk": string(r.Risk), "rule": r.Rule,
		"path": r.Path, "deadline": r.Deadline.UTC().Format(time.RFC3339)}
	if r.Agent != "" {
		d["agent"] = r.Agent
	}
	return d
}

// Create ставит запрос шлюза gatewayID в очередь. Переполнение — ErrQueueFull
// с записью аудита agent.approval.queue_full (не чаще раза в минуту на шлюз
// и агента): по ней поднимается оповещение.
func (s *Service) Create(ctx context.Context, gatewayID string, in CreateInput) (Request, error) {
	if err := in.Validate(); err != nil {
		return Request{}, err
	}
	if s.box == nil {
		return Request{}, ErrNoDataKey
	}
	id, err := s.ids.New()
	if err != nil {
		return Request{}, err
	}
	now := s.now()
	r := Request{ID: id.String(), OrgID: s.orgID, GatewayID: gatewayID, Path: in.Path, App: in.App, Agent: in.Agent,
		User: in.User, Session: in.Session, Server: in.Server, Tool: in.Tool, ApprovedHash: in.ApprovedHash, Risk: in.Risk,
		Rule: in.Rule, Message: in.Message, Severity: in.Severity, ArgsHash: in.ArgsHash, RequestEventID: in.RequestEventID,
		State: Pending, CreatedAt: now, Deadline: now.Add(in.Timeout)}
	keyID, sealed, err := s.box.SealKey(ctx, []byte(in.Args), argsTable, argsColumn, r.ID)
	if err != nil {
		return Request{}, err
	}
	r.Args = &Sealed{Data: sealed, KeyID: keyID, Alg: s.box.Alg()}
	rec := audit.Entry{OrgID: s.orgID, Actor: gatewayActor(gatewayID), Action: "agent.approval.requested",
		Object: audit.Object{Type: "approval", ID: r.ID}, Result: audit.ResultSuccess, Details: requestDetails(&r)}
	err = s.store.Create(ctx, r, rec, MaxPerGateway, MaxPerAgent)
	var qf *QueueFullError
	if errors.As(err, &qf) {
		s.queueFull(ctx, gatewayID, &r, qf.Scope)
	}
	if err != nil {
		return Request{}, err
	}
	return r, nil
}

// queueFull пишет agent.approval.queue_full не чаще queueFullEvery на шлюз
// и агента.
func (s *Service) queueFull(ctx context.Context, gatewayID string, r *Request, scope string) {
	key := gatewayID + "\x1f" + r.App + "\x1f" + r.Agent
	now := s.clock()
	s.mu.Lock()
	last, seen := s.full[key]
	if seen && now.Sub(last) < queueFullEvery {
		s.mu.Unlock()
		return
	}
	if len(s.full) >= 4*MaxPerGateway {
		clear(s.full) // память ограничена; повторная запись раз в минуту — допустимо
	}
	s.full[key] = now
	s.mu.Unlock()
	d := requestDetails(r)
	delete(d, "deadline")
	d["scope"] = scope
	d["limit"] = MaxPerGateway
	if scope == "agent" {
		d["limit"] = MaxPerAgent
	}
	rec := audit.Entry{OrgID: s.orgID, Actor: gatewayActor(gatewayID), Action: "agent.approval.queue_full",
		Object: audit.Object{Type: "gateway", ID: gatewayID}, Result: audit.ResultFailure, Details: d}
	if err := s.store.Record(ctx, rec); err != nil {
		s.logger.Error("подтверждения: запись о переполнении очереди", "error", err, "gateway_id", gatewayID)
	}
}

// Get — запрос по ID для консоли.
func (s *Service) Get(ctx context.Context, id string) (Request, error) {
	if !ValidID(id) {
		return Request{}, ErrNotFound
	}
	return s.store.Get(ctx, s.orgID, id)
}

// List — запросы для консоли, новые первыми.
func (s *Service) List(ctx context.Context, f Filter) ([]Request, error) {
	return s.store.List(ctx, s.orgID, f)
}

// Args расшифровывает маскированные аргументы запроса; nil — удалены по
// сроку.
func (s *Service) Args(ctx context.Context, r Request) ([]byte, error) {
	if r.Args == nil {
		return nil, nil
	}
	if s.box == nil {
		return nil, ErrNoDataKey
	}
	return s.box.OpenContext(ctx, r.Args.KeyID, r.Args.Data, argsTable, argsColumn, r.ID)
}

// gatewayRequest — запрос шлюза: чужой запрос неотличим от несуществующего.
func (s *Service) gatewayRequest(ctx context.Context, gatewayID, id string) (Request, error) {
	if !ValidID(id) {
		return Request{}, ErrNotFound
	}
	r, err := s.store.Get(ctx, s.orgID, id)
	if err != nil {
		return Request{}, err
	}
	if r.GatewayID != gatewayID {
		return Request{}, ErrNotFound
	}
	return r, nil
}

// Wait — долгий опрос шлюза: ждёт закрытия запроса не дольше wait (не
// больше MaxWait) и возвращает его состояние. Запрос со сроком в прошлом
// закрывается как timeout.
func (s *Service) Wait(ctx context.Context, gatewayID, id string, wait time.Duration) (Request, error) {
	wait = min(max(wait, 0), MaxWait)
	until := time.Now().Add(wait)
	for {
		ch := s.subscribe(id)
		r, err := s.gatewayRequest(ctx, gatewayID, id)
		if err == nil && r.State == Pending && !s.now().Before(r.Deadline) {
			r, err = s.expire(ctx, id)
		}
		left := time.Until(until)
		if err != nil || r.State != Pending || left <= 0 {
			s.unsubscribe(id, ch)
			return r, err
		}
		d := min(left, recheck, max(r.Deadline.Sub(s.now()), time.Millisecond))
		t := time.NewTimer(d)
		select {
		case <-ch:
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			s.unsubscribe(id, ch)
			return r, ctx.Err()
		}
		t.Stop()
		s.unsubscribe(id, ch)
	}
}

// expire закрывает просроченный запрос как timeout.
func (s *Service) expire(ctx context.Context, id string) (Request, error) {
	r, err := s.store.Close(ctx, s.orgID, id, func(r *Request) (*audit.Entry, error) {
		if r.State == Pending && !s.now().Before(r.Deadline) {
			r.State, r.ClosedAt = Timeout, r.Deadline
		}
		return nil, nil
	})
	if err == nil {
		s.notify(id)
	}
	return r, err
}

// Cancel — шлюз закрывает запрос: клиент закрыл поток или вызов прерван.
// Закрытый запрос возвращается как есть.
func (s *Service) Cancel(ctx context.Context, gatewayID, id string) (Request, error) {
	if _, err := s.gatewayRequest(ctx, gatewayID, id); err != nil {
		return Request{}, err
	}
	r, err := s.store.Close(ctx, s.orgID, id, func(r *Request) (*audit.Entry, error) {
		if r.State == Pending {
			r.State, r.ClosedAt = Cancelled, s.now()
			if !r.ClosedAt.Before(r.Deadline) {
				r.State, r.ClosedAt = Timeout, r.Deadline
			}
		}
		return nil, nil
	})
	if err == nil {
		s.notify(id)
	}
	return r, err
}

// DecideInput — решение пользователя консоли.
type DecideInput struct {
	Approve bool
	Comment string
	// ArgsHash — хеш аргументов показанного запроса: одобряется увиденное.
	ArgsHash string
}

// Decide закрывает ожидающий запрос решением пользователя консоли с записью
// аудита agent.approval.approve или agent.approval.deny. После срока —
// ErrExpired (запрос закрывается как timeout), закрытый — ErrClosed.
// Одобрение вызова с риском critical — после повторной проверки.
func (s *Service) Decide(ctx context.Context, by By, id string, in DecideInput) (Request, error) {
	if by.Actor.Type != audit.ActorUser || by.Actor.ID == "" {
		return Request{}, ErrHumanRequired
	}
	if !printable(in.Comment, MaxComment) {
		return Request{}, &InputError{Errs: []error{errors.New("comment — до 500 печатных символов")}}
	}
	cur, err := s.Get(ctx, id)
	if err != nil {
		return Request{}, err
	}
	if in.Approve && in.ArgsHash != cur.ArgsHash {
		return Request{}, ErrStale
	}
	if in.Approve && cur.Risk == policy.RiskCritical && cur.State == Pending {
		if by.Confirm == nil {
			return Request{}, ErrConfirmRequired
		}
		if err := by.Confirm(ctx); err != nil {
			return Request{}, err
		}
	}
	var decideErr error
	r, err := s.store.Close(ctx, s.orgID, id, func(r *Request) (*audit.Entry, error) {
		now := s.now()
		switch {
		case r.State != Pending:
			decideErr = ErrClosed
			if r.State == Timeout {
				decideErr = ErrExpired
			}
			return nil, nil
		case !now.Before(r.Deadline):
			r.State, r.ClosedAt = Timeout, r.Deadline
			decideErr = ErrExpired
			return nil, nil
		}
		action := "agent.approval.deny"
		r.State = Denied
		if in.Approve {
			action, r.State = "agent.approval.approve", Approved
		}
		r.ClosedAt, r.DecidedBy, r.DecidedByName, r.Comment = now, by.Actor.ID, by.Actor.Name, in.Comment
		d := requestDetails(r)
		d["waited_ms"] = r.Waited(now).Milliseconds()
		// Текст комментария в неизменяемый журнал не пишется (в нём могут
		// оказаться аргументы вызова) — только длина, как у отметок событий.
		if in.Comment != "" {
			d["comment_len"] = utf8.RuneCountInString(in.Comment)
		}
		return &audit.Entry{OrgID: s.orgID, Actor: by.Actor, SourceIP: by.IP, Action: action,
			Object: audit.Object{Type: "approval", ID: r.ID}, Result: audit.ResultSuccess, Details: d}, nil
	})
	if err != nil {
		return Request{}, err
	}
	s.notify(id)
	if decideErr != nil {
		return r, decideErr
	}
	return r, nil
}

// MaxPending — ID в списке ожидающих из heartbeat.
const MaxPending = MaxPerGateway

// Sync сверяет ожидающие запросы шлюза со списком из heartbeat: запросы,
// которых в нём нет, созданные раньше InterruptGrace, закрываются как
// interrupted — шлюз перезапустился и вызов уже никто не ждёт. stopping —
// шлюз останавливается: закрываются все его ожидающие запросы.
func (s *Service) Sync(ctx context.Context, gatewayID string, pending []string, stopping bool) error {
	now := s.now()
	before := now.Add(-InterruptGrace)
	if stopping {
		before, pending = now.Add(time.Second), nil
	}
	closed, err := s.store.Interrupt(ctx, s.orgID, gatewayID, pending, before, now)
	for _, id := range closed {
		s.notify(id)
	}
	return err
}

// Sweep закрывает просроченные запросы, удаляет аргументы через
// ArgsRetention после закрытия и запросы старше срока метаданных.
func (s *Service) Sweep(ctx context.Context) error {
	now := s.now()
	closed, err := s.store.Expire(ctx, s.orgID, now, batch)
	for _, id := range closed {
		s.notify(id)
	}
	if err != nil {
		return err
	}
	if _, err := s.store.PurgeArgs(ctx, s.orgID, now.Add(-ArgsRetention), batch); err != nil {
		return err
	}
	days := DefaultMetadataDays
	if s.metadata != nil {
		if days, err = s.metadata(ctx); err != nil {
			return err
		}
	}
	// Метаданные не короче срока аргументов: иначе аргументы пережили бы запрос.
	keep := max(time.Duration(days)*24*time.Hour, ArgsRetention)
	_, err = s.store.Delete(ctx, s.orgID, now.Add(-keep), batch)
	return err
}

// Run выполняет Sweep каждые interval до отмены ctx.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
			s.logger.Error("подтверждения: очистка очереди", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) subscribe(id string) chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.waiters[id]
	if set == nil {
		set = map[chan struct{}]struct{}{}
		s.waiters[id] = set
	}
	set[ch] = struct{}{}
	return ch
}

func (s *Service) unsubscribe(id string, ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if set := s.waiters[id]; set != nil {
		delete(set, ch)
		if len(set) == 0 {
			delete(s.waiters, id)
		}
	}
}

// notify будит долгие опросы запроса id.
func (s *Service) notify(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.waiters[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
