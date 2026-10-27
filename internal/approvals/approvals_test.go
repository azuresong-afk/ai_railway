package approvals

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

const (
	gwA    = "01900000-0000-7000-8000-0000000000a1"
	gwB    = "01900000-0000-7000-8000-0000000000b1"
	userID = "01900000-0000-7000-8000-0000000000c1"
)

var argsHash = strings.Repeat("ab", 32)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	mem   *Memory
	svc   *Service
	clock *clock
	by    By
}

func newEnv(t *testing.T) *env {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	key, err := aisecCrypto.RandomBytes(r, aisecCrypto.AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	box, err := keyring.NewStaticKey(p, "01900000-0000-7000-8000-0000000000d1", key)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{mem: NewMemory(), clock: &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)},
		by: By{Actor: audit.Actor{Type: audit.ActorUser, ID: userID, Name: "duty"}, Confirm: func(context.Context) error { return nil }}}
	if e.svc, err = New(Options{Store: e.mem, Provider: p, Box: box, Clock: e.clock.now}); err != nil {
		t.Fatal(err)
	}
	// Подробности каждой записи проходят проверки журнала аудита, как в PGStore.
	t.Cleanup(func() {
		for _, r := range e.mem.Records() {
			if _, err := audit.CanonicalDetails(r.Details); err != nil {
				t.Errorf("%s: %v", r.Action, err)
			}
		}
	})
	return e
}

func input() CreateInput {
	return CreateInput{Path: PathMCP, App: "crm", Agent: "support-bot", User: "u-1", Session: "s-1", Server: "files",
		Tool: "delete_file", Risk: policy.RiskHigh, Rule: "tools-approve", Message: "Удаление файла подтверждает дежурный",
		Severity: policy.High, ArgsHash: argsHash, Args: `{"path":"/tmp/report.txt"}`, Timeout: 10 * time.Minute}
}

func (e *env) create(t *testing.T, gw string, in CreateInput) Request {
	t.Helper()
	r, err := e.svc.Create(context.Background(), gw, in)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func actions(m *Memory, action string) []audit.Entry {
	var out []audit.Entry
	for _, r := range m.Records() {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

func TestDM22_CreateSealsArgsAndAudits(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	if r.State != Pending || !r.Deadline.Equal(e.clock.now().Add(10*time.Minute)) || !ValidID(r.ID) {
		t.Fatalf("запрос: %+v", r)
	}
	got, err := e.svc.Get(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Args == nil || bytes.Contains(got.Args.Data, []byte("report.txt")) {
		t.Fatal("аргументы хранятся открыто")
	}
	plain, err := e.svc.Args(context.Background(), got)
	if err != nil || string(plain) != `{"path":"/tmp/report.txt"}` {
		t.Fatalf("аргументы: %q, %v", plain, err)
	}
	// AAD привязывает шифртекст к ID запроса: чужой ID не расшифровывается.
	other := got
	other.ID = "01900000-0000-7000-8000-0000000000ff"
	if _, err := e.svc.Args(context.Background(), other); err == nil {
		t.Fatal("аргументы расшифрованы под чужим ID")
	}
	recs := actions(e.mem, "agent.approval.requested")
	if len(recs) != 1 || recs[0].Actor.Type != audit.ActorGateway || recs[0].Actor.ID != gwA || recs[0].Object.ID != r.ID {
		t.Fatalf("аудит: %+v", recs)
	}
	for k, v := range details(recs[0]) {
		if strings.Contains(fmt.Sprint(v), "report.txt") || k == "args" || k == "message" {
			t.Fatalf("аргументы или сообщение в аудите: %s=%v", k, v)
		}
	}
}

func TestDM22_CreateValidation(t *testing.T) {
	e := newEnv(t)
	cases := map[string]func(*CreateInput){
		"путь":              func(in *CreateInput) { in.Path = "http" },
		"mcp без агента":    func(in *CreateInput) { in.Agent = "" },
		"chat с сервером":   func(in *CreateInput) { in.Path = PathChat },
		"приложение":        func(in *CreateInput) { in.App = "CRM" },
		"инструмент":        func(in *CreateInput) { in.Tool = "rm -rf" },
		"риск":              func(in *CreateInput) { in.Risk = "extreme" },
		"важность":          func(in *CreateInput) { in.Severity = "urgent" },
		"правило пустое":    func(in *CreateInput) { in.Rule = "" },
		"управляющие":       func(in *CreateInput) { in.User = "a\nb" },
		"хеш":               func(in *CreateInput) { in.ArgsHash = "abc" },
		"одобренный хеш":    func(in *CreateInput) { in.ApprovedHash = strings.Repeat("Z", 64) },
		"аргументы длинные": func(in *CreateInput) { in.Args = strings.Repeat("a", MaxArgs+1) },
		"аргументы с нулём": func(in *CreateInput) { in.Args = "a\x00b" },
		"аргументы не utf8": func(in *CreateInput) { in.Args = "\xff" },
		"срок мал":          func(in *CreateInput) { in.Timeout = 59 * time.Second },
		"срок велик":        func(in *CreateInput) { in.Timeout = 61 * time.Minute },
		"событие":           func(in *CreateInput) { in.RequestEventID = "1" },
	}
	for name, mut := range cases {
		in := input()
		mut(&in)
		var ie *InputError
		if _, err := e.svc.Create(context.Background(), gwA, in); !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Граничные значения допустимы.
	in := input()
	in.Path, in.Agent, in.Server, in.Tool = PathChat, "", policy.FunctionServer, "send_mail"
	in.Args, in.Timeout = strings.Repeat("я", MaxArgs/2), MaxTimeout
	e.create(t, gwA, in)
	in.Timeout = MinTimeout
	in.Args = ""
	e.create(t, gwA, in)
}

func TestDM22_CreateWithoutDataKey(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Options{Store: NewMemory(), Provider: p})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(context.Background(), gwA, input()); !errors.Is(err, ErrNoDataKey) {
		t.Fatalf("без ключа данных: %v", err)
	}
}

func TestDM22_QueueLimits(t *testing.T) {
	e := newEnv(t)
	for range MaxPerAgent {
		e.create(t, gwA, input())
	}
	_, err := e.svc.Create(context.Background(), gwA, input())
	var qf *QueueFullError
	if !errors.As(err, &qf) || qf.Scope != "agent" || !errors.Is(err, ErrQueueFull) {
		t.Fatalf("предел агента: %v", err)
	}
	// Повторное переполнение в ту же минуту не пишет новую запись.
	if _, err := e.svc.Create(context.Background(), gwA, input()); !errors.Is(err, ErrQueueFull) {
		t.Fatal(err)
	}
	if n := len(actions(e.mem, "agent.approval.queue_full")); n != 1 {
		t.Fatalf("записей о переполнении: %d", n)
	}
	e.clock.add(queueFullEvery)
	if _, err := e.svc.Create(context.Background(), gwA, input()); !errors.Is(err, ErrQueueFull) {
		t.Fatal(err)
	}
	full := actions(e.mem, "agent.approval.queue_full")
	if len(full) != 2 || details(full[1])["scope"] != "agent" || details(full[1])["limit"] != MaxPerAgent ||
		full[1].Result != audit.ResultFailure {
		t.Fatalf("записи о переполнении: %+v", full)
	}
	// Другой агент и другой шлюз — свои пределы.
	in := input()
	in.Agent = "other-bot"
	e.create(t, gwA, in)
	e.create(t, gwB, input())

	// Предел шлюза: 256 ожидающих на шлюз при 16 на агента.
	for i := 0; ; i++ {
		in := input()
		in.Agent = fmt.Sprintf("bot-%d", i/MaxPerAgent)
		_, err := e.svc.Create(context.Background(), gwB, in)
		if err != nil {
			if !errors.As(err, &qf) || qf.Scope != "gateway" {
				t.Fatalf("предел шлюза: %v", err)
			}
			break
		}
	}
	pending, err := e.svc.List(context.Background(), Filter{State: Pending})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range pending {
		if r.GatewayID == gwB {
			n++
		}
	}
	if n != MaxPerGateway {
		t.Fatalf("ожидающих на шлюзе: %d", n)
	}
	// Закрытый запрос освобождает место.
	r := pending[0]
	if _, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{}); err != nil {
		t.Fatal(err)
	}
	in = input()
	in.Agent = r.Agent
	e.create(t, r.GatewayID, in)
}

func TestDM22_DecideApprove(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	e.clock.add(90 * time.Second)
	got, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{Approve: true, ArgsHash: argsHash, Comment: "проверено"})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != Approved || got.DecidedBy != userID || got.DecidedByName != "duty" || got.Comment != "проверено" ||
		got.Waited(time.Time{}) != 90*time.Second {
		t.Fatalf("решение: %+v", got)
	}
	recs := actions(e.mem, "agent.approval.approve")
	if len(recs) != 1 || recs[0].Actor.ID != userID || details(recs[0])["waited_ms"] != int64(90000) ||
		details(recs[0])["comment_len"] != 9 || details(recs[0])["comment"] != nil {
		t.Fatalf("аудит: %+v", recs)
	}
	// Повторное решение — запрос уже закрыт.
	if _, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("повторное решение: %v", err)
	}
	if n := len(actions(e.mem, "agent.approval.deny")); n != 0 {
		t.Fatalf("лишняя запись: %d", n)
	}
}

func TestDM22_DecideDeny(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	// Отказ не сверяет хеш аргументов: отклонить можно и не глядя.
	got, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{})
	if err != nil || got.State != Denied {
		t.Fatalf("отказ: %+v, %v", got, err)
	}
	if n := len(actions(e.mem, "agent.approval.deny")); n != 1 {
		t.Fatalf("аудит отказа: %d", n)
	}
}

func TestDM22_DecideRequiresHuman(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	for _, a := range []audit.Actor{{Type: audit.ActorAPIToken, ID: userID}, {Type: audit.ActorGateway, ID: gwA},
		{Type: audit.ActorSystem}, {Type: audit.ActorUser}} {
		if _, err := e.svc.Decide(context.Background(), By{Actor: a}, r.ID, DecideInput{Approve: true, ArgsHash: argsHash}); !errors.Is(err, ErrHumanRequired) {
			t.Errorf("%+v: %v", a, err)
		}
	}
}

func TestDM22_DecideStaleArgs(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	for _, h := range []string{"", strings.Repeat("cd", 32)} {
		if _, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{Approve: true, ArgsHash: h}); !errors.Is(err, ErrStale) {
			t.Errorf("хеш %q: %v", h, err)
		}
	}
	if got := e.get(t, r.ID); got.State != Pending {
		t.Fatalf("запрос закрыт: %s", got.State)
	}
}

func TestDM22_DecideCriticalNeedsConfirm(t *testing.T) {
	e := newEnv(t)
	in := input()
	in.Risk = policy.RiskCritical
	r := e.create(t, gwA, in)
	by := e.by
	by.Confirm = nil
	if _, err := e.svc.Decide(context.Background(), by, r.ID, DecideInput{Approve: true, ArgsHash: argsHash}); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("без проверки: %v", err)
	}
	bad := errors.New("неверный пароль")
	by.Confirm = func(context.Context) error { return bad }
	if _, err := e.svc.Decide(context.Background(), by, r.ID, DecideInput{Approve: true, ArgsHash: argsHash}); !errors.Is(err, bad) {
		t.Fatalf("неверная проверка: %v", err)
	}
	// Отказ по вызову critical повторной проверки не требует.
	by.Confirm = nil
	if got, err := e.svc.Decide(context.Background(), by, r.ID, DecideInput{}); err != nil || got.State != Denied {
		t.Fatalf("отказ: %+v, %v", got, err)
	}
	r = e.create(t, gwA, in)
	called := false
	by.Confirm = func(context.Context) error { called = true; return nil }
	if got, err := e.svc.Decide(context.Background(), by, r.ID, DecideInput{Approve: true, ArgsHash: argsHash}); err != nil || got.State != Approved || !called {
		t.Fatalf("одобрение: %+v, %v, %v", got, err, called)
	}
}

func TestDM22_DecideAfterDeadline(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	e.clock.add(10 * time.Minute)
	got, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{Approve: true, ArgsHash: argsHash})
	if !errors.Is(err, ErrExpired) || got.State != Timeout || !got.ClosedAt.Equal(r.Deadline) {
		t.Fatalf("после срока: %+v, %v", got, err)
	}
	if _, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("повторно после срока: %v", err)
	}
	if n := len(actions(e.mem, "agent.approval.approve")) + len(actions(e.mem, "agent.approval.deny")); n != 0 {
		t.Fatalf("решение после срока записано: %d", n)
	}
}

func TestDM22_DecideComment(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	var ie *InputError
	for _, c := range []string{strings.Repeat("я", MaxComment+1), "a\x07b"} {
		if _, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{Comment: c}); !errors.As(err, &ie) {
			t.Errorf("комментарий %q: %v", c[:3], err)
		}
	}
	if _, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{Comment: strings.Repeat("я", MaxComment)}); err != nil {
		t.Fatal(err)
	}
}

func TestDM22_NotFound(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{"", "x", "01900000-0000-7000-8000-0000000000ff", "01900000-0000-7000-8000-0000000000FF"} {
		if _, err := e.svc.Get(context.Background(), id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get %q: %v", id, err)
		}
		if _, err := e.svc.Decide(context.Background(), e.by, id, DecideInput{}); !errors.Is(err, ErrNotFound) {
			t.Errorf("Decide %q: %v", id, err)
		}
		if _, err := e.svc.Wait(context.Background(), gwA, id, 0); !errors.Is(err, ErrNotFound) {
			t.Errorf("Wait %q: %v", id, err)
		}
	}
}

func TestDM22_ForeignGateway(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	if _, err := e.svc.Wait(context.Background(), gwB, r.ID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("опрос чужого запроса: %v", err)
	}
	if _, err := e.svc.Cancel(context.Background(), gwB, r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("отмена чужого запроса: %v", err)
	}
	if got := e.get(t, r.ID); got.State != Pending {
		t.Fatalf("чужой шлюз закрыл запрос: %s", got.State)
	}
}

func TestDM22_WaitWakesOnDecision(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	done := make(chan Request, 1)
	start := time.Now()
	go func() {
		got, err := e.svc.Wait(context.Background(), gwA, r.ID, MaxWait)
		if err != nil {
			t.Error(err)
		}
		done <- got
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{Approve: true, ArgsHash: argsHash}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.State != Approved || got.ArgsHash != argsHash {
			t.Fatalf("опрос: %+v", got)
		}
		if time.Since(start) > 3*time.Second {
			t.Fatalf("опрос не разбужен решением: %v", time.Since(start))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("опрос не завершился")
	}
}

func TestDM22_WaitReturnsPendingAfterWait(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	start := time.Now()
	got, err := e.svc.Wait(context.Background(), gwA, r.ID, 100*time.Millisecond)
	if err != nil || got.State != Pending {
		t.Fatalf("опрос: %+v, %v", got, err)
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 3*time.Second {
		t.Fatalf("длительность опроса: %v", d)
	}
	// wait больше предела ограничивается MaxWait; отмена контекста прерывает опрос.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := e.svc.Wait(ctx, gwA, r.ID, time.Hour); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("отмена опроса: %v", err)
	}
	e.svc.mu.Lock()
	n := len(e.svc.waiters)
	e.svc.mu.Unlock()
	if n != 0 {
		t.Fatalf("подписки опросов не удалены: %d", n)
	}
}

func TestDM22_WaitExpiresOverdue(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	e.clock.add(11 * time.Minute)
	got, err := e.svc.Wait(context.Background(), gwA, r.ID, 0)
	if err != nil || got.State != Timeout || !got.ClosedAt.Equal(r.Deadline) {
		t.Fatalf("просроченный запрос: %+v, %v", got, err)
	}
}

func TestDM22_Cancel(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	got, err := e.svc.Cancel(context.Background(), gwA, r.ID)
	if err != nil || got.State != Cancelled {
		t.Fatalf("отмена: %+v, %v", got, err)
	}
	// Отменённый не одобряется; повторная отмена возвращает состояние.
	if _, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{Approve: true, ArgsHash: argsHash}); !errors.Is(err, ErrClosed) {
		t.Fatalf("решение по отменённому: %v", err)
	}
	if got, err := e.svc.Cancel(context.Background(), gwA, r.ID); err != nil || got.State != Cancelled {
		t.Fatalf("повторная отмена: %+v, %v", got, err)
	}
	// Отмена одобренного не меняет решения.
	r = e.create(t, gwA, input())
	if _, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{Approve: true, ArgsHash: argsHash}); err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.Cancel(context.Background(), gwA, r.ID); err != nil || got.State != Approved {
		t.Fatalf("отмена одобренного: %+v, %v", got, err)
	}
	// Отмена после срока — timeout.
	r = e.create(t, gwA, input())
	e.clock.add(10 * time.Minute)
	if got, err := e.svc.Cancel(context.Background(), gwA, r.ID); err != nil || got.State != Timeout {
		t.Fatalf("отмена после срока: %+v, %v", got, err)
	}
}

func TestDM22_SyncInterrupts(t *testing.T) {
	e := newEnv(t)
	old := e.create(t, gwA, input())
	kept := e.create(t, gwA, input())
	foreign := e.create(t, gwB, input())
	e.clock.add(InterruptGrace + time.Second)
	fresh := e.create(t, gwA, input())
	if err := e.svc.Sync(context.Background(), gwA, []string{kept.ID}, false); err != nil {
		t.Fatal(err)
	}
	want := map[string]State{old.ID: Interrupted, kept.ID: Pending, foreign.ID: Pending, fresh.ID: Pending}
	for id, st := range want {
		if got := e.get(t, id); got.State != st {
			t.Errorf("%s: %s, ожидалось %s", id, got.State, st)
		}
	}
	// Остановка шлюза закрывает все его ожидающие запросы.
	if err := e.svc.Sync(context.Background(), gwA, []string{kept.ID}, true); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{kept.ID, fresh.ID} {
		if got := e.get(t, id); got.State != Interrupted {
			t.Errorf("%s после остановки: %s", id, got.State)
		}
	}
	if got := e.get(t, foreign.ID); got.State != Pending {
		t.Fatalf("запрос другого шлюза: %s", got.State)
	}
}

func TestDM22_SweepExpiresPurgesDeletes(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	pending := e.create(t, gwA, func() CreateInput { in := input(); in.Timeout = MaxTimeout; return in }())
	e.clock.add(10 * time.Minute)
	if err := e.svc.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := e.get(t, r.ID)
	if got.State != Timeout || got.Args == nil {
		t.Fatalf("после срока: %+v", got)
	}
	if got := e.get(t, pending.ID); got.State != Pending {
		t.Fatalf("ожидающий закрыт: %s", got.State)
	}
	if _, err := e.svc.Cancel(context.Background(), gwA, pending.ID); err != nil {
		t.Fatal(err)
	}
	// Через 30 суток после закрытия аргументы удаляются, запрос остаётся.
	e.clock.add(ArgsRetention + time.Second)
	if err := e.svc.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	got = e.get(t, r.ID)
	if got.Args != nil {
		t.Fatal("аргументы не удалены через 30 суток")
	}
	if args, err := e.svc.Args(context.Background(), got); args != nil || err != nil {
		t.Fatalf("удалённые аргументы: %q, %v", args, err)
	}
	// Через срок метаданных удаляется и запрос.
	e.clock.add(DefaultMetadataDays * 24 * time.Hour)
	if err := e.svc.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Get(context.Background(), r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("запрос не удалён: %v", err)
	}
}

func TestDM22_SweepMetadataNotShorterThanArgs(t *testing.T) {
	e := newEnv(t)
	e.svc.metadata = func(context.Context) (int, error) { return 1, nil }
	r := e.create(t, gwA, input())
	if _, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{}); err != nil {
		t.Fatal(err)
	}
	e.clock.add(10 * 24 * time.Hour)
	if err := e.svc.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.Get(context.Background(), r.ID); err != nil || got.Args == nil {
		t.Fatalf("запрос удалён раньше аргументов: %+v, %v", got, err)
	}
	boom := errors.New("нет настроек")
	e.svc.metadata = func(context.Context) (int, error) { return 0, boom }
	if err := e.svc.Sweep(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("ошибка срока: %v", err)
	}
}

func TestDM22_ListFilterAndPage(t *testing.T) {
	e := newEnv(t)
	var ids []string
	for i := range 5 {
		in := input()
		if i%2 == 1 {
			in.App = "hr"
		}
		ids = append(ids, e.create(t, gwA, in).ID)
		e.clock.add(time.Second)
	}
	if _, err := e.svc.Decide(context.Background(), e.by, ids[0], DecideInput{}); err != nil {
		t.Fatal(err)
	}
	list, err := e.svc.List(context.Background(), Filter{Limit: 2})
	if err != nil || len(list) != 2 || list[0].ID != ids[4] || list[1].ID != ids[3] {
		t.Fatalf("первая страница: %v", err)
	}
	next, err := e.svc.List(context.Background(), Filter{Limit: 10, AfterTime: list[1].CreatedAt, AfterID: list[1].ID})
	if err != nil || len(next) != 3 || next[0].ID != ids[2] {
		t.Fatalf("вторая страница: %d, %v", len(next), err)
	}
	if l := e.list(t, Filter{App: "hr"}); len(l) != 2 {
		t.Fatalf("по приложению: %d", len(l))
	}
	if l := e.list(t, Filter{State: Pending}); len(l) != 4 {
		t.Fatalf("ожидающие: %d", len(l))
	}
	if l := e.list(t, Filter{Agent: "nobody"}); len(l) != 0 {
		t.Fatalf("по агенту: %d", len(l))
	}
}

// Гонка решений: из параллельных одобрения и отказа побеждает одно.
func TestDM22_ConcurrentDecisions(t *testing.T) {
	e := newEnv(t)
	r := e.create(t, gwA, input())
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.svc.Decide(context.Background(), e.by, r.ID, DecideInput{Approve: i%2 == 0, ArgsHash: argsHash})
			if err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			} else if !errors.Is(err, ErrClosed) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := len(actions(e.mem, "agent.approval.approve")) + len(actions(e.mem, "agent.approval.deny")); ok != 1 || n != 1 {
		t.Fatalf("решений: %d, записей: %d", ok, n)
	}
}

func details(r audit.Entry) map[string]any {
	d, _ := r.Details.(map[string]any)
	return d
}

func (e *env) get(t *testing.T, id string) Request {
	t.Helper()
	r, err := e.svc.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *env) list(t *testing.T, f Filter) []Request {
	t.Helper()
	l, err := e.svc.List(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
