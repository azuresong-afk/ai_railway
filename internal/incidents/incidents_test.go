package incidents_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/incidents"
)

// Инциденты на хранилищах в памяти (задача 3.16 этапа 3): DM-08, автомат
// статусов, повтор из оповещения, хронология, комментарии, инструкции.

const (
	testGateway = "01900000-0000-7000-8000-0000000000a1"
	analystID   = "01900000-0000-7000-8000-0000000000b1"
	otherID     = "01900000-0000-7000-8000-0000000000b2"
)

// clock — управляемые часы: общие для оповещений и инцидентов.
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
	alerts    *alerting.Memory
	alertsSvc *alerting.Service
	store     *incidents.Memory
	svc       *incidents.Service
	ids       *ids.Generator
	clock     *clock
	by        incidents.By
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
	c := &clock{t: time.Now().UTC().Truncate(time.Microsecond)}
	e := &env{alerts: alerting.NewMemory(), ids: ids.NewGenerator(r), clock: c}
	e.alerts.Clock = c.now
	e.alertsSvc, err = alerting.New(alerting.Options{Store: e.alerts, Provider: p, Clock: c.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.alertsSvc.EnsureBuiltins(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.store = incidents.NewMemory(e.alerts, e.ids)
	e.store.Clock = c.now
	e.svc, err = incidents.New(incidents.Options{Store: e.store, Provider: p, Alerts: e.alertsSvc, Clock: c.now,
		UserCheck: func(_ context.Context, id string) error {
			if id == analystID || id == otherID {
				return nil
			}
			return incidents.ErrUserInactive
		}})
	if err != nil {
		t.Fatal(err)
	}
	e.by = incidents.By{Actor: audit.Actor{Type: audit.ActorUser, ID: analystID, Name: "analyst"}, UserID: analystID}
	return e
}

// canary — синтетическое событие: канарейка системного промпта в ответе (DM-08).
func (e *env) canary(t *testing.T, app string) *events.Event {
	t.Helper()
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	return &events.Event{ID: u.String(), Time: u.Time(), Type: events.TypeGatewayRequest, App: app, User: "a1b2c3",
		Provider: "mock", Model: "mock-echo", PolicyMode: events.ModeEnforce,
		Decision: &events.Decision{Action: "block", Rule: "canary", Severity: "critical"}, Threats: []string{"DM-08"},
		Findings: []events.Finding{{Detector: "canary", Version: "1.1.0", Category: "leak", Threat: "DM-08", Score: 1,
			Location: "choices[0].message.content"}}}
}

// injection — событие с инъекцией (DM-01): оповещение без инцидента.
func (e *env) injection(t *testing.T, app string, threat string) *events.Event {
	t.Helper()
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	return &events.Event{ID: u.String(), Time: u.Time(), Type: events.TypeGatewayRequest, App: app, User: "a1b2c3",
		Provider: "mock", Model: "mock-echo", PolicyMode: events.ModeEnforce,
		Decision: &events.Decision{Action: "block", Rule: "injection", Severity: "high"}, Threats: []string{threat},
		Findings: []events.Finding{{Detector: "injection.heuristic", Version: "1.0.0", Category: "leak", Threat: threat, Score: 0.9,
			Location: "messages[0].content"}}}
}

func (e *env) ingest(t *testing.T, evs ...*events.Event) {
	t.Helper()
	if err := e.alerts.IngestWithIncidents(context.Background(), testGateway, evs, e.store); err != nil {
		t.Fatal(err)
	}
}

func (e *env) list(t *testing.T, q incidents.Query) []incidents.Incident {
	t.Helper()
	l, err := e.svc.List(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (e *env) card(t *testing.T, id string) incidents.Card {
	t.Helper()
	c, err := e.svc.Card(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) manual(t *testing.T, title string) incidents.Incident {
	t.Helper()
	inc, created, err := e.svc.Create(context.Background(), e.by, incidents.CreateInput{Title: title, Severity: "high",
		Category: incidents.CategoryOther})
	if err != nil || !created {
		t.Fatalf("создание: %v %v", created, err)
	}
	return inc
}

func (e *env) actions(action string) int {
	n := 0
	for _, r := range append(e.store.Records(), e.alerts.Records()...) {
		if r.Action == action {
			n++
		}
	}
	return n
}

func kinds(c incidents.Card) []string {
	var out []string
	for _, x := range c.Related.Timeline {
		out = append(out, x.Kind)
	}
	return out
}

// DM-08 (инцидент), ТЗ 1.4 S4: канарейка в ответе создаёт оповещение и
// инцидент «утечка системного промпта»; повтор по тому же приложению
// дополняет тот же инцидент (open_key оповещения), другое приложение —
// новый инцидент; DM-08 на входе (эвристика инъекций) инцидента не создаёт.
// Закрытие инцидента закрывает оповещение: повтор в окне подавления
// инцидента не создаёт, после окна — новый оповещение и инцидент.
// Покрывает: DM-08 (инцидент)
func TestDM08_CanaryCreatesIncident(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.ingest(t, e.injection(t, "crm-bot", "DM-08"))
	if l := e.list(t, incidents.Query{}); len(l) != 0 {
		t.Fatalf("DM-08 на входе создал инцидент: %+v", l)
	}
	first := e.canary(t, "crm-bot")
	e.ingest(t, first)
	l := e.list(t, incidents.Query{})
	if len(l) != 1 {
		t.Fatalf("инцидентов после канарейки: %d", len(l))
	}
	inc := l[0]
	if inc.Number != 1 || inc.Source != incidents.SourceAuto || inc.Category != incidents.CategorySystemPromptLeak ||
		inc.Severity != "critical" || inc.Status != incidents.StatusNew || !strings.Contains(inc.Title, "crm-bot") ||
		!inc.ReactionDueAt.Equal(inc.CreatedAt.Add(time.Hour)) || len(inc.Stages) != 4 {
		t.Fatalf("инцидент: %+v", inc)
	}
	c := e.card(t, inc.ID)
	if len(c.Related.Alerts) != 1 || c.Related.Alerts[0].IncidentID != inc.ID || len(c.Related.Events) != 1 ||
		c.Related.Events[0].ID != first.ID || !slices.Equal(kinds(c), []string{incidents.KindCreated, incidents.KindAlertLinked}) {
		t.Fatalf("карточка: %+v", c.Related)
	}
	if e.actions("incident.create") != 1 {
		t.Fatal("нет записи incident.create")
	}
	alertID := c.Related.Alerts[0].ID

	// Повтор по тому же приложению — тот же инцидент; другое приложение — новый.
	e.ingest(t, e.canary(t, "crm-bot"), e.canary(t, "hr-bot"))
	l = e.list(t, incidents.Query{})
	if len(l) != 2 {
		t.Fatalf("инцидентов: %d", len(l))
	}
	c = e.card(t, inc.ID)
	if len(c.Related.Events) != 2 || kinds(c)[len(kinds(c))-1] != incidents.KindAlertTriggered {
		t.Fatalf("повтор не дополнил инцидент: %+v", c.Related)
	}
	if hr := byNumber(l, 2); !strings.Contains(hr.Title, "hr-bot") {
		t.Fatalf("второй инцидент: %+v", hr)
	}

	// Закрытие — с резолюцией, связанные оповещения закрываются.
	if _, err := e.svc.SetStatus(ctx, e.by, inc.ID, incidents.StatusInput{Status: "closed", Resolution: "resolved",
		Comment: "Канарейка сменена"}); err != nil {
		t.Fatal(err)
	}
	a, err := e.alertsSvc.Alert(ctx, alertID)
	if err != nil || a.Alert.Status != alerting.StatusClosed || a.Alert.Open {
		t.Fatalf("оповещение не закрыто с инцидентом: %+v %v", a.Alert, err)
	}
	// Окна подавления у DM-08 нет: утечка сразу после закрытия — новый
	// инцидент, а не только счётчик подавленных.
	e.ingest(t, e.canary(t, "crm-bot"))
	l = e.list(t, incidents.Query{Status: incidents.StatusOpen})
	if n := byNumber(l, 3); len(l) != 2 || n.Source != incidents.SourceAuto || !strings.Contains(n.Title, "crm-bot") {
		t.Fatalf("утечка после закрытия: %+v", l)
	}
}

func byNumber(l []incidents.Incident, n int64) incidents.Incident {
	for _, i := range l {
		if i.Number == n {
			return i
		}
	}
	return incidents.Incident{}
}

// ruleID — ID встроенного правила по ключу.
func (e *env) ruleID(t *testing.T, key string) string {
	t.Helper()
	rules, err := e.alertsSvc.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.BuiltinKey == key {
			return r.ID
		}
	}
	t.Fatalf("нет правила %s", key)
	return ""
}

// ТЗ 5.7: автомат статусов — разрешены только переходы вперёд; закрытый не
// меняется; каждый запрещённый переход — ErrTransition или ErrClosed.
func TestIncidentStatusTransitions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	paths := map[string][]string{
		incidents.StatusNew:        nil,
		incidents.StatusInProgress: {incidents.StatusInProgress},
		incidents.StatusContained:  {incidents.StatusInProgress, incidents.StatusContained},
		incidents.StatusClosed:     {incidents.StatusClosed},
	}
	allowed := map[[2]string]bool{
		{"new", "in_progress"}: true, {"new", "closed"}: true, {"in_progress", "contained"}: true,
		{"in_progress", "closed"}: true, {"contained", "closed"}: true,
	}
	for _, from := range incidents.Statuses() {
		for _, to := range []string{incidents.StatusInProgress, incidents.StatusContained, incidents.StatusClosed} {
			inc := e.manual(t, "Переход "+from+" → "+to)
			for _, st := range paths[from] {
				if _, err := e.svc.SetStatus(ctx, e.by, inc.ID, incidents.StatusInput{Status: st, Resolution: res(st)}); err != nil {
					t.Fatalf("подготовка %s: %v", from, err)
				}
			}
			got, err := e.svc.SetStatus(ctx, e.by, inc.ID, incidents.StatusInput{Status: to, Resolution: res(to)})
			switch {
			case allowed[[2]string{from, to}]:
				if err != nil || got.Status != to {
					t.Errorf("%s → %s: %v", from, to, err)
				}
			case from == incidents.StatusClosed:
				if !errors.Is(err, incidents.ErrClosed) {
					t.Errorf("%s → %s: ожидался ErrClosed, %v", from, to, err)
				}
			default:
				if !errors.Is(err, incidents.ErrTransition) {
					t.Errorf("%s → %s: ожидался ErrTransition, %v", from, to, err)
				}
			}
		}
	}
	// Статус «new» назначить нельзя: это не переход.
	inc := e.manual(t, "Назад")
	var ie *incidents.InputError
	if _, err := e.svc.SetStatus(ctx, e.by, inc.ID, incidents.StatusInput{Status: "new"}); !errors.As(err, &ie) {
		t.Fatalf("status=new: %v", err)
	}
}

func res(status string) string {
	if status == incidents.StatusClosed {
		return incidents.ResolutionFalsePositive
	}
	return ""
}

// Закрытие без резолюции и резолюция без закрытия отклоняются; принятие в
// работу отмечает реакцию и назначает субъекта; закрытый не меняется.
func TestIncidentCloseRequiresResolution(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	inc := e.manual(t, "Резолюция")
	var ie *incidents.InputError
	for _, in := range []incidents.StatusInput{
		{Status: "closed"}, {Status: "closed", Resolution: "fixed"}, {Status: "in_progress", Resolution: "resolved"},
		{Status: "closed", Resolution: "resolved", Comment: strings.Repeat("я", incidents.MaxResolutionComment+1)},
	} {
		if _, err := e.svc.SetStatus(ctx, e.by, inc.ID, in); !errors.As(err, &ie) {
			t.Errorf("%+v: ожидалась ошибка ввода, %v", in, err)
		}
	}
	got, err := e.svc.SetStatus(ctx, e.by, inc.ID, incidents.StatusInput{Status: "in_progress"})
	if err != nil || got.AssigneeID != analystID || got.ReactedAt.IsZero() {
		t.Fatalf("в работу: %+v %v", got, err)
	}
	got, err = e.svc.SetStatus(ctx, e.by, inc.ID, incidents.StatusInput{Status: "closed", Resolution: "risk_accepted", Comment: "Принято"})
	if err != nil || got.Resolution != "risk_accepted" || got.ClosedAt.IsZero() || got.ClosedBy != "user:"+analystID {
		t.Fatalf("закрытие: %+v %v", got, err)
	}
	for _, f := range []func() error{
		func() error {
			_, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: "после закрытия"})
			return err
		},
		func() error {
			_, err := e.svc.CompleteStage(ctx, e.by, inc.ID, "triage", incidents.StageInput{})
			return err
		},
		func() error {
			id := otherID
			_, err := e.svc.Assign(ctx, e.by, inc.ID, incidents.AssignInput{UserID: &id})
			return err
		},
	} {
		if err := f(); !errors.Is(err, incidents.ErrClosed) {
			t.Errorf("изменение закрытого: %v", err)
		}
	}
	if n := e.actions("incident.status_changed"); n != 2 {
		t.Fatalf("записей incident.status_changed: %d", n)
	}
}

// ТЗ 6.3, п. 5: инцидент из оповещения — значения из оповещения, ссылки на
// события, ссылка у оповещения; повтор — тот же инцидент без записей;
// другое оповещение добавляется в существующий инцидент.
func TestIncidentFromAlertRepeatSameIncident(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.ingest(t, e.injection(t, "crm-bot", "DM-01"), e.injection(t, "hr-bot", "DM-01"))
	al, err := e.alertsSvc.Alerts(ctx, alerting.AlertQuery{RuleID: e.ruleID(t, alerting.BuiltinInjectionBlocked)})
	if err != nil || len(al) != 2 {
		t.Fatalf("оповещения: %d %v", len(al), err)
	}
	if l := e.list(t, incidents.Query{}); len(l) != 0 {
		t.Fatal("DM-01 создал инцидент автоматически")
	}
	inc, created, err := e.svc.Create(ctx, e.by, incidents.CreateInput{AlertID: al[0].ID})
	if err != nil || !created {
		t.Fatalf("из оповещения: %v %v", created, err)
	}
	if inc.Title != al[0].Title || inc.Severity != al[0].Severity || inc.Category != incidents.CategoryPromptInjection ||
		inc.Source != incidents.SourceAlert {
		t.Fatalf("значения из оповещения: %+v", inc)
	}
	again, created, err := e.svc.Create(ctx, e.by, incidents.CreateInput{AlertID: al[0].ID, Title: "Другое"})
	if err != nil || created || again.ID != inc.ID {
		t.Fatalf("повтор: %+v %v %v", again, created, err)
	}
	if n := e.actions("incident.create"); n != 1 {
		t.Fatalf("записей incident.create: %d", n)
	}
	if _, _, err := e.svc.Create(ctx, e.by, incidents.CreateInput{AlertID: "01900000-0000-7000-8000-0000000fffff"}); !errors.Is(err, incidents.ErrAlertNotFound) {
		t.Fatalf("нет оповещения: %v", err)
	}
	// Второе оповещение — в тот же инцидент; повтор — без записи; в другой — конфликт.
	if _, created, err := e.svc.LinkAlert(ctx, e.by, inc.ID, incidents.LinkInput{AlertID: al[1].ID}); err != nil || !created {
		t.Fatalf("связь: %v %v", created, err)
	}
	if _, created, err := e.svc.LinkAlert(ctx, e.by, inc.ID, incidents.LinkInput{AlertID: al[1].ID}); err != nil || created {
		t.Fatalf("повтор связи: %v %v", created, err)
	}
	other := e.manual(t, "Другой")
	if _, _, err := e.svc.LinkAlert(ctx, e.by, other.ID, incidents.LinkInput{AlertID: al[1].ID}); !errors.Is(err, incidents.ErrLinked) {
		t.Fatalf("в другой инцидент: %v", err)
	}
	c := e.card(t, inc.ID)
	if len(c.Related.Alerts) != 2 || len(c.Related.Events) != 2 || e.actions("incident.alert_linked") != 1 {
		t.Fatalf("карточка: %+v", c.Related)
	}
}

// Хронология и комментарии только добавляются: каждое действие дописывает
// запись в конец, прежние записи не меняются; правка комментария — новая
// запись, только своего и только последней версии.
func TestIncidentTimelineAppendOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	inc := e.manual(t, "Хронология")
	var prev []incidents.TimelineEntry
	check := func(step string) {
		t.Helper()
		cur := e.card(t, inc.ID).Related.Timeline
		if len(cur) != len(prev)+1 {
			t.Fatalf("%s: записей %d, было %d", step, len(cur), len(prev))
		}
		for i := range prev {
			if cur[i].ID != prev[i].ID || cur[i].Kind != prev[i].Kind || !cur[i].At.Equal(prev[i].At) {
				t.Fatalf("%s: запись %d изменилась", step, i)
			}
		}
		prev = cur
	}
	prev = e.card(t, inc.ID).Related.Timeline
	c1, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: "Первичный разбор"})
	if err != nil {
		t.Fatal(err)
	}
	check("комментарий")
	if _, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: "Исправлено", Replaces: c1.ID}); err != nil {
		t.Fatal(err)
	}
	check("правка")
	if _, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: "Ещё раз", Replaces: c1.ID}); !errors.Is(err, incidents.ErrSuperseded) {
		t.Fatalf("правка старой версии: %v", err)
	}
	other := incidents.By{Actor: audit.Actor{Type: audit.ActorUser, ID: otherID, Name: "other"}, UserID: otherID}
	c3, err := e.svc.AddComment(ctx, other, inc.ID, incidents.CommentInput{Body: "Мнение коллеги"})
	if err != nil {
		t.Fatal(err)
	}
	check("комментарий коллеги")
	if _, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: "Чужой", Replaces: c3.ID}); !errors.Is(err, incidents.ErrNotAuthor) {
		t.Fatalf("правка чужого: %v", err)
	}
	if _, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: "x", Replaces: "01900000-0000-7000-8000-0000000fffff"}); !errors.Is(err, incidents.ErrCommentNotFound) {
		t.Fatalf("правка несуществующего: %v", err)
	}
	var ie *incidents.InputError
	for _, body := range []string{"", "   ", strings.Repeat("я", incidents.MaxComment+1), "a\x00b"} {
		if _, err := e.svc.AddComment(ctx, e.by, inc.ID, incidents.CommentInput{Body: body}); !errors.As(err, &ie) {
			t.Errorf("комментарий %q: %v", body, err)
		}
	}
	if _, err := e.svc.CompleteStage(ctx, e.by, inc.ID, "triage", incidents.StageInput{Note: "Источник — пользователь"}); err != nil {
		t.Fatal(err)
	}
	check("этап")
	if _, err := e.svc.CompleteStage(ctx, e.by, inc.ID, "triage", incidents.StageInput{}); !errors.Is(err, incidents.ErrStageDone) {
		t.Fatalf("повторная отметка: %v", err)
	}
	if _, err := e.svc.CompleteStage(ctx, e.by, inc.ID, "eradication", incidents.StageInput{}); !errors.As(err, &ie) {
		t.Fatalf("этап вне шаблона: %v", err)
	}
	id := otherID
	if _, err := e.svc.Assign(ctx, e.by, inc.ID, incidents.AssignInput{UserID: &id}); err != nil {
		t.Fatal(err)
	}
	check("назначение")
	if _, err := e.svc.Assign(ctx, e.by, inc.ID, incidents.AssignInput{UserID: &id}); err != nil {
		t.Fatal(err)
	}
	prev = prev[:len(prev)-1]
	check("назначение без изменений не пишет запись")
	bad := "01900000-0000-7000-8000-0000000fffff"
	if _, err := e.svc.Assign(ctx, e.by, inc.ID, incidents.AssignInput{UserID: &bad}); !errors.Is(err, incidents.ErrUserInactive) {
		t.Fatalf("неактивный: %v", err)
	}
	c := e.card(t, inc.ID)
	if len(c.Related.Comments) != 3 {
		t.Fatalf("комментариев: %d", len(c.Related.Comments))
	}
	v := incidents.CardViewOf(c, time.Now())
	if !v.Comments[0].Superseded || v.Comments[1].Replaces != c1.ID || v.Stages[1].DoneAt == nil {
		t.Fatalf("представление: %+v", v.Comments)
	}
	if e.actions("incident.comment_added") != 3 || e.actions("incident.stage_completed") != 1 || e.actions("incident.assigned") != 1 {
		t.Fatal("нет записей аудита действий")
	}
}

// Повторное открытие — новый инцидент со ссылкой и событиями прежнего; не
// закрытый не открывается; повтор — тот же новый инцидент.
func TestIncidentReopen(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.ingest(t, e.canary(t, "crm-bot"))
	old := e.list(t, incidents.Query{})[0]
	if _, _, err := e.svc.Create(ctx, e.by, incidents.CreateInput{ReopenOf: old.ID}); !errors.Is(err, incidents.ErrNotClosed) {
		t.Fatalf("открытие незакрытого: %v", err)
	}
	if _, err := e.svc.SetStatus(ctx, e.by, old.ID, incidents.StatusInput{Status: "closed", Resolution: "resolved"}); err != nil {
		t.Fatal(err)
	}
	n, created, err := e.svc.Create(ctx, e.by, incidents.CreateInput{ReopenOf: old.ID})
	if err != nil || !created || n.ReopenedFrom != old.ID || n.Source != incidents.SourceReopen || n.Title != old.Title ||
		n.Category != old.Category || n.Status != incidents.StatusNew || n.Number != old.Number+1 {
		t.Fatalf("повторное открытие: %+v %v %v", n, created, err)
	}
	if again, created, err := e.svc.Create(ctx, e.by, incidents.CreateInput{ReopenOf: old.ID}); err != nil || created || again.ID != n.ID {
		t.Fatalf("повтор: %+v %v %v", again, created, err)
	}
	if c := e.card(t, n.ID); len(c.Related.Events) != 1 {
		t.Fatalf("события прежнего: %+v", c.Related.Events)
	}
	if c := e.card(t, old.ID); kinds(c)[len(kinds(c))-1] != incidents.KindReopened || c.Incident.Status != incidents.StatusClosed {
		t.Fatalf("прежний: %v", kinds(c))
	}
	var ie *incidents.InputError
	if _, _, err := e.svc.Create(ctx, e.by, incidents.CreateInput{ReopenOf: old.ID, AlertID: old.ID}); !errors.As(err, &ie) {
		t.Fatalf("оба источника: %v", err)
	}
}

// Ввод при создании вручную: название, серьёзность и категория обязательны.
func TestIncidentCreateValidation(t *testing.T) {
	e := newEnv(t)
	var ie *incidents.InputError
	for _, in := range []incidents.CreateInput{
		{}, {Title: "x", Severity: "high"}, {Title: "x", Severity: "urgent", Category: "other"},
		{Title: "x", Severity: "high", Category: "phishing"}, {Title: strings.Repeat("я", incidents.MaxTitle+1), Severity: "high", Category: "other"},
		{Title: "a\nb", Severity: "high", Category: "other"}, {AlertID: "not-a-uuid"}, {ReopenOf: "01900000"},
	} {
		if _, _, err := e.svc.Create(context.Background(), e.by, in); !errors.As(err, &ie) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	inc := e.manual(t, "Ручной")
	if inc.Source != incidents.SourceManual || inc.Number != 1 || !inc.ReactionDueAt.Equal(inc.CreatedAt.Add(4*time.Hour)) {
		t.Fatalf("ручной: %+v", inc)
	}
}

// Инструкции по категориям: умолчание из кода (версия 1), правка — новая
// версия с аудитом, устаревшая версия — конфликт, без изменений — без записи.
func TestIncidentInstructions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	list, err := e.svc.Categories(ctx)
	if err != nil || len(list) != len(incidents.Categories()) {
		t.Fatalf("категории: %d %v", len(list), err)
	}
	for _, c := range list {
		if c.Instruction.Version != 1 || !c.Instruction.Default() || c.Instruction.Body == "" {
			t.Errorf("умолчание %s: %+v", c.Category.ID, c.Instruction)
		}
	}
	cat := incidents.CategorySystemPromptLeak
	ins, err := e.svc.SetInstructions(ctx, e.by, cat, incidents.InstructionsInput{Body: "Сменить канарейку.", Version: 1})
	if err != nil || ins.Version != 2 || ins.Default() {
		t.Fatalf("правка: %+v %v", ins, err)
	}
	if _, err := e.svc.SetInstructions(ctx, e.by, cat, incidents.InstructionsInput{Body: "Иначе", Version: 1}); !errors.Is(err, incidents.ErrVersionConflict) {
		t.Fatalf("устаревшая версия: %v", err)
	}
	if same, err := e.svc.SetInstructions(ctx, e.by, cat, incidents.InstructionsInput{Body: "Сменить канарейку.", Version: 2}); err != nil || same.Version != 2 {
		t.Fatalf("без изменений: %+v %v", same, err)
	}
	if _, err := e.svc.SetInstructions(ctx, e.by, "phishing", incidents.InstructionsInput{Body: "x", Version: 1}); !errors.Is(err, incidents.ErrNotFound) {
		t.Fatalf("нет категории: %v", err)
	}
	var ie *incidents.InputError
	if _, err := e.svc.SetInstructions(ctx, e.by, cat, incidents.InstructionsInput{Body: strings.Repeat("я", incidents.MaxInstructions+1), Version: 2}); !errors.As(err, &ie) {
		t.Fatalf("длинная: %v", err)
	}
	if n := e.actions("incident_category.update"); n != 1 {
		t.Fatalf("записей incident_category.update: %d", n)
	}
	e.ingest(t, e.canary(t, "crm-bot"))
	if c := e.card(t, e.list(t, incidents.Query{})[0].ID); c.Instruction.Body != "Сменить канарейку." {
		t.Fatalf("инструкция в карточке: %+v", c.Instruction)
	}
}

// Выгрузка: формат, без содержимого событий, запись data.export.
func TestIncidentExport(t *testing.T) {
	e := newEnv(t)
	e.ingest(t, e.canary(t, "crm-bot"))
	inc := e.list(t, incidents.Query{})[0]
	doc, err := e.svc.Export(context.Background(), e.by, inc.ID)
	if err != nil || doc.Format != incidents.DocumentFormat || doc.Number != inc.Number || len(doc.Events) != 1 || len(doc.Alerts) != 1 {
		t.Fatalf("выгрузка: %+v %v", doc, err)
	}
	var rec audit.Entry
	for _, r := range e.store.Records() {
		if r.Action == "data.export" {
			rec = r
		}
	}
	if rec.Object.Type != "incident" || rec.Object.ID != inc.ID {
		t.Fatalf("data.export: %+v", rec)
	}
	if _, err := e.svc.Export(context.Background(), e.by, "01900000-0000-7000-8000-0000000fffff"); !errors.Is(err, incidents.ErrNotFound) {
		t.Fatalf("нет инцидента: %v", err)
	}
}

// Фильтры списка и срок реакции.
func TestIncidentListFilters(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.manual(t, "Первый")
	e.clock.add(time.Second)
	b := e.manual(t, "Второй")
	if _, err := e.svc.SetStatus(ctx, e.by, a.ID, incidents.StatusInput{Status: "closed", Resolution: "resolved"}); err != nil {
		t.Fatal(err)
	}
	if l := e.list(t, incidents.Query{Status: incidents.StatusOpen}); len(l) != 1 || l[0].ID != b.ID {
		t.Fatalf("open: %+v", l)
	}
	if l := e.list(t, incidents.Query{Status: "closed"}); len(l) != 1 || l[0].ID != a.ID {
		t.Fatalf("closed: %+v", l)
	}
	if l := e.list(t, incidents.Query{AssigneeID: analystID}); len(l) != 1 || l[0].ID != a.ID {
		t.Fatalf("assignee: %+v", l)
	}
	if l := e.list(t, incidents.Query{Limit: 1}); len(l) != 1 || l[0].ID != b.ID {
		t.Fatalf("limit: %+v", l)
	}
	if l := e.list(t, incidents.Query{After: &incidents.Position{CreatedAt: b.CreatedAt, ID: b.ID}}); len(l) != 1 || l[0].ID != a.ID {
		t.Fatalf("after: %+v", l)
	}
	if b.Overdue(b.CreatedAt.Add(3*time.Hour)) || !b.Overdue(b.CreatedAt.Add(5*time.Hour)) {
		t.Fatal("срок реакции высокой серьёзности — 4 часа")
	}
}

// DM-08 (3В18 ревью 3.r2): длинная утечка канарейки заполняет хронологию
// автоматическими записями только до MaxAutoTimeline — у разбора остаётся
// запас на ручные действия, а закрытие проходит всегда; запись о закрытии
// видна в карточке.
func TestDM08_CloseAtTimelineLimit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for range incidents.MaxTimeline + 10 {
		e.ingest(t, e.canary(t, "crm-bot"))
	}
	l := e.list(t, incidents.Query{})
	if len(l) != 1 {
		t.Fatalf("инцидентов: %d", len(l))
	}
	id := l[0].ID
	if n := len(e.card(t, id).Related.Timeline); n != incidents.MaxAutoTimeline {
		t.Fatalf("автоматических записей %d, ожидалось %d", n, incidents.MaxAutoTimeline)
	}
	if _, err := e.svc.AddComment(ctx, e.by, id, incidents.CommentInput{Body: "Канарейка утекает, меняем промпт"}); err != nil {
		t.Fatalf("комментарий у предела: %v", err)
	}
	to := otherID
	if _, err := e.svc.Assign(ctx, e.by, id, incidents.AssignInput{UserID: &to}); err != nil {
		t.Fatalf("назначение у предела: %v", err)
	}
	if _, err := e.svc.SetStatus(ctx, e.by, id, incidents.StatusInput{Status: "closed", Resolution: "resolved",
		Comment: "Канарейка сменена"}); err != nil {
		t.Fatalf("закрытие у предела: %v", err)
	}
	if k := kinds(e.card(t, id)); k[len(k)-1] != incidents.KindStatusChanged {
		t.Fatalf("закрытие не видно в хронологии: %v", k[len(k)-3:])
	}
}
