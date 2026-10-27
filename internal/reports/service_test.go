package reports

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	"github.com/azuresong-afk/ai_railway/internal/notify"
)

const testChannel = "01900000-0000-7000-8000-0000000000aa"

// fakeDash — подмена агрегатов.
type fakeDash struct {
	totals events.DashTotals
	apps   []string
}

func (f *fakeDash) Totals(_ context.Context, q events.DashQuery) (events.DashTotals, error) {
	f.apps = append(f.apps, q.App)
	return f.totals, nil
}
func (f *fakeDash) Latency(context.Context, events.DashQuery) (events.DashLatency, error) {
	return events.DashLatency{Bounds: events.DashLatencyBounds, P95: 250, Total: 10}, nil
}
func (f *fakeDash) TopFindings(_ context.Context, _ events.DashQuery, dim, prefix string, _ int) ([]events.DashTop, error) {
	return []events.DashTop{{Key: dim + prefix + "=DM-01", Value: 7}}, nil
}
func (f *fakeDash) PIIBreakdown(context.Context, events.DashQuery) ([]events.DashPIIRow, error) {
	return []events.DashPIIRow{{Category: "pii.snils", App: "crm", Action: "allow", Findings: 3}, {Category: "pii.snils", App: "crm", Action: "redact", Findings: 5}}, nil
}
func (f *fakeDash) RequestsBy(_ context.Context, _ events.DashQuery, dim string, _ int) ([]events.DashRequestRow, error) {
	return []events.DashRequestRow{{Key: dim, Requests: 7, Cost: 1_234_000}}, nil
}

type fakeIncidents struct{ list []incidents.Incident }

func (f *fakeIncidents) List(_ context.Context, q incidents.Query) ([]incidents.Incident, error) {
	var out []incidents.Incident
	for _, in := range f.list {
		if q.After == nil || in.CreatedAt.Before(q.After.CreatedAt) {
			out = append(out, in)
		}
		if len(out) >= q.Limit {
			break
		}
	}
	return out, nil
}

type fakeAlerts struct{}

func (fakeAlerts) Alerts(_ context.Context, q alerting.AlertQuery) ([]alerting.Alert, error) {
	if q.After != nil {
		return nil, nil
	}
	return []alerting.Alert{{ID: "a1", Severity: "high", CreatedAt: q.From}, {ID: "a2", Severity: "low", CreatedAt: q.From}}, nil
}

type fakeFacts struct {
	marks   MarkStats
	budgets []BudgetLine
}

func (f fakeFacts) Marks(context.Context, time.Time, time.Time, string) (MarkStats, error) {
	return f.marks, nil
}
func (f fakeFacts) Inventory(context.Context) (Inventory, error) {
	return Inventory{Apps: 3, AppsByEnv: map[string]int{"prod": 2, "test": 1}, Providers: 2, ExternalProvs: 1, Gateways: 1,
		ExceptionsActive: 2, ExceptionsExpired: 1}, nil
}
func (f fakeFacts) Budgets(context.Context, string) ([]BudgetLine, error) { return f.budgets, nil }

func newBuilder(now time.Time) (*Builder, *fakeDash, *fakeIncidents) {
	d := &fakeDash{totals: events.DashTotals{Requests: 100, WithFindings: 20, Blocked: 4, WouldBlock: 6, Masked: 5, NonTextUnchecked: 2,
		TokensPrompt: 1000, TokensCompletion: 500, Cost: 12_345_678, UnpricedRequests: 3}}
	inc := &fakeIncidents{}
	return &Builder{Dash: d, Incidents: inc, Alerts: fakeAlerts{}, Now: func() time.Time { return now },
		Facts: fakeFacts{marks: MarkStats{FalsePositive: 5, Confirmed: 2, FalseByThreat: []events.DashTop{{Key: "DM-01", Value: 5}}},
			budgets: []BudgetLine{{App: "crm", Mode: "hard", Limit: "1000.00", Spent: "10.00", Percent: 1}}}}, d, inc
}

func params(t testing.TB, kind, app string) Params {
	t.Helper()
	p, err := NewPeriod("2026-10-01", "2026-10-20", mustLoc(t, "Europe/Moscow"), now2026)
	if err != nil {
		t.Fatal(err)
	}
	return Params{Kind: kind, Format: FormatHTML, Period: p, App: app}
}

func docText(d Doc) string {
	var b strings.Builder
	b.WriteString(d.Title + "\n")
	for _, s := range d.Sections {
		b.WriteString(s.Title + "\n" + s.Note + "\n")
		for _, r := range s.Rows {
			for _, c := range r {
				b.WriteString(c.Text + "|")
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// full — права на все разделы отчёта.
var full = Scope{Budgets: true, Incidents: true, Alerts: true}

func TestBuildSummary(t *testing.T) {
	b, dash, _ := newBuilder(now2026)
	doc, err := b.Build(context.Background(), params(t, KindSummary, ""), full)
	if err != nil {
		t.Fatal(err)
	}
	txt := docText(doc)
	for _, want := range []string{"Запросов проверено|100|", "Оценка стоимости, ₽|1.24|", "250 мс", "Инциденты за период", "Оповещения за период", "Исполнение бюджетов за 2026-10", "crm|жёсткий|1000.00"} {
		if !strings.Contains(txt, want) {
			t.Errorf("нет %q в:\n%s", want, txt)
		}
	}
	// Без прав на бюджеты, инциденты и оповещения — этих разделов нет
	// (budgets.read, incidents.read, alerts.read; 3В31 ревью 3.r4).
	doc, _ = b.Build(context.Background(), params(t, KindSummary, ""), Scope{}) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	if txt := docText(doc); strings.Contains(txt, "Исполнение бюджетов") || strings.Contains(txt, "Инциденты за период") ||
		strings.Contains(txt, "Оповещения за период") || !strings.Contains(txt, "у автора отчёта нет права") {
		t.Errorf("разделы без права:\n%s", txt)
	}
	// По приложению: условие передаётся в агрегаты, инцидентов и бюджетов нет.
	dash.apps = nil
	doc, err = b.Build(context.Background(), params(t, KindSummary, "crm"), Scope{Budgets: true})
	if err != nil {
		t.Fatal(err)
	}
	txt = docText(doc)
	if dash.apps[0] != "crm" || strings.Contains(txt, "Исполнение бюджетов") || strings.Contains(txt, "Оповещения за период") {
		t.Errorf("отчёт по приложению: %v\n%s", dash.apps, txt)
	}
	if doc.Rows() == 0 {
		t.Error("Rows() = 0")
	}
}

func TestBuildIncidentsReport(t *testing.T) {
	b, _, inc := newBuilder(now2026)
	base := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		inc.list = append(inc.list, incidents.Incident{ID: fmt.Sprintf("i%d", 5-i), Number: int64(5 - i), Title: "=cmd|calc", Severity: "high",
			Category: "data_leak", Status: incidents.StatusInProgress, CreatedAt: base.Add(-time.Duration(i) * time.Hour),
			ReactedAt: base.Add(-time.Duration(i)*time.Hour + 30*time.Minute), ReactionDueAt: base.Add(time.Hour)})
	}
	// Вне периода: позже и раньше.
	inc.list = append([]incidents.Incident{{ID: "late", Number: 9, CreatedAt: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)}}, inc.list...)
	inc.list = append(inc.list, incidents.Incident{ID: "old", Number: 0, CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)})
	doc, err := b.Build(context.Background(), params(t, KindIncidents, ""), full)
	if err != nil {
		t.Fatal(err)
	}
	txt := docText(doc)
	if !strings.Contains(txt, "Создано инцидентов|5|") || strings.Contains(txt, "|9|") || !strings.Contains(txt, "30 мин") {
		t.Errorf("инциденты:\n%s", txt)
	}
	// Название с формулой в CSV защищено.
	var buf bytes.Buffer
	if err := WriteCSV(&buf, doc, events.DelimSemicolon); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"'=cmd|calc"`) {
		t.Errorf("CSV инцидентов без защиты: %s", buf.String())
	}
}

func TestBuildPilot(t *testing.T) {
	b, _, inc := newBuilder(now2026)
	inc.list = []incidents.Incident{{ID: "i1", Number: 1, Status: incidents.StatusNew, Severity: "low", CreatedAt: time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)}}
	doc, err := b.Build(context.Background(), params(t, KindPilot, ""), full)
	if err != nil {
		t.Fatal(err)
	}
	txt := docText(doc)
	for _, want := range []string{"Что подключено", "Приложений|3|", "prod — 2, test — 1", "Запросов проверено|100|", "pii.snils|8|3|",
		"25 %", "режиме мониторинга 6 запросов", "Не закрыто инцидентов: 1", "без цены", "истёкшим сроком", "Стоимость по моделям", "Рекомендации"} {
		if !strings.Contains(txt, want) {
			t.Errorf("нет %q в:\n%s", want, txt)
		}
	}
	// Без содержимого запросов: в отчёте нет значений находок — только категории и счётчики.
	if strings.Contains(txt, "000-000-000") {
		t.Error("значения находок в отчёте")
	}
}

func TestBuilderNoSource(t *testing.T) {
	if _, err := (&Builder{}).Build(context.Background(), params(t, KindSummary, ""), Scope{}); !errors.Is(err, ErrNoSource) {
		t.Fatalf("%v", err)
	}
}

// fakeMailer запоминает письма; первые fail вызовов отвечают ошибкой.
type fakeMailer struct {
	mu    sync.Mutex
	mails []notify.ReportMail
	calls int
	fail  int
	err   error
	// cancel — вызывается при отправке: остановка сервера посреди письма.
	cancel func()
}

func (f *fakeMailer) SendReport(_ context.Context, _ string, m notify.ReportMail) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m.Before != nil {
		if err := m.Before([]string{"soc@example.ru", "ciso@example.ru"}); err != nil {
			return err
		}
	}
	f.calls++
	if f.cancel != nil {
		f.cancel()
	}
	if f.calls <= f.fail {
		if f.err != nil {
			return f.err
		}
		return &notify.DeliveryError{Code: notify.ErrCodeDial}
	}
	f.mails = append(f.mails, m)
	return nil
}

type fakeChannels struct{ ch map[string]notify.Channel }

func (f fakeChannels) Channels(context.Context) ([]notify.Channel, error) {
	out := make([]notify.Channel, 0, len(f.ch))
	for _, c := range f.ch {
		out = append(out, c)
	}
	return out, nil
}

func (f fakeChannels) Channel(_ context.Context, id string) (notify.Channel, error) {
	if c, ok := f.ch[id]; ok {
		return c, nil
	}
	return notify.Channel{}, notify.ErrNotFound
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type svcEnv struct {
	svc   *Service
	mem   *Memory
	mail  *fakeMailer
	clock *clock
	inc   *fakeIncidents
}

func newSvc(t *testing.T) *svcEnv {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)}
	b, _, inc := newBuilder(clk.t)
	b.Now = clk.now
	e := &svcEnv{mem: NewMemory(), mail: &fakeMailer{}, clock: clk, inc: inc}
	loc := mustLoc(t, "Europe/Moscow")
	e.svc, err = New(Options{Store: e.mem, Builder: b, Mailer: e.mail, IDs: ids.NewGenerator(r), Now: clk.now,
		Channels: fakeChannels{ch: map[string]notify.Channel{
			testChannel:                            {ID: testChannel, Type: notify.TypeEmail, Enabled: true, Settings: notify.Settings{To: []string{"a@example.org"}}},
			"01900000-0000-7000-8000-0000000000ab": {ID: "01900000-0000-7000-8000-0000000000ab", Type: notify.TypeWebhook, Enabled: true},
			"01900000-0000-7000-8000-0000000000ac": {ID: "01900000-0000-7000-8000-0000000000ac", Type: notify.TypeEmail, Enabled: false},
			"01900000-0000-7000-8000-0000000000ad": {ID: "01900000-0000-7000-8000-0000000000ad", Type: notify.TypeEmail, Enabled: true},
		}},
		Location: func(context.Context) (*time.Location, error) { return loc, nil }, Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

var by = By{Actor: audit.Actor{Type: audit.ActorUser, ID: "u1", Name: "admin"}}

func daily() ScheduleInput {
	return ScheduleInput{Name: "Ежедневный", Report: KindSummary, Frequency: FreqDaily, At: "08:00", Format: FormatXLSX, ChannelID: testChannel}
}

func (e *svcEnv) actions() []string {
	var out []string
	for _, a := range e.mem.Audited() {
		out = append(out, a.Action)
	}
	return out
}

func TestScheduleCRUDAudit(t *testing.T) {
	e := newSvc(t)
	ctx := context.Background()
	s, err := e.svc.CreateSchedule(ctx, by, daily())
	if err != nil {
		t.Fatal(err)
	}
	// Сейчас 12:00 МСК, 08:00 уже прошло — следующий запуск завтра.
	if !s.NextRunAt.Equal(utc(2026, 10, 26, 5, 0)) || s.Version != 1 {
		t.Errorf("создание: %+v", s)
	}
	in := daily()
	in.Version, in.At = 1, "13:00"
	u, err := e.svc.UpdateSchedule(ctx, by, s.ID, in)
	if err != nil || u.Version != 2 || !u.NextRunAt.Equal(utc(2026, 10, 25, 10, 0)) {
		t.Fatalf("изменение: %+v %v", u, err)
	}
	if _, err := e.svc.UpdateSchedule(ctx, by, s.ID, in); !errors.Is(err, ErrVersionConflict) {
		t.Errorf("устаревшая версия: %v", err)
	}
	if _, err := e.svc.UpdateSchedule(ctx, by, "01900000-0000-7000-8000-0000000000ff", in); !errors.Is(err, ErrNotFound) {
		t.Errorf("нет расписания: %v", err)
	}
	if err := e.svc.DeleteSchedule(ctx, by, s.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteSchedule(ctx, by, s.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("повторное удаление: %v", err)
	}
	if got := strings.Join(e.actions(), " "); got != "report_schedule.create report_schedule.update report_schedule.delete" {
		t.Errorf("аудит: %s", got)
	}
	// В аудите — действующее лицо и без секретов/адресов получателей.
	for _, a := range e.mem.Audited() {
		if a.Actor.ID != "u1" || a.Object.Type != "report_schedule" || strings.Contains(fmt.Sprint(a.Details), "example.org") {
			t.Errorf("запись аудита: %+v", a)
		}
	}
}

func TestScheduleChannelChecks(t *testing.T) {
	e := newSvc(t)
	for id, want := range map[string]error{
		"01900000-0000-7000-8000-0000000000ab": ErrChannel,      // webhook
		"01900000-0000-7000-8000-0000000000ac": ErrChannel,      // отключён
		"01900000-0000-7000-8000-0000000000ad": ErrNoRecipients, // нет получателей
		"01900000-0000-7000-8000-0000000000fe": ErrChannel,      // нет такого
	} {
		in := daily()
		in.ChannelID = id
		if _, err := e.svc.CreateSchedule(context.Background(), by, in); !errors.Is(err, want) {
			t.Errorf("%s: %v", id, err)
		}
	}
	if len(e.mem.Audited()) != 0 {
		t.Error("отказ записан в аудит как создание")
	}
}

func TestScheduleLimitAndDuplicate(t *testing.T) {
	e := newSvc(t)
	ctx := context.Background()
	if _, err := e.svc.CreateSchedule(ctx, by, daily()); err != nil {
		t.Fatal(err)
	}
	var ie *InputError
	if _, err := e.svc.CreateSchedule(ctx, by, daily()); !errors.As(err, &ie) || ie.Fields["name"] == "" {
		t.Errorf("повтор названия: %v", err)
	}
	for i := 1; i < MaxSchedules; i++ {
		in := daily()
		in.Name = fmt.Sprintf("Расписание %d", i)
		if _, err := e.svc.CreateSchedule(ctx, by, in); err != nil {
			t.Fatal(err)
		}
	}
	in := daily()
	in.Name = "Лишнее"
	if _, err := e.svc.CreateSchedule(ctx, by, in); !errors.Is(err, ErrTooMany) {
		t.Errorf("предел: %v", err)
	}
}

// Срок наступил: письмо уходит один раз с вложением XLSX, период — вчера;
// повторный опрос ничего не отправляет; в аудите data.export от report-schedule.
func TestTickSendsOnce(t *testing.T) {
	e := newSvc(t)
	ctx := context.Background()
	s, err := e.svc.CreateSchedule(ctx, by, daily())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(ctx); err != nil || len(e.mail.mails) != 0 {
		t.Fatalf("до срока: %v %d", err, len(e.mail.mails))
	}
	e.clock.t = utc(2026, 10, 26, 5, 1)
	if err := e.svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.mail.mails) != 1 {
		t.Fatalf("писем %d", len(e.mail.mails))
	}
	m := e.mail.mails[0]
	if !strings.HasSuffix(m.Filename, "summary-2026-10-25_2026-10-25.xlsx") || m.ContentType != ContentType(FormatXLSX) || !bytes.HasPrefix(m.Data, []byte("PK")) ||
		!strings.Contains(m.Subject, "25.10.2026") {
		t.Errorf("письмо: %+v", m)
	}
	runs, _ := e.svc.Runs(ctx, s.ID, 10) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	if len(runs) != 1 || runs[0].Status != RunSent || runs[0].Attempts != 1 || runs[0].Error != "" {
		t.Errorf("журнал: %+v", runs)
	}
	got, _ := e.svc.Schedule(ctx, s.ID) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	if !got.NextRunAt.Equal(utc(2026, 10, 27, 5, 0)) || !got.LastRunAt.Equal(utc(2026, 10, 26, 5, 0)) {
		t.Errorf("расписание после запуска: next %v last %v", got.NextRunAt, got.LastRunAt)
	}
	var export *audit.Entry
	for _, a := range e.mem.Audited() {
		if a.Action == "data.export" {
			a := a
			export = &a
		}
	}
	if export == nil || export.Actor.Type != audit.ActorSystem || !strings.HasPrefix(export.Actor.ID, "report-schedule:") {
		t.Fatalf("data.export: %+v", export)
	}
	// 3Н47 ревью 3.r4: в записи — адреса получателей этой отправки.
	if to, _ := export.Details.(map[string]any)["recipients"].([]string); !slices.Equal(to, []string{"soc@example.ru", "ciso@example.ru"}) {
		t.Fatalf("получатели в data.export: %v", export.Details)
	}
}

// После простоя несколько пропущенных запусков дают одну рассылку — за
// период последнего запуска.
func TestTickCatchUpOnce(t *testing.T) {
	e := newSvc(t)
	ctx := context.Background()
	if _, err := e.svc.CreateSchedule(ctx, by, daily()); err != nil {
		t.Fatal(err)
	}
	e.clock.t = utc(2026, 11, 5, 9, 0) // 10 суток простоя
	if err := e.svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.mail.mails) != 1 || !strings.Contains(e.mail.mails[0].Filename, "2026-11-04_2026-11-04") {
		t.Fatalf("писем %d: %+v", len(e.mail.mails), e.mail.mails)
	}
	if err := e.svc.Tick(ctx); err != nil || len(e.mail.mails) != 1 {
		t.Fatalf("повторно: %v %d", err, len(e.mail.mails))
	}
}

func TestTickDisabledScheduleSkipped(t *testing.T) {
	e := newSvc(t)
	ctx := context.Background()
	in := daily()
	off := false
	in.Enabled = &off
	if _, err := e.svc.CreateSchedule(ctx, by, in); err != nil {
		t.Fatal(err)
	}
	e.clock.t = utc(2026, 10, 27, 9, 0)
	if err := e.svc.Tick(ctx); err != nil || len(e.mail.mails) != 0 {
		t.Fatalf("%v %d", err, len(e.mail.mails))
	}
}

// Сбой отправки: повторы с задержками 30 с, 2 мин, 8 мин, 10 мин; после
// пятой попытки — report.delivery_failed и статус failed.
func TestTickRetriesThenFails(t *testing.T) {
	e := newSvc(t)
	ctx := context.Background()
	s, _ := e.svc.CreateSchedule(ctx, by, daily()) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	e.mail.fail = 100
	e.clock.t = utc(2026, 10, 26, 5, 1)
	var at []time.Time
	for i := 0; i < 8; i++ {
		if err := e.svc.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		runs, _ := e.svc.Runs(ctx, s.ID, 1) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
		if runs[0].Status == RunPending {
			at = append(at, runs[0].NextAt)
			e.clock.t = runs[0].NextAt
		}
	}
	runs, _ := e.svc.Runs(ctx, s.ID, 1) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	if runs[0].Status != RunFailed || runs[0].Attempts != MaxAttempts || runs[0].Error != "dial" || e.mail.calls != MaxAttempts {
		t.Fatalf("итог: %+v, вызовов %d", runs[0], e.mail.calls)
	}
	if len(at) != 4 || at[0].Sub(utc(2026, 10, 26, 5, 1)) != 30*time.Second || at[1].Sub(at[0]) != 2*time.Minute || at[2].Sub(at[1]) != 8*time.Minute ||
		at[3].Sub(at[2]) != 10*time.Minute {
		t.Errorf("задержки: %v", at)
	}
	// data.export пишется до каждой отправки (3В32 ревью 3.r4).
	if acts := strings.Join(e.actions(), " "); !strings.Contains(acts, "report.delivery_failed") || strings.Count(acts, "data.export") != MaxAttempts {
		t.Errorf("аудит: %v", e.actions())
	}
	// Окончательный отказ не мешает следующему запуску по расписанию.
	e.mail.fail = 0
	e.clock.t = utc(2026, 10, 27, 5, 1)
	if err := e.svc.Tick(ctx); err != nil || len(e.mail.mails) != 1 {
		t.Fatalf("следующий запуск: %v %d", err, len(e.mail.mails))
	}
	// 3Н47 ревью 3.r4: завершённые запуски старше RunRetention удаляются,
	// новые остаются.
	e.mail.fail = 100
	e.clock.t = utc(2026, 10, 26, 5, 1).Add(RunRetention + 23*time.Hour)
	if err := e.svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	runs, _ = e.svc.Runs(ctx, s.ID, 10) //nolint:gosec // G104: ошибка проверена ниже по содержимому
	if len(runs) != 2 || runs[1].Status != RunSent || runs[0].Status != RunPending {
		t.Fatalf("журнал после очистки: %+v", runs)
	}
}

func TestTickRecovers(t *testing.T) {
	e := newSvc(t)
	ctx := context.Background()
	s, _ := e.svc.CreateSchedule(ctx, by, daily()) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	e.mail.fail = 2
	e.clock.t = utc(2026, 10, 26, 5, 1)
	for i := 0; i < 5; i++ {
		_ = e.svc.Tick(ctx)                 //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
		runs, _ := e.svc.Runs(ctx, s.ID, 1) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
		if runs[0].Status == RunPending {
			e.clock.t = runs[0].NextAt
		}
	}
	runs, _ := e.svc.Runs(ctx, s.ID, 1) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	if runs[0].Status != RunSent || runs[0].Attempts != 3 || len(e.mail.mails) != 1 {
		t.Fatalf("%+v %d", runs[0], len(e.mail.mails))
	}
}

func TestTickBuildFailure(t *testing.T) {
	e := newSvc(t)
	ctx := context.Background()
	s, _ := e.svc.CreateSchedule(ctx, by, daily()) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	e.svc.o.Builder.Facts = nil                    // источник пропал
	e.clock.t = utc(2026, 10, 26, 5, 1)
	_ = e.svc.Tick(ctx)                 //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	runs, _ := e.svc.Runs(ctx, s.ID, 1) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	if runs[0].Status != RunPending || runs[0].Error != ErrCodeBuild || e.mail.calls != 0 {
		t.Fatalf("%+v", runs[0])
	}
}

func TestRenderFormats(t *testing.T) {
	var b bytes.Buffer
	for _, f := range []string{FormatHTML, FormatCSV, FormatXLSX} {
		b.Reset()
		if err := Render(&b, sampleDoc(), f, events.DelimSemicolon); err != nil || b.Len() == 0 {
			t.Errorf("%s: %v", f, err)
		}
	}
	if err := Render(&b, sampleDoc(), "pdf", events.DelimSemicolon); err == nil {
		t.Error("pdf принят")
	}
}

// УПД.2 (3В31 ревью 3.r4): «По инцидентам» без права на инциденты не
// строится, «Итоги пилота» — без списка и счётчиков инцидентов.
func TestBuildScopeWithoutIncidents(t *testing.T) {
	b, _, _ := newBuilder(now2026)
	if _, err := b.Build(context.Background(), params(t, KindIncidents, ""), Scope{Budgets: true, Alerts: true}); !errors.Is(err, ErrScope) {
		t.Fatalf("отчёт по инцидентам без права: %v", err)
	}
	doc, err := b.Build(context.Background(), params(t, KindPilot, ""), Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if txt := docText(doc); strings.Contains(txt, "Не закрыто инцидентов") || !strings.Contains(txt, "у автора отчёта нет права") {
		t.Errorf("итоги пилота без права на инциденты:\n%s", txt)
	}
}

// 3В32 ревью 3.r4: без записи data.export письмо не уходит, повторы
// конечны; запуск, взятый в работу и не завершённый (падение сервера во
// время отправки), расходует попытку и после пятой — failed без письма.
func TestTickAuditFailureAndInterruptedRuns(t *testing.T) {
	e := newSvc(t)
	ctx := context.Background()
	sch, err := e.svc.CreateSchedule(ctx, by, daily())
	if err != nil {
		t.Fatal(err)
	}
	e.mem.RecordErr = errors.New("база аудита недоступна")
	e.clock.t = utc(2026, 10, 26, 5, 1)
	for i := 0; i < 8; i++ {
		if err := e.svc.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		e.clock.t = e.clock.t.Add(time.Hour)
	}
	if e.mail.calls != 0 {
		t.Fatalf("письма без записи аудита: %d", e.mail.calls)
	}
	runs, _ := e.svc.Runs(ctx, sch.ID, 10) //nolint:gosec // G104: ошибка проверена ниже по содержимому
	if len(runs) == 0 || runs[len(runs)-1].Status != RunFailed || runs[len(runs)-1].Error != ErrCodeAudit {
		t.Fatalf("запуск при сбое аудита: %+v", runs)
	}

	// Прерванные отправки: сервер останавливается посреди письма, запуск
	// остаётся pending, но каждая попытка засчитана.
	e.mem.RecordErr = nil
	e.clock.t = utc(2026, 10, 28, 5, 1)
	for i := 0; i < MaxAttempts; i++ {
		cctx, cancel := context.WithCancel(ctx)
		e.mail.cancel = cancel
		if err := e.svc.Tick(cctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("прерывание %d: %v", i, err)
		}
		e.clock.t = e.clock.t.Add(runLease)
	}
	e.mail.cancel = nil
	calls := e.mail.calls
	if err := e.svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if e.mail.calls != calls {
		t.Fatal("письмо после исчерпанных попыток")
	}
	if !strings.Contains(strings.Join(e.actions(), " "), "report.delivery_failed") {
		t.Errorf("нет report.delivery_failed: %v", e.actions())
	}
}
