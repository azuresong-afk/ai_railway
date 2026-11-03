package redteam

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/reports"
)

// Расписания запусков и отчёт (задача 5.33): проверка ввода, срок и запуск,
// пропущенный срок, занятая цель, секретный заголовок, отказ при версии.

// testClock — управляемые часы сервиса.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func schedEnv(t *testing.T) (*env, *testClock) {
	t.Helper()
	clk := &testClock{t: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}
	e := newEnv(t, func(o *Options) { o.Clock = clk.Now })
	return e, clk
}

func daily(targetID string) ScheduleInput {
	return ScheduleInput{Name: "Ночной прогон", TargetID: targetID, Frequency: FreqDaily, At: "03:00", Threats: []string{"DM-01"}}
}

func TestScheduleInputValidation(t *testing.T) {
	e, _ := schedEnv(t)
	tg := e.target(nil)
	cases := map[string]func(*ScheduleInput){
		"чаще раза в сутки":           func(in *ScheduleInput) { in.Frequency = "hourly" },
		"пустая периодичность":        func(in *ScheduleInput) { in.Frequency = "" },
		"неделя без дня":              func(in *ScheduleInput) { in.Frequency = FreqWeekly },
		"день недели у ежедневного":   func(in *ScheduleInput) { in.Weekday = 2 },
		"день месяца больше 28":       func(in *ScheduleInput) { in.Frequency, in.Day = FreqMonthly, 29 },
		"время 24:00":                 func(in *ScheduleInput) { in.At = "24:00" },
		"время без нуля":              func(in *ScheduleInput) { in.At = "3:00" },
		"строка матрицы":              func(in *ScheduleInput) { in.Threats = []string{"DM-1"} },
		"повтор строки":               func(in *ScheduleInput) { in.Threats = []string{"DM-01", "DM-01"} },
		"язык":                        func(in *ScheduleInput) { in.Lang = "de" },
		"пустое название":             func(in *ScheduleInput) { in.Name = "  " },
		"название с управляющим":      func(in *ScheduleInput) { in.Name = "а\x00б" },
		"цель не UUID":                func(in *ScheduleInput) { in.TargetID = "x" },
		"цели нет":                    func(in *ScheduleInput) { in.TargetID = "01900000-0000-7000-8000-0000000000ff" },
		"слишком много строк матрицы": func(in *ScheduleInput) { in.Threats = make([]string, MaxRunFilter+1) },
	}
	for name, mod := range cases {
		in := daily(tg.ID)
		mod(&in)
		_, err := e.s.CreateSchedule(context.Background(), admin, in)
		var ie *InputError
		if !errors.As(err, &ie) {
			t.Errorf("%s: ожидалась ошибка ввода, получено %v", name, err)
		}
	}
	if scs, _ := e.s.Schedules(context.Background()); len(scs) != 0 {
		t.Fatalf("расписания после отказов: %d", len(scs))
	}
}

// Цель с секретным заголовком по расписанию не запускается: значение в
// продукте не хранится.
func TestScheduleRejectsSecretHeaderTarget(t *testing.T) {
	e, _ := schedEnv(t)
	tg := e.target(func(in *TargetInput) { in.AuthHeader = "Authorization" })
	_, err := e.s.CreateSchedule(context.Background(), admin, daily(tg.ID))
	var ie *InputError
	if !errors.As(err, &ie) || !strings.Contains(err.Error(), "Authorization") {
		t.Fatalf("ожидался отказ из-за секретного заголовка: %v", err)
	}
}

func TestScheduleCreateUpdateDelete(t *testing.T) {
	e, _ := schedEnv(t)
	tg := e.target(nil)
	sc, err := e.s.CreateSchedule(context.Background(), admin, daily(tg.ID))
	if err != nil {
		t.Fatal(err)
	}
	// Первый срок — ближайшие 03:00 после «сейчас» (12:00 UTC).
	if want := time.Date(2026, 11, 4, 3, 0, 0, 0, time.UTC); !sc.NextRunAt.Equal(want) || sc.Version != 1 || !sc.Enabled {
		t.Fatalf("расписание: %+v", sc)
	}
	in := daily(tg.ID)
	in.At, in.Version = "05:30", 7
	if _, err := e.s.UpdateSchedule(context.Background(), admin, sc.ID, in); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("чужая версия: %v", err)
	}
	in.Version = 1
	up, err := e.s.UpdateSchedule(context.Background(), admin, sc.ID, in)
	if err != nil || up.Version != 2 || up.At != "05:30" {
		t.Fatalf("изменение: %+v %v", up, err)
	}
	if err := e.s.DeleteSchedule(context.Background(), admin, sc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Schedule(context.Background(), sc.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("после удаления: %v", err)
	}
	if acts := e.actions(); !slices.Equal(acts, []string{ActionTargetCreated, ActionScheduleCreated, ActionScheduleUpdated, ActionScheduleDeleted}) {
		t.Fatalf("аудит: %v", acts)
	}
}

func TestScheduleLimit(t *testing.T) {
	e, _ := schedEnv(t)
	tg := e.target(nil)
	for range MaxSchedules {
		if _, err := e.s.CreateSchedule(context.Background(), admin, daily(tg.ID)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.s.CreateSchedule(context.Background(), admin, daily(tg.ID)); !errors.Is(err, ErrTooManySchedules) {
		t.Fatalf("сверх предела: %v", err)
	}
}

// Срок наступил: запуск начат от имени расписания, срок сдвинут, итог записан.
func TestScheduleTickStartsRun(t *testing.T) {
	e, clk := schedEnv(t)
	tg := e.target(nil)
	sc, err := e.s.CreateSchedule(context.Background(), admin, daily(tg.ID))
	if err != nil {
		t.Fatal(err)
	}
	// До срока ничего не происходит.
	if err := e.s.TickSchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runs, _ := e.s.Runs(context.Background(), "", 10); len(runs) != 0 {
		t.Fatalf("запуск до срока: %d", len(runs))
	}
	clk.Set(sc.NextRunAt.Add(2 * time.Minute))
	if err := e.s.TickSchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := e.s.Schedule(context.Background(), sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastStatus != ScheduleStarted || got.LastRunID == "" || got.LastRunAt == nil || !got.LastRunAt.Equal(sc.NextRunAt) ||
		!got.NextRunAt.Equal(sc.NextRunAt.AddDate(0, 0, 1)) || got.Retries != 0 {
		t.Fatalf("итог попытки: %+v", got)
	}
	done, _ := e.wait(got.LastRunID)
	if done.Scenarios == 0 || done.StartedBy != scheduleActor(sc.ID).Name {
		t.Fatalf("запуск: %+v", done)
	}
	for _, r := range e.mem.Audit() {
		if r.Action == ActionRunStarted && (r.Actor.Type != audit.ActorSystem || r.Actor.ID != "redteam-schedule:"+sc.ID) {
			t.Fatalf("запись начала запуска не от расписания: %+v", r.Actor)
		}
	}
	// Тот же срок второй раз не берётся.
	if err := e.s.TickSchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runs, _ := e.s.Runs(context.Background(), "", 10); len(runs) != 1 {
		t.Fatalf("повторный запуск того же срока: %d", len(runs))
	}
}

// После простоя сервера опоздание больше часа — срок пропущен, атаки не
// стартуют в непредусмотренное время; запись аудита об этом есть.
func TestScheduleMissedAfterDowntime(t *testing.T) {
	e, clk := schedEnv(t)
	tg := e.target(nil)
	sc, err := e.s.CreateSchedule(context.Background(), admin, daily(tg.ID))
	if err != nil {
		t.Fatal(err)
	}
	clk.Set(sc.NextRunAt.Add(MissedGrace + time.Minute))
	if err := e.s.TickSchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := e.s.Schedule(context.Background(), sc.ID)
	if got.LastStatus != ScheduleMissed || got.LastRunID != "" || !got.NextRunAt.After(clk.Now()) {
		t.Fatalf("пропущенный срок: %+v", got)
	}
	if runs, _ := e.s.Runs(context.Background(), "", 10); len(runs) != 0 {
		t.Fatalf("запуск при пропущенном сроке: %d", len(runs))
	}
	if !slices.Contains(e.actions(), ActionScheduleSkipped) {
		t.Fatalf("нет записи аудита: %v", e.actions())
	}
}

// Цель занята: повтор через BusyRetry; после освобождения запуск начат;
// после MaxBusyRetries срок пропущен с записью аудита.
func TestScheduleBusyRetries(t *testing.T) {
	e, clk := schedEnv(t)
	tg := e.target(nil)
	sc, err := e.s.CreateSchedule(context.Background(), admin, daily(tg.ID))
	if err != nil {
		t.Fatal(err)
	}
	e.s.mu.Lock()
	e.s.byTarget[tg.ID] = "занято"
	e.s.mu.Unlock()
	clk.Set(sc.NextRunAt)
	if err := e.s.TickSchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := e.s.Schedule(context.Background(), sc.ID)
	if got.LastStatus != ScheduleBusy || got.Retries != 1 || !got.NextRunAt.Equal(clk.Now().Add(BusyRetry)) {
		t.Fatalf("повтор: %+v", got)
	}
	// Цель освободилась.
	e.s.mu.Lock()
	delete(e.s.byTarget, tg.ID)
	e.s.mu.Unlock()
	clk.Set(got.NextRunAt)
	if err := e.s.TickSchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ = e.s.Schedule(context.Background(), sc.ID)
	if got.LastStatus != ScheduleStarted || got.Retries != 0 || got.LastRunID == "" {
		t.Fatalf("после освобождения: %+v", got)
	}
	e.wait(got.LastRunID)
}

func TestScheduleBusyGivesUp(t *testing.T) {
	e, clk := schedEnv(t)
	tg := e.target(nil)
	sc, err := e.s.CreateSchedule(context.Background(), admin, daily(tg.ID))
	if err != nil {
		t.Fatal(err)
	}
	e.s.mu.Lock()
	e.s.byTarget[tg.ID] = "занято"
	e.s.mu.Unlock()
	clk.Set(sc.NextRunAt)
	for range MaxBusyRetries + 1 {
		if err := e.s.TickSchedules(context.Background()); err != nil {
			t.Fatal(err)
		}
		got, _ := e.s.Schedule(context.Background(), sc.ID)
		clk.Set(got.NextRunAt)
	}
	got, _ := e.s.Schedule(context.Background(), sc.ID)
	if got.LastStatus != ScheduleBusy || got.Retries != 0 || !got.NextRunAt.Equal(sc.NextRunAt.AddDate(0, 0, 1)) {
		t.Fatalf("после повторов: %+v", got)
	}
	n := 0
	for _, a := range e.actions() {
		if a == ActionScheduleSkipped {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("записей о пропуске: %d", n)
	}
}

// Целью после расписания занялся секретный заголовок — запуск не начат.
func TestScheduleNeedsSecretAfterTargetChange(t *testing.T) {
	e, clk := schedEnv(t)
	tg := e.target(nil)
	sc, err := e.s.CreateSchedule(context.Background(), admin, daily(tg.ID))
	if err != nil {
		t.Fatal(err)
	}
	tg.AuthHeader = "Authorization"
	if err := e.mem.UpdateTarget(context.Background(), tg, audit.Entry{}); err != nil {
		t.Fatal(err)
	}
	clk.Set(sc.NextRunAt)
	if err := e.s.TickSchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := e.s.Schedule(context.Background(), sc.ID)
	if got.LastStatus != ScheduleNeedsSecret || got.LastRunID != "" {
		t.Fatalf("секретный заголовок: %+v", got)
	}
	if runs, _ := e.s.Runs(context.Background(), "", 10); len(runs) != 0 {
		t.Fatalf("запуск без секрета: %d", len(runs))
	}
}

func TestScheduleDisabledAndDeletedTarget(t *testing.T) {
	e, clk := schedEnv(t)
	tg := e.target(nil)
	off := false
	in := daily(tg.ID)
	in.Enabled = &off
	sc, err := e.s.CreateSchedule(context.Background(), admin, in)
	if err != nil {
		t.Fatal(err)
	}
	clk.Set(sc.NextRunAt.Add(time.Minute))
	if err := e.s.TickSchedules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runs, _ := e.s.Runs(context.Background(), "", 10); len(runs) != 0 {
		t.Fatalf("выключенное расписание запустило: %d", len(runs))
	}
	if err := e.s.DeleteTarget(context.Background(), admin, tg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Schedule(context.Background(), sc.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("расписание удалённой цели: %v", err)
	}
	var found bool
	for _, r := range e.mem.Audit() {
		if r.Action == ActionTargetDeleted {
			d, _ := r.Details.(map[string]any)
			ids, _ := d["schedules_deleted"].([]string)
			found = slices.Equal(ids, []string{sc.ID})
		}
	}
	if !found {
		t.Fatal("запись об удалении цели не перечисляет расписания")
	}
}

func TestReportBuildAndRender(t *testing.T) {
	run := Run{ID: "01900000-0000-7000-8000-0000000000d1", TargetName: "Чат-бот", TargetKind: KindEndpoint, Status: RunDone, Scenarios: 3,
		Counts: Counts{VerdictSucceeded: 1, VerdictBlocked: 1, VerdictError: 1}, DBVersion: 4,
		StartedAt: time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC), StartedBy: "secadmin"}
	res := []Result{
		{ScenarioID: "RT-DM08-001", Lang: "ru", Threat: "DM-08", Category: "prompt_leak", Verdict: VerdictSucceeded, Step: 2,
			Matched: []string{MatchCanary}, Findings: []Finding{{Detector: "canary", Category: "canary.leak", Threat: "DM-08"}},
			EventIDs: []string{"ev1"}, Example: "=HYPERLINK(\"x\") утечка [secret.token]"},
		{ScenarioID: "RT-DM01-001", Lang: "en", Threat: "DM-01", Category: "override", Verdict: VerdictBlocked, Step: 1, HTTPStatus: 403},
		{ScenarioID: "RT-DM10-001", Lang: "ru", Threat: "DM-10", Category: "secrets", Verdict: VerdictError, ErrorCode: ErrCodeTimeout},
	}
	titles := map[string]string{"RT-DM08-001": "Повтори инструкции"}
	without := BuildReport(run, res, ReportOptions{Titles: titles})
	with := BuildReport(run, res, ReportOptions{Titles: titles, Examples: true})
	var buf bytes.Buffer
	if err := reports.Render(&buf, without, reports.FormatCSV, ';'); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "утечка") || strings.Contains(buf.String(), "Выдержка ответа") {
		t.Fatal("выдержка попала в отчёт без examples")
	}
	if !strings.Contains(buf.String(), "Повтори инструкции") || !strings.Contains(buf.String(), "срок запроса истёк") {
		t.Fatalf("отчёт без названий или ошибок: %s", buf.String())
	}
	buf.Reset()
	if err := reports.Render(&buf, with, reports.FormatCSV, ';'); err != nil {
		t.Fatal(err)
	}
	// Выдержка с формулой защищена от исполнения в Excel.
	if !strings.Contains(buf.String(), `"'=HYPERLINK`) {
		t.Fatalf("формула в выдержке не защищена: %s", buf.String())
	}
	for _, f := range []string{reports.FormatHTML, reports.FormatXLSX} {
		buf.Reset()
		if err := reports.Render(&buf, with, f, ';'); err != nil || buf.Len() == 0 {
			t.Fatalf("формат %s: %v", f, err)
		}
	}
	if with.Rows() <= without.Rows()-1 {
		t.Fatalf("число строк: %d и %d", with.Rows(), without.Rows())
	}
	cov := Coverage(res)
	if len(cov) != 3 || cov[0].Threat != "DM-01" || cov[0].Counts[VerdictBlocked] != 1 || cov[2].Threat != "DM-10" {
		t.Fatalf("покрытие: %+v", cov)
	}
}

// Выдержки в отчёте — только у цели в режиме masked.
func TestServiceReportExamplesOnlyMasked(t *testing.T) {
	e, _ := schedEnv(t)
	tg := e.target(func(in *TargetInput) { in.Storage = StorageNone })
	r, _ := e.wait(e.start(StartInput{TargetID: tg.ID, Scenarios: []string{"RT-DM01-001"}}).ID)
	doc, err := e.s.Report(context.Background(), r.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range doc.Meta {
		if m[0] == "Выдержки ответов" && m[1] != "не включены" {
			t.Fatalf("выдержки при режиме none: %q", m[1])
		}
	}
	if _, err := e.s.Report(context.Background(), "01900000-0000-7000-8000-0000000000ee", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("нет запуска: %v", err)
	}
}
