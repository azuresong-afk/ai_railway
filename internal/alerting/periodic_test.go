package alerting

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// detection — событие с находкой серьёзности sev от пользователя user.
func (e *env) detection(t *testing.T, app, user, sev string) *events.Event {
	t.Helper()
	ev := e.event(t, app, "gigachat", "redact")
	ev.User = user
	ev.Decision.Severity = sev
	ev.Threats = []string{"DM-03"}
	return ev
}

// quotaReject — запрос, отклонённый квотой шлюза (DM-36).
func (e *env) quotaReject(t *testing.T, app string) *events.Event {
	t.Helper()
	ev := e.event(t, app, "gigachat", "block", "DM-36")
	ev.Decision = &events.Decision{Action: "block", Rule: "quota.requests_per_minute"}
	ev.Content = nil
	return ev
}

func (e *env) periodic(t *testing.T, loc *time.Location, usage ...BudgetUsage) PeriodicResult {
	t.Helper()
	res, err := e.mem.Periodic(context.Background(), loc, usage)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func repeat[T any](n int, f func() T) []T {
	out := make([]T, n)
	for i := range out {
		out[i] = f()
	}
	return out
}

// DM-16: серия срабатываний от одного пользователя — оповещение по
// правилу «частота» ровно на пороге (10 за 10 минут), отдельно по каждому
// пользователю; без новых событий проход ничего не добавляет, новые события
// в окне дополняют открытое оповещение, события вне окна не считаются.
func TestDM16_ProbingSeriesAlert(t *testing.T) {
	e := newEnv(t)
	d := func() *events.Event { return e.detection(t, "crm-bot", "u-attacker", "medium") }
	e.ingest(t, repeat(9, d)...)
	e.ingest(t, e.detection(t, "crm-bot", "u-quiet", "low"), e.detection(t, "crm-bot", "u-quiet", "low"))
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinProbingSeries); len(got) != 0 {
		t.Fatalf("9 событий из 10 — оповещение: %+v", got)
	}
	e.tick(time.Minute)
	e.ingest(t, d())
	e.ingest(t, repeat(10, func() *events.Event { return e.detection(t, "hr-bot", "u-other", "critical") })...)
	e.tick(time.Minute)
	res := e.periodic(t, nil)
	got := e.alerts(t, BuiltinProbingSeries)
	if len(got) != 2 || res.Triggers != 2 {
		t.Fatalf("ожидалось 2 оповещения: %+v %+v", got, res)
	}
	var a Alert
	for _, x := range got {
		if x.Values["user"] == "u-attacker" {
			a = x
		}
	}
	if a.Count != 10 || a.Kind != KindFrequency || a.Severity != "high" ||
		a.Title != "Серия срабатываний от одного пользователя — crm-bot, u-attacker" || a.Details["events_in_window"] != int64(10) {
		t.Fatalf("оповещение: %+v", a)
	}
	card, err := e.svc.Alert(context.Background(), a.ID)
	if err != nil || len(card.Events) != 10 {
		t.Fatalf("ссылки на события: %d %v", len(card.Events), err)
	}
	if s := fmt.Sprintf("%+v", card); strings.Contains(s, "Игнорируй") {
		t.Fatalf("содержимое запроса в оповещении: %s", s)
	}
	if !slices.Contains(e.mem.Enqueued(), a.ID) {
		t.Fatal("новое оповещение не поставлено в очередь доставки")
	}
	// Без новых событий — без изменений.
	e.tick(time.Minute)
	e.periodic(t, nil)
	if c, err := e.svc.Alert(context.Background(), a.ID); err != nil || c.Alert.Count != 10 {
		t.Fatalf("повторный проход изменил счёт: %d", c.Alert.Count)
	}
	// Ещё два события в окне — то же оповещение, счёт +2, в очередь не идёт.
	queued := len(e.mem.Enqueued())
	e.ingest(t, d(), d())
	e.tick(time.Minute)
	e.periodic(t, nil)
	if c, err := e.svc.Alert(context.Background(), a.ID); err != nil || c.Alert.Count != 12 || len(e.alerts(t, BuiltinProbingSeries)) != 2 {
		t.Fatalf("дополнение открытого: %+v", c.Alert)
	}
	if len(e.mem.Enqueued()) != queued {
		t.Fatal("дополнение открытого оповещения поставлено в очередь")
	}
	// Через 11 минут прежние события вне окна: 9 новых порога не дают.
	e.tick(11 * time.Minute)
	e.ingest(t, repeat(9, d)...)
	e.tick(time.Minute)
	e.periodic(t, nil)
	if c, err := e.svc.Alert(context.Background(), a.ID); err != nil || c.Alert.Count != 12 {
		t.Fatalf("события вне окна учтены: %d", c.Alert.Count)
	}
	// Сбой прохода — повтор не удваивает оповещение.
	e.mem.Err = errors.New("сбой СУБД")
	if _, err := e.mem.Periodic(context.Background(), nil, nil); err == nil {
		t.Fatal("ожидался сбой")
	}
	e.ingest(t, d())
	e.tick(time.Minute)
	e.periodic(t, nil)
	e.periodic(t, nil)
	if c, err := e.svc.Alert(context.Background(), a.ID); err != nil || c.Alert.Count != 22 || len(e.alerts(t, BuiltinProbingSeries)) != 2 {
		t.Fatalf("после сбоя: %+v", c.Alert)
	}
}

// DM-36: серия отказов по квотам — правило «частота» по угрозе DM-36 с
// действием block (20 за 10 минут на приложение).
func TestDM36_QuotaAlert(t *testing.T) {
	e := newEnv(t)
	q := func() *events.Event { return e.quotaReject(t, "crm-bot") }
	e.ingest(t, repeat(19, q)...)
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinQuotaExceeded); len(got) != 0 {
		t.Fatalf("19 отказов — оповещение: %+v", got)
	}
	e.ingest(t, q())
	e.periodic(t, nil)
	got := e.alerts(t, BuiltinQuotaExceeded)
	if len(got) != 1 || got[0].Values["app"] != "crm-bot" || got[0].Count != 20 || got[0].Title != "Серия отказов по квотам — crm-bot" {
		t.Fatalf("отказы по квотам: %+v", got)
	}
}

// history — минутные агрегаты: в каждый час [from, to) volume запросов и
// токенов ответов, одной точкой в начале часа.
func history(app string, from, to time.Time, volume float64) []Activity {
	var out []Activity
	for h := from.Truncate(time.Hour); h.Before(to); h = h.Add(time.Hour) {
		out = append(out, Activity{Bucket: h, App: app, Requests: volume, CompletionTokens: volume * 1000})
	}
	return out
}

// spread — volume за последний час окна аномалии, равными долями по минутам.
func spread(app string, now time.Time, volume float64) []Activity {
	end := now.Truncate(time.Minute).Add(-AnomalyLag)
	var out []Activity
	for m := end.Add(-AnomalyWindow); m.Before(end); m = m.Add(time.Minute) {
		out = append(out, Activity{Bucket: m, App: app, Requests: volume / 60, CompletionTokens: volume * 1000 / 60})
	}
	return out
}

// DM-36: резкий рост запросов — объём за час не меньше трёх медиан того же
// часа недели и не меньше наименьшего объёма; ниже порога, малое
// приложение и приложение на обучении — без оповещения.
func TestDM36_ActivitySpike(t *testing.T) {
	e := newEnv(t)
	now := e.clock.t
	weekAgo3 := now.Add(-22 * 24 * time.Hour)
	e.mem.AddActivity(history("crm-bot", weekAgo3, now.Add(-2*time.Hour), 100)...)
	e.mem.AddActivity(history("tiny", weekAgo3, now.Add(-2*time.Hour), 10)...)
	e.mem.AddActivity(history("fresh", now.Add(-10*24*time.Hour), now.Add(-2*time.Hour), 10)...)
	e.mem.AddActivity(spread("crm-bot", now, 240)...)
	e.mem.AddActivity(spread("tiny", now, 90)...)
	e.mem.AddActivity(spread("fresh", now, 5000)...)
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinActivitySpike); len(got) != 0 {
		t.Fatalf("ниже порога — оповещение: %+v", got)
	}
	r, st, ok, err := e.svc.RuleState(context.Background(), e.rule(t, BuiltinActivitySpike).ID)
	if err != nil || !ok || st.Learning || r.Kind != KindAnomaly {
		t.Fatalf("состояние: %+v %v %v", st, ok, err)
	}
	keys := map[string]KeyState{}
	for _, k := range st.Keys {
		keys[k.Group["app"]] = k
	}
	if k := keys["crm-bot"]; k.Learning || k.Samples != 3 || k.Baseline < 99.9 || k.Baseline > 100.1 || k.Triggered {
		t.Fatalf("crm-bot: %+v", k)
	}
	if k := keys["fresh"]; !k.Learning || k.ReadyAt == nil || k.Triggered {
		t.Fatalf("fresh на обучении: %+v", k)
	}
	// Ровно три медианы — порог.
	e.mem.AddActivity(spread("crm-bot", now, 60)...)
	e.periodic(t, nil)
	got := e.alerts(t, BuiltinActivitySpike)
	if len(got) != 1 || got[0].Values["app"] != "crm-bot" || got[0].Severity != "medium" ||
		got[0].Title != "Резкий рост запросов приложения — crm-bot" {
		t.Fatalf("рост запросов: %+v", got)
	}
	if got[0].Details["metric"] != MetricRequests || got[0].Details["baseline_weeks"] != 3 {
		t.Fatalf("подробности: %+v", got[0].Details)
	}
}

// DM-17: аномальный объём ответов модели (токены ответов) — правило
// «аномалия» по метрике completion_tokens.
func TestDM17_ExtractionVolumeAnomaly(t *testing.T) {
	e := newEnv(t)
	now := e.clock.t
	e.mem.AddActivity(history("rag-bot", now.Add(-28*24*time.Hour), now.Add(-2*time.Hour), 100)...)
	e.mem.AddActivity(spread("rag-bot", now, 200)...)
	// Запросов вдвое больше обычного, но токенов ответов — в 50 раз.
	e.mem.AddActivity(Activity{Bucket: now.Add(-30 * time.Minute), App: "rag-bot", CompletionTokens: 4_800_000})
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinActivitySpike); len(got) != 0 {
		t.Fatalf("рост запросов вдвое — оповещение: %+v", got)
	}
	got := e.alerts(t, BuiltinExtractionVolume)
	if len(got) != 1 || got[0].Values["app"] != "rag-bot" || got[0].Severity != "high" || got[0].Kind != KindAnomaly {
		t.Fatalf("объём ответов: %+v", got)
	}
	// Повторный проход дополняет открытое оповещение, нового нет.
	e.tick(time.Minute)
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinExtractionVolume); len(got) != 1 || got[0].Count != 2 {
		t.Fatalf("повтор: %+v", got)
	}
}

// Пустая история: правило «аномалия» молчит, состояние показывает обучение.
func TestAnomalyEmptyHistory(t *testing.T) {
	e := newEnv(t)
	e.mem.AddActivity(spread("crm-bot", e.clock.t, 100000)...)
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinActivitySpike); len(got) != 0 {
		t.Fatalf("без истории — оповещение: %+v", got)
	}
	_, st, ok, err := e.svc.RuleState(context.Background(), e.rule(t, BuiltinActivitySpike).ID)
	if err != nil || !ok || !st.Learning || st.LearningUntil == nil || len(st.Keys) != 1 || !st.Keys[0].Learning {
		t.Fatalf("состояние: %+v %v %v", st, ok, err)
	}
	want := e.clock.t.Add(-AnomalyLag - AnomalyWindow).Truncate(time.Hour).Add(LearningPeriod + AnomalyWindow)
	if !st.LearningUntil.Equal(want) {
		t.Fatalf("конец обучения %v, ожидалось %v", st.LearningUntil, want)
	}
	// Совсем без данных — обучение без ключей.
	e2 := newEnv(t)
	e2.periodic(t, nil)
	_, st, ok, err = e2.svc.RuleState(context.Background(), e2.rule(t, BuiltinActivitySpike).ID)
	if err != nil || !ok || !st.Learning || len(st.Keys) != 0 {
		t.Fatalf("пустое состояние: %+v %v %v", st, ok, err)
	}
	// У правила «порог» состояния фоновой задачи нет.
	if _, _, ok, err := e2.svc.RuleState(context.Background(), e2.rule(t, BuiltinInjectionBlocked).ID); ok || err != nil {
		t.Fatalf("состояние порога: %v %v", ok, err)
	}
}

// Перевод часов в поясе установки: неделя назад — тот же час на часах
// (Europe/Berlin, конец летнего времени 25.10.2026). По 168 часам UTC окна
// двух прошлых недель попали бы на соседний час, медиана упала бы вдвое и
// обычный объём дал бы ложное оповещение.
func TestAnomalyBaselineAcrossDST(t *testing.T) {
	berlin, err := bundle.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	// Переход на зимнее (25.10.2026) и на летнее время (29.03.2026).
	for _, day := range []time.Time{time.Date(2026, 11, 2, 0, 0, 0, 0, berlin), time.Date(2026, 4, 6, 0, 0, 0, 0, berlin)} {
		t.Run(day.Format("2006-01-02"), func(t *testing.T) {
			e := newEnv(t)
			e.clock.t = day.Add(10*time.Hour + 32*time.Minute).UTC()
			// История: каждый день по 100 запросов в 9 и 10 часов по Берлину.
			var hist []Activity
			for d := 1; d <= 22; d++ {
				prev := day.AddDate(0, 0, -d)
				for _, h := range []int{9, 10} {
					at := time.Date(prev.Year(), prev.Month(), prev.Day(), h, 0, 0, 0, berlin)
					hist = append(hist, Activity{Bucket: at.UTC(), App: "crm-bot", Requests: 100})
				}
			}
			e.mem.AddActivity(hist...)
			e.mem.AddActivity(spread("crm-bot", e.clock.t, 150)...)
			e.periodic(t, berlin)
			if got := e.alerts(t, BuiltinActivitySpike); len(got) != 0 {
				t.Fatalf("ложное оповещение после перевода часов: %+v", got)
			}
			_, st, _, err := e.svc.RuleState(context.Background(), e.rule(t, BuiltinActivitySpike).ID)
			if err != nil || len(st.Keys) != 1 || st.Keys[0].Baseline < 99.9 || st.Keys[0].Baseline > 100.1 {
				t.Fatalf("базовая линия: %+v %v", st.Keys, err)
			}
			// Тот же расчёт по UTC: окна двух недель до перевода — на час
			// в стороне по местным часам, медиана 50 и ложное оповещение.
			e.periodic(t, time.UTC)
			if got := e.alerts(t, BuiltinActivitySpike); len(got) != 1 {
				t.Fatalf("контроль по UTC: %+v", got)
			}
		})
	}
}

// Изменение условия или группировки «частоты» сбрасывает её счётчики:
// события, учтённые по старому условию, не дают срабатывания по новому
// (3В11 ревью 3.12); изменение получателей счётчики сохраняет.
func TestFrequencyCountsResetOnRuleChange(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	b := e.rule(t, BuiltinProbingSeries)
	e.ingest(t, repeat(9, func() *events.Event { return e.detection(t, "crm-bot", "u-1", "medium") })...)
	in := RuleInput{Name: b.Name, Description: b.Description, Severity: b.Severity, GroupBy: b.GroupBy,
		Condition: b.Condition, SuppressMinutes: &b.SuppressMinutes,
		Recipients: Recipients{Roles: []string{"analyst"}, Users: []string{}}, Version: b.Version}
	r, err := e.svc.UpdateRule(ctx, e.admin, b.ID, in)
	if err != nil {
		t.Fatal(err)
	}
	e.ingest(t, e.detection(t, "crm-bot", "u-1", "medium"))
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinProbingSeries); len(got) != 1 || got[0].Count != 10 {
		t.Fatalf("смена получателей сбросила счётчики: %+v", got)
	}
	e.tick(time.Minute)
	e.ingest(t, repeat(9, func() *events.Event { return e.detection(t, "hr-bot", "u-2", "high") })...)
	in.Version, in.Condition.MinSeverity = r.Version, "high"
	if _, err := e.svc.UpdateRule(ctx, e.admin, b.ID, in); err != nil {
		t.Fatal(err)
	}
	e.ingest(t, e.detection(t, "hr-bot", "u-2", "high"))
	e.periodic(t, nil)
	for _, a := range e.alerts(t, BuiltinProbingSeries) {
		if a.Values["user"] == "u-2" {
			t.Fatalf("старые счётчики по новому условию: %+v", a)
		}
	}
}

// Окно «частоты» — ровно W минут, включая текущую (3Н8 ревью 3.12):
// событие W минут назад уже вне окна, W−1 — в окне.
func TestFrequencyWindowBoundary(t *testing.T) {
	e := newEnv(t)
	e.clock.t = e.clock.t.Truncate(time.Minute).Add(30 * time.Second)
	d := func() *events.Event { return e.detection(t, "crm-bot", "u-edge", "medium") }
	e.ingest(t, d()) // через 10 минут — вне окна
	e.tick(time.Minute)
	e.ingest(t, repeat(8, d)...)
	e.tick(9 * time.Minute)
	e.ingest(t, d())
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinProbingSeries); len(got) != 0 {
		t.Fatalf("событие на границе окна учтено: %+v", got)
	}
	e.ingest(t, d())
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinProbingSeries); len(got) != 1 || got[0].Count != 10 {
		t.Fatalf("10 событий за 10 минут: %+v", got)
	}
}

// DM-15: бюджет — оповещение при 80 % и 100 % месячного бюджета, одно на
// порог в месяц: повтор, закрытие и окно подавления нового не дают; в
// новом месяце (по поясу установки) пороги отсчитываются заново.
func TestDM15_BudgetAlerts(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	msk, err := bundle.LoadLocation("Europe/Moscow")
	if err != nil {
		t.Fatal(err)
	}
	e.clock.t = time.Date(2026, 10, 31, 18, 30, 0, 0, time.UTC)
	oct := bundle.Month(e.clock.t, msk)
	u := func(pct int64, month string) BudgetUsage {
		return BudgetUsage{AppID: "01900000-0000-7000-8000-00000000ab01", App: "crm-bot", Month: month, Mode: "soft",
			Percent: pct, Exhausted: pct >= 100}
	}
	e.periodic(t, msk, u(79, oct))
	if got := e.alerts(t, BuiltinBudget); len(got) != 0 {
		t.Fatalf("79 %% — оповещение: %+v", got)
	}
	e.periodic(t, msk, u(80, oct))
	got := e.alerts(t, BuiltinBudget)
	if len(got) != 1 || got[0].Values["threshold"] != "80 %" || got[0].Values["month"] != "2026-10" ||
		got[0].Title != "Расход бюджета приложения — crm-bot, 2026-10, 80 %" || got[0].Kind != KindBudget {
		t.Fatalf("80 %%: %+v", got)
	}
	if !slices.Contains(e.mem.Enqueued(), got[0].ID) {
		t.Fatal("оповещение о бюджете не в очереди доставки")
	}
	e.periodic(t, msk, u(85, oct))
	if _, err := e.svc.SetStatus(ctx, e.admin, got[0].ID, StatusClosed, ""); err != nil {
		t.Fatal(err)
	}
	e.tick(2 * time.Hour)
	e.periodic(t, msk, u(90, oct))
	if got := e.alerts(t, BuiltinBudget); len(got) != 1 || got[0].Suppressed != 0 {
		t.Fatalf("повтор порога в месяце: %+v", got)
	}
	// Ровно 100 % — исчерпан.
	e.periodic(t, msk, u(100, oct))
	if got := e.alerts(t, BuiltinBudget); len(got) != 2 || got[0].Values["threshold"] != "100 %" {
		t.Fatalf("100 %%: %+v", got)
	}
	// Смена месяца по Москве: 21:30 UTC 31.10 — уже ноябрь.
	e.clock.t = time.Date(2026, 10, 31, 21, 30, 0, 0, time.UTC)
	nov := bundle.Month(e.clock.t, msk)
	if nov != "2026-11" {
		t.Fatalf("месяц: %s", nov)
	}
	e.periodic(t, msk, u(81, nov))
	got = e.alerts(t, BuiltinBudget)
	if len(got) != 3 || got[0].Values["month"] != "2026-11" || got[0].Values["threshold"] != "80 %" {
		t.Fatalf("новый месяц: %+v", got)
	}
	_, st, ok, err := e.svc.RuleState(ctx, e.rule(t, BuiltinBudget).ID)
	if err != nil || !ok || st.Month != "2026-11" || len(st.Keys) != 1 || st.Keys[0].Current != 81 {
		t.Fatalf("состояние бюджета: %+v %v", st, err)
	}
}

// Новое оповещение любого вида ставится в очередь доставки один раз;
// дополнение открытого — нет.
func TestNewAlertsEnqueued(t *testing.T) {
	e := newEnv(t)
	e.ingest(t, e.event(t, "crm-bot", "m", "block", "DM-01"), e.event(t, "crm-bot", "m", "block", "DM-01"))
	e.ingest(t, e.event(t, "crm-bot", "m", "block", "DM-01"))
	var all []Alert
	for _, k := range []string{BuiltinInjectionBlocked, BuiltinNewModel, BuiltinNewProvider, BuiltinNewRiskyUser} {
		all = append(all, e.alerts(t, k)...)
	}
	q := e.mem.Enqueued()
	if len(all) != 4 || len(q) != 4 {
		t.Fatalf("оповещений %d, в очереди %d", len(all), len(q))
	}
	for _, a := range all {
		if !slices.Contains(q, a.ID) {
			t.Fatalf("не в очереди: %+v", a)
		}
	}
}
