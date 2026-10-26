package alerting_test

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// rewindJob сдвигает отметку последнего прохода фоновой задачи, чтобы
// следующий проход не был пропущен как повтор той же минуты.
func (e *pgEnv) rewindJob(t *testing.T) {
	t.Helper()
	if _, err := e.owner.Exec(pgCtx(t), `UPDATE alert_job_runs SET ran_at = ran_at - interval '2 minutes'`); err != nil {
		t.Fatal(err)
	}
}

func (e *pgEnv) periodic(t *testing.T) alerting.PeriodicResult {
	t.Helper()
	res, err := e.alerts.Periodic(pgCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Фоновая задача правил на PostgreSQL (задача 3.12): поминутные счётчики
// «частоты» при приёме, «аномалия» по агрегатам событий, «бюджет» по
// расходу; повтор прохода и параллельный экземпляр не удваивают
// оповещения, каждое новое оповещение ставится в очередь доставки той же
// транзакцией, права роли сервера на новые таблицы.
func TestPGPeriodicRules(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	var mu sync.Mutex
	var enqueued []string
	failAt := 0 // номер вызова очереди, который завершится ошибкой; 0 — без сбоев
	e.alerts.SetEnqueue(func(ctx context.Context, tx pgx.Tx, alertID, severity string) (int, error) {
		// Очередь пишет в той же транзакции: она должна быть рабочей.
		if _, err := tx.Exec(ctx, "SELECT 1"); err != nil {
			return 0, err
		}
		mu.Lock()
		defer mu.Unlock()
		enqueued = append(enqueued, alertID)
		if len(enqueued) == failAt {
			return 0, errors.New("сбой очереди доставки")
		}
		return 1, nil
	})
	var usage []alerting.BudgetUsage
	e.alerts.SetBudgetSource(func(context.Context) ([]alerting.BudgetUsage, error) {
		mu.Lock()
		defer mu.Unlock()
		return usage, nil
	})

	// «Частота»: 10 событий серьёзности «высокая» от одного пользователя;
	// повтор пакета счётчики не увеличивает.
	batch := make([]events.Event, 0, 10)
	for range 10 {
		batch = append(batch, e.event(t, "crm-bot", "gigachat", "block", "DM-01"))
	}
	e.ingest(t, batch...)
	e.ingest(t, batch...)
	var counted, pending int64
	if err := e.owner.QueryRow(ctx, `SELECT sum(count), sum(pending) FROM alert_rule_counts WHERE rule_id = $1`,
		e.ruleID(t, alerting.BuiltinProbingSeries)).Scan(&counted, &pending); err != nil || counted != 10 || pending != 10 {
		t.Fatalf("счётчики: %d %d %v", counted, pending, err)
	}

	// «Аномалия»: 22 суток по 10 запросов в час, в последний час — 400.
	now := time.Now().UTC()
	start := now.Add(-22 * 24 * time.Hour).Truncate(time.Hour)
	var hours []time.Time
	for h := start; h.Before(now.Add(-2 * time.Hour)); h = h.Add(time.Hour) {
		hours = append(hours, h)
	}
	if _, err := e.owner.Exec(ctx, `INSERT INTO event_aggregates_hour (org_id, bucket, app, type, action, severity, events,
			with_findings, non_text_unchecked, tokens_prompt, tokens_completion, threats)
		SELECT $1, h, 'crm-bot', 'gateway_request', 'allow', '', 10, 0, 0, 100, 100, '{}' FROM unnest($2::timestamptz[]) AS h`,
		audit.DefaultOrgID, hours); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, `INSERT INTO event_aggregates_minute (org_id, bucket, app, type, action, severity, events,
			with_findings, non_text_unchecked, tokens_prompt, tokens_completion, threats)
		VALUES ($1, $2, 'crm-bot', 'gateway_request', 'allow', '', 400, 0, 0, 100, 100, '{}')`,
		audit.DefaultOrgID, now.Add(-30*time.Minute).Truncate(time.Minute)); err != nil {
		t.Fatal(err)
	}

	// «Бюджет»: 85 % — предупреждение.
	mu.Lock()
	usage = []alerting.BudgetUsage{{AppID: "01900000-0000-7000-8000-0000000000c1", App: "crm-bot", Month: now.Format("2006-01"),
		Mode: "soft", Percent: 85}}
	mu.Unlock()

	// Сбой посреди прохода (очередь доставки на втором оповещении): правило
	// со сбоем откатывается в своей точке сохранения, остальные правила и
	// отметка прохода фиксируются (3В17 ревью 3.r2); следующий проход
	// досчитывает упавшее правило.
	var before int
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FROM alerts`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	base := len(enqueued) // оповещения приёма событий уже в очереди
	failAt = base + 2
	mu.Unlock()
	res, err := e.alerts.Periodic(ctx)
	if err != nil || res.Rules == 0 || res.Triggers != 2 {
		t.Fatalf("сбой одного правила прервал проход: %+v %v", res, err)
	}
	var alertsN, runs, failed int
	if err := e.owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM alerts), (SELECT count(*) FROM alert_job_runs),
		(SELECT count(*) FROM alert_rule_state WHERE state->>'warning' = 'evaluation_failed')`).
		Scan(&alertsN, &runs, &failed); err != nil || alertsN != before+2 || runs != 1 || failed != 1 {
		t.Fatalf("после сбоя правила: оповещений %d из %d, отметок %d, упавших %d, %v", alertsN, before, runs, failed, err)
	}
	mu.Lock()
	failAt = 0
	enqueued = append(enqueued[:base+1], enqueued[base+2:]...) // постановка отката не пережила
	mu.Unlock()
	e.rewindJob(t)
	e.periodic(t)
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FROM alert_rule_state WHERE state->>'warning' = 'evaluation_failed'`).
		Scan(&failed); err != nil || failed != 0 {
		t.Fatalf("предупреждение после успешного прохода: %d %v", failed, err)
	}
	probe := e.list(t, alerting.BuiltinProbingSeries)
	if len(probe) != 1 || probe[0].Count != 10 || probe[0].Values["app"] != "crm-bot" {
		t.Fatalf("частота: %+v", probe)
	}
	card, err := e.svc.Alert(ctx, probe[0].ID)
	if err != nil || len(card.Events) != 10 {
		t.Fatalf("события частоты: %d %v", len(card.Events), err)
	}
	spike := e.list(t, alerting.BuiltinActivitySpike)
	if len(spike) != 1 || spike[0].Values["app"] != "crm-bot" {
		t.Fatalf("аномалия: %+v", spike)
	}
	budget := e.list(t, alerting.BuiltinBudget)
	if len(budget) != 1 || budget[0].Values["threshold"] != "80 %" {
		t.Fatalf("бюджет: %+v", budget)
	}
	_, st, ok, err := e.svc.RuleState(ctx, e.ruleID(t, alerting.BuiltinActivitySpike))
	if err != nil || !ok || st.Learning || len(st.Keys) != 1 || !st.Keys[0].Triggered || math.Abs(st.Keys[0].Baseline-10) > 1e-9 ||
		st.Keys[0].Current != 400 || st.Keys[0].Samples != 3 {
		t.Fatalf("состояние аномалии: %+v %v %v", st, ok, err)
	}
	// Объём ответов ниже наименьшего — без оповещения, ключ не обучается.
	if got := e.list(t, alerting.BuiltinExtractionVolume); len(got) != 0 {
		t.Fatalf("объём ответов: %+v", got)
	}

	var after int
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FROM alerts`).Scan(&after); err != nil || after != before+3 {
		t.Fatalf("после повтора прохода: %d из %d, %v", after, before, err)
	}

	// Повтор в ту же минуту пропускается; после неё — без дублей.
	if res := e.periodic(t); !res.Skipped {
		t.Fatalf("повтор в ту же минуту: %+v", res)
	}
	e.rewindJob(t)
	e.periodic(t)
	if p, b := e.list(t, alerting.BuiltinProbingSeries), e.list(t, alerting.BuiltinBudget); len(p) != 1 || p[0].Count != 10 || len(b) != 1 {
		t.Fatalf("повтор прохода: %+v %+v", p, b)
	}
	// Новые события того же ключа дополняют открытое оповещение ровно на
	// своё число: учтённые раньше не считаются снова (3В10 ревью 3.12).
	more := []events.Event{e.event(t, "crm-bot", "gigachat", "block", "DM-01"), e.event(t, "crm-bot", "gigachat", "block", "DM-01"),
		e.event(t, "crm-bot", "gigachat", "block", "DM-01")}
	e.ingest(t, more...)
	e.rewindJob(t)
	e.periodic(t)
	if p := e.list(t, alerting.BuiltinProbingSeries); len(p) != 1 || p[0].Count != 13 {
		t.Fatalf("дополнение частоты: %+v", p)
	}
	if err := e.owner.QueryRow(ctx, `SELECT sum(pending) FROM alert_rule_counts WHERE rule_id = $1`,
		e.ruleID(t, alerting.BuiltinProbingSeries)).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending после учёта: %d %v", pending, err)
	}

	// Исчерпание бюджета — второй порог; два экземпляра сервера — один проход.
	mu.Lock()
	usage[0].Percent, usage[0].Exhausted = 100, true
	mu.Unlock()
	e.rewindJob(t)
	var wg sync.WaitGroup
	results := make(chan alerting.PeriodicResult, 2)
	for range 2 {
		wg.Go(func() {
			r, err := e.alerts.Periodic(ctx)
			if err != nil {
				t.Error(err)
			}
			results <- r
		})
	}
	wg.Wait()
	close(results)
	ran := 0
	for r := range results {
		if !r.Skipped {
			ran++
		}
	}
	if ran != 1 {
		t.Fatalf("параллельные проходы: выполнено %d", ran)
	}
	if b := e.list(t, alerting.BuiltinBudget); len(b) != 2 {
		t.Fatalf("исчерпание бюджета: %+v", b)
	}

	// Каждое новое оповещение — в очереди доставки, ровно один раз.
	var total int
	if err := e.owner.QueryRow(ctx, `SELECT count(*) FROM alerts`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	seen := map[string]bool{}
	for _, id := range enqueued {
		if seen[id] {
			t.Fatalf("оповещение %s поставлено дважды", id)
		}
		seen[id] = true
	}
	n := len(enqueued)
	mu.Unlock()
	if n != total {
		t.Fatalf("в очереди %d из %d оповещений", n, total)
	}

	// Роль сервера: ключи счётчиков и состояния не меняются.
	if _, err := e.app.Exec(ctx, `UPDATE alert_rule_counts SET group_key = 'x'`); sqlState(err) != "42501" {
		t.Fatalf("изменение ключа счётчика: %v", err)
	}
	if _, err := e.app.Exec(ctx, `UPDATE alert_rule_state SET rule_id = rule_id`); sqlState(err) != "42501" {
		t.Fatalf("изменение правила состояния: %v", err)
	}
	if _, err := e.app.Exec(ctx, `DELETE FROM alert_rule_state`); sqlState(err) != "42501" {
		t.Fatalf("удаление состояния: %v", err)
	}
}
