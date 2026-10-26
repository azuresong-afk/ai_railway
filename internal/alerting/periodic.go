package alerting

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
)

// Фоновая задача правил «частота», «аномалия» и «бюджет» (ADR-0020, п. 1;
// решение Р3; задача 3.12): раз в минуту внутри сервера, без cron. Проход —
// одна транзакция: срабатывания, отметка учтённых событий «частоты»,
// пороги бюджета, состояние правил и отметка прохода (alert_job_runs)
// фиксируются вместе. Каждое правило — в своей точке сохранения: сбой
// правила откатывает только его вычисление (3В17 ревью 3.r2), сбой прохода
// (тайм-аут, состояние) — всё; следующий проход повторяет вычисление;
// повтор не удваивает оповещения — ключ дедупликации движка (open_key) и
// отметки в alert_seen. Остановку задачи видно по условию alert_job_stale
// «Состояния системы» (DM-44).

const (
	// PeriodicInterval — период задачи.
	PeriodicInterval = time.Minute
	// PeriodicTimeout — предел одного прохода.
	PeriodicTimeout = 30 * time.Second
	// periodicMinGap — проход не повторяется раньше: второй экземпляр
	// сервера не считает ту же минуту дважды.
	periodicMinGap = 50 * time.Second
	// countRetention — счётчики «частоты» старше наибольшего окна не нужны.
	countRetention = MaxWindowMinutes*time.Minute + time.Hour
)

// periodicOps — действия фоновой задачи в одной транзакции.
type periodicOps interface {
	freqOps
	activityOps
	// frequencyDue — ключи правила «частота», у которых в окне от since не
	// меньше Count событий и есть не учтённые в оповещениях; отметка
	// «учтено» ставится той же транзакцией.
	frequencyDue(ctx context.Context, r *Rule, since time.Time) ([]freqDue, error)
	// saveState — состояние правила для API.
	saveState(ctx context.Context, ruleID string, st RuleState) error
	// pruneCounts удаляет счётчики «частоты» старше before.
	pruneCounts(ctx context.Context, before time.Time) error
	// isolate выполняет fn в точке сохранения: ошибка fn откатывает только
	// её изменения, транзакция прохода остаётся рабочей (3В17 ревью 3.r2).
	isolate(ctx context.Context, fn func() error) error
}

// PeriodicResult — итог прохода.
type PeriodicResult struct {
	// Skipped — проход выполняет другой экземпляр или он был только что.
	Skipped bool
	// Rules — вычисленных правил; Triggers — срабатываний.
	Rules    int
	Triggers int
}

func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// Предупреждения в состоянии правила (RuleState.Warning).
const (
	// WarnEvaluationFailed — вычисление правила в последнем проходе упало
	// и откатано отдельно от остальных правил (3В17 ревью 3.r2); причина —
	// в техническом журнале сервера.
	WarnEvaluationFailed = "evaluation_failed"
	// WarnTimezoneInvalid — часовой пояс установки не распознан, «аномалия»
	// и «бюджет» считаются по UTC (3Н36 ревью 3.r2).
	WarnTimezoneInvalid = "timezone_invalid"
)

// errRuleSkipped — правило пропущено до следующего прохода без
// сохранения состояния (неверное условие, расход бюджетов недоступен).
var errRuleSkipped = errors.New("оповещения: правило пропущено")

// runPeriodic вычисляет включённые правила «частота», «аномалия» и
// «бюджет». usage — расход приложений (budgetErr — его не удалось
// прочитать: правила «бюджет» пропускаются до следующего прохода);
// tzInvalid — пояс установки не распознан, loc — UTC. Каждое правило
// считается в своей точке сохранения (3В17 ревью 3.r2): сбой одного правила
// откатывает только его срабатывания и отмечается в его состоянии, а
// остальные правила и отметка прохода фиксируются. Истечение
// PeriodicTimeout прерывает проход целиком.
func runPeriodic(ctx context.Context, ops periodicOps, now time.Time, loc *time.Location, tzInvalid bool, usage []BudgetUsage,
	budgetErr error, skipped func(error)) (PeriodicResult, error) {
	var res PeriodicResult
	rules, err := ops.activeRules(ctx, KindFrequency, KindAnomaly, KindBudget)
	if err != nil {
		return res, err
	}
	// «Частота» — последней: обнуление pending блокирует строки счётчиков,
	// которые пишет приём событий, до конца прохода (3В10 ревью 3.12).
	slices.SortStableFunc(rules, func(a, b Rule) int {
		return cmpBool(a.Kind == KindFrequency, b.Kind == KindFrequency)
	})
	for i := range rules {
		r := &rules[i]
		var st RuleState
		var n int
		err := ops.isolate(ctx, func() error {
			var err error
			st, n, err = evaluateRule(ctx, ops, r, now, loc, usage, budgetErr)
			return err
		})
		switch {
		case errors.Is(err, errRuleSkipped):
			if skipped != nil {
				skipped(err)
			}
			continue
		case err != nil && ctx.Err() != nil:
			return res, err
		case err != nil:
			if skipped != nil {
				skipped(err)
			}
			st, n = RuleState{EvaluatedAt: now.UTC(), Keys: []KeyState{}, Warning: WarnEvaluationFailed}, 0
		}
		if tzInvalid && st.Warning == "" && r.Kind != KindFrequency {
			st.Warning = WarnTimezoneInvalid
		}
		if err := ops.saveState(ctx, r.ID, st); err != nil {
			return res, err
		}
		res.Triggers += n
		res.Rules++
	}
	return res, ops.pruneCounts(ctx, now.Add(-countRetention))
}

// evaluateRule — вычисление одного правила: состояние и число срабатываний.
func evaluateRule(ctx context.Context, ops periodicOps, r *Rule, now time.Time, loc *time.Location, usage []BudgetUsage,
	budgetErr error) (RuleState, int, error) {
	st := RuleState{EvaluatedAt: now.UTC(), Keys: []KeyState{}}
	switch r.Kind {
	case KindFrequency:
		if _, err := compile(*r); err != nil {
			return st, 0, fmt.Errorf("%w: %w", errRuleSkipped, err)
		}
		due, err := ops.frequencyDue(ctx, r, frequencySince(r, now))
		if err != nil {
			return st, 0, err
		}
		for _, d := range due {
			t := frequencyTrigger(r, d)
			if err := ops.raise(ctx, r, &t); err != nil {
				return st, 0, err
			}
			st.Keys = append(st.Keys, KeyState{Group: d.Values, Current: float64(d.InWindow), Triggered: true})
		}
		trimState(&st)
		return st, len(due), nil
	case KindAnomaly:
		a, err := evaluateAnomaly(ctx, ops, r, now, loc)
		if err != nil {
			return st, 0, err
		}
		slices.SortFunc(a.Triggers, func(x, y Trigger) int { return strings.Compare(x.Key, y.Key) })
		for i := range a.Triggers {
			if err := ops.raise(ctx, r, &a.Triggers[i]); err != nil {
				return st, 0, err
			}
		}
		return a.State, len(a.Triggers), nil
	case KindBudget:
		if budgetErr != nil {
			return st, 0, fmt.Errorf("%w: %w", errRuleSkipped, budgetErr)
		}
		st, n, err := evaluateBudget(ctx, ops, r, slices.Clone(usage))
		if err != nil {
			return st, 0, err
		}
		st.EvaluatedAt = now.UTC()
		st.Learning = false
		return st, n, nil
	}
	return st, 0, nil
}

// Periodic — фоновая задача хранилища (PGStore).
type Periodic interface {
	Periodic(ctx context.Context) (PeriodicResult, error)
}

// RunPeriodic выполняет проход каждые every до отмены ctx. Сбой пишется в
// технический журнал без значений ключей; следующий проход — по расписанию.
func RunPeriodic(ctx context.Context, p Periodic, every time.Duration, logger *slog.Logger) {
	if every <= 0 {
		every = PeriodicInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := p.Periodic(ctx); err != nil && ctx.Err() == nil {
			logger.Error("оповещения: фоновая задача правил не выполнена", "class", "alerting", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
