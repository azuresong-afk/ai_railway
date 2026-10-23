package alerting

import (
	"context"
	"log/slog"
	"slices"
	"time"
)

// Фоновая задача правил «частота», «аномалия» и «бюджет» (ADR-0020, п. 1;
// решение Р3; задача 3.12): раз в минуту внутри сервера, без cron. Проход —
// одна транзакция: срабатывания, отметка учтённых событий «частоты»,
// пороги бюджета, состояние правил и отметка прохода (alert_job_runs)
// фиксируются вместе. Сбой откатывает всё, следующий проход повторяет
// вычисление; повтор не удваивает оповещения — ключ дедупликации движка
// (open_key) и отметки в alert_seen.

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

// runPeriodic вычисляет включённые правила «частота», «аномалия» и
// «бюджет». usage — расход приложений (budgetErr — его не удалось
// прочитать: правила «бюджет» пропускаются до следующего прохода).
func runPeriodic(ctx context.Context, ops periodicOps, now time.Time, loc *time.Location, usage []BudgetUsage,
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
		st := RuleState{EvaluatedAt: now.UTC(), Keys: []KeyState{}}
		switch r.Kind {
		case KindFrequency:
			if _, err := compile(*r); err != nil {
				if skipped != nil {
					skipped(err)
				}
				continue
			}
			due, err := ops.frequencyDue(ctx, r, frequencySince(r, now))
			if err != nil {
				return res, err
			}
			for _, d := range due {
				t := frequencyTrigger(r, d)
				if err := ops.raise(ctx, r, &t); err != nil {
					return res, err
				}
				st.Keys = append(st.Keys, KeyState{Group: d.Values, Current: float64(d.InWindow), Triggered: true})
			}
			res.Triggers += len(due)
			trimState(&st)
		case KindAnomaly:
			a, err := evaluateAnomaly(ctx, ops, r, now, loc)
			if err != nil {
				return res, err
			}
			slices.SortFunc(a.Triggers, func(x, y Trigger) int {
				if x.Key < y.Key {
					return -1
				}
				if x.Key > y.Key {
					return 1
				}
				return 0
			})
			for i := range a.Triggers {
				if err := ops.raise(ctx, r, &a.Triggers[i]); err != nil {
					return res, err
				}
			}
			res.Triggers += len(a.Triggers)
			st = a.State
		case KindBudget:
			if budgetErr != nil {
				if skipped != nil {
					skipped(budgetErr)
				}
				continue
			}
			var n int
			if st, n, err = evaluateBudget(ctx, ops, r, slices.Clone(usage)); err != nil {
				return res, err
			}
			res.Triggers += n
			st.EvaluatedAt = now.UTC()
			st.Learning = false
		}
		if err := ops.saveState(ctx, r.ID, st); err != nil {
			return res, err
		}
		res.Rules++
	}
	return res, ops.pruneCounts(ctx, now.Add(-countRetention))
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
