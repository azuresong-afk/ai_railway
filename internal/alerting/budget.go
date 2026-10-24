package alerting

import (
	"context"
	"slices"
	"strconv"
)

// Правило «бюджет» (ТЗ 5.6, 5.8, DM-15; задача 3.12): израсходовано
// WarnPercent (по умолчанию 80 %) и 100 % месячного бюджета приложения.
// Расход и месяц в часовом поясе установки — из учёта расхода (задача 3.18,
// budget_usage). Оповещение — одно на порог в месяц: достигнутый порог
// запоминается в alert_seen («бюджет, приложение, месяц, порог») в той же
// транзакции, что и оповещение, поэтому закрытое оповещение после окна
// подавления не появляется снова, а в новом месяце пороги отсчитываются
// заново.

// BudgetUsage — расход приложения с заданным бюджетом за текущий месяц.
type BudgetUsage struct {
	AppID string
	// App — slug приложения: то же значение, что в событиях и группировке.
	App   string
	Month string
	Mode  string
	// Percent — расход в целых процентах бюджета (вниз); Exhausted — расход
	// достиг бюджета.
	Percent   int64
	Exhausted bool
}

// BudgetSource — расход приложений с бюджетом за текущий месяц.
type BudgetSource func(ctx context.Context) ([]BudgetUsage, error)

// budgetGroup — поля ключа оповещения о бюджете: приложение, месяц, порог.
var budgetGroup = []string{"app", "month", "threshold"}

// budgetLevels — достигнутые пороги расхода u по правилу r.
func budgetLevels(r *Rule, u BudgetUsage) []int {
	warn := r.Condition.WarnPercent
	if warn == 0 {
		warn = DefaultWarnPercent
	}
	var out []int
	if u.Percent >= int64(warn) || u.Exhausted {
		out = append(out, warn)
	}
	if u.Exhausted || u.Percent >= 100 {
		out = append(out, 100)
	}
	return out
}

// evaluateBudget поднимает оповещения о впервые достигнутых в месяце порогах
// и возвращает их число.
func evaluateBudget(ctx context.Context, ops txOps, r *Rule, usage []BudgetUsage) (RuleState, int, error) {
	st := RuleState{Keys: []KeyState{}}
	raised := 0
	keyed := *r
	keyed.GroupBy = budgetGroup
	slices.SortFunc(usage, func(a, b BudgetUsage) int {
		if a.App < b.App {
			return -1
		}
		if a.App > b.App {
			return 1
		}
		return 0
	})
	for _, u := range usage {
		st.Month = u.Month
		st.Keys = append(st.Keys, KeyState{Group: map[string]string{"app": u.App}, Current: float64(u.Percent),
			Triggered: len(budgetLevels(r, u)) > 0})
		for _, lvl := range budgetLevels(r, u) {
			mark := "budget:" + u.AppID + ":" + u.Month + ":" + strconv.Itoa(lvl)
			fresh, err := ops.markSeen(ctx, r.ID, []string{mark})
			if err != nil {
				return st, raised, err
			}
			if len(fresh) == 0 {
				continue
			}
			values := map[string]string{"app": u.App, "month": u.Month, "threshold": strconv.Itoa(lvl) + " %"}
			t := Trigger{Key: GroupKey(budgetGroup, values), Values: values, Count: 1,
				Details: map[string]any{"app_id": u.AppID, "month": u.Month, "percent": u.Percent, "threshold_percent": lvl,
					"mode": u.Mode, "exhausted": u.Exhausted}}
			if err := ops.raise(ctx, &keyed, &t); err != nil {
				return st, raised, err
			}
			raised++
		}
	}
	trimState(&st)
	return st, raised, nil
}
