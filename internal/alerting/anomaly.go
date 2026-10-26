package alerting

import (
	"context"
	"slices"
	"time"
)

// Правило «аномалия» (ТЗ 5.6, DM-17, DM-36; задача 3.12). Объём метрики за
// последний час сравнивается с базовой линией — медианой объёмов того же
// часа недели за прошлые недели по почасовым агрегатам событий (без
// содержимого). Час недели — по часовому поясу установки: при переводе
// часов неделя назад — та же стрелка на часах, а не ровно 168 часов.
// Оповещение — при объёме не меньше MinVolume и не меньше Factor медиан.
// Пока у ключа нет двух недель истории (период обучения 14 суток), правило
// по нему молчит; это видно в состоянии правила (RuleState).

// Параметры базовой линии.
const (
	// AnomalyWindow — окно текущего объёма.
	AnomalyWindow = time.Hour
	// AnomalyLag — окно заканчивается раньше текущей минуты: агрегаты
	// пересчитываются с отставанием до минуты (events.aggregateLag).
	AnomalyLag = 2 * time.Minute
	// LearningPeriod — период обучения: до него правило по ключу молчит.
	LearningPeriod = 14 * 24 * time.Hour
	// MinBaselineWeeks и MaxBaselineWeeks — недель в базовой линии.
	MinBaselineWeeks = 2
	MaxBaselineWeeks = 8
	// maxStateKeys — ключей в состоянии правила для API.
	maxStateKeys = 50
)

// activityOps — объёмы по агрегатам событий. Ключ — значение приложения
// (byApp) или пустая строка (вся установка).
type activityOps interface {
	// windowVolume — объём метрики за [from, to) по минутным агрегатам.
	windowVolume(ctx context.Context, metric string, byApp bool, from, to time.Time) (map[string]float64, error)
	// hourVolumes — объём метрики по часам hours (начала часов UTC).
	hourVolumes(ctx context.Context, metric string, byApp bool, hours []time.Time) (map[string]map[time.Time]float64, error)
	// firstSeen — начало первого часа с объёмом метрики не раньше since.
	firstSeen(ctx context.Context, metric string, byApp bool, since time.Time) (map[string]time.Time, error)
}

// KeyState — состояние ключа правила для API.
type KeyState struct {
	Group map[string]string `json:"group"`
	// Learning — у ключа меньше двух недель истории: правило по нему молчит.
	Learning bool `json:"learning"`
	// ReadyAt — когда закончится обучение (по первым данным ключа).
	ReadyAt *time.Time `json:"ready_at,omitempty"`
	Current float64    `json:"current"`
	// Baseline — медиана базовой линии; Samples — недель в ней.
	Baseline  float64 `json:"baseline"`
	Samples   int     `json:"samples"`
	Triggered bool    `json:"triggered"`
}

// RuleState — состояние правила, которое считает фоновая задача:
// последнее вычисление, обучение и ключи (не больше 50).
type RuleState struct {
	EvaluatedAt time.Time `json:"evaluated_at"`
	// Learning — ни у одного ключа обучение не закончено: правило молчит.
	Learning bool `json:"learning"`
	// LearningUntil — ближайшее окончание обучения среди ключей на обучении.
	LearningUntil *time.Time `json:"learning_until,omitempty"`
	// Month — месяц бюджета в часовом поясе установки (правило «бюджет»).
	Month string     `json:"month,omitempty"`
	Keys  []KeyState `json:"keys"`
	// KeysTotal — ключей всего, если их больше maxStateKeys.
	KeysTotal int `json:"keys_total"`
	// Warning — предупреждение последнего прохода: WarnEvaluationFailed,
	// WarnTimezoneInvalid; пусто — нет.
	Warning string `json:"warning,omitempty"`
}

// median — медиана выборки (не пустой).
func median(xs []float64) float64 {
	s := slices.Clone(xs)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// weekWindow — окно той же длины k недель назад по часам пояса loc.
func weekWindow(start time.Time, k int, loc *time.Location) (time.Time, time.Time) {
	s := start.In(loc).AddDate(0, 0, -7*k).UTC()
	return s, s.Add(AnomalyWindow)
}

// overlapHours — часы UTC, пересекающие [from, to), с долей пересечения.
func overlapHours(from, to time.Time) map[time.Time]float64 {
	out := map[time.Time]float64{}
	for h := from.Truncate(time.Hour); h.Before(to); h = h.Add(time.Hour) {
		lo, hi := maxTime(h, from), minTime(h.Add(time.Hour), to)
		if hi.After(lo) {
			out[h] = float64(hi.Sub(lo)) / float64(time.Hour)
		}
	}
	return out
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// anomalyResult — срабатывания и состояние правила «аномалия».
type anomalyResult struct {
	Triggers []Trigger
	State    RuleState
}

// evaluateAnomaly вычисляет правило r на момент now (часы СУБД).
func evaluateAnomaly(ctx context.Context, ops activityOps, r *Rule, now time.Time, loc *time.Location) (anomalyResult, error) {
	c := r.Condition
	byApp := slices.Contains(r.GroupBy, "app")
	end := now.UTC().Truncate(time.Minute).Add(-AnomalyLag)
	start := end.Add(-AnomalyWindow)
	cur, err := ops.windowVolume(ctx, c.Metric, byApp, start, end)
	if err != nil {
		return anomalyResult{}, err
	}
	weights := make([]map[time.Time]float64, MaxBaselineWeeks)
	starts := make([]time.Time, MaxBaselineWeeks)
	var hours []time.Time
	for k := 1; k <= MaxBaselineWeeks; k++ {
		s, e := weekWindow(start, k, loc)
		starts[k-1] = s
		weights[k-1] = overlapHours(s, e)
		for h := range weights[k-1] {
			hours = append(hours, h)
		}
	}
	slices.SortFunc(hours, func(a, b time.Time) int { return a.Compare(b) })
	hours = slices.Compact(hours)
	vols, err := ops.hourVolumes(ctx, c.Metric, byApp, hours)
	if err != nil {
		return anomalyResult{}, err
	}
	seen, err := ops.firstSeen(ctx, c.Metric, byApp, starts[MaxBaselineWeeks-1].Truncate(time.Hour))
	if err != nil {
		return anomalyResult{}, err
	}
	keys := make([]string, 0, len(cur)+len(seen))
	for k := range cur {
		keys = append(keys, k)
	}
	for k := range seen {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)

	res := anomalyResult{State: RuleState{EvaluatedAt: now.UTC(), Learning: true, Keys: []KeyState{}}}
	for _, key := range keys {
		values := map[string]string{}
		if byApp {
			values["app"] = key
		}
		ks := KeyState{Group: values, Current: cur[key]}
		first, ok := seen[key]
		if !ok {
			// Данные впервые в текущем окне: обучение начинается с них.
			first = start.Truncate(time.Hour)
		}
		var samples []float64
		for k := range MaxBaselineWeeks {
			if starts[k].Before(first) {
				continue
			}
			v := 0.0
			for h, w := range weights[k] {
				v += w * vols[key][h]
			}
			samples = append(samples, v)
		}
		ks.Samples = len(samples)
		ready := first.Add(LearningPeriod + AnomalyWindow)
		if len(samples) < MinBaselineWeeks || end.Before(ready) {
			ks.Learning = true
			ks.ReadyAt = &ready
			if res.State.LearningUntil == nil || ready.Before(*res.State.LearningUntil) {
				t := ready
				res.State.LearningUntil = &t
			}
		} else {
			res.State.Learning = false
			ks.Baseline = median(samples)
			if ks.Current >= float64(c.MinVolume) && ks.Current >= c.Factor*ks.Baseline {
				ks.Triggered = true
				res.Triggers = append(res.Triggers, Trigger{Key: GroupKey(r.GroupBy, values), Values: values, Count: 1,
					Details: map[string]any{"metric": c.Metric, "current": ks.Current, "baseline_median": ks.Baseline,
						"factor": c.Factor, "min_volume": c.MinVolume, "baseline_weeks": ks.Samples,
						"window_start": start.Format(time.RFC3339), "window_end": end.Format(time.RFC3339)}})
			}
		}
		res.State.Keys = append(res.State.Keys, ks)
	}
	if !res.State.Learning {
		res.State.LearningUntil = nil
	}
	trimState(&res.State)
	return res, nil
}

// trimState оставляет в состоянии не больше maxStateKeys ключей: сначала
// сработавшие, затем по убыванию текущего объёма.
func trimState(st *RuleState) {
	st.KeysTotal = len(st.Keys)
	slices.SortStableFunc(st.Keys, func(a, b KeyState) int {
		switch {
		case a.Triggered != b.Triggered:
			if a.Triggered {
				return -1
			}
			return 1
		case a.Current > b.Current:
			return -1
		case a.Current < b.Current:
			return 1
		}
		return 0
	})
	if len(st.Keys) > maxStateKeys {
		st.Keys = st.Keys[:maxStateKeys]
	}
}
