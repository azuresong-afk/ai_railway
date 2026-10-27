package alerting

import (
	"context"
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// txOps — действия движка внутри одной транзакции: PostgreSQL (pgOps) или
// хранилище в памяти (Memory).
type txOps interface {
	// activeRules — включённые правила перечисленных видов.
	activeRules(ctx context.Context, kinds ...string) ([]Rule, error)
	// markSeen запоминает значения правила «новое» и возвращает те, что
	// встречены впервые.
	markSeen(ctx context.Context, ruleID string, values []string) ([]string, error)
	// raise учитывает срабатывание: дополняет открытое оповещение, считает
	// подавленное или создаёт новое (ADR-0020, п. 3).
	raise(ctx context.Context, r *Rule, t *Trigger) error
	// ruleByKey — встроенное правило по ключу.
	ruleByKey(ctx context.Context, key string) (Rule, bool, error)
}

// group — срабатывания правила по ключам в порядке появления.
type group struct {
	order []string
	by    map[string]*Trigger
}

func (g *group) get(key string, values map[string]string) *Trigger {
	if t, ok := g.by[key]; ok {
		return t
	}
	t := &Trigger{Key: key, Values: values}
	g.by[key] = t
	g.order = append(g.order, key)
	return t
}

// process проверяет принятые события правилами «порог» и «новое» и
// учитывает срабатывания. Правило, условие которого не разбирается
// (например, после изменения языка фильтров), пропускается с вызовом
// skipped: приём событий из-за него не останавливается.
func process(ctx context.Context, ops txOps, gatewayID string, evs []*events.Event, skipped func(error)) error {
	if len(evs) == 0 {
		return nil
	}
	rules, err := ops.activeRules(ctx, KindThreshold, KindNew)
	if err != nil || len(rules) == 0 {
		return err
	}
	recs := make([]events.Record, len(evs))
	for i, e := range evs {
		recs[i] = events.RecordOf(gatewayID, e)
	}
	for _, r := range rules {
		if r.Kind == KindNew && r.Condition.Field == ToolField {
			// agents.tool_new поднимает сервер по tools:observe (agents.go):
			// имя инструмента в событии без сервера ключом не годится.
			continue
		}
		c, err := compile(r)
		if err != nil {
			if skipped != nil {
				skipped(err)
			}
			continue
		}
		g := group{by: map[string]*Trigger{}}
		for i := range recs {
			rec := &recs[i]
			if !c.matches(rec) {
				continue
			}
			values := make(map[string]string, len(r.GroupBy))
			for _, f := range r.GroupBy {
				values[f] = fieldValue(rec, f)
			}
			if r.Kind == KindNew && values[r.Condition.Field] == "" {
				continue
			}
			g.get(GroupKey(r.GroupBy, values), values).add(EventRef{ID: rec.ID, TS: rec.TS}, rec.Time)
		}
		keys := g.order
		if r.Kind == KindNew && len(keys) > 0 {
			vals := make([]string, len(keys))
			for i, k := range keys {
				vals[i] = g.by[k].Values[r.Condition.Field]
			}
			fresh, err := ops.markSeen(ctx, r.ID, vals)
			if err != nil {
				return err
			}
			keys = keys[:0:0]
			for _, k := range g.order {
				if slices.Contains(fresh, g.by[k].Values[r.Condition.Field]) {
					keys = append(keys, k)
				}
			}
		}
		// Порядок ключей фиксирован: параллельные пакеты берут блокировки
		// строк оповещений в одном порядке.
		slices.Sort(keys)
		for _, k := range keys {
			if err := ops.raise(ctx, &r, g.by[k]); err != nil {
				return err
			}
		}
	}
	return nil
}

// Raise — срабатывание встроенного правила вне приёма событий (изменение
// получателей, системные условия): учитывается в транзакции действия.
type Raise struct {
	Key     string
	Trigger Trigger
}

// raiseBuiltin учитывает срабатывания встроенных правил; отсутствующее
// правило (сервер ещё не создал встроенные) — ошибка: действие без
// оповещения не выполняется.
func raiseBuiltin(ctx context.Context, ops txOps, raises []Raise) error {
	for i := range raises {
		r, ok, err := ops.ruleByKey(ctx, raises[i].Key)
		if err != nil {
			return err
		}
		if !ok {
			return errNoBuiltin
		}
		if !r.Enabled {
			continue
		}
		if err := ops.raise(ctx, &r, &raises[i].Trigger); err != nil {
			return err
		}
	}
	return nil
}
