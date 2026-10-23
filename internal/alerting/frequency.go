package alerting

import (
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Правило «частота» (ТЗ 5.6, DM-16; задача 3.12): Count подходящих событий
// за WindowMinutes минут по ключу group_by. Подходящие события считаются в
// транзакции приёма в поминутные счётчики правила (alert_rule_counts) —
// агрегат без содержимого, как поминутные агрегаты событий; сами
// срабатывания поднимает фоновая задача раз в минуту (periodic.go) по сумме
// счётчиков в окне. Повтор пакета событий до счётчиков не доходит (дубли
// отсекает приём), сбой фоновой задачи откатывает и оповещение, и отметку
// учтённых срабатываний: оповещение не теряется и не удваивается.

// maxCountRefs — ссылок на события в одной строке счётчика: оповещению
// хватает примеров, а не полного списка.
const maxCountRefs = 20

// countRow — прирост счётчика правила за минуту по ключу.
type countRow struct {
	Key    string
	Values map[string]string
	Bucket time.Time
	Count  int64
	Refs   []EventRef
}

// freqOps — счётчики правила «частота» в транзакции приёма.
type freqOps interface {
	txOps
	// addCounts прибавляет счётчики правила; rows упорядочены по ключу и
	// минуте (блокировки строк — в одном порядке у параллельных пакетов).
	addCounts(ctx context.Context, ruleID string, rows []countRow) error
}

// countFrequency учитывает принятые события в счётчиках включённых правил
// «частота». Правило с неразборным условием пропускается, как в process.
func countFrequency(ctx context.Context, ops freqOps, now time.Time, gatewayID string, evs []*events.Event, skipped func(error)) error {
	if len(evs) == 0 {
		return nil
	}
	rules, err := ops.activeRules(ctx, KindFrequency)
	if err != nil || len(rules) == 0 {
		return err
	}
	recs := make([]events.Record, len(evs))
	for i, e := range evs {
		recs[i] = events.RecordOf(gatewayID, e)
	}
	for _, r := range rules {
		c, err := compile(r)
		if err != nil {
			if skipped != nil {
				skipped(err)
			}
			continue
		}
		by := map[string]*countRow{}
		since := frequencySince(&r, now)
		for i := range recs {
			rec := &recs[i]
			if !c.matches(rec) {
				continue
			}
			values := make(map[string]string, len(r.GroupBy))
			for _, f := range r.GroupBy {
				values[f] = fieldValue(rec, f)
			}
			key := GroupKey(r.GroupBy, values)
			bucket := rec.Time.UTC().Truncate(time.Minute)
			if bucket.Before(since) {
				// Событие старше окна правила (приём допускает до 7 суток):
				// в срабатывание оно уже не войдёт (3Н10 ревью 3.12).
				continue
			}
			id := key + keySep + strconv.FormatInt(bucket.Unix(), 10)
			row, ok := by[id]
			if !ok {
				row = &countRow{Key: key, Values: values, Bucket: bucket}
				by[id] = row
			}
			row.Count++
			if len(row.Refs) < maxCountRefs {
				row.Refs = append(row.Refs, EventRef{ID: rec.ID, TS: rec.TS})
			}
		}
		if len(by) == 0 {
			continue
		}
		rows := make([]countRow, 0, len(by))
		for _, row := range by {
			rows = append(rows, *row)
		}
		slices.SortFunc(rows, func(a, b countRow) int {
			if a.Key != b.Key {
				if a.Key < b.Key {
					return -1
				}
				return 1
			}
			return a.Bucket.Compare(b.Bucket)
		})
		if err := ops.addCounts(ctx, r.ID, rows); err != nil {
			return err
		}
	}
	return nil
}

// freqDue — ключ правила «частота», у которого в окне не меньше Count
// событий и есть ещё не учтённые в оповещениях.
type freqDue struct {
	Key    string
	Values map[string]string
	// InWindow — событий в окне; Pending — ещё не учтённых в оповещении.
	InWindow int64
	Pending  int64
	First    time.Time
	Last     time.Time
	Refs     []EventRef
}

// frequencySince — начало окна правила r на момент now: W минут, включая
// текущую неполную (минуты счётчиков — по началу минуты, 3Н8 ревью 3.12).
func frequencySince(r *Rule, now time.Time) time.Time {
	return now.UTC().Truncate(time.Minute).Add(-time.Duration(r.Condition.WindowMinutes-1) * time.Minute)
}

// countsStale — изменение правила r делает его счётчики непригодными:
// сменились условие или группировка (3В11 ревью 3.12). Счётчики такого
// правила удаляются той же транзакцией, что меняет правило.
func countsStale(old, cur *Rule) bool {
	return old.Kind == KindFrequency && (old.Condition != cur.Condition || !slices.Equal(old.GroupBy, cur.GroupBy))
}

// frequencyTrigger — срабатывание по ключу: в оповещение идут только ещё не
// учтённые события, чтобы каждое минутное повторение не удваивало счёт.
func frequencyTrigger(r *Rule, d freqDue) Trigger {
	return Trigger{Key: d.Key, Values: d.Values, Count: d.Pending, FirstEvent: d.First, LastEvent: d.Last,
		Events: d.Refs, Details: map[string]any{"window_minutes": r.Condition.WindowMinutes, "threshold": r.Condition.Count,
			"events_in_window": d.InWindow}}
}
