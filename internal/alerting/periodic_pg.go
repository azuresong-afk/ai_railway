package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// periodicLockID — ключ pg_try_advisory_xact_lock фоновой задачи правил:
// два экземпляра сервера не считают проход одновременно.
const periodicLockID int64 = 0x6169_7365_6361_6c72 // «aisecalr»

// firstSeenTTL — как долго годится прочитанное начало истории ключей:
// запрос идёт по восьми неделям почасовых агрегатов, раз в минуту — дорого.
const firstSeenTTL = time.Hour

// maxStateJSON — предел состояния правила в JSON (ограничение столбца).
const maxStateJSON = 16 << 10

// Enqueue ставит новое оповещение в очередь доставки по каналам в
// транзакции его создания (notify.PGStore.EnqueueAlertTx, задача 3.14).
type Enqueue func(ctx context.Context, tx pgx.Tx, alertID, severity string) (int, error)

// periodicDeps — подключаемое к PGStore после создания: очередь доставки и
// расход бюджетов (сервисы создаются позже хранилища).
type periodicDeps struct {
	mu      sync.Mutex
	enqueue Enqueue
	budgets BudgetSource
	// seen — кэш начала истории ключей по метрике и группировке.
	seen map[string]seenCache
}

type seenCache struct {
	at   time.Time
	data map[string]time.Time
}

// SetEnqueue подключает очередь доставки уведомлений: каждое новое
// оповещение (не дополнение открытого) ставится в неё той же транзакцией.
func (s *PGStore) SetEnqueue(fn Enqueue) {
	s.deps.mu.Lock()
	defer s.deps.mu.Unlock()
	s.deps.enqueue = fn
}

// SetBudgetSource подключает расход приложений для правил «бюджет».
func (s *PGStore) SetBudgetSource(fn BudgetSource) {
	s.deps.mu.Lock()
	defer s.deps.mu.Unlock()
	s.deps.budgets = fn
}

func (s *PGStore) enqueueFn() Enqueue {
	s.deps.mu.Lock()
	defer s.deps.mu.Unlock()
	return s.deps.enqueue
}

// Periodic — один проход фоновой задачи (см. periodic.go).
func (s *PGStore) Periodic(ctx context.Context) (PeriodicResult, error) {
	ctx, cancel := context.WithTimeout(ctx, PeriodicTimeout)
	defer cancel()
	s.deps.mu.Lock()
	budgets := s.deps.budgets
	s.deps.mu.Unlock()
	var usage []BudgetUsage
	budgetErr := errors.New("оповещения: расход бюджетов не подключён")
	if budgets != nil {
		usage, budgetErr = budgets(ctx)
	}
	var res PeriodicResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		res = PeriodicResult{}
		var locked bool
		if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", periodicLockID).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			res.Skipped = true
			return nil
		}
		var now time.Time
		var last *time.Time
		if err := tx.QueryRow(ctx, `SELECT now(), (SELECT ran_at FROM alert_job_runs WHERE org_id = $1 AND job = 'periodic')`,
			s.orgID).Scan(&now, &last); err != nil {
			return err
		}
		// Пропуск — только если проход был в последние periodicMinGap: при
		// шаге часов СУБД назад отметка оказывается в будущем, и задача не
		// должна молчать до неё (3Н36 ревью 3.r2).
		if last != nil && now.Sub(*last) >= 0 && now.Sub(*last) < periodicMinGap {
			res.Skipped = true
			return nil
		}
		tz := "UTC"
		err := tx.QueryRow(ctx, `SELECT timezone FROM install_settings WHERE org_id = $1`, s.orgID).Scan(&tz)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		loc, err := bundle.LoadLocation(tz)
		tzInvalid := err != nil
		if tzInvalid {
			loc = time.UTC
		}
		r, err := runPeriodic(ctx, pgOps{s: s, tx: tx}, now, loc, tzInvalid, usage, budgetErr, func(err error) {
			s.logger.Warn("оповещения: правило пропущено фоновой задачей", "class", "alerting", "error", err)
		})
		if err != nil {
			return err
		}
		res = r
		_, err = tx.Exec(ctx, `INSERT INTO alert_job_runs (org_id, job, ran_at) VALUES ($1, 'periodic', $2)
			ON CONFLICT (org_id, job) DO UPDATE SET ran_at = EXCLUDED.ran_at`, s.orgID, now)
		return err
	})
	if err != nil {
		return PeriodicResult{}, fmt.Errorf("оповещения: фоновая задача: %w", dbErr(err))
	}
	return res, nil
}

// isolate — см. periodicOps: SAVEPOINT на правило; при ошибке — откат к
// нему, транзакция прохода продолжается.
func (o pgOps) isolate(ctx context.Context, fn func() error) error {
	if _, err := o.tx.Exec(ctx, "SAVEPOINT alert_rule"); err != nil {
		return err
	}
	if err := fn(); err != nil {
		if _, rbErr := o.tx.Exec(ctx, "ROLLBACK TO SAVEPOINT alert_rule"); rbErr != nil {
			return errors.Join(err, rbErr)
		}
		return err
	}
	_, err := o.tx.Exec(ctx, "RELEASE SAVEPOINT alert_rule")
	return err
}

// addCounts — см. freqOps. Ссылки на события — не больше maxCountRefs на
// строку; pending растёт вместе со счётчиком.
func (o pgOps) addCounts(ctx context.Context, ruleID string, rows []countRow) error {
	keys := make([]string, len(rows))
	buckets := make([]time.Time, len(rows))
	values := make([]string, len(rows))
	counts := make([]int64, len(rows))
	refs := make([]string, len(rows))
	for i, r := range rows {
		v, err := json.Marshal(r.Values)
		if err != nil {
			return err
		}
		type ref struct {
			ID string    `json:"id"`
			TS time.Time `json:"ts"`
		}
		rs := make([]ref, len(r.Refs))
		for j, x := range r.Refs {
			rs[j] = ref{ID: x.ID, TS: x.TS.UTC()}
		}
		b, err := json.Marshal(rs)
		if err != nil {
			return err
		}
		keys[i], buckets[i], values[i], counts[i], refs[i] = r.Key, r.Bucket, string(v), r.Count, string(b)
	}
	_, err := o.tx.Exec(ctx, `INSERT INTO alert_rule_counts (rule_id, group_key, bucket, group_values, count, pending, event_refs)
		SELECT $1, k, b, v::jsonb, n, n, e::jsonb
		FROM unnest($2::text[], $3::timestamptz[], $4::text[], $5::bigint[], $6::text[]) WITH ORDINALITY AS u(k, b, v, n, e, i)
		ORDER BY i
		ON CONFLICT (rule_id, group_key, bucket) DO UPDATE SET count = alert_rule_counts.count + EXCLUDED.count,
			pending = alert_rule_counts.pending + EXCLUDED.pending,
			event_refs = CASE WHEN jsonb_array_length(alert_rule_counts.event_refs) >= $7 THEN alert_rule_counts.event_refs
				ELSE (SELECT jsonb_agg(x ORDER BY n) FROM (SELECT x, n FROM jsonb_array_elements(alert_rule_counts.event_refs || EXCLUDED.event_refs)
					WITH ORDINALITY AS e(x, n) ORDER BY n LIMIT $7) AS s) END`,
		ruleID, keys, buckets, values, counts, refs, maxCountRefs)
	return err
}

// frequencyDue — см. periodicOps. Сначала без блокировок выбираются ключи,
// у которых в окне набрался порог и есть неучтённые события (старейшие
// неучтённые — первыми, чтобы ключи за пределом выборки не ждали вечно).
// Затем строки этих ключей блокируются в порядке байтов ключа и минуты —
// том же, в каком их блокирует приём (countFrequency), — и их pending
// обнуляется: учитывается ровно то, что прочитано под блокировкой, а
// события, принятые после, остаются неучтёнными (3В10 ревью 3.12).
func (o pgOps) frequencyDue(ctx context.Context, r *Rule, since time.Time) ([]freqDue, error) {
	rows, err := o.tx.Query(ctx, `SELECT group_key, (array_agg(group_values ORDER BY bucket DESC))[1], sum(count)::bigint,
			min(bucket), max(bucket)
		FROM alert_rule_counts WHERE rule_id = $1 AND bucket >= $2
		GROUP BY group_key HAVING sum(count) >= $3 AND sum(pending) > 0
		ORDER BY min(bucket) FILTER (WHERE pending > 0), group_key LIMIT $4`, r.ID, since, r.Condition.Count, MaxRules*5)
	if err != nil {
		return nil, err
	}
	due, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (freqDue, error) {
		var d freqDue
		var v []byte
		if err := row.Scan(&d.Key, &v, &d.InWindow, &d.First, &d.Last); err != nil {
			return d, err
		}
		d.First, d.Last = d.First.UTC(), d.Last.UTC()
		return d, json.Unmarshal(v, &d.Values)
	})
	if err != nil || len(due) == 0 {
		return nil, err
	}
	keys := make([]string, len(due))
	for i := range due {
		keys[i] = due[i].Key
	}
	// Обнуляются pending и примеры строк ключа в окне; RETURNING — значения
	// до обнуления.
	locked, err := o.tx.Query(ctx, `WITH old AS (
			SELECT group_key, bucket, pending, event_refs FROM alert_rule_counts
			WHERE rule_id = $1 AND group_key = ANY($2) AND bucket >= $3 AND pending > 0
			ORDER BY group_key COLLATE "C", bucket FOR UPDATE)
		UPDATE alert_rule_counts c SET pending = 0, event_refs = '[]'
		FROM old WHERE c.rule_id = $1 AND c.group_key = old.group_key AND c.bucket = old.bucket
		RETURNING old.group_key, old.bucket, old.pending, old.event_refs`, r.ID, keys, since)
	if err != nil {
		return nil, err
	}
	type taken struct {
		bucket  time.Time
		pending int64
		refs    []EventRef
	}
	byKey := map[string][]taken{}
	var key string
	var x taken
	var raw []byte
	if _, err := pgx.ForEachRow(locked, []any{&key, &x.bucket, &x.pending, &raw}, func() error {
		var refs []struct {
			ID string    `json:"id"`
			TS time.Time `json:"ts"`
		}
		if err := json.Unmarshal(raw, &refs); err != nil {
			return err
		}
		t := taken{bucket: x.bucket.UTC(), pending: x.pending}
		for _, ref := range refs {
			t.refs = append(t.refs, EventRef{ID: ref.ID, TS: ref.TS.UTC()})
		}
		byKey[key] = append(byKey[key], t)
		return nil
	}); err != nil {
		return nil, err
	}
	out := due[:0]
	for _, d := range due {
		ts := byKey[d.Key]
		slices.SortFunc(ts, func(a, b taken) int { return a.bucket.Compare(b.bucket) })
		for _, t := range ts {
			d.Pending += t.pending
			for _, ref := range t.refs {
				if len(d.Refs) < MaxAlertEvents {
					d.Refs = append(d.Refs, ref)
				}
			}
		}
		// Неучтённые события ключа забрал другой проход — срабатывания нет.
		if d.Pending > 0 {
			out = append(out, d)
		}
	}
	return out, nil
}

// pruneCounts — см. periodicOps.
func (o pgOps) pruneCounts(ctx context.Context, before time.Time) error {
	_, err := o.tx.Exec(ctx, `DELETE FROM alert_rule_counts WHERE bucket < $1
		AND rule_id IN (SELECT id FROM alert_rules WHERE org_id = $2)`, before, o.s.orgID)
	return err
}

// saveState — см. periodicOps. Начало серии сбоев (failing_since) берётся
// из прежнего состояния, если серия продолжается.
func (o pgOps) saveState(ctx context.Context, ruleID string, st RuleState) error {
	b, err := json.Marshal(st)
	for err == nil && len(b) > maxStateJSON && len(st.Keys) > 0 {
		st.Keys = st.Keys[:len(st.Keys)/2]
		b, err = json.Marshal(st)
	}
	if err != nil {
		return err
	}
	_, err = o.tx.Exec(ctx, `INSERT INTO alert_rule_state (rule_id, evaluated_at, state) VALUES ($1, $2, $3)
		ON CONFLICT (rule_id) DO UPDATE SET evaluated_at = EXCLUDED.evaluated_at,
			state = CASE WHEN EXCLUDED.state ? 'failing_since' AND alert_rule_state.state ? 'failing_since'
				THEN jsonb_set(EXCLUDED.state, '{failing_since}', alert_rule_state.state->'failing_since')
				ELSE EXCLUDED.state END`,
		ruleID, st.EvaluatedAt, b)
	return err
}

// metricSQL — выражение объёма и условие типа событий метрики (константы
// кода, не ввод).
func metricSQL(metric string) (expr, where string) {
	switch metric {
	case MetricTokens:
		return "tokens_prompt + tokens_completion", ""
	case MetricCompletionTokens:
		return "tokens_completion", ""
	}
	return "events", " AND type IN ('gateway_request', 'check')"
}

func keySQL(byApp bool) string {
	if byApp {
		return "app"
	}
	return "''"
}

// windowVolume — см. activityOps.
func (o pgOps) windowVolume(ctx context.Context, metric string, byApp bool, from, to time.Time) (map[string]float64, error) {
	expr, where := metricSQL(metric)
	rows, err := o.tx.Query(ctx, `SELECT `+keySQL(byApp)+`, sum(`+expr+`)::float8 FROM event_aggregates_minute
		WHERE org_id = $1 AND bucket >= $2 AND bucket < $3`+where+` GROUP BY 1`, o.s.orgID, from, to)
	if err != nil {
		return nil, err
	}
	out := map[string]float64{}
	var k string
	var v float64
	_, err = pgx.ForEachRow(rows, []any{&k, &v}, func() error {
		if v > 0 && (!byApp || k != "") {
			out[k] = v
		}
		return nil
	})
	return out, err
}

// hourVolumes — см. activityOps.
func (o pgOps) hourVolumes(ctx context.Context, metric string, byApp bool, hours []time.Time) (map[string]map[time.Time]float64, error) {
	expr, where := metricSQL(metric)
	rows, err := o.tx.Query(ctx, `SELECT `+keySQL(byApp)+`, bucket, sum(`+expr+`)::float8 FROM event_aggregates_hour
		WHERE org_id = $1 AND bucket = ANY($2::timestamptz[])`+where+` GROUP BY 1, 2`, o.s.orgID, hours)
	if err != nil {
		return nil, err
	}
	out := map[string]map[time.Time]float64{}
	var k string
	var b time.Time
	var v float64
	_, err = pgx.ForEachRow(rows, []any{&k, &b, &v}, func() error {
		if byApp && k == "" {
			return nil
		}
		if out[k] == nil {
			out[k] = map[time.Time]float64{}
		}
		out[k][b.UTC()] = v
		return nil
	})
	return out, err
}

// firstSeen — см. activityOps. Результат кэшируется на firstSeenTTL: ключ,
// появившийся позже, до обновления кэша считается новым (на обучении).
func (o pgOps) firstSeen(ctx context.Context, metric string, byApp bool, since time.Time) (map[string]time.Time, error) {
	ck := metric + "|" + keySQL(byApp)
	d := &o.s.deps
	d.mu.Lock()
	c, ok := d.seen[ck]
	d.mu.Unlock()
	if ok && time.Since(c.at) < firstSeenTTL {
		return c.data, nil
	}
	expr, where := metricSQL(metric)
	rows, err := o.tx.Query(ctx, `SELECT `+keySQL(byApp)+`, min(bucket) FROM event_aggregates_hour
		WHERE org_id = $1 AND bucket >= $2 AND `+expr+` > 0`+where+` GROUP BY 1`, o.s.orgID, since)
	if err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	var k string
	var b time.Time
	if _, err := pgx.ForEachRow(rows, []any{&k, &b}, func() error {
		if !byApp || k != "" {
			out[k] = b.UTC()
		}
		return nil
	}); err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.seen == nil {
		d.seen = map[string]seenCache{}
	}
	d.seen[ck] = seenCache{at: time.Now(), data: out}
	d.mu.Unlock()
	return out, nil
}

// RuleState — см. Store.
func (s *PGStore) RuleState(ctx context.Context, orgID, ruleID string) (RuleState, bool, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var raw []byte
	err := s.db.QueryRow(ctx, `SELECT s.state FROM alert_rule_state s JOIN alert_rules r ON r.id = s.rule_id
		WHERE r.org_id = $1 AND s.rule_id = $2`, orgID, ruleID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return RuleState{}, false, nil
	}
	if err != nil {
		return RuleState{}, false, err
	}
	var st RuleState
	if err := json.Unmarshal(raw, &st); err != nil {
		return RuleState{}, false, fmt.Errorf("оповещения: состояние правила %s: %w", ruleID, err)
	}
	return st, true, nil
}
