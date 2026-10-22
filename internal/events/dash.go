package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Агрегаты для дашбордов (ТЗ 5.8, 6.4; задача 3.19): почасовые таблицы без
// содержимого запросов (миграция 0036). Строки добавляет хук приёма в
// транзакции записи событий; прошлые периоды и сбойные часы досчитывает
// фоновая задача пересчётом по таблице events. Один и тот же SELECT (dashEv
// и производные) используют хук, пересчёт и чтение коротких периодов прямо
// из events, поэтому расхождений между путями нет. Минутные агрегаты
// оповещений и event_aggregates_* не используются.

// Параметры агрегатов дашбордов.
const (
	// DashBackfillEvery — период задачи досчёта.
	DashBackfillEvery = 30 * time.Second
	// dashChunk — часов за один шаг пересчёта: короткая эксклюзивная
	// блокировка, приём событий ждёт не дольше шага.
	dashChunk = 6 * time.Hour
	// dashMax — предел сумм токенов и стоимости в строке (защита от
	// переполнения bigint при сложении).
	dashMax = "4e18"
	// dashLockID — ключ advisory-блокировки: хук берёт общую, пересчёт —
	// исключительную, поэтому пересчёт часа не смешивается с приростом хука.
	dashLockID int64 = 0x6169_7365_6364_6173 // «aisecdas»
	// DashLatencyOverflow — корзина гистограммы «больше последней границы».
	DashLatencyOverflow = 2147483647
)

// DashLatencyBounds — верхние границы корзин гистограммы задержки шлюза, мс.
var DashLatencyBounds = []int{5, 10, 25, 50, 100, 250, 500, 1000, 5000}

// dashScopeRange и dashScopeIDs — какие события берёт SELECT.
const (
	dashScopeRange = "e.ts >= $2 AND e.ts < $3"
	dashScopeIDs   = "(e.id, e.ts) IN (SELECT * FROM unnest($2::uuid[], $3::timestamptz[]))"
)

// dashEv — события в нужной области с ценой модели и числами из details.
// unit — корзина времени: 'hour' для записи, параметр для чтения. Число
// токенов и задержка ограничены сверху: чужое значение не должно
// переполнить bigint и сорвать приём пакета.
func dashEv(scope, unit string) string {
	num := func(path string, max string) string {
		return "COALESCE(LEAST(GREATEST((" + path + ")::numeric, 0), " + max + "), 0)"
	}
	var lat strings.Builder
	lat.WriteString("CASE")
	for _, b := range DashLatencyBounds {
		fmt.Fprintf(&lat, " WHEN gw_ms <= %d THEN %d", b, b)
	}
	fmt.Fprintf(&lat, " ELSE %d END", DashLatencyOverflow)
	return `ev0 AS (
	SELECT e.id, e.org_id, date_trunc(` + unit + `, e.ts, 'UTC') AS bucket,
		COALESCE(e.app, '') AS app, COALESCE(e.provider, '') AS provider, COALESCE(e.model, '') AS model,
		COALESCE(e.action, '') AS action, COALESCE(e.policy_mode, '') AS mode, COALESCE(e.user_alias, '') AS user_alias,
		e.non_text_unchecked, e.details,
		jsonb_array_length(CASE WHEN jsonb_typeof(e.details->'findings') = 'array' THEN e.details->'findings' ELSE '[]'::jsonb END) > 0 AS has_f,
		` + num("e.details->'tokens'->>'prompt'", "1e12") + `::bigint AS tp,
		` + num("e.details->'tokens'->>'completion'", "1e12") + `::bigint AS tc,
		p.input_price, p.output_price,
		CASE WHEN e.details->'latency_ms'->>'total' IS NULL THEN NULL
			ELSE GREATEST(` + num("e.details->'latency_ms'->>'total'", "3.6e6") + ` - ` + num("e.details->'latency_ms'->>'provider'", "3.6e6") + `, 0) END AS gw_ms
	FROM events e
	LEFT JOIN providers pr ON pr.org_id = e.org_id AND pr.slug = e.provider
	LEFT JOIN model_prices p ON p.org_id = e.org_id AND p.provider_id = pr.id AND p.model = e.model
	WHERE e.org_id = $1 AND e.type IN ('gateway_request', 'check') AND ` + scope + `
),
ev AS (
	SELECT ev0.*, CASE WHEN input_price IS NULL THEN 0::numeric
		ELSE LEAST(tp::numeric * input_price + tc::numeric * output_price, ` + dashMax + `) END AS cost,
		input_price IS NULL AND tp + tc > 0 AS unpriced,
		CASE WHEN gw_ms IS NULL THEN NULL ELSE ` + lat.String() + ` END AS le
	FROM ev0
)`
}

// Запросы выборки по группам таблиц: колонки совпадают с таблицами dash_*,
// поэтому чтение из events и из агрегатов использует одни и те же запросы.
const (
	dashReqSel = `SELECT org_id, bucket, app, provider, model, action, mode, count(*) AS requests,
		count(*) FILTER (WHERE has_f) AS with_findings, count(*) FILTER (WHERE non_text_unchecked) AS non_text_unchecked,
		LEAST(sum(tp), ` + dashMax + `)::bigint AS tokens_prompt, LEAST(sum(tc), ` + dashMax + `)::bigint AS tokens_completion,
		LEAST(sum(cost), ` + dashMax + `)::bigint AS cost, count(*) FILTER (WHERE unpriced) AS unpriced_requests
		FROM ev GROUP BY org_id, bucket, app, provider, model, action, mode`
	dashFindSel = `SELECT ev.org_id, ev.bucket, ev.app, COALESCE(f->>'detector', '') AS detector,
		COALESCE(f->>'category', '') AS category, COALESCE(f->>'threat', '') AS threat, ev.action, count(*) AS findings
		FROM ev CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(ev.details->'findings') = 'array'
			THEN ev.details->'findings' ELSE '[]'::jsonb END) AS f
		GROUP BY ev.org_id, ev.bucket, ev.app, detector, category, threat, ev.action`
	dashUserSel = `SELECT org_id, bucket, app, user_alias, count(*) AS requests,
		LEAST(sum(tp), ` + dashMax + `)::bigint AS tokens_prompt, LEAST(sum(tc), ` + dashMax + `)::bigint AS tokens_completion,
		LEAST(sum(cost), ` + dashMax + `)::bigint AS cost
		FROM ev WHERE user_alias <> '' GROUP BY org_id, bucket, app, user_alias`
	dashLatSel = `SELECT org_id, bucket, app, le, count(*) AS n FROM ev WHERE le IS NOT NULL GROUP BY org_id, bucket, app, le`
)

// dashAdd — сложение счётчиков при конфликте ключа (прирост хука).
func dashAdd(table string, cols []string, capped bool) string {
	set := make([]string, len(cols))
	for i, c := range cols {
		if capped {
			set[i] = fmt.Sprintf("%[1]s = LEAST(%[2]s.%[1]s::numeric + EXCLUDED.%[1]s, %[3]s)::bigint", c, table, dashMax)
		} else {
			set[i] = fmt.Sprintf("%[1]s = %[2]s.%[1]s + EXCLUDED.%[1]s", c, table)
		}
	}
	return strings.Join(set, ", ")
}

// dashWrites — вставки четырёх таблиц из ev; additive — прирост к имеющимся
// строкам (хук), иначе простая вставка после очистки часов (пересчёт).
func dashWrites(additive bool) []string {
	ins := func(table, keys, cols, sel string, plain, capped []string) string {
		q := "INSERT INTO " + table + " (" + keys + ", " + cols + ") " + sel
		if additive {
			q += " ON CONFLICT (" + keys + ") DO UPDATE SET " + dashAdd(table, plain, false)
			if len(capped) > 0 {
				q += ", " + dashAdd(table, capped, true)
			}
		}
		return q
	}
	return []string{
		ins("dash_req_hour", "org_id, bucket, app, provider, model, action, mode",
			"requests, with_findings, non_text_unchecked, tokens_prompt, tokens_completion, cost, unpriced_requests", dashReqSel,
			[]string{"requests", "with_findings", "non_text_unchecked", "unpriced_requests"},
			[]string{"tokens_prompt", "tokens_completion", "cost"}),
		ins("dash_find_hour", "org_id, bucket, app, detector, category, threat, action", "findings", dashFindSel,
			[]string{"findings"}, nil),
		ins("dash_user_hour", "org_id, bucket, app, user_alias", "requests, tokens_prompt, tokens_completion, cost", dashUserSel,
			[]string{"requests"}, []string{"tokens_prompt", "tokens_completion", "cost"}),
		ins("dash_latency_hour", "org_id, bucket, app, le", "n", dashLatSel, []string{"n"}, nil),
	}
}

var (
	dashAddSQL     = dashWrites(true)
	dashReplaceSQL = dashWrites(false)
)

// DashDB — доступ к PostgreSQL для агрегатов дашбордов; *pgxpool.Pool
// ему соответствует.
type DashDB interface {
	PGDB
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// DashStore — агрегаты дашбордов: запись (хук, досчёт) и чтение.
type DashStore struct {
	db     DashDB
	rdb    PGDB
	orgID  string
	logger *slog.Logger
}

// NewDashStore создаёт хранилище; rdb — пул чтения (nil — как db).
func NewDashStore(db DashDB, rdb PGDB, orgID string, logger *slog.Logger) (*DashStore, error) {
	if db == nil || orgID == "" || logger == nil {
		return nil, fmt.Errorf("агрегаты дашбордов: нужны база, организация и журнал")
	}
	if rdb == nil {
		rdb = db
	}
	return &DashStore{db: db, rdb: rdb, orgID: orgID, logger: logger}, nil
}

// Hook — хук приёма событий (WithIngestHook).
func (d *DashStore) Hook() IngestHook { return dashHook{d} }

type dashHook struct{ d *DashStore }

// OnIngest прибавляет новые события к почасовым агрегатам. Сбой
// агрегатов не должен отбрасывать пакет событий: прирост идёт в точке
// сохранения, при ошибке она откатывается, часы помечаются к досчёту.
func (h dashHook) OnIngest(ctx context.Context, tx pgx.Tx, _ string, accepted []*Event) error {
	var evIDs []string
	var evTS []time.Time
	var minTS, maxTS time.Time
	for _, e := range accepted {
		if e.Type != TypeGatewayRequest && e.Type != TypeCheck {
			continue
		}
		ts, err := PartitionTime(e.ID)
		if err != nil {
			continue
		}
		evIDs, evTS = append(evIDs, e.ID), append(evTS, ts)
		if minTS.IsZero() || ts.Before(minTS) {
			minTS = ts
		}
		if ts.After(maxTS) {
			maxTS = ts
		}
	}
	if len(evIDs) == 0 {
		return nil
	}
	err := h.d.addInSavepoint(ctx, tx, evIDs, evTS)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return err
	}
	h.d.logger.Error("агрегаты дашбордов не обновлены, часы будут досчитаны", "class", "db", "error", err)
	hours := func(t time.Time) time.Time { return t.UTC().Truncate(time.Hour) }
	_, mErr := tx.Exec(ctx, `UPDATE dash_state SET backfill_done = false, updated_at = clock_timestamp(),
		backfill_cursor = LEAST(COALESCE(backfill_cursor, $2), $2), backfill_until = GREATEST(backfill_until, $3)
		WHERE org_id = $1`, h.d.orgID, hours(minTS), hours(maxTS).Add(time.Hour))
	if mErr != nil {
		return dbError("метка досчёта агрегатов", mErr)
	}
	return nil
}

func (d *DashStore) addInSavepoint(ctx context.Context, tx pgx.Tx, ids []string, ts []time.Time) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = sp.Rollback(context.WithoutCancel(ctx)) //nolint:gosec // G104: откат точки сохранения, исходная ошибка важнее
		return err
	}
	if _, err := sp.Exec(ctx, "SELECT pg_advisory_xact_lock_shared($1)", dashLockID); err != nil {
		return fail(err)
	}
	for _, q := range dashAddSQL {
		if _, err := sp.Exec(ctx, "WITH "+dashEv(dashScopeIDs, "'hour'")+" "+q, d.orgID, ids, ts); err != nil {
			return fail(err)
		}
	}
	return sp.Commit(ctx)
}

// ChainHooks объединяет хуки приёма: вызываются по порядку, первая ошибка
// прерывает приём пакета.
func ChainHooks(hooks ...IngestHook) IngestHook {
	var list []IngestHook
	for _, h := range hooks {
		if h != nil {
			list = append(list, h)
		}
	}
	return chain(list)
}

type chain []IngestHook

func (c chain) OnIngest(ctx context.Context, tx pgx.Tx, gatewayID string, accepted []*Event) error {
	for _, h := range c {
		if err := h.OnIngest(ctx, tx, gatewayID, accepted); err != nil {
			return err
		}
	}
	return nil
}

// Recompute заменяет агрегаты часов [from, to) пересчётом по таблице events
// (границы округляются до часа). Цены берутся текущие.
func (d *DashStore) Recompute(ctx context.Context, from, to time.Time) error {
	from, to = from.UTC().Truncate(time.Hour), to.UTC().Truncate(time.Hour)
	if !from.Before(to) {
		return nil
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	tx, err := d.db.Begin(ctx)
	if err != nil {
		return dbError("пересчёт агрегатов дашбордов", err)
	}
	defer func() {
		rctx, c := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer c()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после фиксации безвреден
	}()
	if err := d.recomputeTx(ctx, tx, from, to); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbError("пересчёт агрегатов дашбордов", err)
	}
	return nil
}

func (d *DashStore) recomputeTx(ctx context.Context, tx pgx.Tx, from, to time.Time) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", dashLockID); err != nil {
		return dbError("блокировка агрегатов дашбордов", err)
	}
	for _, t := range []string{"dash_req_hour", "dash_find_hour", "dash_user_hour", "dash_latency_hour"} {
		if _, err := tx.Exec(ctx, "DELETE FROM "+t+" WHERE org_id = $1 AND bucket >= $2 AND bucket < $3", d.orgID, from, to); err != nil {
			return dbError("очистка агрегатов дашбордов", err)
		}
	}
	for _, q := range dashReplaceSQL {
		if _, err := tx.Exec(ctx, "WITH "+dashEv(dashScopeRange, "'hour'")+" "+q, d.orgID, from, to); err != nil {
			return dbError("пересчёт агрегатов дашбордов", err)
		}
	}
	return nil
}

// Init создаёт отметку досчёта при первом запуске: хук включается с этого
// момента, события раньше досчитывает RunBackfill.
func (d *DashStore) Init(ctx context.Context) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	_, err := d.db.Exec(ctx, `INSERT INTO dash_state (org_id, live_since, backfill_until, backfill_done, updated_at)
		VALUES ($1, clock_timestamp(), date_trunc('hour', clock_timestamp(), 'UTC') + interval '1 hour', false, clock_timestamp())
		ON CONFLICT (org_id) DO NOTHING`, d.orgID)
	if err != nil {
		return dbError("отметка агрегатов дашбордов", err)
	}
	return nil
}

// BackfillStep пересчитывает следующую часть интервала досчёта; done — всё
// досчитано. Часть — не больше dashChunk часов, под блокировкой строки
// отметки: два сервера не пересчитывают один интервал.
func (d *DashStore) BackfillStep(ctx context.Context) (done bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, AggregateTimeout)
	defer cancel()
	tx, err := d.db.Begin(ctx)
	if err != nil {
		return false, dbError("досчёт агрегатов дашбордов", err)
	}
	defer func() {
		rctx, c := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer c()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после фиксации безвреден
	}()
	var cursor *time.Time
	var until time.Time
	var isDone bool
	if err := tx.QueryRow(ctx, `SELECT backfill_cursor, backfill_until, backfill_done FROM dash_state
		WHERE org_id = $1 FOR UPDATE`, d.orgID).Scan(&cursor, &until, &isDone); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return true, nil
		}
		return false, dbError("отметка досчёта агрегатов дашбордов", err)
	}
	if isDone {
		return true, nil
	}
	var from time.Time
	if cursor != nil {
		from = *cursor
	} else {
		var first *time.Time
		if err := tx.QueryRow(ctx, "SELECT min(ts) FROM events WHERE org_id = $1", d.orgID).Scan(&first); err != nil {
			return false, dbError("начало досчёта агрегатов дашбордов", err)
		}
		if first == nil {
			from = until
		} else {
			from = first.UTC().Truncate(time.Hour)
		}
	}
	next := from.Add(dashChunk)
	if next.After(until) {
		next = until
	}
	if from.Before(next) {
		if err := d.recomputeTx(ctx, tx, from, next); err != nil {
			return false, err
		}
	}
	finished := !next.Before(until)
	if _, err := tx.Exec(ctx, `UPDATE dash_state SET backfill_cursor = $2, backfill_done = $3, updated_at = clock_timestamp()
		WHERE org_id = $1`, d.orgID, next, finished); err != nil {
		return false, dbError("отметка досчёта агрегатов дашбордов", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, dbError("досчёт агрегатов дашбордов", err)
	}
	return finished, nil
}

// RunBackfill досчитывает прошлые периоды и сбойные часы каждые every до
// отмены ctx; пока есть что считать, части идут подряд. Затем срок
// хранения: агрегаты старше метаданных событий удаляются (раз в проход).
func (d *DashStore) RunBackfill(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		for range 128 {
			done, err := d.BackfillStep(ctx)
			if err != nil {
				if ctx.Err() == nil {
					d.logger.Error("агрегаты дашбордов не досчитаны", "class", "db", "error", err)
				}
				break
			}
			if done {
				break
			}
		}
		if err := d.Trim(ctx); err != nil && ctx.Err() == nil {
			d.logger.Error("срок хранения агрегатов дашбордов не применён", "class", "db", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Trim удаляет агрегаты старше срока хранения метаданных событий.
func (d *DashStore) Trim(ctx context.Context) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var days int
	if err := d.db.QueryRow(ctx, "SELECT metadata_days FROM event_settings").Scan(&days); err != nil {
		return dbError("срок хранения агрегатов дашбордов", err)
	}
	cut := time.Now().UTC().AddDate(0, 0, -days)
	for _, t := range []string{"dash_req_hour", "dash_find_hour", "dash_user_hour", "dash_latency_hour"} {
		if _, err := d.db.Exec(ctx, "DELETE FROM "+t+" WHERE org_id = $1 AND bucket < $2", d.orgID, cut); err != nil {
			return dbError("срок хранения агрегатов дашбордов", err)
		}
	}
	return nil
}

// Ready — досчёт прошлых периодов закончен: агрегаты полные.
func (d *DashStore) Ready(ctx context.Context) (bool, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var done bool
	err := d.rdb.QueryRow(ctx, "SELECT backfill_done FROM dash_state WHERE org_id = $1", d.orgID).Scan(&done)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, dbError("отметка досчёта агрегатов дашбордов", err)
	}
	return done, nil
}
