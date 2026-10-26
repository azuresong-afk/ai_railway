package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Агрегаты для дашбордов (ТЗ 5.8, 6.4; задача 3.19): почасовые таблицы без
// содержимого запросов (миграция 0037). Строки добавляет хук приёма в
// транзакции записи событий; прошлые периоды и сбойные часы досчитывает
// фоновая задача пересчётом по таблице events. Один и тот же SELECT (dashEv
// и производные) используют хук, пересчёт и чтение коротких периодов прямо
// из events, поэтому расхождений между путями нет. Минутные агрегаты
// оповещений и event_aggregates_* не используются.

// Параметры агрегатов дашбордов.
const (
	// DashBackfillEvery — период задачи досчёта.
	DashBackfillEvery = 30 * time.Second
	// dashChunk — наибольшая часть одного шага досчёта. После таймаута часть
	// делится пополам (не меньше часа), после успеха растёт обратно.
	dashChunk = 6 * time.Hour
	// dashChunkEvents — не больше событий в части досчёта (кроме части в
	// один час): время шага зависит от числа событий, а не от часов.
	dashChunkEvents = 100_000
	// dashDirtyHours — сколько помеченных хуком часов пересчитывается за шаг.
	dashDirtyHours = 6
	// dashMax — предел сумм токенов и стоимости в строке (защита от
	// переполнения bigint при сложении).
	dashMax = "4e18"
	// dashLockClass — первый ключ advisory-блокировки часа (второй — номер
	// часа от начала эпохи): хук пробует общую без ожидания, пересчёт берёт
	// исключительную, поэтому пересчёт часа не смешивается с приростом хука,
	// а досчёт старых часов не мешает приёму текущих (3В25 ревью 3.r3).
	dashLockClass int32 = 0x6173_6461 // «asda»
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
	// chunk — текущая наибольшая часть досчёта (dashChunk, после таймаута
	// меньше).
	chunk atomic.Int64
}

// NewDashStore создаёт хранилище; rdb — пул чтения (nil — как db).
func NewDashStore(db DashDB, rdb PGDB, orgID string, logger *slog.Logger) (*DashStore, error) {
	if db == nil || orgID == "" || logger == nil {
		return nil, fmt.Errorf("агрегаты дашбордов: нужны база, организация и журнал")
	}
	if rdb == nil {
		rdb = db
	}
	d := &DashStore{db: db, rdb: rdb, orgID: orgID, logger: logger}
	d.chunk.Store(int64(dashChunk))
	return d, nil
}

// errDashBusy — час агрегатов сейчас пересчитывается: хук не ждёт.
var errDashBusy = errors.New("агрегаты дашбордов: час пересчитывается")

// dashHour — номер часа от начала эпохи (второй ключ блокировки часа).
func dashHour(t time.Time) int32 {
	return int32(t.UTC().Unix() / 3600) //nolint:gosec // G115: номер часа до 2^31 — год 246 000
}

// Hook — хук приёма событий (WithIngestHook).
func (d *DashStore) Hook() IngestHook { return dashHook{d} }

type dashHook struct{ d *DashStore }

// OnIngest прибавляет новые события к почасовым агрегатам. Сбой
// агрегатов не должен отбрасывать и задерживать пакет событий: прирост идёт
// в точке сохранения; час пересчитывается (блокировка часа занята) или
// прирост не удался — точка откатывается, часы пакета помечаются к досчёту
// (dash_dirty_hours) без ожидания и без строки dash_state (3В25 ревью 3.r3).
func (h dashHook) OnIngest(ctx context.Context, tx pgx.Tx, _ string, accepted []*Event) error {
	var evIDs []string
	var evTS []time.Time
	var hours []int32
	for _, e := range accepted {
		if e.Type != TypeGatewayRequest && e.Type != TypeCheck {
			continue
		}
		ts, err := PartitionTime(e.ID)
		if err != nil {
			continue
		}
		evIDs, evTS = append(evIDs, e.ID), append(evTS, ts)
		if hr := dashHour(ts); !slices.Contains(hours, hr) {
			hours = append(hours, hr)
		}
	}
	if len(evIDs) == 0 {
		return nil
	}
	err := h.d.addInSavepoint(ctx, tx, evIDs, evTS, hours)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return err
	}
	if errors.Is(err, errDashBusy) {
		h.d.logger.Debug("час агрегатов дашбордов пересчитывается, часы будут досчитаны", "hours", len(hours))
	} else {
		h.d.logger.Error("агрегаты дашбордов не обновлены, часы будут досчитаны", "class", "db", "error", err)
	}
	if _, mErr := tx.Exec(ctx, `INSERT INTO dash_dirty_hours (org_id, bucket, marked_at)
		SELECT $1, to_timestamp(h::bigint * 3600), clock_timestamp() FROM unnest($2::int[]) AS h`, h.d.orgID, hours); mErr != nil {
		return dbError("метка досчёта агрегатов", mErr)
	}
	return nil
}

func (d *DashStore) addInSavepoint(ctx context.Context, tx pgx.Tx, ids []string, ts []time.Time, hours []int32) error {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = sp.Rollback(context.WithoutCancel(ctx)) //nolint:gosec // G104: откат точки сохранения, исходная ошибка важнее
		return err
	}
	// Общие блокировки часов пакета без ожидания: досчёт держит
	// исключительную на время пересчёта части.
	var locked bool
	if err := sp.QueryRow(ctx, "SELECT bool_and(pg_try_advisory_xact_lock_shared($1, h)) FROM unnest($2::int[]) AS h",
		dashLockClass, hours).Scan(&locked); err != nil {
		return fail(err)
	}
	if !locked {
		return fail(errDashBusy)
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
	// Исключительные блокировки пересчитываемых часов по возрастанию: хук,
	// которому час нужен, не ждёт, а помечает его к досчёту.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1, h) FROM generate_series($2::int, $3::int - 1) AS h ORDER BY h",
		dashLockClass, dashHour(from), dashHour(to)); err != nil {
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

// BackfillStep пересчитывает часы, помеченные хуком, а когда их нет —
// следующую часть интервала досчёта; done — всё досчитано. Часть — не
// больше dashChunk часов и dashChunkEvents событий, под блокировкой строки
// отметки: два сервера не пересчитывают один интервал.
func (d *DashStore) BackfillStep(ctx context.Context) (done bool, err error) {
	return d.backfillStep(ctx, time.Now())
}

// backfillStep — шаг досчёта; помеченные часы — только отмеченные раньше
// before: часы, помеченные во время пересчёта, ждут следующего прохода, а
// не зацикливают его.
func (d *DashStore) backfillStep(ctx context.Context, before time.Time) (done bool, err error) {
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
	dirty, err := d.recomputeDirty(ctx, tx, before)
	if err != nil {
		return false, err
	}
	if dirty {
		if err := tx.Commit(ctx); err != nil {
			return false, dbError("досчёт агрегатов дашбордов", err)
		}
		return false, nil
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
	next := from.Add(time.Duration(d.chunk.Load()))
	if next.After(until) {
		next = until
	}
	if from.Add(time.Hour).Before(next) {
		// Часть — не больше dashChunkEvents событий: граница — час события
		// с этим номером, но не меньше одного часа.
		var nth *time.Time
		err := tx.QueryRow(ctx, `SELECT ts FROM events WHERE org_id = $1 AND ts >= $2 AND ts < $3 ORDER BY ts OFFSET $4 LIMIT 1`,
			d.orgID, from, next, dashChunkEvents).Scan(&nth)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, dbError("досчёт агрегатов дашбордов", err)
		}
		if nth != nil {
			next = nth.UTC().Truncate(time.Hour)
			if !next.After(from) {
				next = from.Add(time.Hour)
			}
		}
	}
	if from.Before(next) {
		if err := d.recomputeTx(ctx, tx, from, next); err != nil {
			if ctx.Err() != nil {
				// Часть не уложилась в срок: следующая попытка — с вдвое
				// меньшей частью после паузы прохода (RunBackfill).
				d.chunk.Store(max(d.chunk.Load()/2, int64(time.Hour)))
			}
			return false, err
		}
		d.chunk.Store(min(d.chunk.Load()*2, int64(dashChunk)))
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
		start := time.Now()
		for range 128 {
			done, err := d.backfillStep(ctx, start)
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

// recomputeDirty пересчитывает до dashDirtyHours часов, помеченных хуком до
// before, и снимает их метки; false — пересчитывать нечего. Метки снимаются
// до пересчёта: пересчёт видит все события, чьи транзакции успели
// зафиксировать снятые метки, а метка, вставленная позже, остаётся.
func (d *DashStore) recomputeDirty(ctx context.Context, tx pgx.Tx, before time.Time) (bool, error) {
	rows, err := tx.Query(ctx, `WITH pick AS (
			SELECT DISTINCT bucket FROM dash_dirty_hours WHERE org_id = $1 AND marked_at < $2 ORDER BY bucket LIMIT $3)
		DELETE FROM dash_dirty_hours d USING pick WHERE d.org_id = $1 AND d.bucket = pick.bucket AND d.marked_at < $2
		RETURNING d.bucket`, d.orgID, before, dashDirtyHours)
	if err != nil {
		return false, dbError("метки досчёта агрегатов дашбордов", err)
	}
	var hours []time.Time
	for rows.Next() {
		var b time.Time
		if err := rows.Scan(&b); err != nil {
			rows.Close()
			return false, dbError("метки досчёта агрегатов дашбордов", err)
		}
		if !slices.ContainsFunc(hours, b.Equal) {
			hours = append(hours, b)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, dbError("метки досчёта агрегатов дашбордов", err)
	}
	slices.SortFunc(hours, time.Time.Compare)
	for _, h := range hours {
		if err := d.recomputeTx(ctx, tx, h, h.Add(time.Hour)); err != nil {
			return false, err
		}
	}
	return len(hours) > 0, nil
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
	err := d.rdb.QueryRow(ctx, `SELECT backfill_done AND NOT EXISTS (SELECT 1 FROM dash_dirty_hours WHERE org_id = $1)
		FROM dash_state WHERE org_id = $1`, d.orgID).Scan(&done)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, dbError("отметка досчёта агрегатов дашбордов", err)
	}
	return done, nil
}
