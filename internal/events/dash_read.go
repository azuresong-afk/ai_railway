package events

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Чтение агрегатов дашбордов. Период длиннее DashRawMax берётся из
// почасовых таблиц, короче — прямо из events тем же SELECT (минутные
// корзины): 15 минут и 1 час нельзя показать часовыми корзинами.

// Пределы чтения.
const (
	// DashRawMax — наибольший период чтения прямо из events.
	DashRawMax = 2 * time.Hour
	// DashMaxHourly — наибольший период с часовыми точками; длиннее —
	// по суткам.
	DashMaxHourly = 31 * 24 * time.Hour
	// DashMaxRange — наибольший произвольный период.
	DashMaxRange = 366 * 24 * time.Hour
	// DashMaxTop — наибольшее число строк «топ».
	DashMaxTop = 50
	// DashMaxSeriesRows — наибольшее число строк ряда.
	DashMaxSeriesRows = 20_000
	// DashFeedMax — наибольшее число строк «Ленты решений».
	DashFeedMax = 100
)

// Корзины времени рядов.
const (
	UnitMinute = "minute"
	UnitHour   = "hour"
	UnitDay    = "day"
)

// ErrDashRange — период пуст, перевёрнут или длиннее DashMaxRange.
var ErrDashRange = errors.New("период дашборда пуст или длиннее 366 суток")

// DashQuery — период и условия чтения.
type DashQuery struct {
	From, To time.Time
	// App — slug приложения; пусто — все.
	App string
	// TZ — часовой пояс установки: границы суток и дни недели.
	TZ string
}

// Raw — период читается из events.
func (q DashQuery) Raw() bool { return q.To.Sub(q.From) <= DashRawMax }

// Unit — корзина времени рядов.
func (q DashQuery) Unit() string {
	switch d := q.To.Sub(q.From); {
	case d <= DashRawMax:
		return UnitMinute
	case d <= DashMaxHourly:
		return UnitHour
	default:
		return UnitDay
	}
}

// Normalize округляет начало периода до часа вниз для почасовых таблиц:
// строки хранятся по часам, неполный час на краю не разрезается.
func (q DashQuery) Normalize() DashQuery {
	q.From, q.To = q.From.UTC(), q.To.UTC()
	if !q.Raw() {
		q.From = q.From.Truncate(time.Hour)
	}
	return q
}

func (q DashQuery) validate() error {
	if q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) || q.To.Sub(q.From) > DashMaxRange {
		return ErrDashRange
	}
	if len(q.App) > MaxFilterValue || q.TZ == "" || len(q.TZ) > 64 {
		return errors.New("условия дашборда заданы неверно")
	}
	return nil
}

// ctes — общий префикс запросов: CTE req, fnd, usr, lat из events или
// таблиц. Параметры: $1 организация, $2 с, $3 по, $4 корзина чтения
// events, $5 приложение (пусто — все).
func (q DashQuery) ctes() string {
	if q.Raw() {
		return "WITH " + dashEv(dashScopeRange+" AND ($5::text = '' OR e.app = $5)", "$4::text") +
			", req AS (" + dashReqSel + "), fnd AS (" + dashFindSel + "), usr AS (" + dashUserSel + "), lat AS (" + dashLatSel + ") "
	}
	t := func(name string) string {
		return "SELECT * FROM " + name + " WHERE org_id = $1 AND bucket >= $2 AND bucket < $3 AND $4::text <> '' AND ($5::text = '' OR app = $5)"
	}
	return "WITH req AS (" + t("dash_req_hour") + "), fnd AS (" + t("dash_find_hour") + "), usr AS (" + t("dash_user_hour") +
		"), lat AS (" + t("dash_latency_hour") + ") "
}

func (d *DashStore) query(ctx context.Context, q DashQuery, body string, extra ...any) (pgx.Rows, context.CancelFunc, error) {
	if err := q.validate(); err != nil {
		return nil, nil, err
	}
	q = q.Normalize()
	ctx, cancel := pgCtx(ctx)
	args := append([]any{d.orgID, q.From, q.To, UnitMinute, q.App}, extra...)
	rows, err := d.rdb.Query(ctx, q.ctes()+body, args...)
	if err != nil {
		cancel()
		return nil, nil, dbError("дашборд", err)
	}
	return rows, cancel, nil
}

func collect[T any](ctx context.Context, d *DashStore, q DashQuery, body string, scan func(pgx.Rows) (T, error), extra ...any) ([]T, error) {
	rows, cancel, err := d.query(ctx, q, body, extra...)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, dbError("дашборд", err)
		}
		out = append(out, v)
		if len(out) > DashMaxSeriesRows {
			return nil, ErrTooManyRows
		}
	}
	if err := rows.Err(); err != nil {
		return nil, dbError("дашборд", err)
	}
	return out, nil
}

// DashTotals — итоги периода.
type DashTotals struct {
	Requests         int64 `json:"requests"`
	WithFindings     int64 `json:"with_findings"`
	NonTextUnchecked int64 `json:"non_text_unchecked"`
	// Blocked — заблокировано (режим enforce); WouldBlock — заблокировало
	// бы (режим monitor); Masked — ПДн или секреты замаскированы.
	Blocked          int64 `json:"blocked"`
	WouldBlock       int64 `json:"would_block"`
	Masked           int64 `json:"masked"`
	TokensPrompt     int64 `json:"tokens_prompt"`
	TokensCompletion int64 `json:"tokens_completion"`
	// Cost — стоимость, 1e-7 ₽; UnpricedRequests — запросы моделей без цены.
	Cost             int64 `json:"cost"`
	UnpricedRequests int64 `json:"unpriced_requests"`
}

const (
	dashBlocked    = "(action = 'block' AND mode <> 'monitor')"
	dashWouldBlock = "(action = 'block' AND mode = 'monitor')"
	dashMasked     = "(action IN ('redact', 'pseudonymize'))"
)

// Totals — итоги периода.
func (d *DashStore) Totals(ctx context.Context, q DashQuery) (DashTotals, error) {
	rows, err := collect(ctx, d, q, `SELECT COALESCE(sum(requests), 0)::bigint, COALESCE(sum(with_findings), 0)::bigint,
		COALESCE(sum(non_text_unchecked), 0)::bigint,
		COALESCE(sum(requests) FILTER (WHERE `+dashBlocked+`), 0)::bigint,
		COALESCE(sum(requests) FILTER (WHERE `+dashWouldBlock+`), 0)::bigint,
		COALESCE(sum(requests) FILTER (WHERE `+dashMasked+`), 0)::bigint,
		COALESCE(sum(tokens_prompt), 0)::bigint, COALESCE(sum(tokens_completion), 0)::bigint,
		COALESCE(sum(cost), 0)::bigint, COALESCE(sum(unpriced_requests), 0)::bigint FROM req`,
		func(r pgx.Rows) (t DashTotals, err error) {
			err = r.Scan(&t.Requests, &t.WithFindings, &t.NonTextUnchecked, &t.Blocked, &t.WouldBlock, &t.Masked,
				&t.TokensPrompt, &t.TokensCompletion, &t.Cost, &t.UnpricedRequests)
			return
		})
	if err != nil || len(rows) == 0 {
		return DashTotals{}, err
	}
	return rows[0], nil
}

// DashLatency — гистограмма задержки шлюза (всего минус провайдер) и p95.
type DashLatency struct {
	// Bounds и Counts — верхние границы корзин, мс (последняя —
	// DashLatencyOverflow), и число запросов в каждой.
	Bounds []int   `json:"bounds"`
	Counts []int64 `json:"counts"`
	// P95 — верхняя граница корзины 95-го процентиля, мс; 0 — данных нет;
	// DashLatencyOverflow — больше последней границы.
	P95   int   `json:"p95"`
	Total int64 `json:"total"`
}

// Latency — гистограмма задержки и её p95.
func (d *DashStore) Latency(ctx context.Context, q DashQuery) (DashLatency, error) {
	type row struct {
		le int
		n  int64
	}
	rows, err := collect(ctx, d, q, `SELECT le, sum(n)::bigint FROM lat GROUP BY le ORDER BY le`,
		func(r pgx.Rows) (v row, err error) { err = r.Scan(&v.le, &v.n); return })
	if err != nil {
		return DashLatency{}, err
	}
	out := DashLatency{Bounds: append(append([]int{}, DashLatencyBounds...), DashLatencyOverflow),
		Counts: make([]int64, len(DashLatencyBounds)+1)}
	for _, r := range rows {
		for i, b := range out.Bounds {
			if b == r.le {
				out.Counts[i] += r.n
				out.Total += r.n
			}
		}
	}
	if out.Total > 0 {
		need := (out.Total*95 + 99) / 100
		var acc int64
		for i, c := range out.Counts {
			if acc += c; acc >= need {
				out.P95 = out.Bounds[i]
				break
			}
		}
	}
	return out, nil
}

// DashPoint — точка ряда: начало корзины и значение по ключу.
type DashPoint struct {
	Bucket time.Time `json:"bucket"`
	Key    string    `json:"key"`
	Value  int64     `json:"value"`
}

const dashBucket = "date_trunc($7::text, bucket, $6::text)"

// DecisionSeries — запросы по решениям во времени: blocked, would_block,
// masked, allowed.
func (d *DashStore) DecisionSeries(ctx context.Context, q DashQuery) ([]DashPoint, error) {
	return collect(ctx, d, q, `SELECT `+dashBucket+` AS b, CASE WHEN `+dashWouldBlock+` THEN 'would_block'
		WHEN `+dashBlocked+` THEN 'blocked' WHEN `+dashMasked+` THEN 'masked' ELSE 'allowed' END AS k, sum(requests)::bigint
		FROM req GROUP BY 1, 2 ORDER BY 1, 2`, scanPoint, q.TZ, q.Unit())
}

func scanPoint(r pgx.Rows) (p DashPoint, err error) {
	err = r.Scan(&p.Bucket, &p.Key, &p.Value)
	p.Bucket = p.Bucket.UTC()
	return
}

// Измерения находок.
const (
	DimDetector = "detector"
	DimThreat   = "threat"
	DimCategory = "category"
	DimApp      = "app"
)

func findDim(dim string) (string, error) {
	switch dim {
	case DimDetector, DimThreat, DimCategory, DimApp:
		return dim, nil
	}
	return "", fmt.Errorf("измерение находок: %q", dim)
}

// FindingSeries — находки по измерению во времени; prefix отбирает
// категории («pii.» — только ПДн), пусто — все находки.
func (d *DashStore) FindingSeries(ctx context.Context, q DashQuery, dim, prefix string) ([]DashPoint, error) {
	col, err := findDim(dim)
	if err != nil {
		return nil, err
	}
	return collect(ctx, d, q, `SELECT `+dashBucket+` AS b, `+col+` AS k, sum(findings)::bigint FROM fnd
		WHERE $8::text = '' OR category LIKE $8::text || '%' GROUP BY 1, 2 ORDER BY 1, 2`, scanPoint, q.TZ, q.Unit(), prefix)
}

// DashTop — строка «топ»: ключ и находки.
type DashTop struct {
	Key   string `json:"key"`
	Value int64  `json:"value"`
}

// TopFindings — находки по измерению, по убыванию.
func (d *DashStore) TopFindings(ctx context.Context, q DashQuery, dim, prefix string, limit int) ([]DashTop, error) {
	col, err := findDim(dim)
	if err != nil {
		return nil, err
	}
	return collect(ctx, d, q, `SELECT `+col+`, sum(findings)::bigint AS n FROM fnd
		WHERE $6::text = '' OR category LIKE $6::text || '%' GROUP BY 1 ORDER BY n DESC, 1 LIMIT $7`,
		func(r pgx.Rows) (t DashTop, err error) { err = r.Scan(&t.Key, &t.Value); return }, prefix, clampTop(limit))
}

func clampTop(n int) int {
	return min(max(n, 1), DashMaxTop)
}

// DashPIIRow — находки ПДн: тип, приложение и действие.
type DashPIIRow struct {
	Category string `json:"category"`
	App      string `json:"app"`
	Action   string `json:"action"`
	Findings int64  `json:"findings"`
}

// PIIBreakdown — находки ПДн по типам, приложениям и действиям.
func (d *DashStore) PIIBreakdown(ctx context.Context, q DashQuery) ([]DashPIIRow, error) {
	return collect(ctx, d, q, `SELECT category, app, action, sum(findings)::bigint AS n FROM fnd
		WHERE category LIKE 'pii.%' GROUP BY 1, 2, 3 ORDER BY n DESC, 1, 2, 3 LIMIT 1000`,
		func(r pgx.Rows) (v DashPIIRow, err error) {
			err = r.Scan(&v.Category, &v.App, &v.Action, &v.Findings)
			return
		})
}

// DashCell — ячейка тепловой карты: день недели (1 — понедельник), час
// суток в поясе установки и находки.
type DashCell struct {
	Weekday  int   `json:"weekday"`
	Hour     int   `json:"hour"`
	Findings int64 `json:"findings"`
}

// Heatmap — находки по дням недели и часам суток.
func (d *DashStore) Heatmap(ctx context.Context, q DashQuery) ([]DashCell, error) {
	return collect(ctx, d, q, `SELECT extract(isodow FROM bucket AT TIME ZONE $6::text)::int AS wd,
		extract(hour FROM bucket AT TIME ZONE $6::text)::int AS h, sum(findings)::bigint FROM fnd GROUP BY 1, 2 ORDER BY 1, 2`,
		func(r pgx.Rows) (c DashCell, err error) { err = r.Scan(&c.Weekday, &c.Hour, &c.Findings); return }, q.TZ)
}

// DashRequestRow — запросы по приложению, модели или провайдеру.
type DashRequestRow struct {
	Key              string `json:"key"`
	Requests         int64  `json:"requests"`
	WithFindings     int64  `json:"with_findings"`
	Blocked          int64  `json:"blocked"`
	WouldBlock       int64  `json:"would_block"`
	Masked           int64  `json:"masked"`
	TokensPrompt     int64  `json:"tokens_prompt"`
	TokensCompletion int64  `json:"tokens_completion"`
	Cost             int64  `json:"cost"`
	UnpricedRequests int64  `json:"unpriced_requests"`
}

// Измерения запросов.
const (
	DimModel    = "model"
	DimProvider = "provider"
	DimUser     = "user"
	DimDept     = "department"
)

// RequestsBy — запросы по приложению, модели, провайдеру, пользователю
// (псевдоним) или подразделению приложения, по убыванию запросов.
func (d *DashStore) RequestsBy(ctx context.Context, q DashQuery, dim string, limit int) ([]DashRequestRow, error) {
	scan := func(r pgx.Rows) (v DashRequestRow, err error) {
		err = r.Scan(&v.Key, &v.Requests, &v.WithFindings, &v.Blocked, &v.WouldBlock, &v.Masked, &v.TokensPrompt,
			&v.TokensCompletion, &v.Cost, &v.UnpricedRequests)
		return
	}
	sums := `sum(requests)::bigint AS n, sum(with_findings)::bigint,
		COALESCE(sum(requests) FILTER (WHERE ` + dashBlocked + `), 0)::bigint, COALESCE(sum(requests) FILTER (WHERE ` + dashWouldBlock + `), 0)::bigint,
		COALESCE(sum(requests) FILTER (WHERE ` + dashMasked + `), 0)::bigint, sum(tokens_prompt)::bigint, sum(tokens_completion)::bigint,
		sum(cost)::bigint, sum(unpriced_requests)::bigint`
	switch dim {
	case DimApp, DimModel, DimProvider:
		return collect(ctx, d, q, `SELECT `+dim+`, `+sums+` FROM req GROUP BY 1 ORDER BY n DESC, 1 LIMIT $6`, scan, clampTop(limit))
	case DimDept:
		return collect(ctx, d, q, `SELECT COALESCE(a.department, ''), `+sums+` FROM req
			LEFT JOIN applications a ON a.org_id = $1 AND a.slug = req.app GROUP BY 1 ORDER BY n DESC, 1 LIMIT $6`, scan, clampTop(limit))
	case DimUser:
		return collect(ctx, d, q, `SELECT user_alias, sum(requests)::bigint AS n, 0::bigint, 0::bigint, 0::bigint, 0::bigint,
			sum(tokens_prompt)::bigint, sum(tokens_completion)::bigint, sum(cost)::bigint, 0::bigint FROM usr
			GROUP BY 1 ORDER BY n DESC, 1 LIMIT $6`, scan, clampTop(limit))
	}
	return nil, fmt.Errorf("измерение запросов: %q", dim)
}

// DashUsagePoint — расход по корзине времени.
type DashUsagePoint struct {
	Bucket   time.Time `json:"bucket"`
	Requests int64     `json:"requests"`
	Tokens   int64     `json:"tokens"`
	Cost     int64     `json:"cost"`
}

// UsageSeries — запросы, токены и стоимость во времени.
func (d *DashStore) UsageSeries(ctx context.Context, q DashQuery) ([]DashUsagePoint, error) {
	return collect(ctx, d, q, `SELECT `+dashBucket+` AS b, sum(requests)::bigint, (sum(tokens_prompt) + sum(tokens_completion))::bigint,
		sum(cost)::bigint FROM req GROUP BY 1 ORDER BY 1`,
		func(r pgx.Rows) (p DashUsagePoint, err error) {
			err = r.Scan(&p.Bucket, &p.Requests, &p.Tokens, &p.Cost)
			p.Bucket = p.Bucket.UTC()
			return
		}, q.TZ, q.Unit())
}

// DashFeedItem — решение в «Ленте решений»: метаданные события без
// содержимого и без псевдонима пользователя.
type DashFeedItem struct {
	ID         string    `json:"id"`
	Time       time.Time `json:"time"`
	App        string    `json:"app"`
	Model      string    `json:"model"`
	Action     string    `json:"action"`
	PolicyMode string    `json:"policy_mode"`
	Severity   string    `json:"severity"`
	Rule       string    `json:"rule"`
	Threats    []string  `json:"threats"`
}

// Feed — последние решения до момента to (не старше суток), новые первыми.
// all=false оставляет только решения с действием (не allow и не log).
func (d *DashStore) Feed(ctx context.Context, to time.Time, app string, all bool, limit int) ([]DashFeedItem, error) {
	limit = min(max(limit, 1), DashFeedMax)
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := d.rdb.Query(ctx, `SELECT id::text, ts, COALESCE(app, ''), COALESCE(model, ''), COALESCE(action, ''),
		COALESCE(policy_mode, ''), COALESCE(severity, ''), COALESCE(rule, ''), threats FROM events
		WHERE org_id = $1 AND ts >= $2 AND ts < $3 AND type IN ('gateway_request', 'check') AND ($4::text = '' OR app = $4)
			AND ($5::boolean OR action NOT IN ('allow', 'log'))
		ORDER BY ts DESC, id DESC LIMIT $6`, d.orgID, to.UTC().Add(-24*time.Hour), to.UTC(), app, all, limit)
	if err != nil {
		return nil, dbError("лента решений", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (DashFeedItem, error) {
		var v DashFeedItem
		err := r.Scan(&v.ID, &v.Time, &v.App, &v.Model, &v.Action, &v.PolicyMode, &v.Severity, &v.Rule, &v.Threats)
		v.Time = v.Time.UTC()
		if v.Threats == nil {
			v.Threats = []string{}
		}
		return v, err
	})
	if err != nil {
		return nil, dbError("лента решений", err)
	}
	return out, nil
}
