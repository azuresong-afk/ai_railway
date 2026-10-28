package quotalease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

const (
	// pgTimeout — предел на одну операцию, если у контекста нет своего срока.
	pgTimeout = 10 * time.Second
	// pgRollbackTimeout — предел на откат после отмены контекста.
	pgRollbackTimeout = 5 * time.Second
	// purgeBatch — выдач, удаляемых за один проход очистки.
	purgeBatch = 10000
	// unitsCap — предел сумм в SQL (MaxUnits).
	unitsCap = "4611686018427387904"
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0064_quota_leases). SQL только
// параметризованный.
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал аудита должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("аренда квот: нет БД или журнала аудита")
	}
	return &PGStore{db: db, audit: a}, nil
}

func pgCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

func (s *PGStore) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("аренда квот: начало транзакции: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после фиксации безвреден, ошибку скрывает исходная
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("аренда квот: фиксация: %w", err)
	}
	return nil
}

// queryRower — пул или транзакция.
type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// online — действующих шлюзов с heartbeat не старше OnlineAfter.
func online(ctx context.Context, q queryRower, orgID string, now time.Time) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM gateways WHERE org_id = $1 AND status = 'active' AND last_seen_at > $2`,
		orgID, now.Add(-OnlineAfter)).Scan(&n)
	return n, err
}

// Settings — см. Store. До первичной настройки — режим local.
func (s *PGStore) Settings(ctx context.Context, orgID string, now time.Time) (Settings, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	st := Settings{Mode: ModeLocal}
	err := s.db.QueryRow(ctx, `SELECT quota_mode, quota_mode_changed_at FROM install_settings WHERE org_id = $1`, orgID).
		Scan(&st.Mode, &st.ChangedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, err
	}
	if st.ChangedAt != nil {
		t := st.ChangedAt.UTC()
		st.ChangedAt = &t
	}
	st.GatewaysOnline, err = online(ctx, s.db, orgID, now)
	return st, err
}

// SetMode — см. Store. Тот же режим — без изменений и без записи.
func (s *PGStore) SetMode(ctx context.Context, orgID, mode string, now time.Time, fn func(old Settings) (audit.Entry, error)) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var old Settings
		err := tx.QueryRow(ctx, `SELECT quota_mode, quota_mode_changed_at FROM install_settings WHERE org_id = $1 FOR UPDATE`, orgID).
			Scan(&old.Mode, &old.ChangedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotSetUp
		}
		if err != nil {
			return err
		}
		if old.Mode == mode {
			return nil
		}
		if old.GatewaysOnline, err = online(ctx, tx, orgID, now); err != nil {
			return err
		}
		rec, err := fn(old)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE install_settings SET quota_mode = $2, quota_mode_changed_at = $3 WHERE org_id = $1`,
			orgID, mode, now); err != nil {
			return err
		}
		rec.OrgID = orgID
		return s.audit.RecordTx(ctx, tx, rec)
	})
}

// appRow — действующее приложение и его лимиты.
type appRow struct {
	id     string
	quotas struct {
		RPM int64 `json:"requests_per_minute"`
		TPM int64 `json:"tokens_per_minute"`
		TPD int64 `json:"tokens_per_day"`
	}
	// budget — жёсткий бюджет, единицы 1e-7 ₽; 0 — нет.
	budget int64
}

func (a *appRow) limit(quota string) int64 {
	switch quota {
	case QuotaRPM:
		return max(a.quotas.RPM, 0)
	case QuotaTPM:
		return max(a.quotas.TPM, 0)
	case QuotaTPD:
		return max(a.quotas.TPD, 0)
	}
	return a.budget
}

// Lease — см. Store. Одна транзакция на запрос: сначала отчёты (остаток
// возвращается в окно), затем по приложениям и квотам в постоянном
// порядке — блокировка строки quota_locks, автономный расход и выдача.
func (s *PGStore) Lease(ctx context.Context, in LeaseInput) (Response, error) {
	var resp Response
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		resp = Response{ServerTime: in.Now, Apps: []AppResponse{}}
		// Ожидание чужой блокировки quota_locks — не дольше секунды (4Н16
		// ревью 4.r2): шлюз повторит запрос, а не повиснет за долгой
		// транзакцией.
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '1s'`); err != nil {
			return err
		}
		var mode, tz string
		var since *time.Time
		err := tx.QueryRow(ctx, `SELECT quota_mode, timezone, quota_mode_changed_at FROM install_settings WHERE org_id = $1`,
			in.OrgID).Scan(&mode, &tz, &since)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrNotSetUp
		case err != nil:
			return err
		case mode != ModeLeased:
			return ErrModeLocal
		}
		loc, err := bundle.LoadLocation(tz)
		if err != nil {
			return fmt.Errorf("аренда квот: часовой пояс установки: %w", err)
		}
		if resp.Gateways, err = online(ctx, tx, in.OrgID, in.Now); err != nil {
			return err
		}
		resp.Gateways = max(resp.Gateways, 1)
		apps, err := s.apps(ctx, tx, in)
		if err != nil {
			return err
		}
		if err := s.reports(ctx, tx, in, apps); err != nil {
			return err
		}
		reqs := slices.Clone(in.Request.Apps)
		slices.SortFunc(reqs, func(a, b AppRequest) int { return strings.Compare(a.App, b.App) })
		for _, ar := range reqs {
			out := AppResponse{App: ar.App, Quotas: []Grant{}}
			qs := slices.Clone(ar.Quotas)
			slices.SortFunc(qs, func(a, b QuotaRequest) int { return strings.Compare(a.Quota, b.Quota) })
			for _, q := range qs {
				g, err := s.grant(ctx, tx, in, apps[ar.App], ar.App, q, loc, since, resp.Gateways)
				if err != nil {
					return err
				}
				if q.Want > 0 {
					out.Quotas = append(out.Quotas, g)
				}
			}
			if len(out.Quotas) > 0 {
				resp.Apps = append(resp.Apps, out)
			}
		}
		return nil
	})
	return resp, err
}

// apps — действующие приложения запроса по ID (slug); архивных нет.
func (s *PGStore) apps(ctx context.Context, tx pgx.Tx, in LeaseInput) (map[string]*appRow, error) {
	slugs := make([]string, 0, len(in.Request.Apps))
	for _, a := range in.Request.Apps {
		slugs = append(slugs, a.App)
	}
	rows, err := tx.Query(ctx, `SELECT a.slug, a.id::text, a.quotas, COALESCE(b.monthly_limit, 0)
		FROM applications a LEFT JOIN app_budgets b ON b.app_id = a.id AND b.mode = 'hard'
		WHERE a.org_id = $1 AND a.slug = ANY($2) AND a.archived_at IS NULL`, in.OrgID, slugs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*appRow{}
	for rows.Next() {
		var slug string
		var quotas []byte
		a := &appRow{}
		var kopecks int64
		if err := rows.Scan(&slug, &a.id, &quotas, &kopecks); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(quotas, &a.quotas); err != nil {
			return nil, fmt.Errorf("аренда квот: quotas приложения %s: %w", slug, err)
		}
		a.budget = min(max(kopecks, 0), MaxUnits/bundle.CostUnitsPerKopeck) * bundle.CostUnitsPerKopeck
		out[slug] = a
	}
	return out, rows.Err()
}

// reports закрывает аренды по отчётам шлюза: аренда этого шлюза, того же
// приложения и квоты, израсходовано не больше выданного; повтор отчёта с
// тем же числом безвреден.
func (s *PGStore) reports(ctx context.Context, tx pgx.Tx, in LeaseInput, apps map[string]*appRow) error {
	type want struct {
		app, quota string
		used       int64
	}
	byLease := map[string]want{}
	ids := []string{}
	for _, a := range in.Request.Apps {
		for _, q := range a.Quotas {
			for _, r := range q.Reports {
				byLease[r.Lease] = want{a.App, q.Quota, r.Used}
				ids = append(ids, r.Lease)
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	slices.Sort(ids)
	rows, err := tx.Query(ctx, `SELECT id::text, app_id::text, quota, gateway_id, kind, granted, used FROM quota_grants
		WHERE org_id = $1 AND id = ANY($2::uuid[]) ORDER BY id FOR UPDATE`, in.OrgID, ids)
	if err != nil {
		return err
	}
	type found struct {
		app, quota, gw, kind string
		granted              int64
		used                 *int64
	}
	got := map[string]found{}
	for rows.Next() {
		var id string
		var f found
		if err := rows.Scan(&id, &f.app, &f.quota, &f.gw, &f.kind, &f.granted, &f.used); err != nil {
			rows.Close()
			return err
		}
		got[id] = f
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		w := byLease[id]
		f, ok := got[id]
		a := apps[w.app]
		switch {
		// Аренды уже нет (удалена очисткой или вместе с приложением) — отчёт
		// ни на что не влияет.
		case !ok:
			continue
		// Чужая аренда: отчёт с малым числом освободил бы долю другого шлюза.
		// Приложение, архивированное после выдачи, не ищется по ID.
		case f.kind != "lease" || f.gw != in.GatewayID || f.quota != w.quota || (a != nil && f.app != a.id):
			return &Violation{App: w.app, Quota: w.quota, Lease: id, Reason: ReasonUnknownLease}
		case w.used > f.granted:
			return &Violation{App: w.app, Quota: w.quota, Lease: id, Reason: ReasonOverused}
		case f.used != nil && *f.used != w.used:
			return &Violation{App: w.app, Quota: w.quota, Lease: id, Reason: ReasonRereported}
		case f.used != nil:
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE quota_grants SET used = $3, reported_at = $4 WHERE org_id = $1 AND id = $2`,
			in.OrgID, id, w.used, in.Now); err != nil {
			return err
		}
	}
	return nil
}

// grant — автономный расход и выдача по одной квоте приложения.
func (s *PGStore) grant(ctx context.Context, tx pgx.Tx, in LeaseInput, a *appRow, slug string, q QuotaRequest,
	loc *time.Location, since *time.Time, gateways int) (Grant, error) {
	g := Grant{Quota: q.Quota, RequestID: q.RequestID}
	if a == nil {
		g.Unknown = true
		return g, nil
	}
	limit := a.limit(q.Quota)
	if limit == 0 {
		g.Unlimited = true
		return g, nil
	}
	g.Limit = limit
	if _, err := tx.Exec(ctx, `INSERT INTO quota_locks (org_id, app_id, quota) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		in.OrgID, a.id, q.Quota); err != nil {
		return g, err
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM quota_locks WHERE org_id = $1 AND app_id = $2 AND quota = $3 FOR UPDATE`,
		in.OrgID, a.id, q.Quota); err != nil {
		return g, err
	}
	w := windowOf(q.Quota, in.Now, loc)
	// Автономный расход — с ID запроса: повтор не учитывает его дважды.
	// Минутные квоты его не принимают: автономный расход последней минуты
	// шлюз сам засчитывает в первую аренду после восстановления связи.
	if q.Offline > 0 && (q.Quota == QuotaTPD || q.Quota == QuotaBudget) {
		if err := s.offline(ctx, tx, in, a, slug, q, w, limit, gateways); err != nil {
			return g, err
		}
	}
	if q.Want == 0 {
		return g, nil
	}
	if q.Quota == QuotaBudget {
		if err := s.budgetBase(ctx, tx, in, a, slug, w, since); err != nil {
			return g, err
		}
	}
	charged, oldest, err := s.charged(ctx, tx, in, a, q.Quota, w)
	if err != nil {
		return g, err
	}
	free := max(limit-charged, 0)
	// Повтор запроса — та же выдача (если она была): единицы не выдаются
	// дважды.
	var leaseID, appID, quota string
	var granted int64
	var expires time.Time
	err = tx.QueryRow(ctx, `SELECT id::text, app_id::text, quota, granted, expires_at FROM quota_grants
		WHERE org_id = $1 AND gateway_id = $2 AND request_id = $3 AND kind = 'lease'`, in.OrgID, in.GatewayID, q.RequestID).
		Scan(&leaseID, &appID, &quota, &granted, &expires)
	switch {
	case err == nil && (appID != a.id || quota != q.Quota):
		return g, &Violation{App: slug, Quota: q.Quota, Lease: leaseID, Reason: ReasonReusedRequest}
	case err == nil:
		g.Lease, g.Granted, g.TTLMS, g.Remaining = leaseID, granted, max(expires.Sub(in.Now), 0).Milliseconds(), free
		return g, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return g, err
	}
	prev, err := s.prev(ctx, tx, in, a, q.Quota)
	if err != nil {
		return g, err
	}
	g.Granted = min(share(limit, q.Want, gateways, w, prev), free)
	g.Remaining = free - g.Granted
	if g.Granted > 0 {
		if g.Lease, err = in.NewID(); err != nil {
			return g, err
		}
		g.TTLMS = w.ttl.Milliseconds()
		if _, err := tx.Exec(ctx, `INSERT INTO quota_grants (id, org_id, app_id, quota, kind, gateway_id, request_id, window_key,
			granted, granted_at, expires_at) VALUES ($1, $2, $3, $4, 'lease', $5, $6, $7, $8, $9, $10)`,
			g.Lease, in.OrgID, a.id, q.Quota, in.GatewayID, q.RequestID, w.key, g.Granted, in.Now, in.Now.Add(w.ttl)); err != nil {
			return g, err
		}
	}
	switch {
	case g.Granted >= q.Want:
	// Выдача урезана равной долей (сутки и месяц), а остаток в окне есть:
	// шлюз добирает следующим запросом, а не ждёт конца окна.
	case g.Remaining > 0:
		g.RetryAfterMS = time.Second.Milliseconds()
	default:
		g.RetryAfterMS = retryAfter(w, in.Now, oldest).Milliseconds()
	}
	return g, nil
}

// offline учитывает автономный расход шлюза за сутки или месяц — с ID
// запроса: повтор не учитывает его дважды. Автономная доля шлюза в окне —
// лимит, делённый на число шлюзов (ADR-0021, п. 5), поэтому за окно шлюз
// может заявить не больше ceilDiv(limit, gateways) (4В19 ревью 4.r2).
// Сверх этого расход не учитывается, а в аудит пишется
// quota.lease_violation с причиной offline_overclaim; запрос не
// отклоняется: честный шлюз, у которого с тех пор сменилось число шлюзов
// на связи, не должен застревать с неотправленным расходом.
func (s *PGStore) offline(ctx context.Context, tx pgx.Tx, in LeaseInput, a *appRow, slug string, q QuotaRequest,
	w window, limit int64, gateways int) error {
	var dup bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM quota_grants WHERE org_id = $1 AND gateway_id = $2
		AND request_id = $3 AND kind = 'offline')`, in.OrgID, in.GatewayID, q.RequestID).Scan(&dup); err != nil || dup {
		return err
	}
	var claimed int64
	if err := tx.QueryRow(ctx, `SELECT LEAST(COALESCE(SUM(granted), 0), `+unitsCap+`)::bigint FROM quota_grants
		WHERE org_id = $1 AND app_id = $2 AND quota = $3 AND window_key = $4 AND gateway_id = $5 AND kind = 'offline'`,
		in.OrgID, a.id, q.Quota, w.key, in.GatewayID).Scan(&claimed); err != nil {
		return err
	}
	allowed := max(ceilDiv(limit, int64(max(gateways, 1)))-claimed, 0)
	units := min(q.Offline, allowed)
	if units < q.Offline {
		if err := s.audit.RecordTx(ctx, tx, audit.Entry{OrgID: in.OrgID,
			Actor: audit.Actor{Type: audit.ActorGateway, ID: in.GatewayID}, Action: "quota.lease_violation",
			Object: audit.Object{Type: "gateway", ID: in.GatewayID}, Result: audit.ResultFailure,
			Details: map[string]any{"app": slug, "quota": q.Quota, "reason": ReasonOfflineOverclaim,
				"offline": q.Offline, "accepted": units}}); err != nil {
			return err
		}
	}
	id, err := in.NewID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO quota_grants (id, org_id, app_id, quota, kind, gateway_id, request_id, window_key,
		granted, used, granted_at, expires_at, reported_at) VALUES ($1, $2, $3, $4, 'offline', $5, $6, $7, $8, $8, $9, $9, $9)
		ON CONFLICT (org_id, gateway_id, request_id, kind) DO NOTHING`,
		id, in.OrgID, a.id, q.Quota, in.GatewayID, q.RequestID, w.key, units, in.Now)
	return err
}

// budgetBase — расход месяца до включения аренды: при первой выдаче
// бюджета в месяце после смены режима сервер берёт расход из heartbeat
// (budget_usage) одной строкой base. Расход, уже учтённый выдачами в этом
// месяце до повторного включения, считается ещё раз: отказ может наступить
// раньше бюджета, превышения нет.
func (s *PGStore) budgetBase(ctx context.Context, tx pgx.Tx, in LeaseInput, a *appRow, slug string, w window, since *time.Time) error {
	from := time.Time{}
	if since != nil {
		from = *since
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM quota_grants WHERE org_id = $1 AND app_id = $2 AND quota = 'budget'
		AND kind = 'base' AND window_key = $3 AND granted_at >= $4)`, in.OrgID, a.id, w.key, from).Scan(&exists); err != nil || exists {
		return err
	}
	var spent int64
	if err := tx.QueryRow(ctx, `SELECT LEAST(COALESCE(SUM(cost), 0), `+unitsCap+`)::bigint FROM budget_usage
		WHERE org_id = $1 AND month = $2 AND app_slug = $3`, in.OrgID, w.key, slug).Scan(&spent); err != nil {
		return err
	}
	id, err := in.NewID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO quota_grants (id, org_id, app_id, quota, kind, gateway_id, window_key, granted, used,
		granted_at, expires_at, reported_at) VALUES ($1, $2, $3, 'budget', 'base', '', $4, $5, $5, $6, $6, $6)`,
		id, in.OrgID, a.id, w.key, spent, in.Now)
	return err
}

// charged — учтено в окне: выданное по неотчитанным арендам, израсходованное
// по отчитанным, автономный расход и base; oldest — самый ранний срок
// учтённой минутной выдачи (когда освободится её доля).
func (s *PGStore) charged(ctx context.Context, tx pgx.Tx, in LeaseInput, a *appRow, quota string, w window) (int64, time.Time, error) {
	var sum int64
	var oldest *time.Time
	var err error
	if w.key == minuteKey {
		err = tx.QueryRow(ctx, `SELECT LEAST(COALESCE(SUM(COALESCE(used, granted)), 0), `+unitsCap+`)::bigint, min(expires_at)
			FROM quota_grants WHERE org_id = $1 AND app_id = $2 AND quota = $3 AND window_key = 'minute' AND expires_at > $4
			AND COALESCE(used, granted) > 0`,
			in.OrgID, a.id, quota, in.Now.Add(-MinuteWindow)).Scan(&sum, &oldest)
	} else {
		err = tx.QueryRow(ctx, `SELECT LEAST(COALESCE(SUM(COALESCE(used, granted)), 0), `+unitsCap+`)::bigint, NULL::timestamptz
			FROM quota_grants WHERE org_id = $1 AND app_id = $2 AND quota = $3 AND window_key = $4`,
			in.OrgID, a.id, quota, w.key).Scan(&sum, &oldest)
	}
	if oldest == nil {
		return sum, time.Time{}, err
	}
	return sum, *oldest, err
}

// prev — последняя аренда этого шлюза по приложению и квоте.
func (s *PGStore) prev(ctx context.Context, tx pgx.Tx, in LeaseInput, a *appRow, quota string) (*prevGrant, error) {
	var p prevGrant
	var at time.Time
	err := tx.QueryRow(ctx, `SELECT granted, used, granted_at FROM quota_grants WHERE org_id = $1 AND app_id = $2 AND quota = $3
		AND gateway_id = $4 AND kind = 'lease' ORDER BY granted_at DESC LIMIT 1`, in.OrgID, a.id, quota, in.GatewayID).
		Scan(&p.granted, &p.used, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ttl := MinuteTTL
	if quota == QuotaTPD || quota == QuotaBudget {
		ttl = LongTTL
	}
	p.recent = !at.Before(in.Now.Add(-2 * ttl))
	if !p.recent || p.used != nil {
		return &p, nil
	}
	err = tx.QueryRow(ctx, `SELECT count(*) FROM quota_grants WHERE org_id = $1 AND app_id = $2 AND quota = $3
		AND gateway_id = $4 AND kind = 'lease' AND used IS NULL AND granted_at >= $5`,
		in.OrgID, a.id, quota, in.GatewayID, in.Now.Add(-2*ttl)).Scan(&p.unreported)
	return &p, err
}

// retryAfter — когда в окне может освободиться доля: минутное окно — когда
// выйдет самая ранняя учтённая выдача, сутки и месяц — с началом
// следующего.
func retryAfter(w window, now, oldest time.Time) time.Duration {
	if w.key == minuteKey {
		if oldest.IsZero() {
			return w.ttl
		}
		return max(oldest.Add(MinuteWindow).Sub(now), time.Millisecond)
	}
	return max(w.end.Sub(now), time.Millisecond)
}

// Observe — см. Store.
func (s *PGStore) Observe(ctx context.Context, orgID, gatewayID string, autonomous bool, now time.Time) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `INSERT INTO quota_gateway_state (org_id, gateway_id, autonomous, updated_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (org_id, gateway_id) DO UPDATE SET autonomous = EXCLUDED.autonomous, updated_at = EXCLUDED.updated_at`,
		orgID, gatewayID, autonomous, now)
	if err != nil {
		return err
	}
	rows.Close()
	return rows.Err()
}

// Health — см. Store.
func (s *PGStore) Health(ctx context.Context, orgID string, now time.Time) (Health, error) {
	st, err := s.Settings(ctx, orgID, now)
	if err != nil {
		return Health{}, err
	}
	h := Health{Mode: st.Mode, Online: st.GatewaysOnline, Autonomous: []string{}}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT q.gateway_id FROM quota_gateway_state q
		JOIN gateways g ON g.id::text = q.gateway_id AND g.org_id = q.org_id AND g.status = 'active'
		WHERE q.org_id = $1 AND q.autonomous AND q.updated_at > $2 ORDER BY q.gateway_id`, orgID, now.Add(-AutonomousFresh))
	if err != nil {
		return Health{}, err
	}
	h.Autonomous, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if h.Autonomous == nil {
		h.Autonomous = []string{}
	}
	return h, err
}

// Purge — см. Store: выдачи старше двух окон и признаки шлюзов старше суток.
func (s *PGStore) Purge(ctx context.Context, orgID string, now time.Time) (int64, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var n int64
	err := s.db.QueryRow(ctx, `WITH d AS (DELETE FROM quota_grants WHERE id IN (SELECT id FROM quota_grants WHERE org_id = $1
		AND ((window_key = 'minute' AND expires_at < $2) OR (quota = 'tokens_per_day' AND expires_at < $3)
		OR (quota = 'budget' AND expires_at < $4)) LIMIT $5) RETURNING 1) SELECT count(*) FROM d`,
		orgID, now.Add(-2*MinuteWindow), now.Add(-49*time.Hour), now.AddDate(0, -2, -1), purgeBatch).Scan(&n)
	if err != nil {
		return 0, err
	}
	rows, err := s.db.Query(ctx, `DELETE FROM quota_gateway_state WHERE org_id = $1 AND updated_at < $2`, orgID, now.Add(-24*time.Hour))
	if err != nil {
		return n, err
	}
	rows.Close()
	return n, rows.Err()
}

// Record — см. Store.
func (s *PGStore) Record(ctx context.Context, e audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.audit.Record(ctx, e)
}
