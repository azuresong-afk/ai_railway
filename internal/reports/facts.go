package reports

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

// ReadDB — чтение PostgreSQL; *pgxpool.Pool ему соответствует.
type ReadDB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// PGFacts — Facts на сервисах приложений, политик, реестра шлюзов и
// таблице отметок аналитиков (миграция 0036). Читает только счётчики.
type PGFacts struct {
	DB       ReadDB
	OrgID    string
	Apps     *apps.Service
	Policies *versions.Service
	Gateways *gwregistry.Service
	// Timeout — предел на одно чтение; 0 — 15 с.
	Timeout time.Duration
}

func (f *PGFacts) ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	t := f.Timeout
	if t <= 0 {
		t = 15 * time.Second
	}
	return context.WithTimeout(ctx, t)
}

// Marks — отметки событий периода по времени события; app задаёт slug.
func (f *PGFacts) Marks(ctx context.Context, from, to time.Time, app string) (MarkStats, error) {
	if f.DB == nil {
		return MarkStats{}, ErrNoSource
	}
	ctx, cancel := f.ctx(ctx)
	defer cancel()
	var out MarkStats
	rows, err := f.DB.Query(ctx, `SELECT m.mark, count(*)::bigint FROM event_marks m
		JOIN events e ON e.org_id = m.org_id AND e.id = m.event_id AND e.ts = m.event_ts
		WHERE m.org_id = $1 AND m.event_ts >= $2 AND m.event_ts < $3 AND ($4::text = '' OR e.app = $4)
		GROUP BY m.mark`, f.OrgID, from.UTC(), to.UTC(), app)
	if err != nil {
		return out, errors.New("отчёты: чтение отметок")
	}
	for rows.Next() {
		var mark string
		var n int64
		if err := rows.Scan(&mark, &n); err != nil {
			rows.Close()
			return out, errors.New("отчёты: чтение отметок")
		}
		switch mark {
		case "false_positive":
			out.FalsePositive = n
		case "confirmed":
			out.Confirmed = n
		}
	}
	if rows.Err() != nil {
		return out, errors.New("отчёты: чтение отметок")
	}
	rows, err = f.DB.Query(ctx, `SELECT t, count(*)::bigint AS n FROM event_marks m
		JOIN events e ON e.org_id = m.org_id AND e.id = m.event_id AND e.ts = m.event_ts
		CROSS JOIN LATERAL unnest(e.threats) AS t
		WHERE m.org_id = $1 AND m.mark = 'false_positive' AND m.event_ts >= $2 AND m.event_ts < $3 AND ($4::text = '' OR e.app = $4)
		GROUP BY t ORDER BY n DESC, t LIMIT $5`, f.OrgID, from.UTC(), to.UTC(), app, TopRows)
	if err != nil {
		return out, errors.New("отчёты: чтение отметок")
	}
	defer rows.Close()
	for rows.Next() {
		var t events.DashTop
		if err := rows.Scan(&t.Key, &t.Value); err != nil {
			return out, errors.New("отчёты: чтение отметок")
		}
		out.FalseByThreat = append(out.FalseByThreat, t)
	}
	if rows.Err() != nil {
		return out, errors.New("отчёты: чтение отметок")
	}
	return out, nil
}

// Inventory — приложения, провайдеры, шлюзы и исключения политик.
func (f *PGFacts) Inventory(ctx context.Context) (Inventory, error) {
	inv := Inventory{AppsByEnv: map[string]int{}}
	if f.Apps == nil {
		return inv, ErrNoSource
	}
	var after *apps.Cursor
	for {
		page, err := f.Apps.Applications(ctx, "", after, 500)
		if err != nil {
			return inv, err
		}
		for _, a := range page {
			if !a.ArchivedAt.IsZero() {
				continue
			}
			inv.Apps++
			inv.AppsByEnv[a.Env]++
		}
		if len(page) < 500 {
			break
		}
		last := page[len(page)-1]
		after = &apps.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	provs, err := f.Apps.Providers(ctx)
	if err != nil {
		return inv, err
	}
	inv.Providers = len(provs)
	for _, p := range provs {
		if p.External {
			inv.ExternalProvs++
		}
	}
	if f.Gateways != nil {
		gws, err := f.Gateways.List(ctx)
		if err != nil {
			return inv, err
		}
		for _, g := range gws {
			if g.Status == gwregistry.StatusActive {
				inv.Gateways++
			}
		}
	}
	if f.Policies != nil {
		list, err := f.Policies.List(ctx)
		if err != nil {
			return inv, err
		}
		for _, s := range list {
			if s.Template {
				continue
			}
			_, ex, err := f.Policies.Exceptions(ctx, s.Slug, 0)
			if err != nil {
				return inv, err
			}
			for _, e := range ex {
				if e.Expired {
					inv.ExceptionsExpired++
				} else {
					inv.ExceptionsActive++
				}
			}
		}
	}
	return inv, nil
}

// Budgets — бюджеты и расход приложений за месяц (YYYY-MM часового пояса установки).
func (f *PGFacts) Budgets(ctx context.Context, month string) ([]BudgetLine, error) {
	if f.Apps == nil {
		return nil, ErrNoSource
	}
	list, _, err := f.Apps.BudgetStatuses(ctx, month)
	if err != nil {
		return nil, err
	}
	out := make([]BudgetLine, 0, len(list))
	for _, st := range list {
		l := BudgetLine{App: st.App.Slug, Spent: apps.FormatCost(st.Cost), Percent: st.Percent, Exhausted: st.Exhausted}
		if st.Budget != nil {
			l.Mode, l.Limit = st.Budget.Mode, apps.FormatMoney(st.Budget.Limit, apps.BudgetDigits)
		}
		out = append(out, l)
	}
	return out, nil
}
