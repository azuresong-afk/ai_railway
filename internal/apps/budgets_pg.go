package apps

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

// Цены, бюджеты и расход на PostgreSQL (миграция 0031_budgets).

const priceCols = `id::text, org_id::text, provider_id::text, model, input_price, output_price,
	created_at, created_by, updated_at, updated_by`

func scanPrice(row pgx.Row) (Price, error) {
	var p Price
	if err := row.Scan(&p.ID, &p.OrgID, &p.ProviderID, &p.Model, &p.Input, &p.Output,
		&p.CreatedAt, &p.CreatedBy, &p.UpdatedAt, &p.UpdatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Price{}, ErrNotFound
		}
		return Price{}, err
	}
	return p, nil
}

const budgetCols = `app_id::text, org_id::text, mode, monthly_limit, created_at, created_by, updated_at, updated_by`

func scanBudget(row pgx.Row) (Budget, error) {
	var b Budget
	if err := row.Scan(&b.AppID, &b.OrgID, &b.Mode, &b.Limit, &b.CreatedAt, &b.CreatedBy, &b.UpdatedAt, &b.UpdatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Budget{}, ErrNoBudget
		}
		return Budget{}, err
	}
	return b, nil
}

// CreatePrice — см. Store.
func (s *PGStore) CreatePrice(ctx context.Context, p Price, rec audit.Entry) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO model_prices (id, org_id, provider_id, model, input_price, output_price,
			created_at, created_by, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			p.ID, p.OrgID, p.ProviderID, p.Model, p.Input, p.Output, p.CreatedAt, p.CreatedBy, p.UpdatedAt, p.UpdatedBy)
		var pe *pgconn.PgError
		switch {
		case errors.As(err, &pe) && pe.Code == "23505":
			return ErrPriceExists
		case errors.As(err, &pe) && pe.Code == "23503":
			return ErrProviderNotFound
		case err != nil:
			return fmt.Errorf("приложения: цена: %w", err)
		}
		return s.record(ctx, tx, rec)
	})
}

// UpdatePrice — см. Store.
func (s *PGStore) UpdatePrice(ctx context.Context, orgID, id string, fn func(*Price) (audit.Entry, error)) (Price, error) {
	var out Price
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		p, err := scanPrice(tx.QueryRow(ctx, `SELECT `+priceCols+` FROM model_prices WHERE org_id = $1 AND id = $2 FOR UPDATE`, orgID, id))
		if err != nil {
			return err
		}
		prev := p
		rec, err := fn(&p)
		if err != nil {
			return err
		}
		if p.ID != prev.ID || p.ProviderID != prev.ProviderID || p.Model != prev.Model {
			return errImmutable
		}
		if _, err := tx.Exec(ctx, `UPDATE model_prices SET input_price = $3, output_price = $4, updated_at = $5, updated_by = $6
			WHERE org_id = $1 AND id = $2`, orgID, id, p.Input, p.Output, p.UpdatedAt, p.UpdatedBy); err != nil {
			return fmt.Errorf("приложения: цена: %w", err)
		}
		out = p
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// DeletePrice — см. Store.
func (s *PGStore) DeletePrice(ctx context.Context, orgID, id string, fn func(Price) (audit.Entry, error)) (Price, error) {
	var out Price
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		p, err := scanPrice(tx.QueryRow(ctx, `SELECT `+priceCols+` FROM model_prices WHERE org_id = $1 AND id = $2 FOR UPDATE`, orgID, id))
		if err != nil {
			return err
		}
		rec, err := fn(p)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM model_prices WHERE org_id = $1 AND id = $2`, orgID, id); err != nil {
			return fmt.Errorf("приложения: цена: %w", err)
		}
		out = p
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// Prices — см. Store.
func (s *PGStore) Prices(ctx context.Context, orgID string) ([]Price, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+priceCols+` FROM model_prices WHERE org_id = $1 ORDER BY provider_id, model`, orgID)
	if err != nil {
		return nil, fmt.Errorf("приложения: цены: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Price, error) { return scanPrice(r) })
	if err != nil {
		return nil, fmt.Errorf("приложения: цены: %w", err)
	}
	return out, nil
}

// SetBudget — см. Store.
func (s *PGStore) SetBudget(ctx context.Context, orgID, appID string, fn func(a Application, prev *Budget) (Budget, audit.Entry, error)) (Budget, error) {
	var out Budget
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		a, err := lockApp(ctx, tx, orgID, appID)
		if err != nil {
			return err
		}
		var prev *Budget
		switch b, err := scanBudget(tx.QueryRow(ctx, `SELECT `+budgetCols+` FROM app_budgets WHERE org_id = $1 AND app_id = $2 FOR UPDATE`,
			orgID, appID)); {
		case err == nil:
			prev = &b
		case !errors.Is(err, ErrNoBudget):
			return err
		}
		next, rec, err := fn(a, prev)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO app_budgets (app_id, org_id, mode, monthly_limit, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (app_id) DO UPDATE SET mode = EXCLUDED.mode, monthly_limit = EXCLUDED.monthly_limit,
				updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
			appID, orgID, next.Mode, next.Limit, next.CreatedAt, next.CreatedBy, next.UpdatedAt, next.UpdatedBy); err != nil {
			return fmt.Errorf("приложения: бюджет: %w", err)
		}
		out = next
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// DeleteBudget — см. Store.
func (s *PGStore) DeleteBudget(ctx context.Context, orgID, appID string, fn func(a Application, b Budget) (audit.Entry, error)) (Budget, error) {
	var out Budget
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		a, err := lockApp(ctx, tx, orgID, appID)
		if err != nil {
			return err
		}
		b, err := scanBudget(tx.QueryRow(ctx, `SELECT `+budgetCols+` FROM app_budgets WHERE org_id = $1 AND app_id = $2 FOR UPDATE`,
			orgID, appID))
		if err != nil {
			return err
		}
		rec, err := fn(a, b)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM app_budgets WHERE org_id = $1 AND app_id = $2`, orgID, appID); err != nil {
			return fmt.Errorf("приложения: бюджет: %w", err)
		}
		out = b
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// Budget — см. Store.
func (s *PGStore) Budget(ctx context.Context, orgID, appID string) (Budget, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanBudget(s.db.QueryRow(ctx, `SELECT `+budgetCols+` FROM app_budgets WHERE org_id = $1 AND app_id = $2`, orgID, appID))
}

// Budgets — см. Store.
func (s *PGStore) Budgets(ctx context.Context, orgID string) ([]Budget, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+budgetCols+` FROM app_budgets WHERE org_id = $1 ORDER BY app_id`, orgID)
	if err != nil {
		return nil, fmt.Errorf("приложения: бюджеты: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Budget, error) { return scanBudget(r) })
	if err != nil {
		return nil, fmt.Errorf("приложения: бюджеты: %w", err)
	}
	return out, nil
}

// SaveUsage — см. Store. Одна инструкция на все строки: счётчики
// неизвестных приложений не вставляются, существующие растут только вверх.
func (s *PGStore) SaveUsage(ctx context.Context, orgID, gatewayID string, startedAt time.Time, months []gwregistry.BudgetMonth, now time.Time) error {
	var apps, mons []string
	var cost, pt, ut, req, ureq []int64
	for _, m := range months {
		for _, u := range m.Apps {
			apps, mons = append(apps, u.App), append(mons, m.Month)
			cost, pt, ut = append(cost, u.Cost), append(pt, u.PricedTokens), append(ut, u.UnpricedTokens)
			req, ureq = append(req, u.Requests), append(ureq, u.UnpricedRequests)
		}
	}
	if len(apps) == 0 {
		return nil
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		return saveUsage(ctx, tx, orgID, gatewayID, startedAt, now, apps, mons, cost, pt, ut, req, ureq)
	})
}

func saveUsage(ctx context.Context, tx pgx.Tx, orgID, gatewayID string, startedAt, now time.Time, apps, mons []string,
	cost, pt, ut, req, ureq []int64) error {
	_, err := tx.Exec(ctx, `INSERT INTO budget_usage (org_id, gateway_id, started_at, app_slug, month, cost, priced_tokens,
			unpriced_tokens, requests, unpriced_requests, updated_at)
		SELECT $1, $2, $3, u.app, u.month, u.cost, u.pt, u.ut, u.req, u.ureq, $4
		FROM unnest($5::text[], $6::text[], $7::bigint[], $8::bigint[], $9::bigint[], $10::bigint[], $11::bigint[])
			AS u (app, month, cost, pt, ut, req, ureq)
		WHERE EXISTS (SELECT 1 FROM applications a WHERE a.org_id = $1 AND a.slug = u.app)
		ON CONFLICT (org_id, month, app_slug, gateway_id, started_at) DO UPDATE SET
			cost = GREATEST(budget_usage.cost, EXCLUDED.cost),
			priced_tokens = GREATEST(budget_usage.priced_tokens, EXCLUDED.priced_tokens),
			unpriced_tokens = GREATEST(budget_usage.unpriced_tokens, EXCLUDED.unpriced_tokens),
			requests = GREATEST(budget_usage.requests, EXCLUDED.requests),
			unpriced_requests = GREATEST(budget_usage.unpriced_requests, EXCLUDED.unpriced_requests),
			updated_at = EXCLUDED.updated_at`,
		orgID, gatewayID, startedAt, now, apps, mons, cost, pt, ut, req, ureq)
	if err != nil {
		return fmt.Errorf("приложения: расход: %w", err)
	}
	return nil
}

// Суммы bigint в PostgreSQL — numeric: ограничиваются int64 (LEAST).

// HardUsageOthers — см. Store.
func (s *PGStore) HardUsageOthers(ctx context.Context, orgID, month, gatewayID string, startedAt time.Time) (map[string]int64, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT a.slug, LEAST(COALESCE(sum(u.cost), 0), 9223372036854775807)::bigint
		FROM app_budgets b
		JOIN applications a ON a.id = b.app_id
		LEFT JOIN budget_usage u ON u.org_id = b.org_id AND u.month = $2 AND u.app_slug = a.slug
			AND NOT (u.gateway_id = $3 AND u.started_at = $4)
		WHERE b.org_id = $1 AND b.mode = 'hard'
		GROUP BY a.slug`, orgID, month, gatewayID, startedAt)
	if err != nil {
		return nil, fmt.Errorf("приложения: расход: %w", err)
	}
	out := map[string]int64{}
	var slug string
	var v int64
	if _, err := pgx.ForEachRow(rows, []any{&slug, &v}, func() error { out[slug] = v; return nil }); err != nil {
		return nil, fmt.Errorf("приложения: расход: %w", err)
	}
	return out, nil
}

// PruneUsage — см. Store.
func (s *PGStore) PruneUsage(ctx context.Context, orgID, before string) (int64, error) {
	var n int64
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM budget_usage WHERE org_id = $1 AND month < $2", orgID, before)
		if err != nil {
			return fmt.Errorf("приложения: срок хранения расхода: %w", err)
		}
		n = tag.RowsAffected()
		return nil
	})
	return n, err
}

// Usage — см. Store.
func (s *PGStore) Usage(ctx context.Context, orgID, month string) (map[string]Usage, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT app_slug,
			LEAST(sum(cost), 9223372036854775807)::bigint,
			LEAST(sum(priced_tokens), 9223372036854775807)::bigint,
			LEAST(sum(unpriced_tokens), 9223372036854775807)::bigint,
			LEAST(sum(requests), 9223372036854775807)::bigint,
			LEAST(sum(unpriced_requests), 9223372036854775807)::bigint
		FROM budget_usage WHERE org_id = $1 AND month = $2 GROUP BY app_slug`, orgID, month)
	if err != nil {
		return nil, fmt.Errorf("приложения: расход: %w", err)
	}
	out := map[string]Usage{}
	var slug string
	var u Usage
	if _, err := pgx.ForEachRow(rows, []any{&slug, &u.Cost, &u.PricedTokens, &u.UnpricedTokens, &u.Requests, &u.UnpricedRequests},
		func() error { out[slug] = u; return nil }); err != nil {
		return nil, fmt.Errorf("приложения: расход: %w", err)
	}
	return out, nil
}
