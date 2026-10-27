package apps

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Эталоны системного промпта в PostgreSQL (миграция 0051_prompt_baselines).

const promptCols = `app_id::text, org_id::text, mode, hash, text_bytes, text_sealed, text_key_id::text, text_alg,
	created_at, created_by, updated_at, updated_by`

func scanPrompt(row pgx.Row) (PromptBaseline, error) {
	var b PromptBaseline
	err := row.Scan(&b.AppID, &b.OrgID, &b.Mode, &b.Hash, &b.Size, &b.Text.Data, &b.Text.KeyID, &b.Text.Alg,
		&b.CreatedAt, &b.CreatedBy, &b.UpdatedAt, &b.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return PromptBaseline{}, ErrNoPromptBaseline
	}
	if err != nil {
		return PromptBaseline{}, fmt.Errorf("приложения: эталон системного промпта: %w", err)
	}
	b.CreatedAt, b.UpdatedAt = b.CreatedAt.UTC(), b.UpdatedAt.UTC()
	b.Text.SetAt = b.UpdatedAt
	return b, nil
}

// SetPromptBaseline — см. Store.
func (s *PGStore) SetPromptBaseline(ctx context.Context, orgID, appID string,
	fn func(a Application, prev *PromptBaseline) (PromptBaseline, audit.Entry, error)) (PromptBaseline, error) {
	var out PromptBaseline
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// Блокировка приложения упорядочивает и первую запись эталона.
		a, err := lockApp(ctx, tx, orgID, appID)
		if err != nil {
			return err
		}
		var prev *PromptBaseline
		switch b, err := scanPrompt(tx.QueryRow(ctx, `SELECT `+promptCols+` FROM prompt_baselines WHERE org_id = $1 AND app_id = $2 FOR UPDATE`,
			orgID, appID)); {
		case err == nil:
			prev = &b
		case !errors.Is(err, ErrNoPromptBaseline):
			return err
		}
		next, rec, err := fn(a, prev)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO prompt_baselines (app_id, org_id, mode, hash, text_bytes, text_sealed, text_key_id, text_alg,
				created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (app_id) DO UPDATE SET mode = EXCLUDED.mode, hash = EXCLUDED.hash, text_bytes = EXCLUDED.text_bytes,
				text_sealed = EXCLUDED.text_sealed, text_key_id = EXCLUDED.text_key_id, text_alg = EXCLUDED.text_alg,
				updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
			appID, orgID, next.Mode, next.Hash, next.Size, next.Text.Data, next.Text.KeyID, next.Text.Alg,
			next.CreatedAt, next.CreatedBy, next.UpdatedAt, next.UpdatedBy); err != nil {
			return fmt.Errorf("приложения: эталон системного промпта: %w", err)
		}
		out = next
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// DeletePromptBaseline — см. Store.
func (s *PGStore) DeletePromptBaseline(ctx context.Context, orgID, appID string,
	fn func(a Application, b PromptBaseline) (audit.Entry, error)) (PromptBaseline, error) {
	var out PromptBaseline
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		a, err := lockApp(ctx, tx, orgID, appID)
		if err != nil {
			return err
		}
		b, err := scanPrompt(tx.QueryRow(ctx, `SELECT `+promptCols+` FROM prompt_baselines WHERE org_id = $1 AND app_id = $2 FOR UPDATE`,
			orgID, appID))
		if err != nil {
			return err
		}
		rec, err := fn(a, b)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM prompt_baselines WHERE org_id = $1 AND app_id = $2`, orgID, appID); err != nil {
			return fmt.Errorf("приложения: эталон системного промпта: %w", err)
		}
		out = b
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// PromptBaseline — см. Store.
func (s *PGStore) PromptBaseline(ctx context.Context, orgID, appID string) (PromptBaseline, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var exists bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM applications WHERE org_id = $1 AND id = $2)`, orgID, appID).Scan(&exists); err != nil {
		return PromptBaseline{}, fmt.Errorf("приложения: эталон системного промпта: %w", err)
	}
	if !exists {
		return PromptBaseline{}, ErrNotFound
	}
	return scanPrompt(s.db.QueryRow(ctx, `SELECT `+promptCols+` FROM prompt_baselines WHERE org_id = $1 AND app_id = $2`, orgID, appID))
}

// PromptBaselines — см. Store.
func (s *PGStore) PromptBaselines(ctx context.Context, orgID string) ([]PromptBaseline, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+promptCols+` FROM prompt_baselines WHERE org_id = $1 ORDER BY app_id`, orgID)
	if err != nil {
		return nil, fmt.Errorf("приложения: эталоны системного промпта: %w", err)
	}
	defer rows.Close()
	var out []PromptBaseline
	for rows.Next() {
		b, err := scanPrompt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
