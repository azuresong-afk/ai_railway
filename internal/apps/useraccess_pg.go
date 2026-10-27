package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Пользователь приложения по JWT в PostgreSQL (миграция 0057_app_user_access).

const userAccessCols = `app_id::text, org_id::text, mode, issuer, audience, groups_claim, leeway_seconds, model_groups::text,
	updated_at, updated_by`

func scanUserAccess(row pgx.Row) (UserAccess, error) {
	var u UserAccess
	var mg string
	err := row.Scan(&u.AppID, &u.OrgID, &u.Mode, &u.Issuer, &u.Audience, &u.GroupsClaim, &u.Leeway, &mg, &u.UpdatedAt, &u.UpdatedBy)
	if err != nil {
		return UserAccess{}, err
	}
	if err := json.Unmarshal([]byte(mg), &u.ModelGroups); err != nil {
		return UserAccess{}, fmt.Errorf("приложения: model_groups: %w", err)
	}
	if u.ModelGroups == nil {
		u.ModelGroups = map[string][]string{}
	}
	u.Configured, u.UpdatedAt = true, u.UpdatedAt.UTC()
	return u, nil
}

// SetUserAccess — см. Store.
func (s *PGStore) SetUserAccess(ctx context.Context, orgID, appID string,
	fn func(a Application, prev UserAccess) (UserAccess, audit.Entry, error)) (UserAccess, error) {
	var out UserAccess
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// Блокировка приложения упорядочивает и первую запись.
		a, err := lockApp(ctx, tx, orgID, appID)
		if err != nil {
			return err
		}
		prev, err := scanUserAccess(tx.QueryRow(ctx, `SELECT `+userAccessCols+` FROM app_user_access
			WHERE org_id = $1 AND app_id = $2 FOR UPDATE`, orgID, appID))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			prev = DefaultUserAccess(appID, orgID)
		case err != nil:
			return fmt.Errorf("приложения: пользователь по JWT: %w", err)
		}
		next, rec, err := fn(a, prev)
		if errors.Is(err, errUnchanged) {
			out = prev
			return nil
		}
		if err != nil {
			return err
		}
		mg, err := json.Marshal(next.ModelGroups)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO app_user_access (app_id, org_id, mode, issuer, audience, groups_claim, leeway_seconds,
				model_groups, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)
			ON CONFLICT (app_id) DO UPDATE SET mode = EXCLUDED.mode, issuer = EXCLUDED.issuer, audience = EXCLUDED.audience,
				groups_claim = EXCLUDED.groups_claim, leeway_seconds = EXCLUDED.leeway_seconds, model_groups = EXCLUDED.model_groups,
				updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
			appID, orgID, next.Mode, next.Issuer, next.Audience, next.GroupsClaim, next.Leeway, string(mg),
			next.UpdatedAt, next.UpdatedBy); err != nil {
			return fmt.Errorf("приложения: пользователь по JWT: %w", err)
		}
		out = next
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// UserAccess — см. Store.
func (s *PGStore) UserAccess(ctx context.Context, orgID, appID string) (UserAccess, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var exists bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM applications WHERE org_id = $1 AND id = $2)`, orgID, appID).Scan(&exists); err != nil {
		return UserAccess{}, fmt.Errorf("приложения: пользователь по JWT: %w", err)
	}
	if !exists {
		return UserAccess{}, ErrNotFound
	}
	u, err := scanUserAccess(s.db.QueryRow(ctx, `SELECT `+userAccessCols+` FROM app_user_access WHERE org_id = $1 AND app_id = $2`,
		orgID, appID))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return DefaultUserAccess(appID, orgID), nil
	case err != nil:
		return UserAccess{}, fmt.Errorf("приложения: пользователь по JWT: %w", err)
	}
	return u, nil
}

// UserAccessList — см. Store.
func (s *PGStore) UserAccessList(ctx context.Context, orgID string) ([]UserAccess, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+userAccessCols+` FROM app_user_access WHERE org_id = $1 ORDER BY app_id`, orgID)
	if err != nil {
		return nil, fmt.Errorf("приложения: пользователи по JWT: %w", err)
	}
	defer rows.Close()
	var out []UserAccess
	for rows.Next() {
		u, err := scanUserAccess(rows)
		if err != nil {
			return nil, fmt.Errorf("приложения: пользователи по JWT: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
