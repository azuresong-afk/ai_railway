package auth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// PGAPITokens — APITokenStore на PostgreSQL (миграция 0012_api_tokens).
// Записи аудита выпуска и отзыва пишутся в той же транзакции.
type PGAPITokens struct {
	pg *PGStore
}

// NewPGAPITokens создаёт хранилище токенов; журнал должен работать через тот же пул.
func NewPGAPITokens(db PGDB, a *audit.Log) (*PGAPITokens, error) {
	s, err := NewPGStore(db, a)
	if err != nil {
		return nil, fmt.Errorf("токены API: %w", err)
	}
	return &PGAPITokens{pg: s}, nil
}

var _ APITokenStore = (*PGAPITokens)(nil)

const patCols = `t.id::text, t.org_id::text, t.user_id::text, t.name, t.prefix, t.token_hash, t.hash_alg,
	t.permissions, t.expires_at, t.created_at, t.last_used_at, host(t.last_used_ip), t.revoked_at,
	t.revoked_by::text, t.revoke_reason`

// apiTokenScan — назначения столбцов patCols и разбор после Scan.
type apiTokenScan struct {
	t                 APIToken
	perms             []string
	lastUsed, revoked *time.Time
	ip, by, revReason *string
}

func (d *apiTokenScan) dst() []any {
	return []any{&d.t.ID, &d.t.OrgID, &d.t.UserID, &d.t.Name, &d.t.Prefix, &d.t.Hash, &d.t.HashAlg,
		&d.perms, &d.t.ExpiresAt, &d.t.CreatedAt, &d.lastUsed, &d.ip, &d.revoked, &d.by, &d.revReason}
}

func (d *apiTokenScan) finish() APIToken {
	t := d.t
	t.Grants = parseTokenGrants(d.perms)
	t.LastUsedAt, t.RevokedAt = deref(d.lastUsed), deref(d.revoked)
	if d.ip != nil {
		if a, err := netip.ParseAddr(*d.ip); err == nil {
			t.LastUsedIP = a
		}
	}
	if d.by != nil {
		t.RevokedBy = *d.by
	}
	if d.revReason != nil {
		t.RevokeReason = *d.revReason
	}
	return t
}

// formatTokenGrants — область токена для столбца permissions.
func formatTokenGrants(g Grants) []string { return grantList(g) }

// parseTokenGrants разбирает столбец permissions. Разрешения не из
// каталога, недопустимые для токена и неизвестные области пропускаются:
// прав они не дают.
func parseTokenGrants(perms []string) Grants {
	g := Grants{}
	for _, e := range perms {
		perm, scope, ok := strings.Cut(e, ":")
		if !ok || !TokenGrantable(perm) {
			continue
		}
		addGrant(g, perm, scope)
	}
	return g
}

func scanAPIToken(row pgx.Row) (APIToken, error) {
	var d apiTokenScan
	if err := row.Scan(d.dst()...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return APIToken{}, ErrAPITokenNotFound
		}
		return APIToken{}, fmt.Errorf("токены API: разбор: %w", err)
	}
	return d.finish(), nil
}

// CreateAPIToken сохраняет токен под блокировкой строки владельца: параллельные
// выпуски не превысят MaxAPITokensPerUser.
func (s *PGAPITokens) CreateAPIToken(ctx context.Context, t APIToken, fn func(owner Actor) (audit.Entry, error)) error {
	if !validUUID(t.UserID) {
		return ErrNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.pg.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM users WHERE org_id = $1 AND id = $2 FOR UPDATE", t.OrgID, t.UserID); err != nil {
			return fmt.Errorf("токены API: владелец: %w", err)
		}
		owner, err := loadActor(ctx, tx, t.OrgID, t.UserID, false)
		if err != nil {
			return err
		}
		rec, err := fn(owner)
		if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2`,
			t.UserID, t.CreatedAt).Scan(&n); err != nil {
			return fmt.Errorf("токены API: число: %w", err)
		}
		if n >= MaxAPITokensPerUser {
			return ErrTooManyAPITokens
		}
		if _, err := tx.Exec(ctx, `INSERT INTO api_tokens (id, org_id, user_id, name, prefix, token_hash, hash_alg,
			permissions, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			t.ID, t.OrgID, t.UserID, t.Name, t.Prefix, t.Hash, t.HashAlg, formatTokenGrants(t.Grants),
			t.ExpiresAt, t.CreatedAt); err != nil {
			return fmt.Errorf("токены API: выпуск: %w", err)
		}
		return s.pg.record(ctx, tx, rec)
	})
}

// APITokenByPrefix — токен и владелец одним запросом.
func (s *PGAPITokens) APITokenByPrefix(ctx context.Context, prefix string) (APIToken, User, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var d apiTokenScan
	u, err := scanUser(s.pg.db.QueryRow(ctx, "SELECT "+userCols+", "+patCols+
		" FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.prefix = $1", prefix), d.dst()...)
	if err != nil {
		return APIToken{}, User{}, err
	}
	return d.finish(), u, nil
}

// APITokenByID — токен организации.
func (s *PGAPITokens) APITokenByID(ctx context.Context, orgID, id string) (APIToken, error) {
	if !validUUID(id) {
		return APIToken{}, ErrAPITokenNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanAPIToken(s.pg.db.QueryRow(ctx, "SELECT "+patCols+" FROM api_tokens t WHERE t.org_id = $1 AND t.id = $2", orgID, id))
}

// ListAPITokens — страница токенов по (created_at, id).
func (s *PGAPITokens) ListAPITokens(ctx context.Context, orgID, userID string, after *UserCursor, limit int) ([]APIToken, error) {
	if userID != "" && !validUUID(userID) {
		return nil, nil
	}
	var (
		afterAt *time.Time
		afterID *string
	)
	if after != nil {
		if _, err := store.ParseUUID(after.ID); err != nil {
			return nil, nil
		}
		afterAt, afterID = &after.CreatedAt, &after.ID
	}
	var user *string
	if userID != "" {
		user = &userID
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.pg.db.Query(ctx, "SELECT "+patCols+` FROM api_tokens t
		WHERE t.org_id = $1 AND ($2::uuid IS NULL OR t.user_id = $2::uuid)
		AND ($3::timestamptz IS NULL OR (t.created_at, t.id) > ($3::timestamptz, $4::uuid))
		ORDER BY t.created_at, t.id LIMIT $5`, orgID, user, afterAt, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("токены API: список: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (APIToken, error) { return scanAPIToken(r) })
	if err != nil {
		return nil, fmt.Errorf("токены API: список: %w", err)
	}
	return out, nil
}

// TouchAPIToken отмечает использование; у отозванного токена отметка не меняется.
func (s *PGAPITokens) TouchAPIToken(ctx context.Context, id string, now time.Time, ip netip.Addr) error {
	var addr *string
	if ip.IsValid() {
		a := ip.WithZone("").Unmap().String()
		addr = &a
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	if _, err := s.pg.db.Exec(ctx, `UPDATE api_tokens SET last_used_at = $2, last_used_ip = $3::inet
		WHERE id = $1 AND revoked_at IS NULL`, id, now, addr); err != nil {
		return fmt.Errorf("токены API: отметка использования: %w", err)
	}
	return nil
}

// RevokeAPIToken отзывает токен под блокировкой: строки владельца (FOR
// SHARE), затем токена — тот же порядок, что у выпуска.
func (s *PGAPITokens) RevokeAPIToken(ctx context.Context, orgID, id, byID string, now time.Time,
	fn func(t APIToken, owner User) (string, audit.Entry, error)) (APIToken, error) {
	if !validUUID(id) {
		return APIToken{}, ErrAPITokenNotFound
	}
	var by *string
	if validUUID(byID) {
		by = &byID
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var out APIToken
	err := s.pg.inTx(ctx, func(tx pgx.Tx) error {
		var userID string
		err := tx.QueryRow(ctx, "SELECT user_id::text FROM api_tokens WHERE org_id = $1 AND id = $2", orgID, id).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAPITokenNotFound
		}
		if err != nil {
			return fmt.Errorf("токены API: отзыв: %w", err)
		}
		owner, err := scanUser(tx.QueryRow(ctx, "SELECT "+userCols+" FROM users u WHERE u.id = $1 FOR SHARE", userID))
		if err != nil {
			return err
		}
		t, err := scanAPIToken(tx.QueryRow(ctx, "SELECT "+patCols+" FROM api_tokens t WHERE t.id = $1 FOR UPDATE", id))
		if err != nil {
			return err
		}
		reason, rec, err := fn(t, owner)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at = $2, revoked_by = $3::uuid, revoke_reason = $4
			WHERE id = $1`, id, now, by, reason); err != nil {
			return fmt.Errorf("токены API: отзыв: %w", err)
		}
		t.RevokedAt, t.RevokeReason = now, reason
		if by != nil {
			t.RevokedBy = *by
		}
		out = t
		return s.pg.record(ctx, tx, rec)
	})
	return out, err
}
