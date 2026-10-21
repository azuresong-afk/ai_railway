package gwregistry

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

const (
	// pgTimeout — предел на одну операцию, если у контекста нет своего срока.
	pgTimeout = 10 * time.Second
	// pgRollbackTimeout — предел на откат после отмены контекста.
	pgRollbackTimeout = 5 * time.Second
	// maxListed — предел выборки списка шлюзов.
	maxListed = 1000
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0007_gateways).
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("реестр шлюзов: нет БД или журнала аудита")
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
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("реестр шлюзов: начало транзакции: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после коммита безвреден, ошибку скрывает исходная
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("реестр шлюзов: фиксация: %w", err)
	}
	return nil
}

const gatewayCols = `id::text, org_id::text, name, status, created_at, created_by, registered_at, revoked_at,
	cert_serial, cert_not_after, last_seen_at, host(last_addr), version, bundle_etag`

func scanGateway(row pgx.Row) (Gateway, error) {
	var g Gateway
	var registered, revoked, notAfter, seen *time.Time
	var serial, addr, version, etag *string
	if err := row.Scan(&g.ID, &g.OrgID, &g.Name, &g.Status, &g.CreatedAt, &g.CreatedBy, &registered, &revoked,
		&serial, &notAfter, &seen, &addr, &version, &etag); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Gateway{}, ErrNotFound
		}
		return Gateway{}, err
	}
	g.RegisteredAt, g.RevokedAt, g.CertNotAfter, g.LastSeenAt = deref(registered), deref(revoked), deref(notAfter), deref(seen)
	g.CertSerial, g.Version, g.BundleETag = derefS(serial), derefS(version), derefS(etag)
	if addr != nil {
		if a, err := netip.ParseAddr(*addr); err == nil {
			g.LastAddr = a
		}
	}
	return g, nil
}

func deref(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func derefS(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (s *PGStore) record(ctx context.Context, tx pgx.Tx, rec audit.Entry) error {
	if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
		return fmt.Errorf("реестр шлюзов: %w", err)
	}
	return nil
}

// CreateToken — см. Store. Выполняется под логином владельца схемы (aisec-cli).
func (s *PGStore) CreateToken(ctx context.Context, t NewToken, rec func(Gateway) audit.Entry) (Gateway, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var gw Gateway
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		gw, err = scanGateway(tx.QueryRow(ctx, "SELECT "+gatewayCols+" FROM gateways WHERE org_id = $1 AND name = $2 FOR UPDATE",
			t.OrgID, t.Name))
		switch {
		case errors.Is(err, ErrNotFound) && t.Reregister:
			return ErrNotFound
		case errors.Is(err, ErrNotFound):
			gw, err = scanGateway(tx.QueryRow(ctx, `INSERT INTO gateways (id, org_id, name, status, created_at, created_by)
				VALUES ($1, $2, $3, 'pending', $4, $5) ON CONFLICT (org_id, name) DO NOTHING RETURNING `+gatewayCols,
				t.GatewayID, t.OrgID, t.Name, t.CreatedAt, t.CreatedBy))
			if errors.Is(err, ErrNotFound) {
				return ErrNameTaken // параллельный выпуск с тем же именем
			}
			if err != nil {
				return fmt.Errorf("реестр шлюзов: создание: %w", err)
			}
		case err != nil:
			return fmt.Errorf("реестр шлюзов: %w", err)
		case !t.Reregister:
			return ErrNameTaken
		case gw.Status == StatusRevoked:
			return ErrRevoked
		}
		if _, err := tx.Exec(ctx, "UPDATE gateway_tokens SET used_at = $2 WHERE gateway_id = $1 AND used_at IS NULL",
			gw.ID, t.CreatedAt); err != nil {
			return fmt.Errorf("реестр шлюзов: прежние токены: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO gateway_tokens (id, gateway_id, hash_alg, token_hash, created_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)`, t.TokenID, gw.ID, t.HashAlg, t.Hash, t.CreatedAt, t.ExpiresAt); err != nil {
			return fmt.Errorf("реестр шлюзов: токен: %w", err)
		}
		return s.record(ctx, tx, rec(gw))
	})
	return gw, err
}

// Register — см. Store. Токен блокируется строкой (FOR UPDATE): из
// параллельных регистраций с одним токеном пройдёт ровно одна.
func (s *PGStore) Register(ctx context.Context, hashAlg string, hash []byte, now time.Time,
	issue func(Gateway) (aisecCrypto.CertInfo, error), rec func(Gateway) audit.Entry) (Gateway, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var gw Gateway
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var tokenID, gatewayID string
		var stored []byte
		err := tx.QueryRow(ctx, `SELECT t.id::text, t.gateway_id::text, t.token_hash FROM gateway_tokens t
			JOIN gateways g ON g.id = t.gateway_id
			WHERE t.token_hash = $1 AND t.hash_alg = $2 AND t.used_at IS NULL AND t.expires_at > $3 AND g.status <> 'revoked'
			FOR UPDATE OF t, g`, hash, hashAlg, now).Scan(&tokenID, &gatewayID, &stored)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenInvalid
		}
		if err != nil {
			return fmt.Errorf("реестр шлюзов: токен: %w", err)
		}
		// Хеш уже совпал в индексе; сверка за постоянное время — вторая линия.
		if !aisecCrypto.Equal(stored, hash) {
			return ErrTokenInvalid
		}
		if _, err := tx.Exec(ctx, "UPDATE gateway_tokens SET used_at = $2 WHERE id = $1", tokenID, now); err != nil {
			return fmt.Errorf("реестр шлюзов: погашение токена: %w", err)
		}
		cur, err := scanGateway(tx.QueryRow(ctx, "SELECT "+gatewayCols+" FROM gateways WHERE id = $1", gatewayID))
		if err != nil {
			return fmt.Errorf("реестр шлюзов: %w", err)
		}
		info, err := issue(cur)
		if err != nil {
			return err
		}
		gw, err = scanGateway(tx.QueryRow(ctx, `UPDATE gateways SET status = 'active', registered_at = $2,
			cert_serial = $3, cert_not_after = $4 WHERE id = $1 RETURNING `+gatewayCols,
			gatewayID, now, info.Serial, info.NotAfter))
		if err != nil {
			return fmt.Errorf("реестр шлюзов: регистрация: %w", err)
		}
		return s.record(ctx, tx, rec(gw))
	})
	return gw, err
}

// BySerial — см. Store.
func (s *PGStore) BySerial(ctx context.Context, serial string) (Gateway, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanGateway(s.db.QueryRow(ctx, "SELECT "+gatewayCols+" FROM gateways WHERE cert_serial = $1", serial))
}

// Touch — см. Store.
func (s *PGStore) Touch(ctx context.Context, id string, hb Heartbeat) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var addr *string
	if hb.Addr.IsValid() {
		a := hb.Addr.Unmap().String()
		addr = &a
	}
	tag, err := s.db.Exec(ctx, `UPDATE gateways SET last_seen_at = $2, last_addr = $3::inet, version = $4, bundle_etag = $5
		WHERE id = $1 AND status = 'active'`, id, hb.At, addr, hb.Version, nullStr(hb.BundleETag))
	if err != nil {
		return fmt.Errorf("реестр шлюзов: heartbeat: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Revoke — см. Store. Выполняется под логином владельца схемы (aisec-cli).
func (s *PGStore) Revoke(ctx context.Context, orgID, name string, now time.Time, rec func(Gateway) audit.Entry) (Gateway, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var gw Gateway
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		cur, err := scanGateway(tx.QueryRow(ctx, "SELECT "+gatewayCols+" FROM gateways WHERE org_id = $1 AND name = $2 FOR UPDATE", orgID, name))
		if err != nil {
			return err
		}
		if cur.Status == StatusRevoked {
			return ErrRevoked
		}
		if _, err := tx.Exec(ctx, "UPDATE gateway_tokens SET used_at = $2 WHERE gateway_id = $1 AND used_at IS NULL", cur.ID, now); err != nil {
			return fmt.Errorf("реестр шлюзов: токены: %w", err)
		}
		gw, err = scanGateway(tx.QueryRow(ctx, "UPDATE gateways SET status = 'revoked', revoked_at = $2 WHERE id = $1 RETURNING "+gatewayCols,
			cur.ID, now))
		if err != nil {
			return fmt.Errorf("реестр шлюзов: отзыв: %w", err)
		}
		return s.record(ctx, tx, rec(gw))
	})
	return gw, err
}

// List — см. Store.
func (s *PGStore) List(ctx context.Context, orgID string) ([]Gateway, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, "SELECT "+gatewayCols+" FROM gateways WHERE org_id = $1 ORDER BY name LIMIT $2", orgID, maxListed)
	if err != nil {
		return nil, fmt.Errorf("реестр шлюзов: список: %w", err)
	}
	defer rows.Close()
	var out []Gateway
	for rows.Next() {
		g, err := scanGateway(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
