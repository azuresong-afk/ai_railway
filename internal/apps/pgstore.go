package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

const (
	// pgTimeout — предел на одну операцию, если у контекста нет своего срока.
	pgTimeout = 10 * time.Second
	// pgRollbackTimeout — предел на откат после отмены контекста.
	pgRollbackTimeout = 5 * time.Second
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0014_applications).
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("приложения: нет БД или журнала аудита")
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
		return fmt.Errorf("приложения: начало транзакции: %w", err)
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
		return fmt.Errorf("приложения: фиксация: %w", err)
	}
	return nil
}

func (s *PGStore) record(ctx context.Context, tx pgx.Tx, rec audit.Entry) error {
	if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
		return fmt.Errorf("приложения: %w", err)
	}
	return nil
}

// pgErr переводит нарушения ограничений: уникальность — ErrSlugTaken,
// внешний ключ на провайдера — ErrProviderNotFound.
func pgErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch {
		case pe.Code == "23505":
			return ErrSlugTaken
		case pe.Code == "23503" && pe.ConstraintName == "applications_provider_id_fkey":
			return ErrProviderNotFound
		}
	}
	return err
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func derefS(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefT(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// --- Провайдеры ---

const providerCols = `id::text, org_id::text, slug, name, type, base_url, ca_pem, auth_url, scope, folder_id,
	connect_timeout_s, header_timeout_s, response_timeout_s, stream_idle_timeout_s, external,
	credential, credential_key_id::text, credential_alg, credential_set_at, created_at, created_by, updated_at, updated_by`

func scanProvider(row pgx.Row) (Provider, error) {
	var p Provider
	var authURL, scope, folder, keyID, alg *string
	var cred []byte
	var setAt *time.Time
	if err := row.Scan(&p.ID, &p.OrgID, &p.Slug, &p.Name, &p.Type, &p.BaseURL, &p.CAPEM, &authURL, &scope, &folder,
		&p.ConnectTimeout, &p.HeaderTimeout, &p.ResponseTimeout, &p.StreamIdleTimeout, &p.External,
		&cred, &keyID, &alg, &setAt, &p.CreatedAt, &p.CreatedBy, &p.UpdatedAt, &p.UpdatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Provider{}, ErrNotFound
		}
		return Provider{}, err
	}
	p.AuthURL, p.Scope, p.FolderID = derefS(authURL), derefS(scope), derefS(folder)
	p.CreatedAt, p.UpdatedAt = p.CreatedAt.UTC(), p.UpdatedAt.UTC()
	if cred != nil && keyID != nil && alg != nil && setAt != nil {
		p.Credential = &Sealed{Data: cred, KeyID: *keyID, Alg: *alg, SetAt: setAt.UTC()}
	}
	return p, nil
}

func credCols(p Provider) (data []byte, keyID, alg *string, setAt *time.Time) {
	if p.Credential == nil {
		return nil, nil, nil, nil
	}
	c := p.Credential
	return c.Data, &c.KeyID, &c.Alg, &c.SetAt
}

// CreateProvider — см. Store.
func (s *PGStore) CreateProvider(ctx context.Context, p Provider, rec audit.Entry) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		cred, keyID, alg, setAt := credCols(p)
		_, err := tx.Exec(ctx, `INSERT INTO providers (id, org_id, slug, name, type, base_url, ca_pem, auth_url, scope, folder_id,
			connect_timeout_s, header_timeout_s, response_timeout_s, stream_idle_timeout_s, external,
			credential, credential_key_id, credential_alg, credential_set_at, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)`,
			p.ID, p.OrgID, p.Slug, p.Name, p.Type, p.BaseURL, p.CAPEM, nullStr(p.AuthURL), nullStr(p.Scope), nullStr(p.FolderID),
			p.ConnectTimeout, p.HeaderTimeout, p.ResponseTimeout, p.StreamIdleTimeout, p.External,
			cred, keyID, alg, setAt, p.CreatedAt, p.CreatedBy, p.UpdatedAt, p.UpdatedBy)
		if err != nil {
			return pgErr(err)
		}
		return s.record(ctx, tx, rec)
	})
}

// UpdateProvider — см. Store.
func (s *PGStore) UpdateProvider(ctx context.Context, orgID, id string, fn func(*Provider) (audit.Entry, error)) (Provider, error) {
	var out Provider
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerCols+` FROM providers WHERE org_id = $1 AND id = $2 FOR UPDATE`, orgID, id))
		if err != nil {
			return err
		}
		rec, err := fn(&p)
		if err != nil {
			return err
		}
		cred, keyID, alg, setAt := credCols(p)
		if _, err := tx.Exec(ctx, `UPDATE providers SET name = $3, type = $4, base_url = $5, ca_pem = $6, auth_url = $7,
			scope = $8, folder_id = $9, connect_timeout_s = $10, header_timeout_s = $11, response_timeout_s = $12,
			stream_idle_timeout_s = $13, external = $14, credential = $15, credential_key_id = $16, credential_alg = $17,
			credential_set_at = $18, updated_at = $19, updated_by = $20
			WHERE org_id = $1 AND id = $2`,
			orgID, id, p.Name, p.Type, p.BaseURL, p.CAPEM, nullStr(p.AuthURL), nullStr(p.Scope), nullStr(p.FolderID),
			p.ConnectTimeout, p.HeaderTimeout, p.ResponseTimeout, p.StreamIdleTimeout, p.External,
			cred, keyID, alg, setAt, p.UpdatedAt, p.UpdatedBy); err != nil {
			return pgErr(err)
		}
		out = p
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// DeleteProvider — см. Store.
func (s *PGStore) DeleteProvider(ctx context.Context, orgID, id string, fn func(Provider) (audit.Entry, error)) (Provider, error) {
	var out Provider
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerCols+` FROM providers WHERE org_id = $1 AND id = $2 FOR UPDATE`, orgID, id))
		if err != nil {
			return err
		}
		var used bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM applications WHERE provider_id = $1)`, id).Scan(&used); err != nil {
			return err
		}
		if used {
			return ErrProviderInUse
		}
		rec, err := fn(p)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM providers WHERE org_id = $1 AND id = $2`, orgID, id); err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "23503" {
				return ErrProviderInUse
			}
			return err
		}
		out = p
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// Provider — см. Store.
func (s *PGStore) Provider(ctx context.Context, orgID, id string) (Provider, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanProvider(s.db.QueryRow(ctx, `SELECT `+providerCols+` FROM providers WHERE org_id = $1 AND id = $2`, orgID, id))
}

// Providers — см. Store.
func (s *PGStore) Providers(ctx context.Context, orgID string) ([]Provider, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+providerCols+` FROM providers WHERE org_id = $1 ORDER BY slug LIMIT $2`, orgID, MaxProviders)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Provider{}
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountProviders — см. Store.
func (s *PGStore) CountProviders(ctx context.Context, orgID string) (int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM providers WHERE org_id = $1`, orgID).Scan(&n)
	return n, err
}

// --- Приложения ---

const appCols = `id::text, org_id::text, slug, name, description, department, owner_id::text, env, provider_id::text,
	models, aliases, policy, policy_mode, storage, fail_mode, user_from, quotas, lists, exfil_allow_domains,
	created_at, created_by, updated_at, updated_by, archived_at`

func scanApp(row pgx.Row) (Application, error) {
	var a Application
	var aliases, quotas, ls []byte
	var archived *time.Time
	if err := row.Scan(&a.ID, &a.OrgID, &a.Slug, &a.Name, &a.Description, &a.Department, &a.OwnerID, &a.Env, &a.ProviderID,
		&a.Models, &aliases, &a.Policy, &a.PolicyMode, &a.Storage, &a.FailMode, &a.UserFrom, &quotas, &ls, &a.ExfilAllowDomains,
		&a.CreatedAt, &a.CreatedBy, &a.UpdatedAt, &a.UpdatedBy, &archived); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Application{}, ErrNotFound
		}
		return Application{}, err
	}
	if err := json.Unmarshal(aliases, &a.Aliases); err != nil {
		return Application{}, fmt.Errorf("приложения: aliases: %w", err)
	}
	if err := json.Unmarshal(quotas, &a.Quotas); err != nil {
		return Application{}, fmt.Errorf("приложения: quotas: %w", err)
	}
	if err := json.Unmarshal(ls, &a.Lists); err != nil {
		return Application{}, fmt.Errorf("приложения: lists: %w", err)
	}
	if a.Aliases == nil {
		a.Aliases = map[string]string{}
	}
	if a.Lists == nil {
		a.Lists = []List{}
	}
	if a.ExfilAllowDomains == nil {
		a.ExfilAllowDomains = []string{}
	}
	a.CreatedAt, a.UpdatedAt, a.ArchivedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC(), derefT(archived)
	return a, nil
}

type appJSON struct{ aliases, quotas, lists string }

func encodeApp(a Application) (appJSON, error) {
	aliases := a.Aliases
	if aliases == nil {
		aliases = map[string]string{}
	}
	ls := a.Lists
	if ls == nil {
		ls = []List{}
	}
	var out appJSON
	for _, f := range []struct {
		dst *string
		v   any
	}{{&out.aliases, aliases}, {&out.quotas, a.Quotas}, {&out.lists, ls}} {
		b, err := json.Marshal(f.v)
		if err != nil {
			return appJSON{}, err
		}
		*f.dst = string(b)
	}
	return out, nil
}

func domains(a Application) []string {
	if a.ExfilAllowDomains == nil {
		return []string{}
	}
	return a.ExfilAllowDomains
}

// CreateApplication — см. Store.
func (s *PGStore) CreateApplication(ctx context.Context, a Application, rec audit.Entry) error {
	j, err := encodeApp(a)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		// Провайдер той же организации: внешний ключ не проверяет org_id.
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM providers WHERE org_id = $1 AND id = $2)`, a.OrgID, a.ProviderID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrProviderNotFound
		}
		_, err := tx.Exec(ctx, `INSERT INTO applications (id, org_id, slug, name, description, department, owner_id, env,
			provider_id, models, aliases, policy, policy_mode, storage, fail_mode, user_from, quotas, lists,
			exfil_allow_domains, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13, $14, $15, $16, $17::jsonb, $18::jsonb,
			$19, $20, $21, $22, $23)`,
			a.ID, a.OrgID, a.Slug, a.Name, a.Description, a.Department, a.OwnerID, a.Env, a.ProviderID, a.Models,
			j.aliases, a.Policy, a.PolicyMode, a.Storage, a.FailMode, a.UserFrom, j.quotas, j.lists, domains(a),
			a.CreatedAt, a.CreatedBy, a.UpdatedAt, a.UpdatedBy)
		if err != nil {
			return pgErr(err)
		}
		return s.record(ctx, tx, rec)
	})
}

func lockApp(ctx context.Context, tx pgx.Tx, orgID, id string) (Application, error) {
	return scanApp(tx.QueryRow(ctx, `SELECT `+appCols+` FROM applications WHERE org_id = $1 AND id = $2 FOR UPDATE`, orgID, id))
}

// UpdateApplication — см. Store.
func (s *PGStore) UpdateApplication(ctx context.Context, orgID, id string, fn func(*Application) (audit.Entry, error)) (Application, error) {
	var out Application
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		a, err := lockApp(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		if a.Archived() {
			return ErrArchived
		}
		rec, err := fn(&a)
		if err != nil {
			return err
		}
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM providers WHERE org_id = $1 AND id = $2)`, orgID, a.ProviderID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrProviderNotFound
		}
		j, err := encodeApp(a)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE applications SET name = $3, description = $4, department = $5, owner_id = $6,
			env = $7, provider_id = $8, models = $9, aliases = $10::jsonb, policy = $11, policy_mode = $12, storage = $13,
			fail_mode = $14, user_from = $15, quotas = $16::jsonb, lists = $17::jsonb, exfil_allow_domains = $18,
			updated_at = $19, updated_by = $20
			WHERE org_id = $1 AND id = $2`,
			orgID, id, a.Name, a.Description, a.Department, a.OwnerID, a.Env, a.ProviderID, a.Models, j.aliases,
			a.Policy, a.PolicyMode, a.Storage, a.FailMode, a.UserFrom, j.quotas, j.lists, domains(a),
			a.UpdatedAt, a.UpdatedBy); err != nil {
			return pgErr(err)
		}
		out = a
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// ArchiveApplication — см. Store.
func (s *PGStore) ArchiveApplication(ctx context.Context, orgID, id string, fn func(*Application, int) (audit.Entry, error)) (Application, error) {
	var out Application
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		a, err := lockApp(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		if a.Archived() {
			return ErrArchived
		}
		var open int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM app_keys WHERE app_id = $1 AND revoked_at IS NULL`, id).Scan(&open); err != nil {
			return err
		}
		rec, err := fn(&a, open)
		if err != nil {
			return err
		}
		if !a.Archived() {
			return errImmutable
		}
		if _, err := tx.Exec(ctx, `UPDATE app_keys SET revoked_at = $2, revoked_by = $3 WHERE app_id = $1 AND revoked_at IS NULL`,
			id, a.ArchivedAt, a.UpdatedBy); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE applications SET archived_at = $3, updated_at = $4, updated_by = $5
			WHERE org_id = $1 AND id = $2`, orgID, id, a.ArchivedAt, a.UpdatedAt, a.UpdatedBy); err != nil {
			return err
		}
		out = a
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// Application — см. Store.
func (s *PGStore) Application(ctx context.Context, orgID, id string) (Application, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanApp(s.db.QueryRow(ctx, `SELECT `+appCols+` FROM applications WHERE org_id = $1 AND id = $2`, orgID, id))
}

// Applications — см. Store.
func (s *PGStore) Applications(ctx context.Context, orgID, ownerID string, after *Cursor, limit int) ([]Application, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var afterAt *time.Time
	var afterID *string
	if after != nil {
		afterAt, afterID = &after.CreatedAt, &after.ID
	}
	rows, err := s.db.Query(ctx, `SELECT `+appCols+` FROM applications
		WHERE org_id = $1 AND ($2::uuid IS NULL OR owner_id = $2::uuid)
		  AND ($3::timestamptz IS NULL OR (created_at, id) > ($3::timestamptz, $4::uuid))
		ORDER BY created_at, id LIMIT $5`, orgID, nullStr(ownerID), afterAt, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Application{}
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- Ключи ---

const keyCols = `id::text, org_id::text, app_id::text, name, prefix, key_hash, hash_alg, allowed_cidrs, expires_at,
	created_at, created_by, rotated_from::text, revoked_at, revoked_by`

func scanKey(row pgx.Row) (Key, error) {
	var k Key
	var rotated, revokedBy *string
	var revoked *time.Time
	var cidrs []netip.Prefix
	if err := row.Scan(&k.ID, &k.OrgID, &k.AppID, &k.Name, &k.Prefix, &k.Hash, &k.HashAlg, &cidrs, &k.ExpiresAt,
		&k.CreatedAt, &k.CreatedBy, &rotated, &revoked, &revokedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Key{}, ErrNotFound
		}
		return Key{}, err
	}
	k.AllowedCIDRs = cidrs
	if k.AllowedCIDRs == nil {
		k.AllowedCIDRs = []netip.Prefix{}
	}
	k.RotatedFrom, k.RevokedBy, k.RevokedAt = derefS(rotated), derefS(revokedBy), derefT(revoked)
	k.ExpiresAt, k.CreatedAt = k.ExpiresAt.UTC(), k.CreatedAt.UTC()
	return k, nil
}

func insertKey(ctx context.Context, tx pgx.Tx, k Key) error {
	cidrs := k.AllowedCIDRs
	if cidrs == nil {
		cidrs = []netip.Prefix{}
	}
	_, err := tx.Exec(ctx, `INSERT INTO app_keys (id, org_id, app_id, name, prefix, key_hash, hash_alg, allowed_cidrs,
		expires_at, created_at, created_by, rotated_from) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		k.ID, k.OrgID, k.AppID, k.Name, k.Prefix, k.Hash, k.HashAlg, cidrs, k.ExpiresAt, k.CreatedAt, k.CreatedBy, nullStr(k.RotatedFrom))
	return pgErr(err)
}

// CreateKey — см. Store.
func (s *PGStore) CreateKey(ctx context.Context, orgID, appID string, now time.Time, fn func(Application, int) (Key, audit.Entry, error)) (Key, error) {
	var out Key
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		a, err := lockApp(ctx, tx, orgID, appID)
		if err != nil {
			return err
		}
		var active int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM app_keys WHERE app_id = $1 AND revoked_at IS NULL AND expires_at > $2`,
			appID, now).Scan(&active); err != nil {
			return err
		}
		k, rec, err := fn(a, active)
		if err != nil {
			return err
		}
		if err := insertKey(ctx, tx, k); err != nil {
			return err
		}
		out = k
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// UpdateKey — см. Store.
func (s *PGStore) UpdateKey(ctx context.Context, orgID, id string, now time.Time, fn func(*Key, Application, int) (*Key, audit.Entry, error)) (Key, error) {
	var out Key
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		k, err := scanKey(tx.QueryRow(ctx, `SELECT `+keyCols+` FROM app_keys WHERE org_id = $1 AND id = $2`, orgID, id))
		if err != nil {
			return err
		}
		// Порядок блокировок как в CreateKey: приложение, затем ключ.
		a, err := lockApp(ctx, tx, orgID, k.AppID)
		if err != nil {
			return err
		}
		if k, err = scanKey(tx.QueryRow(ctx, `SELECT `+keyCols+` FROM app_keys WHERE org_id = $1 AND id = $2 FOR UPDATE`, orgID, id)); err != nil {
			return err
		}
		var active int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM app_keys WHERE app_id = $1 AND revoked_at IS NULL AND expires_at > $2`,
			k.AppID, now).Scan(&active); err != nil {
			return err
		}
		created, rec, err := fn(&k, a, active)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE app_keys SET expires_at = $3, revoked_at = $4, revoked_by = $5 WHERE org_id = $1 AND id = $2`,
			orgID, id, k.ExpiresAt, nullTime(k.RevokedAt), nullStr(k.RevokedBy)); err != nil {
			return err
		}
		if created != nil {
			if err := insertKey(ctx, tx, *created); err != nil {
				return err
			}
		}
		out = k
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// Key — см. Store.
func (s *PGStore) Key(ctx context.Context, orgID, id string) (Key, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanKey(s.db.QueryRow(ctx, `SELECT `+keyCols+` FROM app_keys WHERE org_id = $1 AND id = $2`, orgID, id))
}

// ActiveKeys — см. Store.
func (s *PGStore) ActiveKeys(ctx context.Context, orgID string, now time.Time) ([]Key, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+keyCols+` FROM app_keys WHERE org_id = $1 AND revoked_at IS NULL AND expires_at > $2
		ORDER BY app_id, prefix`, orgID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Key{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Keys — см. Store.
func (s *PGStore) Keys(ctx context.Context, orgID, appID string) ([]Key, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+keyCols+` FROM app_keys WHERE org_id = $1 AND app_id = $2
		ORDER BY created_at DESC, id DESC LIMIT $3`, orgID, appID, MaxKeysListed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Key{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
