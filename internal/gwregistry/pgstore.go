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
	cert_serial, cert_not_after, last_seen_at, host(last_addr), version, bundle_etag,
	selftest_ok, selftest_at, selftest_failed, integrity_ok, integrity_at, integrity_reason, integrity_failed,
	manifest_version, manifest_created, manifest_max_version, manifest_max_created, test_signed, bundle_keys_ok,
	verify_requested_at, started_at, cert_ca, next_cert_serial, next_cert_not_after, next_cert_ca, bundle_key`

func scanGateway(row pgx.Row) (Gateway, error) {
	var g Gateway
	var registered, revoked, notAfter, seen *time.Time
	var serial, addr, version, etag, integrityReason *string
	var stOK, inOK *bool
	var stAt, inAt *time.Time
	var stFailed, inFailed *int
	var mVersion, mMaxVersion *string
	var mCreated, mMaxCreated *time.Time
	var testSigned *bool
	var verifyReq, started *time.Time
	var certCA, nextSerial, nextCA *string
	var nextNotAfter *time.Time
	if err := row.Scan(&g.ID, &g.OrgID, &g.Name, &g.Status, &g.CreatedAt, &g.CreatedBy, &registered, &revoked,
		&serial, &notAfter, &seen, &addr, &version, &etag,
		&stOK, &stAt, &stFailed, &inOK, &inAt, &integrityReason, &inFailed,
		&mVersion, &mCreated, &mMaxVersion, &mMaxCreated, &testSigned, &g.BundleKeysOK, &verifyReq, &started,
		&certCA, &nextSerial, &nextNotAfter, &nextCA, &g.BundleKey); err != nil {
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
	if stOK != nil && stAt != nil && stFailed != nil {
		g.Selftest = &CheckReport{OK: *stOK, At: *stAt, Failed: *stFailed}
	}
	if inOK != nil && inAt != nil && inFailed != nil && integrityReason != nil {
		g.Integrity = &CheckReport{OK: *inOK, At: *inAt, Reason: *integrityReason, Failed: *inFailed,
			ManifestVersion: derefS(mVersion), ManifestCreated: deref(mCreated), TestSigned: testSigned != nil && *testSigned}
	}
	g.ManifestMaxVersion, g.ManifestMaxCreated = derefS(mMaxVersion), deref(mMaxCreated)
	g.VerifyRequestedAt, g.StartedAt = deref(verifyReq), deref(started)
	g.CertCA, g.NextCertSerial, g.NextCertNotAfter, g.NextCertCA = derefS(certCA), derefS(nextSerial), deref(nextNotAfter), derefS(nextCA)
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

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
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

// ExpireTokensForRestoreTx гасит все непогашенные токены регистрации
// шлюзов организации в транзакции tx (3В21 ревью 3.r3, РВ.2). Полная копия
// возвращает токены в состояние на момент копии, в том числе погашенные
// позже регистрацией: без этого токен, выпущенный до копии, снова годен до
// своего срока, и тот, кто видел его при передаче, регистрирует свой шлюз
// или перехватывает личность действующего (-reregister). Шлюзы,
// зарегистрированные после копии, регистрируются заново новым токеном.
// Триггер gateway_tokens_guard разрешает только отметку о погашении; время
// не раньше выпуска (CHECK used_at >= created_at). Возвращает число
// погашенных; запись аудита пишет вызывающий в той же транзакции.
func ExpireTokensForRestoreTx(ctx context.Context, tx pgx.Tx, orgID string, now time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE gateway_tokens t SET used_at = greatest($2::timestamptz, t.created_at)
		FROM gateways g WHERE g.id = t.gateway_id AND g.org_id = $1 AND t.used_at IS NULL`, orgID, now)
	if err != nil {
		return 0, fmt.Errorf("реестр шлюзов: погашение токенов регистрации: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Register — см. Store. Токен блокируется строкой (FOR UPDATE): из
// параллельных регистраций с одним токеном пройдёт ровно одна.
func (s *PGStore) Register(ctx context.Context, hashAlg string, hash []byte, now time.Time,
	issue func(Gateway) (Issued, error), rec func(Gateway) audit.Entry) (Gateway, error) {
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
		iss, err := issue(cur)
		if err != nil {
			return err
		}
		// Новая регистрация закрепляет ключ получателя заново (Н27): триггер
		// разрешает смену только вместе с registered_at.
		gw, err = scanGateway(tx.QueryRow(ctx, `UPDATE gateways SET status = 'active', registered_at = $2,
			cert_serial = $3, cert_not_after = $4, cert_ca = $5, bundle_key = $6,
			next_cert_serial = NULL, next_cert_not_after = NULL, next_cert_ca = NULL WHERE id = $1 RETURNING `+gatewayCols,
			gatewayID, now, iss.Info.Serial, iss.Info.NotAfter, nullStr(iss.CA), iss.BundleKey))
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
	return scanGateway(s.db.QueryRow(ctx, "SELECT "+gatewayCols+" FROM gateways WHERE cert_serial = $1 OR next_cert_serial = $1", serial))
}

// ByID — см. Store.
func (s *PGStore) ByID(ctx context.Context, id string) (Gateway, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanGateway(s.db.QueryRow(ctx, "SELECT "+gatewayCols+" FROM gateways WHERE id = $1", id))
}

// SetNextCert — см. Store.
func (s *PGStore) SetNextCert(ctx context.Context, id string, next Issued, rec func(Gateway) audit.Entry) (Gateway, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var gw Gateway
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		gw, err = scanGateway(tx.QueryRow(ctx, `UPDATE gateways SET next_cert_serial = $2, next_cert_not_after = $3, next_cert_ca = $4
			WHERE id = $1 AND status = 'active' RETURNING `+gatewayCols, id, next.Info.Serial, next.Info.NotAfter, next.CA))
		if err != nil {
			return err
		}
		return s.record(ctx, tx, rec(gw))
	})
	return gw, err
}

// PromoteNext — см. Store.
func (s *PGStore) PromoteNext(ctx context.Context, id, serial string, rec func(Gateway) audit.Entry) (Gateway, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var gw Gateway
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		gw, err = scanGateway(tx.QueryRow(ctx, `UPDATE gateways SET cert_serial = next_cert_serial, cert_not_after = next_cert_not_after,
			cert_ca = next_cert_ca, next_cert_serial = NULL, next_cert_not_after = NULL, next_cert_ca = NULL
			WHERE id = $1 AND status = 'active' AND next_cert_serial = $2 RETURNING `+gatewayCols, id, serial))
		if errors.Is(err, ErrNotFound) {
			// Параллельный запрос уже сделал сертификат действующим.
			gw, err = scanGateway(tx.QueryRow(ctx, "SELECT "+gatewayCols+" FROM gateways WHERE id = $1 AND status = 'active'", id))
			return err
		}
		if err != nil {
			return err
		}
		return s.record(ctx, tx, rec(gw))
	})
	return gw, err
}

// PinBundleKey — см. Store.
func (s *PGStore) PinBundleKey(ctx context.Context, id string, key []byte, rec func(Gateway) audit.Entry) (Gateway, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var gw Gateway
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		gw, err = scanGateway(tx.QueryRow(ctx, `UPDATE gateways SET bundle_key = $2
			WHERE id = $1 AND status = 'active' AND bundle_key IS NULL RETURNING `+gatewayCols, id, key))
		if errors.Is(err, ErrNotFound) {
			gw, err = scanGateway(tx.QueryRow(ctx, "SELECT "+gatewayCols+" FROM gateways WHERE id = $1 AND status = 'active'", id))
			return err
		}
		if err != nil {
			return err
		}
		return s.record(ctx, tx, rec(gw))
	})
	return gw, err
}

// Touch — см. Store.
func (s *PGStore) Touch(ctx context.Context, id string, hb Heartbeat, audits func(TouchChange) []audit.Entry) (TouchChange, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var addr *string
	if hb.Addr.IsValid() {
		a := hb.Addr.Unmap().String()
		addr = &a
	}
	// Итоги проверок обновляются только присланные: старый шлюз или heartbeat
	// без итогов не стирает прежние.
	var stOK, inOK *bool
	var stAt, inAt *time.Time
	var stFailed, inFailed *int
	var inReason, mVersion *string
	var mCreated *time.Time
	var testSigned *bool
	if r := hb.Selftest; r != nil {
		stOK, stAt, stFailed = &r.OK, &r.At, &r.Failed
	}
	if r := hb.Integrity; r != nil {
		inOK, inAt, inFailed, inReason, testSigned = &r.OK, &r.At, &r.Failed, &r.Reason, &r.TestSigned
		if !r.ManifestCreated.IsZero() {
			mVersion, mCreated = &r.ManifestVersion, &r.ManifestCreated
		}
	}
	var ch TouchChange
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		ch = TouchChange{}
		var requested, started, notAfter *time.Time
		var certCA *string
		err := tx.QueryRow(ctx, `SELECT verify_requested_at, started_at, cert_ca, cert_not_after FROM gateways
			WHERE id = $1 AND status = 'active' FOR UPDATE`, id).Scan(&requested, &started, &certCA, &notAfter)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("реестр шлюзов: heartbeat: %w", err)
		}
		// Запрос выполнен, если шлюз прислал итог целостности именно на него.
		ch.VerifyRequested, ch.CertCA, ch.CertNotAfter = deref(requested), derefS(certCA), deref(notAfter)
		ch.VerifyDone = requested != nil && hb.Integrity != nil && hb.VerifyRequest.Equal(*requested)
		next, setStarted := startChange(deref(started), hb, &ch)
		// Максимум манифеста растёт только по успешным проверкам (В20): текущий
		// манифест старше максимума — откат шлюза.
		tag, err := tx.Exec(ctx, `UPDATE gateways SET last_seen_at = $2, last_addr = $3::inet, version = $4, bundle_etag = $5,
			selftest_ok = COALESCE($6, selftest_ok), selftest_at = COALESCE($7, selftest_at),
			selftest_failed = COALESCE($8, selftest_failed),
			integrity_ok = COALESCE($9, integrity_ok), integrity_at = COALESCE($10, integrity_at),
			integrity_reason = COALESCE($11, integrity_reason), integrity_failed = COALESCE($12, integrity_failed),
			manifest_version = CASE WHEN $9::boolean IS NULL THEN manifest_version ELSE $13 END,
			manifest_created = CASE WHEN $9::boolean IS NULL THEN manifest_created ELSE $14 END,
			manifest_max_version = CASE WHEN $9 AND $14::timestamptz IS NOT NULL
				AND (manifest_max_created IS NULL OR $14 > manifest_max_created) THEN $13 ELSE manifest_max_version END,
			manifest_max_created = CASE WHEN $9 AND $14::timestamptz IS NOT NULL
				AND (manifest_max_created IS NULL OR $14 > manifest_max_created) THEN $14 ELSE manifest_max_created END,
			test_signed = COALESCE($15, test_signed), bundle_keys_ok = COALESCE($16, bundle_keys_ok),
			verify_requested_at = CASE WHEN $17 THEN NULL ELSE verify_requested_at END,
			started_at = CASE WHEN $18 THEN $19 ELSE started_at END
			WHERE id = $1 AND status = 'active'`, id, hb.At, addr, hb.Version, nullStr(hb.BundleETag),
			stOK, stAt, stFailed, inOK, inAt, inReason, inFailed, mVersion, mCreated, testSigned, hb.BundleKeysOK, ch.VerifyDone,
			setStarted, nullTime(next))
		if err != nil {
			return fmt.Errorf("реестр шлюзов: heartbeat: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		for _, rec := range audits(ch) {
			if err := s.record(ctx, tx, rec); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return TouchChange{}, err
	}
	return ch, nil
}

// RequestVerify — см. Store.
func (s *PGStore) RequestVerify(ctx context.Context, orgID string, at time.Time, rec func(int) audit.Entry) (int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var n int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE gateways SET verify_requested_at = $2 WHERE org_id = $1 AND status = 'active'", orgID, at)
		if err != nil {
			return fmt.Errorf("реестр шлюзов: запрос проверки: %w", err)
		}
		n = int(tag.RowsAffected())
		return s.record(ctx, tx, rec(n))
	})
	return n, err
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

// AcceptRollback — см. Store. Выполняется под логином владельца схемы
// (aisec-cli).
func (s *PGStore) AcceptRollback(ctx context.Context, orgID, name string, rec func(prev, cur Gateway) audit.Entry) (Gateway, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var gw Gateway
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		cur, err := scanGateway(tx.QueryRow(ctx, "SELECT "+gatewayCols+" FROM gateways WHERE org_id = $1 AND name = $2 FOR UPDATE", orgID, name))
		if err != nil {
			return err
		}
		if err := checkAcceptRollback(cur); err != nil {
			return err
		}
		gw, err = scanGateway(tx.QueryRow(ctx, `UPDATE gateways SET manifest_max_version = manifest_version,
			manifest_max_created = manifest_created WHERE id = $1 RETURNING `+gatewayCols, cur.ID))
		if err != nil {
			return fmt.Errorf("реестр шлюзов: откат: %w", err)
		}
		return s.record(ctx, tx, rec(cur, gw))
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
