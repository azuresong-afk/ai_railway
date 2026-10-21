package auth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

const (
	// pgTimeout — предел на одну операцию, если у контекста нет своего срока.
	pgTimeout = 10 * time.Second
	// pgRollbackTimeout — предел на откат после отмены контекста.
	pgRollbackTimeout = 5 * time.Second
	// maxListedSessions — предел выборки сессий одного пользователя.
	maxListedSessions = 100
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL (миграция 0004_users). Записи аудита
// изменений пишутся журналом в той же транзакции.
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("хранилище учётных записей: нет БД или журнала аудита")
	}
	return &PGStore{db: db, audit: a}, nil
}

func pgCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

// inTx выполняет fn в транзакции; ошибка fn откатывает её.
func (s *PGStore) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("учётные записи: начало транзакции: %w", err)
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
		return fmt.Errorf("учётные записи: фиксация: %w", err)
	}
	return nil
}

func (s *PGStore) record(ctx context.Context, tx pgx.Tx, rec audit.Entry) error {
	if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
		return fmt.Errorf("учётные записи: %w", err)
	}
	return nil
}

const policyCols = `password_min_length, password_min_classes, password_history, password_max_age_days,
	password_warn_days, lockout_threshold, lockout_minutes, session_idle_minutes, session_max_per_user,
	temp_password_hours, mfa_required_all`

// Policy возвращает настройки; нет строки — DefaultPolicy.
func (s *PGStore) Policy(ctx context.Context, orgID string) (Policy, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var p Policy
	err := s.db.QueryRow(ctx, "SELECT "+policyCols+" FROM auth_settings WHERE org_id = $1", orgID).Scan(
		&p.PasswordMinLength, &p.PasswordMinClasses, &p.PasswordHistory, &p.PasswordMaxAgeDays,
		&p.PasswordWarnDays, &p.LockoutThreshold, &p.LockoutMinutes, &p.SessionIdleMinutes,
		&p.SessionMaxPerUser, &p.TempPasswordHours, &p.MFARequiredAll)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultPolicy(), nil
	}
	if err != nil {
		return Policy{}, fmt.Errorf("настройки входа: %w", err)
	}
	return p, nil
}

// SetPolicy сохраняет настройки и запись аудита одной транзакцией.
func (s *PGStore) SetPolicy(ctx context.Context, orgID string, p Policy, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO auth_settings (org_id, `+policyCols+`, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
			ON CONFLICT (org_id) DO UPDATE SET
			password_min_length = EXCLUDED.password_min_length, password_min_classes = EXCLUDED.password_min_classes,
			password_history = EXCLUDED.password_history, password_max_age_days = EXCLUDED.password_max_age_days,
			password_warn_days = EXCLUDED.password_warn_days, lockout_threshold = EXCLUDED.lockout_threshold,
			lockout_minutes = EXCLUDED.lockout_minutes, session_idle_minutes = EXCLUDED.session_idle_minutes,
			session_max_per_user = EXCLUDED.session_max_per_user, temp_password_hours = EXCLUDED.temp_password_hours,
			mfa_required_all = EXCLUDED.mfa_required_all, updated_at = now()`,
			orgID, p.PasswordMinLength, p.PasswordMinClasses, p.PasswordHistory, p.PasswordMaxAgeDays,
			p.PasswordWarnDays, p.LockoutThreshold, p.LockoutMinutes, p.SessionIdleMinutes,
			p.SessionMaxPerUser, p.TempPasswordHours, p.MFARequiredAll)
		if err != nil {
			return fmt.Errorf("настройки входа: запись: %w", err)
		}
		return s.record(ctx, tx, rec)
	})
}

// HasUsers — есть ли в организации хотя бы одна учётная запись.
func (s *PGStore) HasUsers(ctx context.Context, orgID string) (bool, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var ok bool
	if err := s.db.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE org_id = $1)", orgID).Scan(&ok); err != nil {
		return false, fmt.Errorf("учётные записи: %w", err)
	}
	return ok, nil
}

const userCols = `u.id::text, u.org_id::text, u.login, u.display_name, u.role, u.status, u.password_hash,
	u.password_changed_at, u.must_change_password, u.temp_password_expires_at, u.failed_attempts,
	u.locked_at, u.locked_until, u.created_at, u.created_by, u.deactivated_at, u.last_login_at`

func scanUser(row pgx.Row, extra ...any) (User, error) {
	var (
		u                                  User
		role, status                       string
		temp, lockedAt, lockedUntil, deact *time.Time
		lastLogin                          *time.Time
	)
	dst := []any{&u.ID, &u.OrgID, &u.Login, &u.DisplayName, &role, &status, &u.PasswordHash,
		&u.PasswordChangedAt, &u.MustChangePassword, &temp, &u.FailedAttempts,
		&lockedAt, &lockedUntil, &u.CreatedAt, &u.CreatedBy, &deact, &lastLogin}
	if err := row.Scan(append(dst, extra...)...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("учётные записи: разбор: %w", err)
	}
	u.Role, u.Status = Role(role), Status(status)
	u.TempPasswordExpires = deref(temp)
	u.LockedAt, u.LockedUntil = deref(lockedAt), deref(lockedUntil)
	u.DeactivatedAt, u.LastLoginAt = deref(deact), deref(lastLogin)
	return u, nil
}

func deref(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// UserByLogin — учётная запись по нормализованному логину.
func (s *PGStore) UserByLogin(ctx context.Context, orgID, login string) (User, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanUser(s.db.QueryRow(ctx, "SELECT "+userCols+" FROM users u WHERE u.org_id = $1 AND u.login = $2", orgID, login))
}

// UserByID — учётная запись по ID; неверный UUID — ErrNotFound.
func (s *PGStore) UserByID(ctx context.Context, orgID, id string) (User, error) {
	if _, err := store.ParseUUID(id); err != nil {
		return User{}, ErrNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanUser(s.db.QueryRow(ctx, "SELECT "+userCols+" FROM users u WHERE u.org_id = $1 AND u.id = $2", orgID, id))
}

// ListUsers — страница пользователей по (created_at, id).
func (s *PGStore) ListUsers(ctx context.Context, orgID string, after *UserCursor, limit int) ([]User, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var (
		rows pgx.Rows
		err  error
	)
	if after == nil {
		rows, err = s.db.Query(ctx, "SELECT "+userCols+" FROM users u WHERE u.org_id = $1 ORDER BY u.created_at, u.id LIMIT $2",
			orgID, limit)
	} else {
		if _, perr := store.ParseUUID(after.ID); perr != nil {
			return nil, nil
		}
		rows, err = s.db.Query(ctx, "SELECT "+userCols+` FROM users u WHERE u.org_id = $1 AND (u.created_at, u.id) > ($2, $3)
			ORDER BY u.created_at, u.id LIMIT $4`, orgID, after.CreatedAt, after.ID, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("учётные записи: список: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("учётные записи: список: %w", err)
	}
	return out, nil
}

// CreateUser добавляет учётную запись и запись аудита одной транзакцией.
func (s *PGStore) CreateUser(ctx context.Context, u User, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash,
			password_changed_at, must_change_password, temp_password_expires_at, created_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			u.ID, u.OrgID, u.Login, u.DisplayName, string(u.Role), string(u.Status), u.PasswordHash,
			u.PasswordChangedAt, u.MustChangePassword, nullTime(u.TempPasswordExpires), u.CreatedAt, u.CreatedBy)
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return ErrLoginTaken
		}
		if err != nil {
			return fmt.Errorf("учётные записи: создание: %w", err)
		}
		return s.record(ctx, tx, rec)
	})
}

// setupLockKey — ключ рекомендательной блокировки первичной настройки:
// две настройки с разными токенами не создадут двух первых администраторов.
const setupLockKey = 0x61697365632d7375 // "aisec-su"

// SetupFirstUser гасит токен и создаёт первую учётную запись одной
// транзакцией. Токен гасится условным UPDATE: из параллельных запросов с
// одним токеном пройдёт ровно один.
func (s *PGStore) SetupFirstUser(ctx context.Context, tokenHash []byte, hashAlg string, u User, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(setupLockKey)); err != nil {
			return fmt.Errorf("первичная настройка: блокировка: %w", err)
		}
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE org_id = $1)", u.OrgID).Scan(&exists); err != nil {
			return fmt.Errorf("первичная настройка: %w", err)
		}
		if exists {
			return ErrSetupUnavailable
		}
		var tokenID string
		err := tx.QueryRow(ctx, `UPDATE setup_tokens SET used_at = $4 WHERE token_hash = $1 AND hash_alg = $2
			AND org_id = $3 AND used_at IS NULL AND expires_at > $4 RETURNING id::text`,
			tokenHash, hashAlg, u.OrgID, u.CreatedAt).Scan(&tokenID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSetupUnavailable
		}
		if err != nil {
			return fmt.Errorf("первичная настройка: токен: %w", err)
		}
		AddDetail(&rec, "setup_record_id", tokenID)
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash,
			password_changed_at, must_change_password, temp_password_expires_at, created_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			u.ID, u.OrgID, u.Login, u.DisplayName, string(u.Role), string(u.Status), u.PasswordHash,
			u.PasswordChangedAt, u.MustChangePassword, nullTime(u.TempPasswordExpires), u.CreatedAt, u.CreatedBy); err != nil {
			return fmt.Errorf("первичная настройка: создание: %w", err)
		}
		return s.record(ctx, tx, rec)
	})
}

// RecordFailure считает неудачу под блокировкой строки: параллельные
// неудачи не теряются, блокировка наступает ровно один раз, а записи аудита
// фиксируются вместе со счётчиком.
func (s *PGStore) RecordFailure(ctx context.Context, userID string, now time.Time, threshold int, lockUntil time.Time,
	recs func(attempts int, lockedNow bool) []audit.Entry) (int, bool, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var attempts int
	var lockedNow bool
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		attempts, lockedNow = 0, false
		var lockedAt, lockedUntil *time.Time
		err := tx.QueryRow(ctx, "SELECT failed_attempts, locked_at, locked_until FROM users WHERE id = $1 FOR UPDATE", userID).
			Scan(&attempts, &lockedAt, &lockedUntil)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("учётные записи: счётчик неудач: %w", err)
		}
		// Истёкшая блокировка снимается: счёт начинается заново.
		if lockedAt != nil && lockedUntil != nil && !now.Before(*lockedUntil) {
			attempts, lockedAt, lockedUntil = 0, nil, nil
		}
		attempts++
		if lockedAt == nil && attempts >= threshold {
			lockedNow = true
			lockedAt, lockedUntil = &now, nullTime(lockUntil)
		}
		_, err = tx.Exec(ctx, "UPDATE users SET failed_attempts = $2, locked_at = $3, locked_until = $4 WHERE id = $1",
			userID, attempts, lockedAt, lockedUntil)
		if err != nil {
			return fmt.Errorf("учётные записи: счётчик неудач: %w", err)
		}
		if recs == nil {
			return nil
		}
		for _, rec := range recs(attempts, lockedNow) {
			if err := s.record(ctx, tx, rec); err != nil {
				return err
			}
		}
		return nil
	})
	return attempts, lockedNow, err
}

// PasswordHistory — прежние хеши, новые первыми.
func (s *PGStore) PasswordHistory(ctx context.Context, userID string, n int) ([]string, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, "SELECT password_hash FROM password_history WHERE user_id = $1 ORDER BY id DESC LIMIT $2", userID, n)
	if err != nil {
		return nil, fmt.Errorf("история паролей: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// SetPassword меняет пароль, историю и сессии одной транзакцией с аудитом.
func (s *PGStore) SetPassword(ctx context.Context, ch PasswordChange, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var old, status string
		err := tx.QueryRow(ctx, "SELECT password_hash, status FROM users WHERE id = $1 FOR UPDATE", ch.UserID).Scan(&old, &status)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("смена пароля: %w", err)
		}
		if ch.RequireActive && Status(status) != StatusActive {
			return ErrDeactivated
		}
		// Пароль сменили параллельно после проверки текущего — отказ.
		if ch.ExpectHash != "" && ch.ExpectHash != old {
			return ErrWrongPassword
		}
		if ch.KeepSession != "" {
			var live bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sessions WHERE id = $1 AND user_id = $2
				AND revoked_at IS NULL)`, ch.KeepSession, ch.UserID).Scan(&live); err != nil {
				return fmt.Errorf("смена пароля: сессия: %w", err)
			}
			if !live {
				return ErrUnauthenticated
			}
		}
		if ch.Keep > 0 {
			if _, err := tx.Exec(ctx, "INSERT INTO password_history (user_id, password_hash, created_at) VALUES ($1, $2, $3)",
				ch.UserID, old, ch.Now); err != nil {
				return fmt.Errorf("история паролей: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM password_history WHERE user_id = $1 AND id NOT IN
			(SELECT id FROM password_history WHERE user_id = $1 ORDER BY id DESC LIMIT $2)`, ch.UserID, ch.Keep); err != nil {
			return fmt.Errorf("история паролей: %w", err)
		}
		var tempExp *time.Time
		if ch.Temporary {
			tempExp = nullTime(ch.TempExpires)
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, password_changed_at = $3,
			must_change_password = $4, temp_password_expires_at = $5,
			failed_attempts = CASE WHEN $6 THEN 0 ELSE failed_attempts END,
			locked_at = CASE WHEN $6 THEN NULL ELSE locked_at END,
			locked_until = CASE WHEN $6 THEN NULL ELSE locked_until END
			WHERE id = $1`, ch.UserID, ch.NewHash, ch.Now, ch.Temporary, tempExp, ch.Unlock); err != nil {
			return fmt.Errorf("смена пароля: %w", err)
		}
		var keep *string
		if ch.KeepSession != "" {
			keep = &ch.KeepSession
		}
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = $3, revoke_reason = $4
			WHERE user_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2::uuid)`,
			ch.UserID, keep, ch.Now, ch.RevokeReason); err != nil {
			return fmt.Errorf("смена пароля: завершение сессий: %w", err)
		}
		if keep != nil {
			if _, err := tx.Exec(ctx, "UPDATE sessions SET state = $2 WHERE id = $1 AND revoked_at IS NULL",
				*keep, string(SessionActive)); err != nil {
				return fmt.Errorf("смена пароля: сессия: %w", err)
			}
		}
		return s.record(ctx, tx, rec)
	})
}

// SetStatus меняет состояние записи. Строки активных администраторов
// безопасности блокируются в порядке ID до строки цели: две встречные
// деактивации не оставят систему без администратора и не зациклятся.
func (s *PGStore) SetStatus(ctx context.Context, orgID, userID string, st Status, now time.Time, rec audit.Entry) error {
	if _, err := store.ParseUUID(userID); err != nil {
		return ErrNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var admins []string
		if st == StatusDeactivated {
			rows, err := tx.Query(ctx, `SELECT id::text FROM users WHERE org_id = $1 AND role = $2 AND status = $3
				ORDER BY id FOR UPDATE`, orgID, string(RoleSecurityAdmin), string(StatusActive))
			if err != nil {
				return fmt.Errorf("учётные записи: администраторы: %w", err)
			}
			if admins, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
				return fmt.Errorf("учётные записи: администраторы: %w", err)
			}
		}
		var role, status string
		err := tx.QueryRow(ctx, "SELECT role, status FROM users WHERE org_id = $1 AND id = $2 FOR UPDATE", orgID, userID).
			Scan(&role, &status)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("учётные записи: %w", err)
		}
		AddDetail(&rec, "previous_status", status)
		if st == StatusDeactivated {
			if Role(role) == RoleSecurityAdmin && Status(status) == StatusActive && len(admins) <= 1 {
				return ErrLastAdmin
			}
			if _, err := tx.Exec(ctx, "UPDATE users SET status = $2, deactivated_at = $3 WHERE id = $1",
				userID, string(st), now); err != nil {
				return fmt.Errorf("учётные записи: деактивация: %w", err)
			}
			if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = $2, revoke_reason = $3
				WHERE user_id = $1 AND revoked_at IS NULL`, userID, now, RevokeDeactivated); err != nil {
				return fmt.Errorf("учётные записи: завершение сессий: %w", err)
			}
		} else {
			if _, err := tx.Exec(ctx, `UPDATE users SET status = $2, deactivated_at = NULL,
				failed_attempts = 0, locked_at = NULL, locked_until = NULL WHERE id = $1`, userID, string(st)); err != nil {
				return fmt.Errorf("учётные записи: активация: %w", err)
			}
		}
		return s.record(ctx, tx, rec)
	})
}

const sessionCols = `s.id::text, s.user_id::text, s.token_hash, s.csrf_hash, s.state, s.created_at, s.last_seen_at,
	s.expires_at, s.revoked_at, host(s.source_ip), s.user_agent`

func sessionDst(se *Session, state *string, revoked **time.Time, ip **string) []any {
	return []any{&se.ID, &se.UserID, &se.TokenHash, &se.CSRFHash, state, &se.CreatedAt, &se.LastSeenAt,
		&se.ExpiresAt, revoked, ip, &se.UserAgent}
}

func finishSession(se *Session, state string, revoked *time.Time, ip *string) {
	se.State = SessionState(state)
	se.RevokedAt = deref(revoked)
	if ip != nil {
		if a, err := netip.ParseAddr(*ip); err == nil {
			se.SourceIP = a
		}
	}
}

// CreateSession сохраняет сессию и вытесняет самые старые сверх лимита.
// Строка пользователя блокируется: параллельные входы не превысят лимит,
// а вход не пройдёт мимо параллельной блокировки, деактивации или смены пароля.
func (s *PGStore) CreateSession(ctx context.Context, se Session, limit int, login *LoginCheck, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var (
			status, hash          string
			lockedAt, lockedUntil *time.Time
		)
		err := tx.QueryRow(ctx, "SELECT status, password_hash, locked_at, locked_until FROM users WHERE id = $1 FOR UPDATE",
			se.UserID).Scan(&status, &hash, &lockedAt, &lockedUntil)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("сессии: %w", err)
		}
		if login != nil {
			if lockedAt != nil && (lockedUntil == nil || login.Now.Before(*lockedUntil)) {
				return ErrLocked
			}
			if Status(status) != StatusActive || hash != login.VerifiedHash {
				return ErrInvalidCredentials
			}
			var newHash *string
			if login.Rehash != "" {
				newHash = &login.Rehash
			}
			// KeepFailures: счётчик сохраняется до второго фактора, но истёкшая
			// блокировка снимается вместе со счётчиком (как в RecordFailure).
			if _, err := tx.Exec(ctx, `UPDATE users SET failed_attempts = CASE WHEN $4 AND locked_at IS NULL THEN failed_attempts ELSE 0 END,
				locked_at = NULL, locked_until = NULL, last_login_at = $2, password_hash = COALESCE($3, password_hash)
				WHERE id = $1`, se.UserID, login.Now, newHash, login.KeepFailures); err != nil {
				return fmt.Errorf("учётные записи: отметка входа: %w", err)
			}
		}
		if err := insertSession(ctx, tx, se); err != nil {
			return err
		}
		if err := evictSessions(ctx, tx, se.UserID, se.State, se.CreatedAt, limit, &rec); err != nil {
			return err
		}
		return s.record(ctx, tx, rec)
	})
}

func insertSession(ctx context.Context, tx pgx.Tx, se Session) error {
	var ip *string
	if se.SourceIP.IsValid() {
		a := se.SourceIP.WithZone("").Unmap().String()
		ip = &a
	}
	if _, err := tx.Exec(ctx, `INSERT INTO sessions (id, user_id, token_hash, csrf_hash, state, created_at,
		last_seen_at, expires_at, source_ip, user_agent) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::inet, $10)`,
		se.ID, se.UserID, se.TokenHash, se.CSRFHash, string(se.State), se.CreatedAt, se.LastSeenAt,
		se.ExpiresAt, ip, se.UserAgent); err != nil {
		return fmt.Errorf("сессии: создание: %w", err)
	}
	return nil
}

// evictSessions завершает самые старые незавершённые сессии пользователя
// того же рода, что state (до второго фактора или полные), сверх limit и
// добавляет их ID в подробности rec (evicted_sessions). Сессии до второго
// фактора полные не вытесняют: вход по одному паролю не выбьет из консоли
// пользователя, вошедшего полностью.
func evictSessions(ctx context.Context, tx pgx.Tx, userID string, state SessionState, now time.Time, limit int, rec *audit.Entry) error {
	rows, err := tx.Query(ctx, `UPDATE sessions SET revoked_at = $2, revoke_reason = $3 WHERE id IN
		(SELECT id FROM sessions WHERE user_id = $1 AND revoked_at IS NULL
		 AND (state IN ('mfa_pending', 'mfa_setup')) = $5
		 ORDER BY created_at DESC, id DESC OFFSET $4) RETURNING id::text`, userID, now, RevokeLimit, limit, preMFA(state))
	if err != nil {
		return fmt.Errorf("сессии: лимит: %w", err)
	}
	evicted, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("сессии: лимит: %w", err)
	}
	if len(evicted) > 0 {
		AddDetail(rec, "evicted_sessions", evicted)
	}
	return nil
}

// SessionByToken — незавершённая сессия по хешу токена.
func (s *PGStore) SessionByToken(ctx context.Context, tokenHash []byte) (Session, User, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var (
		se      Session
		state   string
		revoked *time.Time
		ip      *string
	)
	row := s.db.QueryRow(ctx, "SELECT "+userCols+", "+sessionCols+
		" FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.revoked_at IS NULL", tokenHash)
	u, err := scanUser(row, sessionDst(&se, &state, &revoked, &ip)...)
	if err != nil {
		return Session{}, User{}, err
	}
	finishSession(&se, state, revoked, ip)
	return se, u, nil
}

// TouchSession отмечает активность.
func (s *PGStore) TouchSession(ctx context.Context, id string, now time.Time) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	if _, err := s.db.Exec(ctx, "UPDATE sessions SET last_seen_at = $2 WHERE id = $1 AND revoked_at IS NULL AND last_seen_at < $2",
		id, now); err != nil {
		return fmt.Errorf("сессии: активность: %w", err)
	}
	return nil
}

// SetSessionState меняет состояние сессии.
func (s *PGStore) SetSessionState(ctx context.Context, id string, st SessionState) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	if _, err := s.db.Exec(ctx, "UPDATE sessions SET state = $2 WHERE id = $1 AND revoked_at IS NULL", id, string(st)); err != nil {
		return fmt.Errorf("сессии: состояние: %w", err)
	}
	return nil
}

// RevokeSession завершает сессию с записью аудита; уже завершённая — без
// записи (выход и истечение могут совпасть).
func (s *PGStore) RevokeSession(ctx context.Context, id, reason string, now time.Time, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE sessions SET revoked_at = $2, revoke_reason = $3 WHERE id = $1 AND revoked_at IS NULL",
			id, now, reason)
		if err != nil {
			return fmt.Errorf("сессии: завершение: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		return s.record(ctx, tx, rec)
	})
}

// RevokeUserSessions завершает все сессии пользователя с записью аудита.
func (s *PGStore) RevokeUserSessions(ctx context.Context, userID, reason string, now time.Time, rec audit.Entry) (int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var n int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE sessions SET revoked_at = $2, revoke_reason = $3 WHERE user_id = $1 AND revoked_at IS NULL",
			userID, now, reason)
		if err != nil {
			return fmt.Errorf("сессии: завершение: %w", err)
		}
		n = int(tag.RowsAffected())
		return s.record(ctx, tx, rec)
	})
	return n, err
}

// ListSessions — незавершённые сессии пользователя, новые первыми.
func (s *PGStore) ListSessions(ctx context.Context, userID string) ([]Session, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, "SELECT "+sessionCols+` FROM sessions s WHERE s.user_id = $1 AND s.revoked_at IS NULL
		ORDER BY s.created_at DESC, s.id DESC LIMIT $2`, userID, maxListedSessions)
	if err != nil {
		return nil, fmt.Errorf("сессии: список: %w", err)
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var (
			se      Session
			state   string
			revoked *time.Time
			ip      *string
		)
		if err := rows.Scan(sessionDst(&se, &state, &revoked, &ip)...); err != nil {
			return nil, fmt.Errorf("сессии: разбор: %w", err)
		}
		finishSession(&se, state, revoked, ip)
		out = append(out, se)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("сессии: список: %w", err)
	}
	return out, nil
}

var _ Store = (*PGStore)(nil)
