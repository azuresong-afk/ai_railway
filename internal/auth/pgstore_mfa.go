package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Второй фактор в PostgreSQL (миграция mfa, ADR-0006): шаг последнего
// принятого кода меняется только условием last_step < $шаг в той же
// записи — из параллельных запросов с одним кодом пройдёт ровно один.

// MFA — второй фактор пользователя.
func (s *PGStore) MFA(ctx context.Context, userID string) (MFA, error) {
	if _, err := store.ParseUUID(userID); err != nil {
		return MFA{}, ErrNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var (
		m       MFA
		state   string
		enabled *time.Time
	)
	err := s.db.QueryRow(ctx, `SELECT user_id::text, state, secret, data_key_id::text, alg, last_step, created_at, enabled_at
		FROM user_mfa WHERE user_id = $1`, userID).Scan(&m.UserID, &state, &m.Secret, &m.KeyID, &m.Alg, &m.LastStep,
		&m.CreatedAt, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return MFA{}, ErrNotFound
	}
	if err != nil {
		return MFA{}, fmt.Errorf("второй фактор: %w", err)
	}
	m.State, m.EnabledAt = MFAState(state), deref(enabled)
	return m, nil
}

// SaveMFAPending сохраняет неподтверждённый секрет с записью аудита.
// Подключённый фактор условие ON CONFLICT … WHERE не трогает — тогда ни
// одна строка не вернётся.
func (s *PGStore) SaveMFAPending(ctx context.Context, m MFA, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx, `INSERT INTO user_mfa (user_id, state, secret, data_key_id, alg, created_at)
			VALUES ($1, 'pending', $2, $3, $4, $5)
			ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, data_key_id = EXCLUDED.data_key_id,
			alg = EXCLUDED.alg, created_at = EXCLUDED.created_at WHERE user_mfa.state = 'pending'
			RETURNING user_id::text`, m.UserID, m.Secret, m.KeyID, m.Alg, m.CreatedAt).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMFAEnabled
		}
		if err != nil {
			return fmt.Errorf("второй фактор: сохранение: %w", err)
		}
		return s.record(ctx, tx, rec)
	})
}

// replaceCodes гасит неиспользованные коды восстановления и сохраняет новые.
func replaceCodes(ctx context.Context, tx pgx.Tx, userID string, hashes [][]byte, now time.Time) error {
	if _, err := tx.Exec(ctx, "UPDATE recovery_codes SET used_at = $2 WHERE user_id = $1 AND used_at IS NULL",
		userID, now); err != nil {
		return fmt.Errorf("коды восстановления: %w", err)
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, "INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES ($1, $2, $3)",
			userID, h, now); err != nil {
			return fmt.Errorf("коды восстановления: %w", err)
		}
	}
	return nil
}

// MFAStep проверяет код и выполняет действие одной транзакцией. Строка
// пользователя блокируется первой: параллельные попытки идут по очереди,
// и каждая видит неудачи предыдущих (ИАФ.4).
func (s *PGStore) MFAStep(ctx context.Context, st MFAStep, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	failed := false
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		failed = false
		var (
			status                string
			attempts              int
			lockedAt, lockedUntil *time.Time
		)
		err := tx.QueryRow(ctx, "SELECT status, failed_attempts, locked_at, locked_until FROM users WHERE id = $1 FOR UPDATE",
			st.UserID).Scan(&status, &attempts, &lockedAt, &lockedUntil)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnauthenticated
		}
		if err != nil {
			return fmt.Errorf("второй фактор: %w", err)
		}
		if Status(status) != StatusActive {
			return ErrUnauthenticated
		}
		if lockedAt != nil {
			if lockedUntil == nil || st.Now.Before(*lockedUntil) {
				return ErrLocked
			}
			// Истёкшая блокировка снимается: счёт начинается заново.
			attempts, lockedAt, lockedUntil = 0, nil, nil
		}
		var state string
		err = tx.QueryRow(ctx, "SELECT state FROM sessions WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL FOR UPDATE",
			st.SessionID, st.UserID).Scan(&state)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnauthenticated
		}
		if err != nil {
			return fmt.Errorf("сессии: %w", err)
		}
		if SessionState(state) != st.FromState {
			return ErrSessionState
		}
		m, err := mfaForUpdate(ctx, tx, st.UserID)
		if err != nil {
			return err
		}
		if want := mfaWant(st.Kind); m.State != want {
			if want == MFAPending {
				return ErrMFAEnabled
			}
			return ErrMFANotEnabled
		}
		var (
			step int64
			ok   bool
		)
		switch {
		case st.Check != nil:
			if step, ok, err = st.Check(m); err != nil {
				return err
			}
			ok = ok && step > m.LastStep
		case st.RecoveryHash != nil && st.Kind == MFAStepVerify:
			tag, err := tx.Exec(ctx, `UPDATE recovery_codes SET used_at = $3
				WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`, st.UserID, st.RecoveryHash, st.Now)
			if err != nil {
				return fmt.Errorf("коды восстановления: %w", err)
			}
			ok = tag.RowsAffected() == 1
		}
		if !ok {
			failed = true
			return s.mfaFailure(ctx, tx, st, attempts, lockedAt)
		}
		if step > 0 {
			if _, err := tx.Exec(ctx, `UPDATE user_mfa SET last_step = $2,
				state = CASE WHEN $3 THEN 'enabled' ELSE state END,
				enabled_at = CASE WHEN $3 THEN $4 ELSE enabled_at END
				WHERE user_id = $1 AND last_step < $2`, st.UserID, step, st.Kind == MFAStepConfirm, st.Now); err != nil {
				return fmt.Errorf("второй фактор: %w", err)
			}
		}
		if st.RecoveryHashes != nil {
			if err := replaceCodes(ctx, tx, st.UserID, st.RecoveryHashes, st.Now); err != nil {
				return err
			}
		}
		if st.NewSession != nil {
			if err := s.replaceSession(ctx, tx, st, &rec); err != nil {
				return err
			}
		} else if _, err := tx.Exec(ctx, "UPDATE sessions SET mfa_verified = true WHERE id = $1 AND NOT mfa_verified",
			st.SessionID); err != nil {
			// Код принят в полной сессии (подключение фактора, новые коды):
			// сессия прошла второй фактор (В6 ревью 2.r2).
			return fmt.Errorf("сессии: второй фактор: %w", err)
		}
		if st.Kind == MFAStepVerify {
			if _, err := tx.Exec(ctx, "UPDATE users SET failed_attempts = 0, locked_at = NULL, locked_until = NULL WHERE id = $1",
				st.UserID); err != nil {
				return fmt.Errorf("учётные записи: счётчик неудач: %w", err)
			}
			var left int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL",
				st.UserID).Scan(&left); err != nil {
				return fmt.Errorf("коды восстановления: %w", err)
			}
			AddDetail(&rec, "recovery_codes_left", left)
		}
		if rec.Action == "" {
			// Повторная проверка (MFAStepReauth): успех запишет само действие.
			return nil
		}
		return s.record(ctx, tx, rec)
	})
	if err == nil && failed {
		return ErrInvalidCode
	}
	return err
}

// mfaWant — в каком состоянии должен быть фактор для действия.
func mfaWant(k MFAStepKind) MFAState {
	if k == MFAStepConfirm {
		return MFAPending
	}
	return MFAEnabled
}

func mfaForUpdate(ctx context.Context, tx pgx.Tx, userID string) (MFA, error) {
	var (
		m       MFA
		state   string
		enabled *time.Time
	)
	err := tx.QueryRow(ctx, `SELECT user_id::text, state, secret, data_key_id::text, alg, last_step, created_at, enabled_at
		FROM user_mfa WHERE user_id = $1 FOR UPDATE`, userID).Scan(&m.UserID, &state, &m.Secret, &m.KeyID, &m.Alg, &m.LastStep,
		&m.CreatedAt, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return MFA{}, ErrMFANotEnabled
	}
	if err != nil {
		return MFA{}, fmt.Errorf("второй фактор: %w", err)
	}
	m.State, m.EnabledAt = MFAState(state), deref(enabled)
	return m, nil
}

// mfaFailure считает неверный код: счётчик, блокировка на пороге и
// завершение всех сессий пользователя, записи аудита — в той же транзакции.
func (s *PGStore) mfaFailure(ctx context.Context, tx pgx.Tx, st MFAStep, attempts int, lockedAt *time.Time) error {
	attempts++
	lockedNow := lockedAt == nil && attempts >= st.Threshold
	var lockedUntil *time.Time
	if lockedNow {
		lockedAt, lockedUntil = &st.Now, nullTime(st.LockUntil)
	}
	if _, err := tx.Exec(ctx, "UPDATE users SET failed_attempts = $2, locked_at = $3, locked_until = $4 WHERE id = $1",
		st.UserID, attempts, lockedAt, lockedUntil); err != nil {
		return fmt.Errorf("учётные записи: счётчик неудач: %w", err)
	}
	if attempts >= st.Threshold {
		if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = $2, revoke_reason = $3
			WHERE user_id = $1 AND revoked_at IS NULL`, st.UserID, st.Now, RevokeLocked); err != nil {
			return fmt.Errorf("сессии: завершение: %w", err)
		}
	}
	if st.Failed == nil {
		return nil
	}
	for _, r := range st.Failed(attempts, lockedNow) {
		if err := s.record(ctx, tx, r); err != nil {
			return err
		}
	}
	return nil
}

// replaceSession завершает сессию до второго фактора и сохраняет полную с
// новыми токенами; полные сессии сверх лимита завершаются (УПД.4).
func (s *PGStore) replaceSession(ctx context.Context, tx pgx.Tx, st MFAStep, rec *audit.Entry) error {
	ns := st.NewSession
	if _, err := tx.Exec(ctx, "UPDATE sessions SET revoked_at = $2, revoke_reason = $3 WHERE id = $1",
		st.SessionID, st.Now, RevokeMFAPassed); err != nil {
		return fmt.Errorf("сессии: замена: %w", err)
	}
	if err := insertSession(ctx, tx, *ns); err != nil {
		return err
	}
	return evictSessions(ctx, tx, ns.UserID, ns.State, st.Now, st.SessionLimit, rec)
}

// ResetMFA удаляет фактор, гасит коды и завершает сессии одной транзакцией.
func (s *PGStore) ResetMFA(ctx context.Context, userID string, now time.Time, rec audit.Entry) error {
	if _, err := store.ParseUUID(userID); err != nil {
		return ErrNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var state string
		err := tx.QueryRow(ctx, "DELETE FROM user_mfa WHERE user_id = $1 RETURNING state", userID).Scan(&state)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMFANotEnabled
		}
		if err != nil {
			return fmt.Errorf("второй фактор: сброс: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE recovery_codes SET used_at = $2 WHERE user_id = $1 AND used_at IS NULL",
			userID, now); err != nil {
			return fmt.Errorf("коды восстановления: %w", err)
		}
		tag, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = $2, revoke_reason = $3
			WHERE user_id = $1 AND revoked_at IS NULL`, userID, now, RevokeMFAReset)
		if err != nil {
			return fmt.Errorf("второй фактор: завершение сессий: %w", err)
		}
		AddDetail(&rec, "previous_state", state)
		AddDetail(&rec, "revoked_sessions", tag.RowsAffected())
		return s.record(ctx, tx, rec)
	})
}
