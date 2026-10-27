package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// IdPStore на PostgreSQL (миграция 0051_oidc); ExternalLogin — и для
// каталога LDAP (0055_ldap).

const (
	idpCols = `enabled, display_name, issuer, client_id, client_secret, client_secret_key_id::text, console_url,
	ca_pem, scopes, groups_claim, required_acr, required_amr, version, updated_at, updated_by::text`
	idpInsertCols = `enabled, display_name, issuer, client_id, client_secret, client_secret_key_id, console_url,
	ca_pem, scopes, groups_claim, required_acr, required_amr, version, updated_at, updated_by`
)

// IdPSettings — настройки организации с таблицей групп.
func (s *PGStore) IdPSettings(ctx context.Context, orgID string) (IdPSettings, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return loadIdP(ctx, s.db, orgID, "")
}

// pgUniqueViolation — SQLSTATE нарушения уникальности.
const pgUniqueViolation = "23505"

func loadIdP(ctx context.Context, q pgQuerier, orgID, lock string) (IdPSettings, error) {
	var st IdPSettings
	err := q.QueryRow(ctx, "SELECT "+idpCols+" FROM oidc_settings WHERE org_id = $1 "+lock, orgID).Scan(
		&st.Enabled, &st.DisplayName, &st.Issuer, &st.ClientID, &st.Secret, &st.SecretKeyID, &st.ConsoleURL,
		&st.CAPEM, &st.Scopes, &st.GroupsClaim, &st.RequiredACR, &st.RequiredAMR, &st.Version, &st.UpdatedAt, &st.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdPSettings{}, ErrIdPNotConfigured
	}
	if err != nil {
		return IdPSettings{}, fmt.Errorf("настройки IdP: %w", err)
	}
	rows, err := q.Query(ctx, "SELECT group_name, role FROM oidc_group_roles WHERE org_id = $1 ORDER BY group_name", orgID)
	if err != nil {
		return IdPSettings{}, fmt.Errorf("настройки IdP: группы: %w", err)
	}
	st.GroupRoles, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (GroupRole, error) {
		var g GroupRole
		var role string
		err := r.Scan(&g.Group, &role)
		g.Role = Role(role)
		return g, err
	})
	if err != nil {
		return IdPSettings{}, fmt.Errorf("настройки IdP: группы: %w", err)
	}
	return st, nil
}

// SaveIdPSettings сохраняет настройки и таблицу групп, завершает сессии
// внешних пользователей и пишет rec одной транзакцией.
func (s *PGStore) SaveIdPSettings(ctx context.Context, orgID string, st IdPSettings, now time.Time, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO oidc_settings (org_id, `+idpInsertCols+`)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
			ON CONFLICT (org_id) DO UPDATE SET enabled = EXCLUDED.enabled, display_name = EXCLUDED.display_name,
			issuer = EXCLUDED.issuer, client_id = EXCLUDED.client_id, client_secret = EXCLUDED.client_secret,
			client_secret_key_id = EXCLUDED.client_secret_key_id, console_url = EXCLUDED.console_url,
			ca_pem = EXCLUDED.ca_pem, scopes = EXCLUDED.scopes, groups_claim = EXCLUDED.groups_claim,
			required_acr = EXCLUDED.required_acr, required_amr = EXCLUDED.required_amr,
			version = oidc_settings.version + 1, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
			orgID, st.Enabled, st.DisplayName, st.Issuer, st.ClientID, st.Secret, st.SecretKeyID, st.ConsoleURL,
			st.CAPEM, st.Scopes, st.GroupsClaim, st.RequiredACR, st.RequiredAMR, 1, now, st.UpdatedBy)
		if err != nil {
			return fmt.Errorf("настройки IdP: запись: %w", err)
		}
		if _, err := tx.Exec(ctx, "DELETE FROM oidc_group_roles WHERE org_id = $1", orgID); err != nil {
			return fmt.Errorf("настройки IdP: группы: %w", err)
		}
		for _, g := range st.GroupRoles {
			if _, err := tx.Exec(ctx, "INSERT INTO oidc_group_roles (org_id, group_name, role) VALUES ($1, $2, $3)",
				orgID, g.Group, string(g.Role)); err != nil {
				if sqlStateOf(err) == pgForeignKeyViolation {
					return ErrRoleNotFound
				}
				return fmt.Errorf("настройки IdP: группы: %w", err)
			}
		}
		if err := revokeExternalSessions(ctx, tx, orgID, SourceOIDC, RevokeIdPChanged, now, &rec); err != nil {
			return err
		}
		return s.record(ctx, tx, rec)
	})
}

// DeleteIdPSettings удаляет настройки (группы — каскадом) и завершает
// сессии внешних пользователей.
func (s *PGStore) DeleteIdPSettings(ctx context.Context, orgID string, now time.Time, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM oidc_settings WHERE org_id = $1", orgID)
		if err != nil {
			return fmt.Errorf("настройки IdP: удаление: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrIdPNotConfigured
		}
		if err := revokeExternalSessions(ctx, tx, orgID, SourceOIDC, RevokeIdPChanged, now, &rec); err != nil {
			return err
		}
		return s.record(ctx, tx, rec)
	})
}

// revokeExternalSessions завершает сессии внешних пользователей
// организации с источником source (причина reason); их число —
// revoked_sessions в rec.
func revokeExternalSessions(ctx context.Context, tx pgx.Tx, orgID string, source AuthSource, reason string,
	now time.Time, rec *audit.Entry) error {
	tag, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = $2, revoke_reason = $3
		WHERE revoked_at IS NULL AND user_id IN (SELECT id FROM users WHERE org_id = $1 AND auth_source = $4)`,
		orgID, now, reason, string(source))
	if err != nil {
		return fmt.Errorf("настройки входа: завершение сессий: %w", err)
	}
	AddDetail(rec, "revoked_sessions", tag.RowsAffected())
	return nil
}

// StartOIDCLogin сохраняет хеш незавершённого входа.
func (s *PGStore) StartOIDCLogin(ctx context.Context, orgID string, idHash []byte, now, expires time.Time, maxPending int) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM oidc_logins WHERE org_id = $1 AND expires_at <= $2", orgID, now); err != nil {
			return fmt.Errorf("вход через IdP: очистка: %w", err)
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM oidc_logins WHERE org_id = $1", orgID).Scan(&n); err != nil {
			return fmt.Errorf("вход через IdP: %w", err)
		}
		if n >= maxPending {
			return ErrTooManyLogins
		}
		if _, err := tx.Exec(ctx, "INSERT INTO oidc_logins (id_hash, org_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
			idHash, orgID, now, expires); err != nil {
			return fmt.Errorf("вход через IdP: %w", err)
		}
		return nil
	})
}

// TakeOIDCLogin удаляет незавершённый вход; DELETE … RETURNING делает его
// одноразовым и при параллельных возвратах.
func (s *PGStore) TakeOIDCLogin(ctx context.Context, orgID string, idHash []byte, now time.Time) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var exp time.Time
	err := s.db.QueryRow(ctx, "DELETE FROM oidc_logins WHERE id_hash = $1 AND org_id = $2 RETURNING expires_at",
		idHash, orgID).Scan(&exp)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("вход через IdP: %w", err)
	}
	if !now.Before(exp) {
		return ErrNotFound
	}
	return nil
}

// UserByIdentity — внешняя учётная запись по издателю и sub.
func (s *PGStore) UserByIdentity(ctx context.Context, orgID, issuer, subject string) (User, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanUser(s.db.QueryRow(ctx, "SELECT "+userCols+` FROM users u
		WHERE u.org_id = $1 AND u.idp_issuer = $2 AND u.idp_subject = $3`, orgID, issuer, subject))
}

// ExternalLogin — учётная запись и сессия внешнего пользователя (IdP или
// каталог — по in.Source) одной транзакцией (ExternalLoginTx).
func (s *PGStore) ExternalLogin(ctx context.Context, in ExternalLoginTx) (User, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var out User
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// Настройки — первыми и с блокировкой: сохранение и удаление
		// настроек ждут конца входа и завершают его сессию, а вход после
		// них видит другую версию и отклоняется.
		var version int
		var enabled bool
		q := "SELECT version, enabled FROM oidc_settings WHERE org_id = $1 FOR SHARE"
		if in.Source == SourceLDAP {
			q = "SELECT version, enabled FROM ldap_settings WHERE org_id = $1 FOR SHARE"
		}
		err := tx.QueryRow(ctx, q, in.OrgID).Scan(&version, &enabled)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (version != in.SettingsVersion || !enabled)) {
			return ErrIdPChanged
		}
		if err != nil {
			return fmt.Errorf("вход через IdP: настройки: %w", err)
		}
		// Строки администраторов безопасности — первыми и в порядке ID, как
		// при назначении роли: встречные изменения не оставят систему без
		// администратора и не взаимоблокируются.
		rows, err := tx.Query(ctx, `SELECT id::text FROM users WHERE org_id = $1 AND role = $2 AND status = $3
			ORDER BY id FOR UPDATE`, in.OrgID, string(RoleSecurityAdmin), string(StatusActive))
		if err != nil {
			return fmt.Errorf("вход через IdP: администраторы: %w", err)
		}
		admins, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("вход через IdP: администраторы: %w", err)
		}
		u, err := scanUser(tx.QueryRow(ctx, "SELECT "+userCols+` FROM users u
			WHERE u.org_id = $1 AND u.idp_issuer = $2 AND u.idp_subject = $3 FOR UPDATE`, in.OrgID, in.Issuer, in.Subject))
		created := false
		prev := in.Role
		switch {
		case errors.Is(err, ErrNotFound):
			if u, err = createExternal(ctx, tx, in); err != nil {
				return err
			}
			created = true
		case err != nil:
			return err
		default:
			if u.Status != StatusActive {
				return ErrDeactivated
			}
			prev = u.Role
			if u.Role != in.Role {
				if u.Role == RoleSecurityAdmin && len(admins) <= 1 {
					return ErrLastAdmin
				}
				if _, err := tx.Exec(ctx, "UPDATE users SET role = $2 WHERE id = $1", u.ID, string(in.Role)); err != nil {
					if sqlStateOf(err) == pgForeignKeyViolation {
						return ErrRoleNotFound
					}
					return fmt.Errorf("вход через IdP: роль: %w", err)
				}
				// Сессии с прежней ролью и прежним требованием второго фактора завершаются.
				if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = $2, revoke_reason = $3
					WHERE user_id = $1 AND revoked_at IS NULL`, u.ID, in.Now, RevokeIdPRoleChanged); err != nil {
					return fmt.Errorf("вход через IdP: завершение сессий: %w", err)
				}
				u.Role = in.Role
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE users SET last_login_at = $2 WHERE id = $1", u.ID, in.Now); err != nil {
			return fmt.Errorf("вход через IdP: отметка входа: %w", err)
		}
		u.LastLoginAt = in.Now
		se := in.Session
		se.UserID = u.ID
		if err := insertSession(ctx, tx, se); err != nil {
			return err
		}
		recs := in.Records(u, created, prev)
		if len(recs) > 0 {
			if err := evictSessions(ctx, tx, u.ID, se.State, se.CreatedAt, in.SessionLimit, &recs[len(recs)-1]); err != nil {
				return err
			}
		}
		for _, r := range recs {
			if err := s.record(ctx, tx, r); err != nil {
				return err
			}
		}
		out = u
		return nil
	})
	return out, err
}

// createExternal добавляет внешнюю учётную запись: логин in.Login, если он
// допустим и свободен, иначе запасной.
func createExternal(ctx context.Context, tx pgx.Tx, in ExternalLoginTx) (User, error) {
	login := in.FallbackLogin
	if in.Login != "" {
		var taken bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE org_id = $1 AND login = $2)",
			in.OrgID, in.Login).Scan(&taken); err != nil {
			return User{}, fmt.Errorf("вход через IdP: логин: %w", err)
		}
		if !taken {
			login = in.Login
		}
	}
	u := User{ID: in.NewUserID, OrgID: in.OrgID, Login: login, DisplayName: in.DisplayName, Role: in.Role,
		Status: StatusActive, PasswordHash: externalPassword, PasswordChangedAt: in.Now, CreatedAt: in.Now,
		CreatedBy: string(in.Source), Source: in.Source, IdPIssuer: in.Issuer, IdPSubject: in.Subject}
	_, err := tx.Exec(ctx, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash,
		password_changed_at, must_change_password, created_at, created_by, auth_source, idp_issuer, idp_subject)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false, $9, $10, $11, $12, $13)`,
		u.ID, u.OrgID, u.Login, u.DisplayName, string(u.Role), string(u.Status), u.PasswordHash, u.PasswordChangedAt,
		u.CreatedAt, u.CreatedBy, string(u.Source), u.IdPIssuer, u.IdPSubject)
	if sqlStateOf(err) == pgForeignKeyViolation {
		return User{}, ErrRoleNotFound
	}
	if sqlStateOf(err) == pgUniqueViolation {
		return User{}, ErrLoginTaken
	}
	if err != nil {
		return User{}, fmt.Errorf("вход через IdP: создание учётной записи: %w", err)
	}
	return u, nil
}

var _ IdPStore = (*PGStore)(nil)
