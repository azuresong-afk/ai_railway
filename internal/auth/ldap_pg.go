package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// LDAPStore на PostgreSQL (миграция 0055_ldap); UserByIdentity и
// ExternalLogin — общие с IdP (idp_pg.go).

const (
	ldapCols = `enabled, url, ca_pem, bind_dn, bind_password, bind_password_key_id::text, user_base_dn, user_filter,
	id_attribute, display_attribute, group_mode, group_base_dn, version, updated_at, updated_by::text`
	ldapInsertCols = `enabled, url, ca_pem, bind_dn, bind_password, bind_password_key_id, user_base_dn, user_filter,
	id_attribute, display_attribute, group_mode, group_base_dn, version, updated_at, updated_by`
)

// LDAPSettings — настройки каталога организации с таблицей групп.
func (s *PGStore) LDAPSettings(ctx context.Context, orgID string) (LDAPSettings, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var st LDAPSettings
	err := s.db.QueryRow(ctx, "SELECT "+ldapCols+" FROM ldap_settings WHERE org_id = $1", orgID).Scan(
		&st.Enabled, &st.URL, &st.CAPEM, &st.BindDN, &st.Secret, &st.SecretKeyID, &st.UserBaseDN, &st.UserFilter,
		&st.IDAttribute, &st.DisplayAttribute, &st.GroupMode, &st.GroupBaseDN, &st.Version, &st.UpdatedAt, &st.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return LDAPSettings{}, ErrLDAPNotConfigured
	}
	if err != nil {
		return LDAPSettings{}, fmt.Errorf("настройки LDAP: %w", err)
	}
	rows, err := s.db.Query(ctx, "SELECT group_dn, role FROM ldap_group_roles WHERE org_id = $1 ORDER BY group_dn", orgID)
	if err != nil {
		return LDAPSettings{}, fmt.Errorf("настройки LDAP: группы: %w", err)
	}
	st.GroupRoles, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (GroupRole, error) {
		var g GroupRole
		var role string
		err := r.Scan(&g.Group, &role)
		g.Role = Role(role)
		return g, err
	})
	if err != nil {
		return LDAPSettings{}, fmt.Errorf("настройки LDAP: группы: %w", err)
	}
	return st, nil
}

// SaveLDAPSettings сохраняет настройки и таблицу групп, завершает сессии
// пользователей каталога и пишет rec одной транзакцией.
func (s *PGStore) SaveLDAPSettings(ctx context.Context, orgID string, st LDAPSettings, now time.Time, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO ldap_settings (org_id, `+ldapInsertCols+`)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
			ON CONFLICT (org_id) DO UPDATE SET enabled = EXCLUDED.enabled, url = EXCLUDED.url, ca_pem = EXCLUDED.ca_pem,
			bind_dn = EXCLUDED.bind_dn, bind_password = EXCLUDED.bind_password,
			bind_password_key_id = EXCLUDED.bind_password_key_id, user_base_dn = EXCLUDED.user_base_dn,
			user_filter = EXCLUDED.user_filter, id_attribute = EXCLUDED.id_attribute,
			display_attribute = EXCLUDED.display_attribute, group_mode = EXCLUDED.group_mode,
			group_base_dn = EXCLUDED.group_base_dn, version = ldap_settings.version + 1,
			updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
			orgID, st.Enabled, st.URL, st.CAPEM, st.BindDN, st.Secret, st.SecretKeyID, st.UserBaseDN, st.UserFilter,
			st.IDAttribute, st.DisplayAttribute, st.GroupMode, st.GroupBaseDN, 1, now, st.UpdatedBy)
		if err != nil {
			return fmt.Errorf("настройки LDAP: запись: %w", err)
		}
		if _, err := tx.Exec(ctx, "DELETE FROM ldap_group_roles WHERE org_id = $1", orgID); err != nil {
			return fmt.Errorf("настройки LDAP: группы: %w", err)
		}
		for _, g := range st.GroupRoles {
			if _, err := tx.Exec(ctx, "INSERT INTO ldap_group_roles (org_id, group_dn, role) VALUES ($1, $2, $3)",
				orgID, g.Group, string(g.Role)); err != nil {
				if sqlStateOf(err) == pgForeignKeyViolation {
					return ErrRoleNotFound
				}
				return fmt.Errorf("настройки LDAP: группы: %w", err)
			}
		}
		if err := revokeExternalSessions(ctx, tx, orgID, SourceLDAP, RevokeLDAPChanged, now, &rec); err != nil {
			return err
		}
		return s.record(ctx, tx, rec)
	})
}

// DeleteLDAPSettings удаляет настройки (группы — каскадом) и завершает
// сессии пользователей каталога.
func (s *PGStore) DeleteLDAPSettings(ctx context.Context, orgID string, now time.Time, rec audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM ldap_settings WHERE org_id = $1", orgID)
		if err != nil {
			return fmt.Errorf("настройки LDAP: удаление: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrLDAPNotConfigured
		}
		if err := revokeExternalSessions(ctx, tx, orgID, SourceLDAP, RevokeLDAPChanged, now, &rec); err != nil {
			return err
		}
		return s.record(ctx, tx, rec)
	})
}

var _ LDAPStore = (*PGStore)(nil)
