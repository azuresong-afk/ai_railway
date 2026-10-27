package backup

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier — запросы внутри транзакции; pgx.Tx ему соответствует.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// SecretOpener расшифровывает секреты ключом данных установки
// (keyring.Box ему соответствует).
type SecretOpener interface {
	Open(keyID string, sealed []byte, table, column, rowID string) ([]byte, error)
}

// SecretSealer шифрует секреты ключом данных новой установки
// (keyring.Box ему соответствует). SealKey возвращает ID версии ключа,
// которой зашифровано (ротация, ADR-0018).
type SecretSealer interface {
	SealKey(ctx context.Context, plaintext []byte, table, column, rowID string) (string, []byte, error)
	KeyID() string
	Alg() string
}

// Места хранения секретов в БД — те же AAD, что у internal/apps и
// internal/auth (ADR-0007, Р4).
const (
	providersTable   = "providers"
	credentialColumn = "credential"
	mfaTable         = "user_mfa"
	mfaColumn        = "secret"
)

// Read снимает копию в транзакции tx. Транзакция — REPEATABLE READ (её
// открывает вызывающий): все таблицы читаются из одного снимка. Секреты
// расшифровываются ключом данных и сразу шифруются ключом секретов копии,
// открытый текст затирается.
func Read(ctx context.Context, tx pgx.Tx, box SecretOpener, keys *Keys, orgID string) (*Snapshot, error) {
	if tx == nil || box == nil || keys == nil {
		return nil, errors.New("резервная копия: нет транзакции, ключа данных или ключей копии")
	}
	s := &Snapshot{Version: FormatVersion, OrgID: orgID}
	steps := []struct {
		what string
		fn   func(context.Context, pgx.Tx, *Snapshot) error
	}{
		{"организация", readOrg},
		{"настройки", readSettings},
		{"роли", readRoles},
		{"пользователи", func(ctx context.Context, tx pgx.Tx, s *Snapshot) error { return readUsers(ctx, tx, s, box, keys) }},
		{"токены API", readAPITokens},
		{"провайдеры", func(ctx context.Context, tx pgx.Tx, s *Snapshot) error { return readProviders(ctx, tx, s, box, keys) }},
		{"приложения", readApplications},
		{"политики", readPolicies},
	}
	for _, st := range steps {
		if err := st.fn(ctx, tx, s); err != nil {
			return nil, fmt.Errorf("резервная копия: %s: %w", st.what, err)
		}
	}
	return s, nil
}

func readOrg(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	if err := tx.QueryRow(ctx, "SELECT name, now() FROM organizations WHERE id = $1", s.OrgID).Scan(&s.OrgName, &s.TakenAt); err != nil {
		return err
	}
	return tx.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM schema_migrations").Scan(&s.SchemaVersion)
}

func readSettings(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	var a AuthSettings
	err := tx.QueryRow(ctx, `SELECT password_min_length, password_min_classes, password_history, password_max_age_days,
		password_warn_days, lockout_threshold, lockout_minutes, session_idle_minutes, session_max_per_user,
		temp_password_hours, mfa_required_all, updated_at FROM auth_settings WHERE org_id = $1`, s.OrgID).Scan(
		&a.PasswordMinLength, &a.PasswordMinClasses, &a.PasswordHistory, &a.PasswordMaxAgeDays, &a.PasswordWarnDays,
		&a.LockoutThreshold, &a.LockoutMinutes, &a.SessionIdleMinutes, &a.SessionMaxPerUser, &a.TempPasswordHours,
		&a.MFARequiredAll, &a.UpdatedAt)
	switch {
	case err == nil:
		s.Settings.Auth = &a
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	var au AuditSettings
	err = tx.QueryRow(ctx, "SELECT disabled_actions, retention_days, updated_at FROM audit_settings WHERE org_id = $1",
		s.OrgID).Scan(&au.DisabledActions, &au.RetentionDays, &au.UpdatedAt)
	switch {
	case err == nil:
		s.Settings.Audit = &au
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	var ev EventSettings
	err = tx.QueryRow(ctx, "SELECT metadata_days, content_days, updated_at FROM event_settings").Scan(
		&ev.MetadataDays, &ev.ContentDays, &ev.UpdatedAt)
	switch {
	case err == nil:
		s.Settings.Events = &ev
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	var in InstallSettings
	err = tx.QueryRow(ctx, "SELECT timezone, retention_mode, updated_at FROM install_settings WHERE org_id = $1",
		s.OrgID).Scan(&in.Timezone, &in.RetentionMode, &in.UpdatedAt)
	switch {
	case err == nil:
		s.Settings.Install = &in
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	return nil
}

func readRoles(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT id, display_name, description, mfa_required, created_at, created_by, updated_at
		FROM roles WHERE org_id = $1 AND NOT builtin ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	s.Roles, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Role, error) {
		var x Role
		err := r.Scan(&x.ID, &x.DisplayName, &x.Description, &x.MFARequired, &x.CreatedAt, &x.CreatedBy, &x.UpdatedAt)
		return x, err
	})
	if err != nil {
		return err
	}
	idx := make(map[string]int, len(s.Roles))
	for i, r := range s.Roles {
		idx[r.ID] = i
	}
	rows, err = tx.Query(ctx, `SELECT role_id, permission, scope FROM role_permissions WHERE org_id = $1
		ORDER BY role_id, permission`, s.OrgID)
	if err != nil {
		return err
	}
	return forEach(rows, func(r pgx.Rows) error {
		var role string
		var p RolePermission
		if err := r.Scan(&role, &p.Permission, &p.Scope); err != nil {
			return err
		}
		i, ok := idx[role]
		if !ok {
			return fmt.Errorf("разрешение у роли %q, которой нет среди своих ролей", role)
		}
		s.Roles[i].Permissions = append(s.Roles[i].Permissions, p)
		return nil
	})
}

func readUsers(ctx context.Context, tx pgx.Tx, s *Snapshot, box SecretOpener, keys *Keys) error {
	rows, err := tx.Query(ctx, `SELECT id::text, login, display_name, role, status, password_hash, password_changed_at,
		must_change_password, temp_password_expires_at, failed_attempts, locked_at, locked_until, created_at, created_by,
		deactivated_at, last_login_at, auth_source, idp_issuer, idp_subject FROM users WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	s.Users, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) {
		var u User
		err := r.Scan(&u.ID, &u.Login, &u.DisplayName, &u.Role, &u.Status, &u.PasswordHash, &u.PasswordChangedAt,
			&u.MustChangePassword, &u.TempPasswordExpiresAt, &u.FailedAttempts, &u.LockedAt, &u.LockedUntil,
			&u.CreatedAt, &u.CreatedBy, &u.DeactivatedAt, &u.LastLoginAt, &u.AuthSource, &u.IdPIssuer, &u.IdPSubject)
		return u, err
	})
	if err != nil {
		return err
	}
	idx := make(map[string]int, len(s.Users))
	for i, u := range s.Users {
		idx[u.ID] = i
	}
	user := func(id string) (*User, error) {
		i, ok := idx[id]
		if !ok {
			return nil, fmt.Errorf("строка пользователя %s другой организации", id)
		}
		return &s.Users[i], nil
	}
	rows, err = tx.Query(ctx, `SELECT h.user_id::text, h.password_hash, h.created_at FROM password_history h
		JOIN users u ON u.id = h.user_id WHERE u.org_id = $1 ORDER BY h.id`, s.OrgID)
	if err != nil {
		return err
	}
	if err := forEach(rows, func(r pgx.Rows) error {
		var id string
		var h PasswordHistory
		if err := r.Scan(&id, &h.PasswordHash, &h.CreatedAt); err != nil {
			return err
		}
		u, err := user(id)
		if err != nil {
			return err
		}
		u.PasswordHistory = append(u.PasswordHistory, h)
		return nil
	}); err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT m.user_id::text, m.state, m.secret, m.data_key_id::text, m.alg, m.last_step,
		m.created_at, m.enabled_at FROM user_mfa m JOIN users u ON u.id = m.user_id WHERE u.org_id = $1`, s.OrgID)
	if err != nil {
		return err
	}
	if err := forEach(rows, func(r pgx.Rows) error {
		var id, keyID string
		var sealed []byte
		m := &MFA{}
		if err := r.Scan(&id, &m.State, &sealed, &keyID, &m.Alg, &m.LastStep, &m.CreatedAt, &m.EnabledAt); err != nil {
			return err
		}
		u, err := user(id)
		if err != nil {
			return err
		}
		if m.Secret, err = reseal(box, keys, keyID, sealed, mfaTable, mfaColumn, secretMFA, id); err != nil {
			return fmt.Errorf("второй фактор %s: %w", u.Login, err)
		}
		u.MFA = m
		return nil
	}); err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT c.user_id::text, c.code_hash, c.created_at, c.used_at FROM recovery_codes c
		JOIN users u ON u.id = c.user_id WHERE u.org_id = $1 ORDER BY c.id`, s.OrgID)
	if err != nil {
		return err
	}
	return forEach(rows, func(r pgx.Rows) error {
		var id string
		var c RecoveryCode
		if err := r.Scan(&id, &c.CodeHash, &c.CreatedAt, &c.UsedAt); err != nil {
			return err
		}
		u, err := user(id)
		if err != nil {
			return err
		}
		u.RecoveryCodes = append(u.RecoveryCodes, c)
		return nil
	})
}

// reseal расшифровывает секрет ключом данных и сразу шифрует ключом
// секретов копии; открытый текст затирается.
func reseal(box SecretOpener, keys *Keys, keyID string, sealed []byte, table, column, kind, id string) ([]byte, error) {
	plain, err := box.Open(keyID, sealed, table, column, id)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return keys.SealSecret(plain, kind, id)
}

func readAPITokens(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT id::text, user_id::text, name, prefix, token_hash, hash_alg, permissions, expires_at,
		created_at, last_used_at, last_used_ip::text, revoked_at, revoked_by::text, revoke_reason
		FROM api_tokens WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	s.APITokens, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (APIToken, error) {
		var t APIToken
		err := r.Scan(&t.ID, &t.UserID, &t.Name, &t.Prefix, &t.TokenHash, &t.HashAlg, &t.Permissions, &t.ExpiresAt,
			&t.CreatedAt, &t.LastUsedAt, &t.LastUsedIP, &t.RevokedAt, &t.RevokedBy, &t.RevokeReason)
		return t, err
	})
	return err
}

func readProviders(ctx context.Context, tx pgx.Tx, s *Snapshot, box SecretOpener, keys *Keys) error {
	rows, err := tx.Query(ctx, `SELECT id::text, slug, name, type, base_url, ca_pem, auth_url, scope, folder_id,
		connect_timeout_s, header_timeout_s, response_timeout_s, stream_idle_timeout_s, external, credential,
		credential_key_id::text, credential_set_at, created_at, created_by, updated_at, updated_by
		FROM providers WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	return forEach(rows, func(r pgx.Rows) error {
		var p Provider
		var sealed []byte
		var keyID *string
		if err := r.Scan(&p.ID, &p.Slug, &p.Name, &p.Type, &p.BaseURL, &p.CAPEM, &p.AuthURL, &p.Scope, &p.FolderID,
			&p.ConnectTimeoutS, &p.HeaderTimeoutS, &p.ResponseTimeoutS, &p.StreamIdleTimeoutS, &p.External, &sealed,
			&keyID, &p.CredentialSetAt, &p.CreatedAt, &p.CreatedBy, &p.UpdatedAt, &p.UpdatedBy); err != nil {
			return err
		}
		if sealed != nil {
			if keyID == nil {
				return fmt.Errorf("провайдер %s: шифротекст без ключа данных", p.Slug)
			}
			var err error
			if p.Credential, err = reseal(box, keys, *keyID, sealed, providersTable, credentialColumn,
				secretProviderCredential, p.ID); err != nil {
				return fmt.Errorf("провайдер %s: %w", p.Slug, err)
			}
		}
		s.Providers = append(s.Providers, p)
		return nil
	})
}

func readApplications(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT id::text, slug, name, description, department, owner_id::text, env,
		provider_id::text, models, aliases::text, policy, policy_mode, storage, fail_mode, user_from, quotas::text,
		lists::text, exfil_allow_domains, created_at, created_by, updated_at, updated_by, archived_at
		FROM applications WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	s.Applications, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Application, error) {
		var a Application
		var aliases, quotas, lists string
		err := r.Scan(&a.ID, &a.Slug, &a.Name, &a.Description, &a.Department, &a.OwnerID, &a.Env, &a.ProviderID,
			&a.Models, &aliases, &a.Policy, &a.PolicyMode, &a.Storage, &a.FailMode, &a.UserFrom, &quotas, &lists,
			&a.ExfilAllowDomains, &a.CreatedAt, &a.CreatedBy, &a.UpdatedAt, &a.UpdatedBy, &a.ArchivedAt)
		a.Aliases, a.Quotas, a.Lists = []byte(aliases), []byte(quotas), []byte(lists)
		return a, err
	})
	if err != nil {
		return err
	}
	idx := make(map[string]int, len(s.Applications))
	for i, a := range s.Applications {
		idx[a.ID] = i
	}
	rows, err = tx.Query(ctx, `SELECT id::text, app_id::text, name, prefix, key_hash, hash_alg, allowed_cidrs::text[],
		expires_at, created_at, created_by, rotated_from::text, revoked_at, revoked_by
		FROM app_keys WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	return forEach(rows, func(r pgx.Rows) error {
		var k AppKey
		var app string
		if err := r.Scan(&k.ID, &app, &k.Name, &k.Prefix, &k.KeyHash, &k.HashAlg, &k.AllowedCIDRs, &k.ExpiresAt,
			&k.CreatedAt, &k.CreatedBy, &k.RotatedFrom, &k.RevokedAt, &k.RevokedBy); err != nil {
			return err
		}
		i, ok := idx[app]
		if !ok {
			return fmt.Errorf("ключ %s приложения другой организации", k.Prefix)
		}
		s.Applications[i].Keys = append(s.Applications[i].Keys, k)
		return nil
	})
}

func readPolicies(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT id::text, slug, name, mode, current_version, created_at, created_by, updated_at,
		updated_by FROM policies WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	s.Policies, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Policy, error) {
		var p Policy
		err := r.Scan(&p.ID, &p.Slug, &p.Name, &p.Mode, &p.CurrentVersion, &p.CreatedAt, &p.CreatedBy, &p.UpdatedAt,
			&p.UpdatedBy)
		return p, err
	})
	if err != nil {
		return err
	}
	idx := make(map[string]int, len(s.Policies))
	for i, p := range s.Policies {
		idx[p.ID] = i
	}
	rows, err = tx.Query(ctx, `SELECT v.policy_id::text, v.version, v.spec_yaml, v.spec_hash, v.hash_alg, v.source,
		v.comment, v.rolled_back_from, v.created_at, v.created_by FROM policy_versions v
		JOIN policies p ON p.id = v.policy_id WHERE p.org_id = $1 ORDER BY v.policy_id, v.version`, s.OrgID)
	if err != nil {
		return err
	}
	return forEach(rows, func(r pgx.Rows) error {
		var id string
		var v PolicyVersion
		if err := r.Scan(&id, &v.Version, &v.SpecYAML, &v.SpecHash, &v.HashAlg, &v.Source, &v.Comment,
			&v.RolledBackFrom, &v.CreatedAt, &v.CreatedBy); err != nil {
			return err
		}
		i, ok := idx[id]
		if !ok {
			return fmt.Errorf("версия политики %s другой организации", id)
		}
		s.Policies[i].Versions = append(s.Policies[i].Versions, v)
		return nil
	})
}

// forEach обходит строки и закрывает их; ошибка итерации не теряется.
func forEach(rows pgx.Rows, fn func(pgx.Rows) error) error {
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// State — что уже есть в установке, куда восстанавливается копия.
type State struct {
	// SchemaVersion — последняя применённая миграция.
	SchemaVersion int
	// DataKey — ключ данных создан (выполнен aisec-cli init).
	DataKey bool
	// Objects — число объектов конфигурации по видам.
	Objects map[string]int
}

// Empty — в установке нет объектов конфигурации: только то, что создают
// миграции и init (организация, предустановленные роли, настройки по
// умолчанию, ключ данных, токен первичной настройки).
func (st State) Empty() bool {
	for _, n := range st.Objects {
		if n > 0 {
			return false
		}
	}
	return true
}

// Inspect описывает установку orgID.
func Inspect(ctx context.Context, q Querier, orgID string) (State, error) {
	st := State{Objects: map[string]int{}}
	if err := q.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM schema_migrations").Scan(&st.SchemaVersion); err != nil {
		return st, fmt.Errorf("версия схемы (миграции применены? aisec-cli migrate): %w", err)
	}
	if err := q.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM data_keys WHERE org_id = $1 AND retired_at IS NULL)",
		orgID).Scan(&st.DataKey); err != nil {
		return st, err
	}
	var users, roles, tokens, providers, apps, policies int
	if err := q.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM users WHERE org_id = $1),
		(SELECT count(*) FROM roles WHERE org_id = $1 AND NOT builtin),
		(SELECT count(*) FROM api_tokens WHERE org_id = $1),
		(SELECT count(*) FROM providers WHERE org_id = $1),
		(SELECT count(*) FROM applications WHERE org_id = $1),
		(SELECT count(*) FROM policies WHERE org_id = $1)`, orgID).Scan(&users, &roles, &tokens, &providers, &apps, &policies); err != nil {
		return st, err
	}
	st.Objects = map[string]int{"users": users, "roles": roles, "api_tokens": tokens, "providers": providers,
		"applications": apps, "policies": policies}
	return st, nil
}

// maxConflicts — сколько совпадений показывать в ошибке.
const maxConflicts = 20

// ConflictError — в установке уже есть объекты копии.
type ConflictError struct{ Items []string }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("в установке уже есть объекты из копии (%d): %v — восстановление поверх существующих объектов не выполняется (ADR-0017)",
		len(e.Items), e.Items)
}

// Conflicts ищет объекты копии, которые уже есть в установке: по ID или по
// уникальному имени (логин, slug, префикс ключа).
func Conflicts(ctx context.Context, q Querier, s *Snapshot) error {
	var userIDs, logins, roleIDs, tokenIDs, tokenPrefixes, provIDs, provSlugs, appIDs, appSlugs, keyIDs, keyPrefixes, polIDs, polSlugs []string
	for _, u := range s.Users {
		userIDs, logins = append(userIDs, u.ID), append(logins, u.Login)
	}
	for _, r := range s.Roles {
		roleIDs = append(roleIDs, r.ID)
	}
	for _, t := range s.APITokens {
		tokenIDs, tokenPrefixes = append(tokenIDs, t.ID), append(tokenPrefixes, t.Prefix)
	}
	for _, p := range s.Providers {
		provIDs, provSlugs = append(provIDs, p.ID), append(provSlugs, p.Slug)
	}
	for _, a := range s.Applications {
		appIDs, appSlugs = append(appIDs, a.ID), append(appSlugs, a.Slug)
		for _, k := range a.Keys {
			keyIDs, keyPrefixes = append(keyIDs, k.ID), append(keyPrefixes, k.Prefix)
		}
	}
	for _, p := range s.Policies {
		polIDs, polSlugs = append(polIDs, p.ID), append(polSlugs, p.Slug)
	}
	rows, err := q.Query(ctx, `
		SELECT 'пользователь ' || login FROM users WHERE id = ANY($1::uuid[]) OR (org_id = $14 AND login = ANY($2))
		UNION ALL SELECT 'роль ' || id FROM roles WHERE org_id = $14 AND id = ANY($3)
		UNION ALL SELECT 'токен API ' || prefix FROM api_tokens WHERE id = ANY($4::uuid[]) OR prefix = ANY($5)
		UNION ALL SELECT 'провайдер ' || slug FROM providers WHERE id = ANY($6::uuid[]) OR (org_id = $14 AND slug = ANY($7))
		UNION ALL SELECT 'приложение ' || slug FROM applications WHERE id = ANY($8::uuid[]) OR (org_id = $14 AND slug = ANY($9))
		UNION ALL SELECT 'ключ приложения ' || prefix FROM app_keys WHERE id = ANY($10::uuid[]) OR prefix = ANY($11)
		UNION ALL SELECT 'политика ' || slug FROM policies WHERE id = ANY($12::uuid[]) OR (org_id = $14 AND slug = ANY($13))
		LIMIT $15`,
		userIDs, logins, roleIDs, tokenIDs, tokenPrefixes, provIDs, provSlugs, appIDs, appSlugs, keyIDs, keyPrefixes,
		polIDs, polSlugs, s.OrgID, maxConflicts)
	if err != nil {
		return err
	}
	items, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	if len(items) > 0 {
		return &ConflictError{Items: items}
	}
	return nil
}

// Prepared — копия, готовая к записи: секреты перешифрованы ключом данных
// новой установки.
type Prepared struct {
	snap      *Snapshot
	keyID     string
	alg       string
	providers map[string][]byte
	mfa       map[string][]byte
}

// Prepare перешифровывает секреты копии ключом данных установки: каждый
// секрет расшифровывается ключом копии и сразу шифруется ключом данных с
// AAD места хранения, открытый текст затирается.
func Prepare(ctx context.Context, a *Archive, box SecretSealer) (*Prepared, error) {
	if a == nil || box == nil {
		return nil, errors.New("резервная копия: нет копии или ключа данных")
	}
	p := &Prepared{snap: a.Snapshot, keyID: box.KeyID(), alg: box.Alg(), providers: map[string][]byte{}, mfa: map[string][]byte{}}
	move := func(sealed []byte, kind, id, table, column string) ([]byte, error) {
		plain, err := a.keys.OpenSecret(sealed, kind, id)
		if err != nil {
			return nil, err
		}
		defer clear(plain)
		keyID, sealed, err := box.SealKey(ctx, plain, table, column, id)
		if err == nil && keyID != p.keyID {
			// Все секреты копии записываются с одним ID ключа: версия
			// сменилась во время восстановления (ADR-0018, п. 3.7).
			return nil, errors.New("ключ данных сменился во время восстановления (ротация): повторите восстановление")
		}
		return sealed, err
	}
	for _, pr := range a.Snapshot.Providers {
		if pr.Credential == nil {
			continue
		}
		out, err := move(pr.Credential, secretProviderCredential, pr.ID, providersTable, credentialColumn)
		if err != nil {
			return nil, fmt.Errorf("провайдер %s: %w", pr.Slug, err)
		}
		p.providers[pr.ID] = out
	}
	for _, u := range a.Snapshot.Users {
		if u.MFA == nil {
			continue
		}
		out, err := move(u.MFA.Secret, secretMFA, u.ID, mfaTable, mfaColumn)
		if err != nil {
			return nil, fmt.Errorf("второй фактор %s: %w", u.Login, err)
		}
		p.mfa[u.ID] = out
	}
	return p, nil
}

// UserHMACKey расшифровывает ключ псевдонимов пользователей; nil — его нет
// в копии. Вызывающий затирает результат после записи в файл.
func (a *Archive) UserHMACKey() ([]byte, error) {
	if a.Snapshot.UserHMACKey == nil {
		return nil, nil
	}
	return a.keys.OpenSecret(a.Snapshot.UserHMACKey, secretUserHMACKey, userHMACKeyID)
}

// SetUserHMACKey шифрует ключ псевдонимов ключом секретов копии.
func (s *Snapshot) SetUserHMACKey(keys *Keys, key []byte) error {
	sealed, err := keys.SealSecret(key, secretUserHMACKey, userHMACKeyID)
	if err != nil {
		return err
	}
	s.UserHMACKey = sealed
	return nil
}

// RestoreOptions — режим восстановления.
type RestoreOptions struct {
	// ReplaceSettings — записать название организации и настройки копии
	// (только пустая установка): в непустую объекты только добавляются.
	ReplaceSettings bool
	// KeepAPITokens — токены API как в копии. По умолчанию действующие
	// токены восстанавливаются отозванными (backup_restore): токен,
	// отозванный после даты копии, не возвращается в силу (В21 ревью 2.r4).
	KeepAPITokens bool
	// Now — время отзыва токенов.
	Now time.Time
}

// Restore записывает копию в транзакции tx. Пустоту установки и
// совпадения (Inspect, Conflicts) вызывающий проверяет в той же
// транзакции. Неиспользованный токен первичной настройки гасится:
// учётные записи восстановлены. Возвращает число токенов API, отозванных
// при восстановлении.
func Restore(ctx context.Context, tx pgx.Tx, p *Prepared, opts RestoreOptions) (int, error) {
	s := p.snap
	revoked := 0
	steps := []struct {
		what string
		fn   func() error
	}{
		{"организация и настройки", func() error {
			if !opts.ReplaceSettings {
				return nil
			}
			return writeSettings(ctx, tx, s)
		}},
		{"роли", func() error { return writeRoles(ctx, tx, s) }},
		{"пользователи", func() error { return writeUsers(ctx, tx, p) }},
		{"токены API", func() (err error) { revoked, err = writeAPITokens(ctx, tx, s, opts); return err }},
		{"провайдеры", func() error { return writeProviders(ctx, tx, p) }},
		{"приложения", func() error { return writeApplications(ctx, tx, s) }},
		{"политики", func() error { return writePolicies(ctx, tx, s) }},
	}
	for _, st := range steps {
		if err := st.fn(); err != nil {
			return 0, fmt.Errorf("резервная копия: восстановление: %s: %w", st.what, err)
		}
	}
	if len(s.Users) > 0 {
		if _, err := tx.Exec(ctx, "UPDATE setup_tokens SET used_at = greatest(now(), created_at) WHERE org_id = $1 AND used_at IS NULL",
			s.OrgID); err != nil {
			return 0, fmt.Errorf("резервная копия: погашение токена первичной настройки: %w", err)
		}
	}
	return revoked, nil
}

func writeSettings(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	if _, err := tx.Exec(ctx, "UPDATE organizations SET name = $2 WHERE id = $1", s.OrgID, s.OrgName); err != nil {
		return err
	}
	if a := s.Settings.Auth; a != nil {
		if _, err := tx.Exec(ctx, `INSERT INTO auth_settings (org_id, password_min_length, password_min_classes,
			password_history, password_max_age_days, password_warn_days, lockout_threshold, lockout_minutes,
			session_idle_minutes, session_max_per_user, temp_password_hours, mfa_required_all, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			ON CONFLICT (org_id) DO UPDATE SET password_min_length = EXCLUDED.password_min_length,
			password_min_classes = EXCLUDED.password_min_classes, password_history = EXCLUDED.password_history,
			password_max_age_days = EXCLUDED.password_max_age_days, password_warn_days = EXCLUDED.password_warn_days,
			lockout_threshold = EXCLUDED.lockout_threshold, lockout_minutes = EXCLUDED.lockout_minutes,
			session_idle_minutes = EXCLUDED.session_idle_minutes, session_max_per_user = EXCLUDED.session_max_per_user,
			temp_password_hours = EXCLUDED.temp_password_hours, mfa_required_all = EXCLUDED.mfa_required_all,
			updated_at = EXCLUDED.updated_at`,
			s.OrgID, a.PasswordMinLength, a.PasswordMinClasses, a.PasswordHistory, a.PasswordMaxAgeDays,
			a.PasswordWarnDays, a.LockoutThreshold, a.LockoutMinutes, a.SessionIdleMinutes, a.SessionMaxPerUser,
			a.TempPasswordHours, a.MFARequiredAll, a.UpdatedAt); err != nil {
			return err
		}
	}
	if a := s.Settings.Audit; a != nil {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_settings (org_id, disabled_actions, retention_days, updated_at)
			VALUES ($1, $2, $3, $4) ON CONFLICT (org_id) DO UPDATE SET disabled_actions = EXCLUDED.disabled_actions,
			retention_days = EXCLUDED.retention_days, updated_at = EXCLUDED.updated_at`,
			s.OrgID, nonNil(a.DisabledActions), a.RetentionDays, a.UpdatedAt); err != nil {
			return err
		}
	}
	if e := s.Settings.Events; e != nil {
		if _, err := tx.Exec(ctx, "UPDATE event_settings SET metadata_days = $1, content_days = $2, updated_at = $3",
			e.MetadataDays, e.ContentDays, e.UpdatedAt); err != nil {
			return err
		}
	}
	if i := s.Settings.Install; i != nil {
		if _, err := tx.Exec(ctx, `INSERT INTO install_settings (org_id, timezone, retention_mode, updated_at)
			VALUES ($1, $2, $3, $4) ON CONFLICT (org_id) DO UPDATE SET timezone = EXCLUDED.timezone,
			retention_mode = EXCLUDED.retention_mode, updated_at = EXCLUDED.updated_at`,
			s.OrgID, i.Timezone, i.RetentionMode, i.UpdatedAt); err != nil {
			return err
		}
	}
	return nil
}

func writeRoles(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	for _, r := range s.Roles {
		if _, err := tx.Exec(ctx, `INSERT INTO roles (org_id, id, display_name, description, mfa_required, created_at,
			created_by, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			s.OrgID, r.ID, r.DisplayName, r.Description, r.MFARequired, r.CreatedAt, r.CreatedBy, r.UpdatedAt); err != nil {
			return fmt.Errorf("%s: %w", r.ID, err)
		}
		for _, p := range r.Permissions {
			if _, err := tx.Exec(ctx, "INSERT INTO role_permissions (org_id, role_id, permission, scope) VALUES ($1, $2, $3, $4)",
				s.OrgID, r.ID, p.Permission, p.Scope); err != nil {
				return fmt.Errorf("%s: %w", r.ID, err)
			}
		}
	}
	return nil
}

func writeUsers(ctx context.Context, tx pgx.Tx, p *Prepared) error {
	s := p.snap
	for _, u := range s.Users {
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash,
			password_changed_at, must_change_password, temp_password_expires_at, failed_attempts, locked_at, locked_until,
			created_at, created_by, deactivated_at, last_login_at, auth_source, idp_issuer, idp_subject)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
			u.ID, s.OrgID, u.Login, u.DisplayName, u.Role, u.Status, u.PasswordHash, u.PasswordChangedAt,
			u.MustChangePassword, u.TempPasswordExpiresAt, u.FailedAttempts, u.LockedAt, u.LockedUntil, u.CreatedAt,
			u.CreatedBy, u.DeactivatedAt, u.LastLoginAt, u.source(), u.IdPIssuer, u.IdPSubject); err != nil {
			return fmt.Errorf("%s: %w", u.Login, err)
		}
		for _, h := range u.PasswordHistory {
			if _, err := tx.Exec(ctx, "INSERT INTO password_history (user_id, password_hash, created_at) VALUES ($1, $2, $3)",
				u.ID, h.PasswordHash, h.CreatedAt); err != nil {
				return fmt.Errorf("%s: %w", u.Login, err)
			}
		}
		if m := u.MFA; m != nil {
			if _, err := tx.Exec(ctx, `INSERT INTO user_mfa (user_id, state, secret, data_key_id, alg, last_step, created_at,
				enabled_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				u.ID, m.State, p.mfa[u.ID], p.keyID, p.alg, m.LastStep, m.CreatedAt, m.EnabledAt); err != nil {
				return fmt.Errorf("%s: %w", u.Login, err)
			}
		}
		for _, c := range u.RecoveryCodes {
			if _, err := tx.Exec(ctx, "INSERT INTO recovery_codes (user_id, code_hash, created_at, used_at) VALUES ($1, $2, $3, $4)",
				u.ID, c.CodeHash, c.CreatedAt, c.UsedAt); err != nil {
				return fmt.Errorf("%s: %w", u.Login, err)
			}
		}
	}
	return nil
}

// tokenRevokedByRestore — причина отзыва токена при восстановлении
// (auth.APITokenRevokedByBackupRestore; пакет auth сюда не импортируется).
const tokenRevokedByRestore = "backup_restore"

func writeAPITokens(ctx context.Context, tx pgx.Tx, s *Snapshot, opts RestoreOptions) (int, error) {
	revoked := 0
	for _, t := range s.APITokens {
		if t.RevokedAt == nil && !opts.KeepAPITokens {
			// Отзыв не раньше выпуска (копия «из будущего» при сбитых часах).
			at, reason := opts.Now.UTC(), tokenRevokedByRestore
			if at.Before(t.CreatedAt) {
				at = t.CreatedAt
			}
			t.RevokedAt, t.RevokedBy, t.RevokeReason = &at, nil, &reason
			revoked++
		}
		if _, err := tx.Exec(ctx, `INSERT INTO api_tokens (id, org_id, user_id, name, prefix, token_hash, hash_alg,
			permissions, expires_at, created_at, last_used_at, last_used_ip, revoked_at, revoked_by, revoke_reason)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::inet, $13, $14::uuid, $15)`,
			t.ID, s.OrgID, t.UserID, t.Name, t.Prefix, t.TokenHash, t.HashAlg, t.Permissions, t.ExpiresAt, t.CreatedAt,
			t.LastUsedAt, t.LastUsedIP, t.RevokedAt, t.RevokedBy, t.RevokeReason); err != nil {
			return 0, fmt.Errorf("%s: %w", t.Prefix, err)
		}
	}
	return revoked, nil
}

func writeProviders(ctx context.Context, tx pgx.Tx, p *Prepared) error {
	s := p.snap
	for _, pr := range s.Providers {
		var cred []byte
		var keyID, alg *string
		if pr.Credential != nil {
			cred, keyID, alg = p.providers[pr.ID], &p.keyID, &p.alg
		}
		if _, err := tx.Exec(ctx, `INSERT INTO providers (id, org_id, slug, name, type, base_url, ca_pem, auth_url, scope,
			folder_id, connect_timeout_s, header_timeout_s, response_timeout_s, stream_idle_timeout_s, external,
			credential, credential_key_id, credential_alg, credential_set_at, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::uuid, $18, $19, $20, $21, $22, $23)`,
			pr.ID, s.OrgID, pr.Slug, pr.Name, pr.Type, pr.BaseURL, pr.CAPEM, pr.AuthURL, pr.Scope, pr.FolderID,
			pr.ConnectTimeoutS, pr.HeaderTimeoutS, pr.ResponseTimeoutS, pr.StreamIdleTimeoutS, pr.External,
			cred, keyID, alg, pr.CredentialSetAt, pr.CreatedAt, pr.CreatedBy, pr.UpdatedAt, pr.UpdatedBy); err != nil {
			return fmt.Errorf("%s: %w", pr.Slug, err)
		}
	}
	return nil
}

func writeApplications(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	for _, a := range s.Applications {
		if _, err := tx.Exec(ctx, `INSERT INTO applications (id, org_id, slug, name, description, department, owner_id, env,
			provider_id, models, aliases, policy, policy_mode, storage, fail_mode, user_from, quotas, lists,
			exfil_allow_domains, created_at, created_by, updated_at, updated_by, archived_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13, $14, $15, $16, $17::jsonb, $18::jsonb,
			$19, $20, $21, $22, $23, $24)`,
			a.ID, s.OrgID, a.Slug, a.Name, a.Description, a.Department, a.OwnerID, a.Env, a.ProviderID, a.Models,
			string(a.Aliases), a.Policy, a.PolicyMode, a.Storage, a.FailMode, a.UserFrom, string(a.Quotas), string(a.Lists),
			nonNil(a.ExfilAllowDomains), a.CreatedAt, a.CreatedBy, a.UpdatedAt, a.UpdatedBy, a.ArchivedAt); err != nil {
			return fmt.Errorf("%s: %w", a.Slug, err)
		}
		for _, k := range keyOrder(a.Keys) {
			if _, err := tx.Exec(ctx, `INSERT INTO app_keys (id, org_id, app_id, name, prefix, key_hash, hash_alg,
				allowed_cidrs, expires_at, created_at, created_by, rotated_from, revoked_at, revoked_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text[]::cidr[], $9, $10, $11, $12::uuid, $13, $14)`,
				k.ID, s.OrgID, a.ID, k.Name, k.Prefix, k.KeyHash, k.HashAlg, nonNil(k.AllowedCIDRs), k.ExpiresAt,
				k.CreatedAt, k.CreatedBy, k.RotatedFrom, k.RevokedAt, k.RevokedBy); err != nil {
				return fmt.Errorf("%s, ключ %s: %w", a.Slug, k.Prefix, err)
			}
		}
	}
	return nil
}

// keyOrder — порядок вставки ключей: предшественник по ротации раньше
// преемника (внешний ключ rotated_from). Ссылки проверены validate:
// предшественник — ключ того же приложения; цикл — ошибка БД при вставке.
func keyOrder(keys []AppKey) []AppKey {
	out := make([]AppKey, 0, len(keys))
	done := make(map[string]bool, len(keys))
	rest := slices.Clone(keys)
	for len(rest) > 0 {
		next := rest[:0]
		for _, k := range rest {
			if k.RotatedFrom == nil || done[*k.RotatedFrom] {
				out = append(out, k)
				done[k.ID] = true
			} else {
				next = append(next, k)
			}
		}
		if len(next) == len(rest) {
			// Цикл: порядок не важен, вставка откажет по внешнему ключу.
			return append(out, next...)
		}
		rest = next
	}
	return out
}

func writePolicies(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	for _, p := range s.Policies {
		if _, err := tx.Exec(ctx, `INSERT INTO policies (id, org_id, slug, name, mode, current_version, created_at,
			created_by, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			p.ID, s.OrgID, p.Slug, p.Name, p.Mode, p.CurrentVersion, p.CreatedAt, p.CreatedBy, p.UpdatedAt,
			p.UpdatedBy); err != nil {
			return fmt.Errorf("%s: %w", p.Slug, err)
		}
		for _, v := range p.Versions {
			if _, err := tx.Exec(ctx, `INSERT INTO policy_versions (policy_id, version, spec_yaml, spec_hash, hash_alg,
				source, comment, rolled_back_from, created_at, created_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
				p.ID, v.Version, v.SpecYAML, v.SpecHash, v.HashAlg, v.Source, v.Comment, v.RolledBackFrom, v.CreatedAt,
				v.CreatedBy); err != nil {
				return fmt.Errorf("%s, версия %d: %w", p.Slug, v.Version, err)
			}
		}
	}
	return nil
}

// nonNil — пустой массив вместо NULL для столбцов NOT NULL.
func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
