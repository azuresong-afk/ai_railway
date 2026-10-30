package backup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Чтение и запись разделов версии 2 (sections.go). Таблицы других модулей
// читаются и пишутся здесь же SQL-запросами: пакеты модулей копия не
// импортирует.

// hasSettingsV2 — в копии есть настройки версии 2, которые переносятся
// только в пустую установку.
func (s *Snapshot) hasSettingsV2() bool {
	if st := s.Settings.Install; st != nil && (st.QuotaMode != nil || st.AlertRetentionDays != nil ||
		st.IncidentRetentionDays != nil || st.ShadowAIRetentionDays != nil) {
		return true
	}
	if len(s.Instructions)+len(s.ShadowAIExclusions)+len(s.Licenses)+len(s.ComplianceMarks) > 0 ||
		s.GatewayTLS != nil || s.OIDC != nil || s.LDAP != nil {
		return true
	}
	for _, r := range s.AlertRules {
		if r.BuiltinKey != nil {
			return true
		}
	}
	return false
}

// resealOptional — reseal для необязательного секрета: nil — секрета нет.
func resealOptional(box SecretOpener, keys *Keys, keyID *string, sealed []byte, table, column, kind, id string) ([]byte, error) {
	if sealed == nil {
		return nil, nil
	}
	if keyID == nil {
		return nil, errors.New("шифротекст без ключа данных")
	}
	return reseal(box, keys, *keyID, sealed, table, column, kind, id)
}

func readChannels(ctx context.Context, tx pgx.Tx, s *Snapshot, box SecretOpener, keys *Keys) error {
	rows, err := tx.Query(ctx, `SELECT id::text, name, type, enabled, min_severity, settings::text, secret_fields, secret,
		secret_key_id::text, audit_stream, version, created_at, created_by, updated_at, updated_by
		FROM notify_channels WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	return forEach(rows, func(r pgx.Rows) error {
		var c NotifyChannel
		var settings string
		var sealed []byte
		var keyID *string
		if err := r.Scan(&c.ID, &c.Name, &c.Type, &c.Enabled, &c.MinSeverity, &settings, &c.SecretFields, &sealed, &keyID,
			&c.AuditStream, &c.Version, &c.CreatedAt, &c.CreatedBy, &c.UpdatedAt, &c.UpdatedBy); err != nil {
			return err
		}
		c.Settings = []byte(settings)
		var err error
		if c.Secret, err = resealOptional(box, keys, keyID, sealed, channelsTable, channelsColumn, secretChannel, c.ID); err != nil {
			return fmt.Errorf("канал %s: %w", c.Name, err)
		}
		s.Channels = append(s.Channels, c)
		return nil
	})
}

func readAlertRules(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT id::text, builtin_key, kind, name, description, enabled, severity, condition::text,
		group_by, suppress_minutes, group_minutes, recipients::text, version, created_at, created_by, updated_at, updated_by
		FROM alert_rules WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	return forEach(rows, func(r pgx.Rows) error {
		var a AlertRule
		var cond, rcpt string
		if err := r.Scan(&a.ID, &a.BuiltinKey, &a.Kind, &a.Name, &a.Description, &a.Enabled, &a.Severity, &cond, &a.GroupBy,
			&a.SuppressMinutes, &a.GroupMinutes, &rcpt, &a.Version, &a.CreatedAt, &a.CreatedBy, &a.UpdatedAt, &a.UpdatedBy); err != nil {
			return err
		}
		a.Condition, a.Recipients = []byte(cond), []byte(rcpt)
		s.AlertRules = append(s.AlertRules, a)
		return nil
	})
}

func readReportSchedules(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT id::text, name, report, frequency, weekday, day, at_time, format, channel_id::text,
		enabled, next_run_at, last_run_at, scope_incidents, scope_alerts, scope_budgets, scope_compliance,
		recipient_user_ids::text[], version, created_at, created_by, updated_at, updated_by
		FROM report_schedules WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	s.ReportSchedules, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReportSchedule, error) {
		var x ReportSchedule
		err := r.Scan(&x.ID, &x.Name, &x.Report, &x.Frequency, &x.Weekday, &x.Day, &x.AtTime, &x.Format, &x.ChannelID,
			&x.Enabled, &x.NextRunAt, &x.LastRunAt, &x.ScopeIncidents, &x.ScopeAlerts, &x.ScopeBudgets, &x.ScopeCompliance,
			&x.RecipientUserIDs, &x.Version, &x.CreatedAt, &x.CreatedBy, &x.UpdatedAt, &x.UpdatedBy)
		return x, err
	})
	return err
}

func readModelPrices(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT id::text, provider_id::text, model, input_price, output_price, created_at, created_by,
		updated_at, updated_by FROM model_prices WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	s.ModelPrices, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ModelPrice, error) {
		var p ModelPrice
		err := r.Scan(&p.ID, &p.ProviderID, &p.Model, &p.InputPrice, &p.OutputPrice, &p.CreatedAt, &p.CreatedBy,
			&p.UpdatedAt, &p.UpdatedBy)
		return p, err
	})
	return err
}

// readAppExtras — бюджеты, эталоны системных промптов и доступ по группам
// приложений копии.
func readAppExtras(ctx context.Context, tx pgx.Tx, s *Snapshot, box SecretOpener, keys *Keys) error {
	idx := make(map[string]int, len(s.Applications))
	for i, a := range s.Applications {
		idx[a.ID] = i
	}
	app := func(id string) (*Application, error) {
		i, ok := idx[id]
		if !ok {
			return nil, fmt.Errorf("строка приложения %s другой организации", id)
		}
		return &s.Applications[i], nil
	}
	rows, err := tx.Query(ctx, `SELECT app_id::text, mode, monthly_limit, created_at, created_by, updated_at, updated_by
		FROM app_budgets WHERE org_id = $1`, s.OrgID)
	if err != nil {
		return err
	}
	if err := forEach(rows, func(r pgx.Rows) error {
		var id string
		b := &AppBudget{}
		if err := r.Scan(&id, &b.Mode, &b.MonthlyLimit, &b.CreatedAt, &b.CreatedBy, &b.UpdatedAt, &b.UpdatedBy); err != nil {
			return err
		}
		a, err := app(id)
		if err != nil {
			return err
		}
		a.Budget = b
		return nil
	}); err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT app_id::text, mode, hash, text_bytes, text_sealed, text_key_id::text, created_at,
		created_by, updated_at, updated_by FROM prompt_baselines WHERE org_id = $1`, s.OrgID)
	if err != nil {
		return err
	}
	if err := forEach(rows, func(r pgx.Rows) error {
		var id, keyID string
		var sealed []byte
		b := &PromptBaseline{}
		if err := r.Scan(&id, &b.Mode, &b.Hash, &b.TextBytes, &sealed, &keyID, &b.CreatedAt, &b.CreatedBy, &b.UpdatedAt,
			&b.UpdatedBy); err != nil {
			return err
		}
		a, err := app(id)
		if err != nil {
			return err
		}
		if b.Text, err = reseal(box, keys, keyID, sealed, baselineTable, baselineColumn, secretBaseline, id); err != nil {
			return fmt.Errorf("эталон промпта %s: %w", a.Slug, err)
		}
		a.Baseline = b
		return nil
	}); err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT app_id::text, mode, issuer, audience, groups_claim, leeway_seconds, model_groups::text,
		updated_at, updated_by FROM app_user_access WHERE org_id = $1`, s.OrgID)
	if err != nil {
		return err
	}
	return forEach(rows, func(r pgx.Rows) error {
		var id, groups string
		u := &AppUserAccess{}
		if err := r.Scan(&id, &u.Mode, &u.Issuer, &u.Audience, &u.GroupsClaim, &u.LeewaySeconds, &groups, &u.UpdatedAt,
			&u.UpdatedBy); err != nil {
			return err
		}
		a, err := app(id)
		if err != nil {
			return err
		}
		u.ModelGroups = []byte(groups)
		a.UserAccess = u
		return nil
	})
}

func readInstructions(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT category, version, body, created_at, created_by FROM incident_instructions
		WHERE org_id = $1 ORDER BY category, version`, s.OrgID)
	if err != nil {
		return err
	}
	s.Instructions, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (IncidentInstruction, error) {
		var i IncidentInstruction
		err := r.Scan(&i.Category, &i.Version, &i.Body, &i.CreatedAt, &i.CreatedBy)
		return i, err
	})
	return err
}

func readGatewayTLS(ctx context.Context, tx pgx.Tx, s *Snapshot, box SecretOpener, keys *Keys) error {
	t := &GatewayTLS{}
	var sealed []byte
	var keyID string
	err := tx.QueryRow(ctx, `SELECT host, chain_pem, chain_len, subject, issuer, serial, fingerprint, not_before, not_after,
		dns_names, ip_addresses, cert_key_alg, key_sealed, key_key_id::text, created_at, created_by, updated_at, updated_by
		FROM gateway_tls WHERE org_id = $1`, s.OrgID).Scan(&t.Host, &t.ChainPEM, &t.ChainLen, &t.Subject, &t.Issuer,
		&t.Serial, &t.Fingerprint, &t.NotBefore, &t.NotAfter, &t.DNSNames, &t.IPAddresses, &t.CertKeyAlg, &sealed, &keyID,
		&t.CreatedAt, &t.CreatedBy, &t.UpdatedAt, &t.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if t.Key, err = reseal(box, keys, keyID, sealed, gatewayTLSTable, gatewayTLSColumn, secretGatewayTLS, s.OrgID); err != nil {
		return err
	}
	s.GatewayTLS = t
	return nil
}

// readGroupRoles читает сопоставление групп роли (oidc_group_roles или
// ldap_group_roles).
func readGroupRoles(ctx context.Context, tx pgx.Tx, query, orgID string) ([]GroupRole, error) {
	rows, err := tx.Query(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (GroupRole, error) {
		var g GroupRole
		err := r.Scan(&g.Group, &g.Role)
		return g, err
	})
}

func readIdP(ctx context.Context, tx pgx.Tx, s *Snapshot, box SecretOpener, keys *Keys) error {
	o := &OIDCSettings{}
	var sealed []byte
	var keyID string
	err := tx.QueryRow(ctx, `SELECT enabled, display_name, issuer, client_id, client_secret, client_secret_key_id::text,
		console_url, ca_pem, scopes, groups_claim, required_acr, required_amr, version, updated_at, updated_by::text
		FROM oidc_settings WHERE org_id = $1`, s.OrgID).Scan(&o.Enabled, &o.DisplayName, &o.Issuer, &o.ClientID, &sealed,
		&keyID, &o.ConsoleURL, &o.CAPEM, &o.Scopes, &o.GroupsClaim, &o.RequiredACR, &o.RequiredAMR, &o.Version, &o.UpdatedAt,
		&o.UpdatedBy)
	switch {
	case err == nil:
		if o.ClientSecret, err = reseal(box, keys, keyID, sealed, oidcTable, oidcColumn, secretOIDC, s.OrgID); err != nil {
			return fmt.Errorf("OIDC: %w", err)
		}
		if o.GroupRoles, err = readGroupRoles(ctx, tx, `SELECT group_name, role FROM oidc_group_roles WHERE org_id = $1
			ORDER BY group_name`, s.OrgID); err != nil {
			return err
		}
		s.OIDC = o
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	l := &LDAPSettings{}
	err = tx.QueryRow(ctx, `SELECT enabled, url, ca_pem, bind_dn, bind_password, bind_password_key_id::text, user_base_dn,
		user_filter, id_attribute, display_attribute, group_mode, group_base_dn, version, updated_at, updated_by::text
		FROM ldap_settings WHERE org_id = $1`, s.OrgID).Scan(&l.Enabled, &l.URL, &l.CAPEM, &l.BindDN, &sealed, &keyID,
		&l.UserBaseDN, &l.UserFilter, &l.IDAttribute, &l.DisplayAttribute, &l.GroupMode, &l.GroupBaseDN, &l.Version,
		&l.UpdatedAt, &l.UpdatedBy)
	switch {
	case err == nil:
		if l.BindPassword, err = reseal(box, keys, keyID, sealed, ldapTable, ldapColumn, secretLDAP, s.OrgID); err != nil {
			return fmt.Errorf("LDAP: %w", err)
		}
		if l.GroupRoles, err = readGroupRoles(ctx, tx, `SELECT group_dn, role FROM ldap_group_roles WHERE org_id = $1
			ORDER BY group_dn`, s.OrgID); err != nil {
			return err
		}
		s.LDAP = l
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	return nil
}

func readMCPServers(ctx context.Context, tx pgx.Tx, s *Snapshot, box SecretOpener, keys *Keys) error {
	rows, err := tx.Query(ctx, `SELECT id::text, slug, name, url, ca_pem, auth_header, credential, credential_key_id::text,
		credential_set_at, external, insecure_http, call_timeout_s, versions, created_at, created_by, updated_at, updated_by
		FROM mcp_servers WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	return forEach(rows, func(r pgx.Rows) error {
		var m MCPServer
		var sealed []byte
		var keyID *string
		if err := r.Scan(&m.ID, &m.Slug, &m.Name, &m.URL, &m.CAPEM, &m.AuthHeader, &sealed, &keyID, &m.CredentialSetAt,
			&m.External, &m.InsecureHTTP, &m.CallTimeoutS, &m.Versions, &m.CreatedAt, &m.CreatedBy, &m.UpdatedAt,
			&m.UpdatedBy); err != nil {
			return err
		}
		var err error
		if m.Credential, err = resealOptional(box, keys, keyID, sealed, mcpTable, mcpColumn, secretMCP, m.ID); err != nil {
			return fmt.Errorf("MCP-сервер %s: %w", m.Slug, err)
		}
		s.MCPServers = append(s.MCPServers, m)
		return nil
	})
}

func readAgents(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT id::text, app_id::text, slug, name, description, owner, status, created_at, created_by,
		updated_at, updated_by FROM agents WHERE org_id = $1 ORDER BY created_at, id`, s.OrgID)
	if err != nil {
		return err
	}
	s.Agents, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Agent, error) {
		var a Agent
		err := r.Scan(&a.ID, &a.AppID, &a.Slug, &a.Name, &a.Description, &a.Owner, &a.Status, &a.CreatedAt, &a.CreatedBy,
			&a.UpdatedAt, &a.UpdatedBy)
		return a, err
	})
	if err != nil {
		return err
	}
	idx := make(map[string]int, len(s.Agents))
	for i, a := range s.Agents {
		idx[a.ID] = i
	}
	rows, err = tx.Query(ctx, `SELECT agent_id::text, server_id::text FROM agent_servers WHERE org_id = $1
		ORDER BY agent_id, server_id`, s.OrgID)
	if err != nil {
		return err
	}
	return forEach(rows, func(r pgx.Rows) error {
		var agent, server string
		if err := r.Scan(&agent, &server); err != nil {
			return err
		}
		i, ok := idx[agent]
		if !ok {
			return fmt.Errorf("MCP-сервер у агента %s другой организации", agent)
		}
		s.Agents[i].ServerIDs = append(s.Agents[i].ServerIDs, server)
		return nil
	})
}

func readAgentTools(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT id::text, server_id::text, agent_id::text, name, descriptor, descriptor_hash,
		approved_descriptor, approved_hash, hash_alg, risk, status, first_seen, last_seen, decided_by, decided_at, comment,
		updated_at FROM agent_tools WHERE org_id = $1 ORDER BY first_seen, id`, s.OrgID)
	if err != nil {
		return err
	}
	s.AgentTools, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (AgentTool, error) {
		var t AgentTool
		err := r.Scan(&t.ID, &t.ServerID, &t.AgentID, &t.Name, &t.Descriptor, &t.DescriptorHash, &t.ApprovedDescriptor,
			&t.ApprovedHash, &t.HashAlg, &t.Risk, &t.Status, &t.FirstSeen, &t.LastSeen, &t.DecidedBy, &t.DecidedAt,
			&t.Comment, &t.UpdatedAt)
		return t, err
	})
	return err
}

func readShadowAIExclusions(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT kind, value, comment, created_at, created_by FROM shadow_ai_exclusions
		WHERE org_id = $1 ORDER BY kind, value`, s.OrgID)
	if err != nil {
		return err
	}
	s.ShadowAIExclusions, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ShadowAIExclusion, error) {
		var e ShadowAIExclusion
		err := r.Scan(&e.Kind, &e.Value, &e.Comment, &e.CreatedAt, &e.CreatedBy)
		return e, err
	})
	return err
}

func readLicenses(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT number, file, loaded_at, loaded_by FROM licenses WHERE org_id = $1 ORDER BY number`,
		s.OrgID)
	if err != nil {
		return err
	}
	if s.Licenses, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (License, error) {
		var l License
		err := r.Scan(&l.Number, &l.File, &l.LoadedAt, &l.LoadedBy)
		return l, err
	}); err != nil {
		return err
	}
	var hw time.Time
	err = tx.QueryRow(ctx, "SELECT high_water FROM license_clock WHERE org_id = $1", s.OrgID).Scan(&hw)
	switch {
	case err == nil:
		s.LicenseClock = &hw
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	return nil
}

func readComplianceMarks(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT requirement_id, status, comment, document, review_by, set_at, set_by
		FROM compliance_marks WHERE org_id = $1 ORDER BY requirement_id`, s.OrgID)
	if err != nil {
		return err
	}
	s.ComplianceMarks, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ComplianceMark, error) {
		var m ComplianceMark
		err := r.Scan(&m.RequirementID, &m.Status, &m.Comment, &m.Document, &m.ReviewBy, &m.SetAt, &m.SetBy)
		return m, err
	})
	return err
}

func writeModelPrices(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	for _, p := range s.ModelPrices {
		if _, err := tx.Exec(ctx, `INSERT INTO model_prices (id, org_id, provider_id, model, input_price, output_price,
			created_at, created_by, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			p.ID, s.OrgID, p.ProviderID, p.Model, p.InputPrice, p.OutputPrice, p.CreatedAt, p.CreatedBy, p.UpdatedAt,
			p.UpdatedBy); err != nil {
			return fmt.Errorf("%s: %w", p.Model, err)
		}
	}
	return nil
}

func writeChannels(ctx context.Context, tx pgx.Tx, p *Prepared, s *Snapshot) error {
	for _, c := range s.Channels {
		var secret []byte
		var keyID *string
		if c.Secret != nil {
			secret, keyID = p.secret(secretChannel, c.ID), &p.keyID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notify_channels (id, org_id, name, type, enabled, min_severity, settings,
			secret_fields, secret, secret_key_id, audit_stream, version, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10::uuid, $11, $12, $13, $14, $15, $16)`,
			c.ID, s.OrgID, c.Name, c.Type, c.Enabled, c.MinSeverity, string(c.Settings), nonNil(c.SecretFields), secret, keyID,
			c.AuditStream, c.Version, c.CreatedAt, c.CreatedBy, c.UpdatedAt, c.UpdatedBy); err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
	}
	return nil
}

func writeMCPServers(ctx context.Context, tx pgx.Tx, p *Prepared, s *Snapshot) error {
	for _, m := range s.MCPServers {
		var cred []byte
		var keyID, alg *string
		if m.Credential != nil {
			cred, keyID, alg = p.secret(secretMCP, m.ID), &p.keyID, &p.alg
		}
		if _, err := tx.Exec(ctx, `INSERT INTO mcp_servers (id, org_id, slug, name, url, ca_pem, auth_header, credential,
			credential_key_id, credential_alg, credential_set_at, external, insecure_http, call_timeout_s, versions,
			created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::uuid, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
			m.ID, s.OrgID, m.Slug, m.Name, m.URL, m.CAPEM, m.AuthHeader, cred, keyID, alg, m.CredentialSetAt, m.External,
			m.InsecureHTTP, m.CallTimeoutS, nonNil(m.Versions), m.CreatedAt, m.CreatedBy, m.UpdatedAt, m.UpdatedBy); err != nil {
			return fmt.Errorf("%s: %w", m.Slug, err)
		}
	}
	return nil
}

func writeAgents(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	for _, a := range s.Agents {
		if _, err := tx.Exec(ctx, `INSERT INTO agents (id, org_id, app_id, slug, name, description, owner, status,
			created_at, created_by, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			a.ID, s.OrgID, a.AppID, a.Slug, a.Name, a.Description, a.Owner, a.Status, a.CreatedAt, a.CreatedBy, a.UpdatedAt,
			a.UpdatedBy); err != nil {
			return fmt.Errorf("%s: %w", a.Slug, err)
		}
		for _, srv := range a.ServerIDs {
			if _, err := tx.Exec(ctx, "INSERT INTO agent_servers (org_id, agent_id, server_id) VALUES ($1, $2, $3)",
				s.OrgID, a.ID, srv); err != nil {
				return fmt.Errorf("%s: %w", a.Slug, err)
			}
		}
	}
	return nil
}

func writeAppExtras(ctx context.Context, tx pgx.Tx, p *Prepared, s *Snapshot) error {
	for _, a := range s.Applications {
		if b := a.Budget; b != nil {
			if _, err := tx.Exec(ctx, `INSERT INTO app_budgets (app_id, org_id, mode, monthly_limit, created_at, created_by,
				updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				a.ID, s.OrgID, b.Mode, b.MonthlyLimit, b.CreatedAt, b.CreatedBy, b.UpdatedAt, b.UpdatedBy); err != nil {
				return fmt.Errorf("%s, бюджет: %w", a.Slug, err)
			}
		}
		if b := a.Baseline; b != nil {
			if _, err := tx.Exec(ctx, `INSERT INTO prompt_baselines (app_id, org_id, mode, hash, text_bytes, text_sealed,
				text_key_id, text_alg, created_at, created_by, updated_at, updated_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
				a.ID, s.OrgID, b.Mode, b.Hash, b.TextBytes, p.secret(secretBaseline, a.ID), p.keyID, p.alg, b.CreatedAt,
				b.CreatedBy, b.UpdatedAt, b.UpdatedBy); err != nil {
				return fmt.Errorf("%s, эталон промпта: %w", a.Slug, err)
			}
		}
		if u := a.UserAccess; u != nil {
			if _, err := tx.Exec(ctx, `INSERT INTO app_user_access (app_id, org_id, mode, issuer, audience, groups_claim,
				leeway_seconds, model_groups, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)`,
				a.ID, s.OrgID, u.Mode, u.Issuer, u.Audience, u.GroupsClaim, u.LeewaySeconds, string(u.ModelGroups),
				u.UpdatedAt, u.UpdatedBy); err != nil {
				return fmt.Errorf("%s, доступ по группам: %w", a.Slug, err)
			}
		}
	}
	return nil
}

func writeAgentTools(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	for _, t := range s.AgentTools {
		if _, err := tx.Exec(ctx, `INSERT INTO agent_tools (id, org_id, server_id, agent_id, name, descriptor, descriptor_hash,
			approved_descriptor, approved_hash, hash_alg, risk, status, first_seen, last_seen, decided_by, decided_at, comment,
			updated_at) VALUES ($1, $2, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
			t.ID, s.OrgID, t.ServerID, t.AgentID, t.Name, t.Descriptor, t.DescriptorHash, t.ApprovedDescriptor, t.ApprovedHash,
			t.HashAlg, t.Risk, t.Status, t.FirstSeen, t.LastSeen, t.DecidedBy, t.DecidedAt, t.Comment, t.UpdatedAt); err != nil {
			return fmt.Errorf("%s: %w", t.Name, err)
		}
	}
	return nil
}

// writeAlertRules записывает правила оповещений. Правило администратора
// добавляется. Встроенное — настройка: только в пустую установку; если
// сервер его уже создал (EnsureBuiltins), строка обновляется значениями
// копии и сохраняет свой ID.
func writeAlertRules(ctx context.Context, tx pgx.Tx, s *Snapshot, replaceSettings bool) error {
	for _, r := range s.AlertRules {
		if r.BuiltinKey != nil {
			if !replaceSettings {
				continue
			}
			tag, err := tx.Exec(ctx, `UPDATE alert_rules SET name = $3, description = $4, enabled = $5, severity = $6,
				condition = $7::jsonb, group_by = $8, suppress_minutes = $9, group_minutes = $10, recipients = $11::jsonb,
				version = $12, updated_at = $13, updated_by = $14 WHERE org_id = $1 AND builtin_key = $2`,
				s.OrgID, *r.BuiltinKey, r.Name, r.Description, r.Enabled, r.Severity, string(r.Condition), nonNil(r.GroupBy),
				r.SuppressMinutes, r.GroupMinutes, string(r.Recipients), r.Version, r.UpdatedAt, r.UpdatedBy)
			if err != nil {
				return fmt.Errorf("%s: %w", *r.BuiltinKey, err)
			}
			if tag.RowsAffected() > 0 {
				continue
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO alert_rules (id, org_id, builtin_key, kind, name, description, enabled, severity,
			condition, group_by, suppress_minutes, group_minutes, recipients, version, created_at, created_by, updated_at,
			updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13::jsonb, $14, $15, $16, $17, $18)`,
			r.ID, s.OrgID, r.BuiltinKey, r.Kind, r.Name, r.Description, r.Enabled, r.Severity, string(r.Condition),
			nonNil(r.GroupBy), r.SuppressMinutes, r.GroupMinutes, string(r.Recipients), r.Version, r.CreatedAt, r.CreatedBy,
			r.UpdatedAt, r.UpdatedBy); err != nil {
			return fmt.Errorf("%s: %w", r.Name, err)
		}
	}
	return nil
}

func writeReportSchedules(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	for _, r := range s.ReportSchedules {
		if _, err := tx.Exec(ctx, `INSERT INTO report_schedules (id, org_id, name, report, frequency, weekday, day, at_time,
			format, channel_id, enabled, next_run_at, last_run_at, scope_incidents, scope_alerts, scope_budgets,
			scope_compliance, recipient_user_ids, version, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18::uuid[], $19, $20, $21,
			$22, $23)`,
			r.ID, s.OrgID, r.Name, r.Report, r.Frequency, r.Weekday, r.Day, r.AtTime, r.Format, r.ChannelID, r.Enabled,
			r.NextRunAt, r.LastRunAt, r.ScopeIncidents, r.ScopeAlerts, r.ScopeBudgets, r.ScopeCompliance,
			nonNil(r.RecipientUserIDs), r.Version, r.CreatedAt, r.CreatedBy, r.UpdatedAt, r.UpdatedBy); err != nil {
			return fmt.Errorf("%s: %w", r.Name, err)
		}
	}
	return nil
}

func writeInstructions(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	for _, i := range s.Instructions {
		if _, err := tx.Exec(ctx, `INSERT INTO incident_instructions (org_id, category, version, body, created_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6)`, s.OrgID, i.Category, i.Version, i.Body, i.CreatedAt, i.CreatedBy); err != nil {
			return fmt.Errorf("%s, версия %d: %w", i.Category, i.Version, err)
		}
	}
	return nil
}

func writeGatewayTLS(ctx context.Context, tx pgx.Tx, p *Prepared, s *Snapshot) error {
	t := s.GatewayTLS
	if t == nil {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO gateway_tls (org_id, host, chain_pem, chain_len, subject, issuer, serial, fingerprint,
		not_before, not_after, dns_names, ip_addresses, cert_key_alg, key_sealed, key_key_id, key_alg, created_at, created_by,
		updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
		s.OrgID, t.Host, t.ChainPEM, t.ChainLen, t.Subject, t.Issuer, t.Serial, t.Fingerprint, t.NotBefore, t.NotAfter,
		nonNil(t.DNSNames), nonNil(t.IPAddresses), t.CertKeyAlg, p.secret(secretGatewayTLS, s.OrgID), p.keyID, p.alg,
		t.CreatedAt, t.CreatedBy, t.UpdatedAt, t.UpdatedBy)
	return err
}

func writeIdP(ctx context.Context, tx pgx.Tx, p *Prepared, s *Snapshot) error {
	if o := s.OIDC; o != nil {
		if _, err := tx.Exec(ctx, `INSERT INTO oidc_settings (org_id, enabled, display_name, issuer, client_id, client_secret,
			client_secret_key_id, console_url, ca_pem, scopes, groups_claim, required_acr, required_amr, version, updated_at,
			updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
			s.OrgID, o.Enabled, o.DisplayName, o.Issuer, o.ClientID, p.secret(secretOIDC, s.OrgID), p.keyID, o.ConsoleURL,
			o.CAPEM, nonNil(o.Scopes), o.GroupsClaim, nonNil(o.RequiredACR), nonNil(o.RequiredAMR), o.Version, o.UpdatedAt,
			o.UpdatedBy); err != nil {
			return fmt.Errorf("OIDC: %w", err)
		}
		for _, g := range o.GroupRoles {
			if _, err := tx.Exec(ctx, "INSERT INTO oidc_group_roles (org_id, group_name, role) VALUES ($1, $2, $3)",
				s.OrgID, g.Group, g.Role); err != nil {
				return fmt.Errorf("OIDC, группа: %w", err)
			}
		}
	}
	if l := s.LDAP; l != nil {
		if _, err := tx.Exec(ctx, `INSERT INTO ldap_settings (org_id, enabled, url, ca_pem, bind_dn, bind_password,
			bind_password_key_id, user_base_dn, user_filter, id_attribute, display_attribute, group_mode, group_base_dn,
			version, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
			s.OrgID, l.Enabled, l.URL, l.CAPEM, l.BindDN, p.secret(secretLDAP, s.OrgID), p.keyID, l.UserBaseDN, l.UserFilter,
			l.IDAttribute, l.DisplayAttribute, l.GroupMode, l.GroupBaseDN, l.Version, l.UpdatedAt, l.UpdatedBy); err != nil {
			return fmt.Errorf("LDAP: %w", err)
		}
		for _, g := range l.GroupRoles {
			if _, err := tx.Exec(ctx, "INSERT INTO ldap_group_roles (org_id, group_dn, role) VALUES ($1, $2, $3)",
				s.OrgID, g.Group, g.Role); err != nil {
				return fmt.Errorf("LDAP, группа: %w", err)
			}
		}
	}
	return nil
}

func writeShadowAIExclusions(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	for _, e := range s.ShadowAIExclusions {
		if _, err := tx.Exec(ctx, `INSERT INTO shadow_ai_exclusions (org_id, kind, value, comment, created_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6)`, s.OrgID, e.Kind, e.Value, e.Comment, e.CreatedAt, e.CreatedBy); err != nil {
			return fmt.Errorf("исключение теневого ИИ (%s): %w", e.Kind, err)
		}
	}
	return nil
}

// writeLicenses записывает лицензии копии (подписи проверены до записи,
// cmd/aisec-cli) и поднимает отметку часов: наибольшее из копии и
// установки, назад она не ставится (ADR-0026, п. 7).
func writeLicenses(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	for _, l := range s.Licenses {
		if _, err := tx.Exec(ctx, "INSERT INTO licenses (org_id, number, file, loaded_at, loaded_by) VALUES ($1, $2, $3, $4, $5)",
			s.OrgID, l.Number, l.File, l.LoadedAt, l.LoadedBy); err != nil {
			return fmt.Errorf("№ %d: %w", l.Number, err)
		}
	}
	if s.LicenseClock == nil {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO license_clock (org_id, high_water) VALUES ($1, $2)
		ON CONFLICT (org_id) DO UPDATE SET high_water = greatest(license_clock.high_water, EXCLUDED.high_water)`,
		s.OrgID, s.LicenseClock.UTC())
	return err
}

func writeComplianceMarks(ctx context.Context, tx pgx.Tx, s *Snapshot) error {
	for _, m := range s.ComplianceMarks {
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_marks (org_id, requirement_id, status, comment, document, review_by,
			set_at, set_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			s.OrgID, m.RequirementID, m.Status, m.Comment, m.Document, m.ReviewBy, m.SetAt, m.SetBy); err != nil {
			return fmt.Errorf("%s: %w", m.RequirementID, err)
		}
	}
	return nil
}
