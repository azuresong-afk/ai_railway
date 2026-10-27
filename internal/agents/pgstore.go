package agents

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/policy"
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

// PGStore — Store на PostgreSQL (миграция 0052_agents).
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("агенты: нет БД или журнала аудита")
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
		return fmt.Errorf("агенты: начало транзакции: %w", err)
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
		return fmt.Errorf("агенты: фиксация: %w", err)
	}
	return nil
}

func (s *PGStore) record(ctx context.Context, tx pgx.Tx, rec audit.Entry) error {
	if err := s.audit.RecordTx(ctx, tx, rec); err != nil {
		return fmt.Errorf("агенты: %w", err)
	}
	return nil
}

// lockOrg — блокировка реестра организации на транзакцию: пределы числа
// объектов считаются без гонки.
func lockOrg(ctx context.Context, tx pgx.Tx, orgID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('aisec.agents:' || $1, 0))`, orgID)
	return err
}

// pgErr переводит нарушения ограничений: уникальность — ErrSlugTaken,
// внешний ключ — ErrInUse при удалении и ErrNotFound при ссылке.
func pgErr(err error, deleting bool) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505":
			return ErrSlugTaken
		case "23503":
			if deleting {
				return ErrInUse
			}
			return invalidf("mcp_servers — MCP-сервер не найден")
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

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func derefT(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

func nullBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nullText(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	return &s
}

// --- MCP-серверы ---

const serverCols = `id::text, org_id::text, slug, name, url, ca_pem, auth_header, credential, credential_key_id::text,
	credential_alg, credential_set_at, external, insecure_http, call_timeout_s, versions, created_at, created_by, updated_at, updated_by`

func scanServer(row pgx.Row) (MCPServer, error) {
	var m MCPServer
	var header, keyID, alg *string
	var cred []byte
	var setAt *time.Time
	if err := row.Scan(&m.ID, &m.OrgID, &m.Slug, &m.Name, &m.URL, &m.CAPEM, &header, &cred, &keyID, &alg, &setAt,
		&m.External, &m.InsecureHTTP, &m.CallTimeout, &m.Versions, &m.CreatedAt, &m.CreatedBy, &m.UpdatedAt, &m.UpdatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MCPServer{}, ErrNotFound
		}
		return MCPServer{}, err
	}
	m.AuthHeader = derefS(header)
	if cred != nil {
		m.Credential = &Sealed{Data: cred, KeyID: derefS(keyID), Alg: derefS(alg), SetAt: derefT(setAt)}
	}
	m.CreatedAt, m.UpdatedAt = m.CreatedAt.UTC(), m.UpdatedAt.UTC()
	return m, nil
}

func credCols(m MCPServer) (data []byte, keyID, alg *string, setAt *time.Time) {
	if m.Credential == nil {
		return nil, nil, nil, nil
	}
	return m.Credential.Data, &m.Credential.KeyID, &m.Credential.Alg, &m.Credential.SetAt
}

// CreateServer — см. Store.
func (s *PGStore) CreateServer(ctx context.Context, m MCPServer, rec audit.Entry) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockOrg(ctx, tx, m.OrgID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM mcp_servers WHERE org_id = $1`, m.OrgID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxServers {
			return ErrTooMany
		}
		data, keyID, alg, setAt := credCols(m)
		if _, err := tx.Exec(ctx, `INSERT INTO mcp_servers (id, org_id, slug, name, url, ca_pem, auth_header, credential,
			credential_key_id, credential_alg, credential_set_at, external, insecure_http, call_timeout_s, versions,
			created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
			m.ID, m.OrgID, m.Slug, m.Name, m.URL, m.CAPEM, nullStr(m.AuthHeader), data, keyID, alg, setAt, m.External,
			m.InsecureHTTP, m.CallTimeout, m.Versions, m.CreatedAt, m.CreatedBy, m.UpdatedAt, m.UpdatedBy); err != nil {
			return pgErr(err, false)
		}
		return s.record(ctx, tx, rec)
	})
}

// UpdateServer — см. Store.
func (s *PGStore) UpdateServer(ctx context.Context, orgID, id string, fn func(*MCPServer) (audit.Entry, error)) (MCPServer, error) {
	var out MCPServer
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		m, err := scanServer(tx.QueryRow(ctx, `SELECT `+serverCols+` FROM mcp_servers WHERE org_id = $1 AND id = $2 FOR UPDATE`, orgID, id))
		if err != nil {
			return err
		}
		rec, err := fn(&m)
		if err != nil {
			return err
		}
		data, keyID, alg, setAt := credCols(m)
		if _, err := tx.Exec(ctx, `UPDATE mcp_servers SET name = $3, url = $4, ca_pem = $5, auth_header = $6, credential = $7,
			credential_key_id = $8, credential_alg = $9, credential_set_at = $10, external = $11, insecure_http = $12,
			call_timeout_s = $13, versions = $14, updated_at = $15, updated_by = $16 WHERE org_id = $1 AND id = $2`,
			orgID, id, m.Name, m.URL, m.CAPEM, nullStr(m.AuthHeader), data, keyID, alg, setAt, m.External, m.InsecureHTTP,
			m.CallTimeout, m.Versions, m.UpdatedAt, m.UpdatedBy); err != nil {
			return pgErr(err, false)
		}
		out = m
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// DeleteServer — см. Store.
func (s *PGStore) DeleteServer(ctx context.Context, orgID, id string, fn func(MCPServer) (audit.Entry, error)) (MCPServer, error) {
	var out MCPServer
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		m, err := scanServer(tx.QueryRow(ctx, `SELECT `+serverCols+` FROM mcp_servers WHERE org_id = $1 AND id = $2 FOR UPDATE`, orgID, id))
		if err != nil {
			return err
		}
		rec, err := fn(m)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mcp_servers WHERE org_id = $1 AND id = $2`, orgID, id); err != nil {
			return pgErr(err, true)
		}
		out = m
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// Server — см. Store.
func (s *PGStore) Server(ctx context.Context, orgID, id string) (MCPServer, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanServer(s.db.QueryRow(ctx, `SELECT `+serverCols+` FROM mcp_servers WHERE org_id = $1 AND id = $2`, orgID, id))
}

// ServerBySlug — см. Store.
func (s *PGStore) ServerBySlug(ctx context.Context, orgID, slug string) (MCPServer, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanServer(s.db.QueryRow(ctx, `SELECT `+serverCols+` FROM mcp_servers WHERE org_id = $1 AND slug = $2`, orgID, slug))
}

// Servers — см. Store.
func (s *PGStore) Servers(ctx context.Context, orgID string) ([]MCPServer, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+serverCols+` FROM mcp_servers WHERE org_id = $1 ORDER BY slug LIMIT $2`, orgID, MaxServers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPServer
	for rows.Next() {
		m, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// --- Агенты ---

const agentCols = `a.id::text, a.org_id::text, a.app_id::text, a.slug, a.name, a.description, a.owner, a.status,
	COALESCE((SELECT array_agg(x.server_id::text ORDER BY x.server_id) FROM agent_servers x WHERE x.agent_id = a.id), '{}'),
	a.created_at, a.created_by, a.updated_at, a.updated_by`

func scanAgent(row pgx.Row) (Agent, error) {
	var a Agent
	if err := row.Scan(&a.ID, &a.OrgID, &a.AppID, &a.Slug, &a.Name, &a.Description, &a.Owner, &a.Status, &a.Servers,
		&a.CreatedAt, &a.CreatedBy, &a.UpdatedAt, &a.UpdatedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Agent{}, ErrNotFound
		}
		return Agent{}, err
	}
	a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	return a, nil
}

// setServers заменяет список MCP-серверов агента (серверы своей
// организации).
func setServers(ctx context.Context, tx pgx.Tx, a Agent) error {
	if _, err := tx.Exec(ctx, `DELETE FROM agent_servers WHERE agent_id = $1 AND NOT (server_id::text = ANY($2))`, a.ID, a.Servers); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mcp_servers WHERE org_id = $1 AND id::text = ANY($2)`, a.OrgID, a.Servers).Scan(&n); err != nil {
		return err
	}
	if n != len(a.Servers) {
		return invalidf("mcp_servers — MCP-сервер не найден")
	}
	_, err := tx.Exec(ctx, `INSERT INTO agent_servers (org_id, agent_id, server_id)
		SELECT $1, $2, unnest($3::uuid[]) ON CONFLICT DO NOTHING`, a.OrgID, a.ID, a.Servers)
	return err
}

// CreateAgent — см. Store.
func (s *PGStore) CreateAgent(ctx context.Context, a Agent, rec audit.Entry) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockOrg(ctx, tx, a.OrgID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM agents WHERE org_id = $1`, a.OrgID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxAgents {
			return ErrTooMany
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agents (id, org_id, app_id, slug, name, description, owner, status,
			created_at, created_by, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			a.ID, a.OrgID, a.AppID, a.Slug, a.Name, a.Description, a.Owner, a.Status, a.CreatedAt, a.CreatedBy,
			a.UpdatedAt, a.UpdatedBy); err != nil {
			return pgErr(err, false)
		}
		if err := setServers(ctx, tx, a); err != nil {
			return pgErr(err, false)
		}
		return s.record(ctx, tx, rec)
	})
}

// UpdateAgent — см. Store.
func (s *PGStore) UpdateAgent(ctx context.Context, orgID, id string, fn func(*Agent) (audit.Entry, error)) (Agent, error) {
	var out Agent
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		a, err := scanAgent(tx.QueryRow(ctx, `SELECT `+agentCols+` FROM agents a WHERE a.org_id = $1 AND a.id = $2 FOR UPDATE`, orgID, id))
		if err != nil {
			return err
		}
		rec, err := fn(&a)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE agents SET name = $3, description = $4, owner = $5, status = $6, updated_at = $7,
			updated_by = $8 WHERE org_id = $1 AND id = $2`, orgID, id, a.Name, a.Description, a.Owner, a.Status, a.UpdatedAt, a.UpdatedBy); err != nil {
			return err
		}
		if err := setServers(ctx, tx, a); err != nil {
			return pgErr(err, false)
		}
		out = a
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// DeleteAgent — см. Store.
func (s *PGStore) DeleteAgent(ctx context.Context, orgID, id string, fn func(Agent) (audit.Entry, error)) (Agent, error) {
	var out Agent
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		a, err := scanAgent(tx.QueryRow(ctx, `SELECT `+agentCols+` FROM agents a WHERE a.org_id = $1 AND a.id = $2 FOR UPDATE`, orgID, id))
		if err != nil {
			return err
		}
		rec, err := fn(a)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM agents WHERE org_id = $1 AND id = $2`, orgID, id); err != nil {
			return pgErr(err, true)
		}
		out = a
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// Agent — см. Store.
func (s *PGStore) Agent(ctx context.Context, orgID, id string) (Agent, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanAgent(s.db.QueryRow(ctx, `SELECT `+agentCols+` FROM agents a WHERE a.org_id = $1 AND a.id = $2`, orgID, id))
}

// AgentBySlug — см. Store.
func (s *PGStore) AgentBySlug(ctx context.Context, orgID, appID, slug string) (Agent, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanAgent(s.db.QueryRow(ctx, `SELECT `+agentCols+` FROM agents a WHERE a.org_id = $1 AND a.app_id = $2 AND a.slug = $3`,
		orgID, appID, slug))
}

// Agents — см. Store.
func (s *PGStore) Agents(ctx context.Context, orgID string, appIDs []string) ([]Agent, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+agentCols+` FROM agents a WHERE a.org_id = $1
		AND ($2::text[] IS NULL OR a.app_id::text = ANY($2)) ORDER BY a.app_id, a.slug LIMIT $3`, orgID, appIDs, MaxAgents)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- Инструменты ---

const toolCols = `id::text, org_id::text, COALESCE(server_id::text, ''), COALESCE(agent_id::text, ''), name, descriptor,
	descriptor_hash, approved_descriptor, approved_hash, hash_alg, risk, status, first_seen, last_seen, decided_by, decided_at,
	comment, updated_at`

func scanTool(row pgx.Row) (Tool, error) {
	var t Tool
	var desc string
	var approved, decidedBy *string
	var decidedAt *time.Time
	var risk, status string
	if err := row.Scan(&t.ID, &t.OrgID, &t.ServerID, &t.AgentID, &t.Name, &desc, &t.Hash, &approved, &t.ApprovedHash,
		&t.HashAlg, &risk, &status, &t.FirstSeen, &t.LastSeen, &decidedBy, &decidedAt, &t.Comment, &t.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Tool{}, ErrNotFound
		}
		return Tool{}, err
	}
	t.Descriptor, t.Risk, t.Status = []byte(desc), policy.ToolRisk(risk), policy.ToolStatus(status)
	if approved != nil {
		t.ApprovedDescriptor = []byte(*approved)
	}
	t.DecidedBy, t.DecidedAt = derefS(decidedBy), derefT(decidedAt)
	t.FirstSeen, t.LastSeen, t.UpdatedAt = t.FirstSeen.UTC(), t.LastSeen.UTC(), t.UpdatedAt.UTC()
	return t, nil
}

func saveTool(ctx context.Context, tx pgx.Tx, t Tool) error {
	_, err := tx.Exec(ctx, `INSERT INTO agent_tools (id, org_id, server_id, agent_id, name, descriptor, descriptor_hash,
		approved_descriptor, approved_hash, hash_alg, risk, status, first_seen, last_seen, decided_by, decided_at, comment, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		ON CONFLICT (id) DO UPDATE SET descriptor = EXCLUDED.descriptor, descriptor_hash = EXCLUDED.descriptor_hash,
		approved_descriptor = EXCLUDED.approved_descriptor, approved_hash = EXCLUDED.approved_hash, hash_alg = EXCLUDED.hash_alg,
		risk = EXCLUDED.risk, status = EXCLUDED.status, last_seen = EXCLUDED.last_seen, decided_by = EXCLUDED.decided_by,
		decided_at = EXCLUDED.decided_at, comment = EXCLUDED.comment, updated_at = EXCLUDED.updated_at`,
		t.ID, t.OrgID, nullStr(t.ServerID), nullStr(t.AgentID), t.Name, string(t.Descriptor), t.Hash,
		nullText(t.ApprovedDescriptor), nullBytes(t.ApprovedHash), t.HashAlg, string(t.Risk), string(t.Status), t.FirstSeen,
		t.LastSeen, nullStr(t.DecidedBy), nullTime(t.DecidedAt), t.Comment, t.UpdatedAt)
	return err
}

// Observe — см. Store.
func (s *PGStore) Observe(ctx context.Context, orgID, serverID, agentID string, names []string,
	fn func(known map[string]Tool, total, owned int) ([]Tool, []audit.Entry, error)) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockOrg(ctx, tx, orgID); err != nil {
			return err
		}
		var total, owned int
		if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE server_id IS NOT DISTINCT FROM $2::uuid
			AND agent_id IS NOT DISTINCT FROM $3::uuid) FROM agent_tools WHERE org_id = $1`,
			orgID, nullStr(serverID), nullStr(agentID)).Scan(&total, &owned); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+toolCols+` FROM agent_tools WHERE org_id = $1
			AND server_id IS NOT DISTINCT FROM $2::uuid AND agent_id IS NOT DISTINCT FROM $3::uuid AND name = ANY($4) FOR UPDATE`,
			orgID, nullStr(serverID), nullStr(agentID), names)
		if err != nil {
			return err
		}
		known := map[string]Tool{}
		for rows.Next() {
			t, err := scanTool(rows)
			if err != nil {
				rows.Close()
				return err
			}
			known[t.Name] = t
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		ts, recs, err := fn(known, total, owned)
		if err != nil {
			return err
		}
		for _, t := range ts {
			if err := saveTool(ctx, tx, t); err != nil {
				return err
			}
		}
		for _, r := range recs {
			if err := s.record(ctx, tx, r); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpdateTool — см. Store.
func (s *PGStore) UpdateTool(ctx context.Context, orgID, id string, fn func(*Tool) (audit.Entry, error)) (Tool, error) {
	var out Tool
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		t, err := scanTool(tx.QueryRow(ctx, `SELECT `+toolCols+` FROM agent_tools WHERE org_id = $1 AND id = $2 FOR UPDATE`, orgID, id))
		if err != nil {
			return err
		}
		rec, err := fn(&t)
		if err != nil {
			return err
		}
		if err := saveTool(ctx, tx, t); err != nil {
			return err
		}
		out = t
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// Tool — см. Store.
func (s *PGStore) Tool(ctx context.Context, orgID, id string) (Tool, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanTool(s.db.QueryRow(ctx, `SELECT `+toolCols+` FROM agent_tools WHERE org_id = $1 AND id = $2`, orgID, id))
}

// Tools — см. Store.
func (s *PGStore) Tools(ctx context.Context, orgID string, f ToolFilter) ([]Tool, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.db.Query(ctx, `SELECT `+toolCols+` FROM agent_tools WHERE org_id = $1
		AND ($2 = '' OR server_id::text = $2) AND ($3 = '' OR agent_id::text = $3) AND ($4 = '' OR status = $4)
		ORDER BY server_id NULLS LAST, agent_id, name LIMIT $5`, orgID, f.ServerID, f.AgentID, string(f.Status), MaxTools)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tool
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
