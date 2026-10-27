package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/agents"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Пределы тел запросов реестра агентов.
const (
	// mcpServerMaxBody — корневые сертификаты до 256 КиБ; переводы строк
	// в JSON занимают по два байта.
	mcpServerMaxBody     = 2*agents.MaxCAPEM + 16<<10
	mcpCredentialMaxBody = 4*agents.MaxCredential + 1<<10
)

// agentRoutes — агенты, MCP-серверы и инструменты (ТЗ 5.10; задача 4.8,
// ADR-0023, разделы 1 и 9). Чтение со ScopeOwn (владелец приложения) —
// только агенты своих приложений, их MCP-серверы и инструменты (УПД.8).
// Одобрение инструментов, риск и признаки external и insecure_http
// MCP-сервера — функция безопасности (agents.tools.approve): ослабление
// требует повторной проверки паролем или кодом (DM-25, DM-40). Учётные
// данные MCP-серверов в ответах не показываются.
func agentRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/agents", Permission: auth.PermAgentsRead, Scoped: true,
			Handler: needAgents(d, d.listAgents)},
		{Method: http.MethodPost, Path: "/api/v1/agents", Permission: auth.PermAgentsManage, Idempotent: true,
			MaxBody: smallMaxBody, Handler: needAgents(d, d.createAgent)},
		{Method: http.MethodGet, Path: "/api/v1/agents/{id}", Permission: auth.PermAgentsRead, Scoped: true,
			Handler: needAgents(d, d.getAgent)},
		{Method: http.MethodPut, Path: "/api/v1/agents/{id}", Permission: auth.PermAgentsManage,
			MaxBody: smallMaxBody, Handler: needAgents(d, d.updateAgent)},
		{Method: http.MethodDelete, Path: "/api/v1/agents/{id}", Permission: auth.PermAgentsManage,
			Handler: needAgents(d, d.deleteAgent)},

		{Method: http.MethodGet, Path: "/api/v1/mcp-servers", Permission: auth.PermAgentsRead, Scoped: true,
			Handler: needAgents(d, d.listMCPServers)},
		{Method: http.MethodPost, Path: "/api/v1/mcp-servers", Permission: auth.PermAgentsManage, Idempotent: true,
			MaxBody: mcpServerMaxBody, Handler: needAgents(d, d.createMCPServer)},
		{Method: http.MethodGet, Path: "/api/v1/mcp-servers/{id}", Permission: auth.PermAgentsRead, Scoped: true,
			Handler: needAgents(d, d.getMCPServer)},
		{Method: http.MethodPut, Path: "/api/v1/mcp-servers/{id}", Permission: auth.PermAgentsManage,
			MaxBody: mcpServerMaxBody, Handler: needAgents(d, d.updateMCPServer)},
		{Method: http.MethodDelete, Path: "/api/v1/mcp-servers/{id}", Permission: auth.PermAgentsManage,
			Handler: needAgents(d, d.deleteMCPServer)},
		{Method: http.MethodPut, Path: "/api/v1/mcp-servers/{id}/credentials", Permission: auth.PermAgentsManage,
			MaxBody: mcpCredentialMaxBody, Handler: needAgents(d, d.setMCPCredential)},
		{Method: http.MethodPut, Path: "/api/v1/mcp-servers/{id}/security", Permission: auth.PermAgentsToolsApprove,
			MaxBody: smallMaxBody, Handler: needAgents(d, d.setMCPSecurity)},

		{Method: http.MethodGet, Path: "/api/v1/agent-tools", Permission: auth.PermAgentsRead, Scoped: true,
			Handler: needAgents(d, d.listAgentTools)},
		{Method: http.MethodGet, Path: "/api/v1/agent-tools/{id}", Permission: auth.PermAgentsRead, Scoped: true,
			Handler: needAgents(d, d.getAgentTool)},
		{Method: http.MethodPost, Path: "/api/v1/agent-tools/{id}/approve", Permission: auth.PermAgentsToolsApprove,
			MaxBody: smallMaxBody, Handler: needAgents(d, d.approveAgentTool)},
		{Method: http.MethodPost, Path: "/api/v1/agent-tools/{id}/revoke", Permission: auth.PermAgentsToolsApprove,
			MaxBody: smallMaxBody, Handler: needAgents(d, d.revokeAgentTool)},
		{Method: http.MethodPut, Path: "/api/v1/agent-tools/{id}/risk", Permission: auth.PermAgentsToolsApprove,
			MaxBody: smallMaxBody, Handler: needAgents(d, d.setAgentToolRisk)},
	}
}

func needAgents(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Agents == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Реестр агентов не подключён на сервере."))
			return
		}
		h(w, r)
	}
}

const (
	agentNotFound     = "Агент не найден."
	mcpServerNotFound = "MCP-сервер не найден."
	agentToolNotFound = "Инструмент не найден."
)

// agentsProblem переводит ошибки реестра агентов в ответы API.
func agentsProblem(logger *slog.Logger, err error, notFound string) *Problem {
	var ie *agents.InputError
	var re *reauthError
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.As(err, &ie):
		fields := make([]FieldError, 0, len(ie.Errs))
		for _, e := range ie.Errs {
			f := ""
			if m := fieldRe.FindStringSubmatch(e.Error()); m != nil {
				f = m[1]
			}
			fields = append(fields, FieldError{Field: f, Detail: e.Error()})
		}
		return Invalid("Проверьте введённые данные.", fields...)
	case errors.Is(err, agents.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, notFound)
	case errors.Is(err, agents.ErrNoApp):
		return Invalid("Проверьте введённые данные.", FieldError{Field: "application_id", Detail: "Приложение не найдено."})
	case errors.Is(err, agents.ErrArchivedApp):
		return NewProblem(http.StatusConflict, CodeConflict, "Приложение в архиве: агентов в нём не создают и не меняют.")
	case errors.Is(err, agents.ErrSlugTaken):
		return NewProblem(http.StatusConflict, CodeConflict, "Такой ID уже занят: выберите другой.")
	case errors.Is(err, agents.ErrInUse):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Объект используется: MCP-сервер указан у агентов или к агенту привязаны ключи приложения. "+
				"Сервер уберите из списков агентов; агента с ключами (в том числе отозванными) удалить нельзя — отключите его.")
	case errors.Is(err, agents.ErrTooMany):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Достигнут предел реестра: 256 агентов, 64 MCP-сервера. Удалите неиспользуемые.")
	case errors.Is(err, agents.ErrConfirmRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Изменение ослабляет защиту: выполните его в консоли с вводом текущего пароля или кода.")
	case errors.Is(err, agents.ErrSecurityRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Адрес http:// и признак «внешний» у MCP-сервера меняет администратор безопасности.")
	case errors.Is(err, agents.ErrServerChanged):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Адрес или корневые сертификаты MCP-сервера только что изменили: проверьте карточку и задайте учётные данные заново.")
	case errors.Is(err, agents.ErrStale):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Описание инструмента изменилось после показа: обновите страницу, сравните описания и повторите одобрение.")
	case errors.Is(err, agents.ErrNoDataKey):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
			"Ключ данных не подключён: учётные данные MCP-серверов сохранить нельзя. Выполните aisec-cli init и перезапустите сервер.")
	}
	logger.Error("агенты: ошибка обработки запроса", "error", err)
	return errInternal()
}

// agentsBy — субъект запроса: признак права agents.tools.approve и
// повторная проверка для ослабления (Н32).
func (d Deps) agentsBy(r *http.Request, re reauthFields, action string) (agents.By, bool) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		return agents.By{}, false
	}
	c := p.Caller
	by := agents.By{Actor: audit.Actor{Type: audit.ActorUser, ID: c.User.ID, Name: c.User.Login}, IP: clientAddr(r),
		Security: p.Grants.Full(auth.PermAgentsToolsApprove)}
	if c.Token != nil {
		by.Actor = audit.Actor{Type: audit.ActorAPIToken, ID: c.Token.ID, Name: c.User.Login + " (" + c.Token.Prefix + ")"}
	}
	by.Confirm = d.confirmFunc(r, re, action, agents.ErrConfirmRequired)
	return by, true
}

// --- Агенты ---

// AgentView — агент в ответах.
type AgentView struct {
	ID            string `json:"id"`
	ApplicationID string `json:"application_id"`
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Owner         string `json:"owner"`
	// MCPServers — ID MCP-серверов, к которым агенту можно обращаться.
	MCPServers []string  `json:"mcp_servers"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	CreatedBy  string    `json:"created_by"`
	UpdatedAt  time.Time `json:"updated_at"`
	UpdatedBy  string    `json:"updated_by"`
}

func agentView(a agents.Agent) AgentView {
	s := a.Servers
	if s == nil {
		s = []string{}
	}
	return AgentView{ID: a.ID, ApplicationID: a.AppID, Slug: a.Slug, Name: a.Name, Description: a.Description, Owner: a.Owner,
		MCPServers: s, Status: a.Status, CreatedAt: a.CreatedAt.UTC(), CreatedBy: a.CreatedBy, UpdatedAt: a.UpdatedAt.UTC(),
		UpdatedBy: a.UpdatedBy}
}

// AgentList — агенты (не больше 256).
type AgentList struct {
	Items []AgentView `json:"items"`
}

func (d Deps) listAgents(w http.ResponseWriter, r *http.Request) {
	owner, ok := ownerScope(r, auth.PermAgentsRead)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	appID := ""
	if vs, ok := r.URL.Query()["application_id"]; ok {
		id, err := store.ParseUUID(vs[0])
		if len(vs) != 1 || err != nil {
			WriteProblem(w, Invalid("Параметры выборки заданы неверно.", FieldError{"application_id", "ID приложения."}))
			return
		}
		appID = string(id)
	}
	list, err := d.Agents.Agents(r.Context(), appID, owner)
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, agentNotFound))
		return
	}
	out := AgentList{Items: make([]AgentView, 0, len(list))}
	for _, a := range list {
		out.Items = append(out.Items, agentView(a))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (d Deps) getAgent(w http.ResponseWriter, r *http.Request) {
	owner, ok := ownerScope(r, auth.PermAgentsRead)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, agentNotFound)
	if !ok {
		return
	}
	a, err := d.Agents.Agent(r.Context(), id, owner)
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, agentNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, agentView(a))
}

type agentRequest struct {
	ApplicationID string   `json:"application_id"`
	Slug          string   `json:"slug"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Owner         string   `json:"owner"`
	MCPServers    []string `json:"mcp_servers"`
	Status        string   `json:"status"`
	reauthFields
}

func (q agentRequest) input() agents.AgentInput {
	return agents.AgentInput{AppID: q.ApplicationID, Slug: q.Slug, Name: q.Name, Description: q.Description, Owner: q.Owner,
		Servers: q.MCPServers, Status: q.Status}
}

func (d Deps) createAgent(w http.ResponseWriter, r *http.Request) {
	var req agentRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.agentsBy(r, req.reauthFields, "agent.create")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	if _, err := store.ParseUUID(req.ApplicationID); err != nil {
		WriteProblem(w, Invalid("Проверьте введённые данные.", FieldError{"application_id", "ID приложения."}))
		return
	}
	a, err := d.Agents.CreateAgent(r.Context(), by, req.input())
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, agentNotFound))
		return
	}
	w.Header().Set("Location", "/api/v1/agents/"+a.ID)
	WriteJSON(w, http.StatusCreated, agentView(a))
}

func (d Deps) updateAgent(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, agentNotFound)
	if !ok {
		return
	}
	var req agentRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.agentsBy(r, req.reauthFields, "agent.update")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	a, err := d.Agents.UpdateAgent(r.Context(), by, id, req.input())
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, agentNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, agentView(a))
}

func (d Deps) deleteAgent(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, agentNotFound)
	if !ok {
		return
	}
	by, ok := d.agentsBy(r, reauthFields{}, "agent.delete")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	if _, err := d.Agents.DeleteAgent(r.Context(), by, id); err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, agentNotFound))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- MCP-серверы ---

// MCPServerView — MCP-сервер в ответах: учётных данных нет, только
// признак и время установки.
type MCPServerView struct {
	ID         string `json:"id"`
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	CAPEM      string `json:"ca_pem"`
	AuthHeader string `json:"auth_header"`
	// External — сервер вне контура заказчика; InsecureHTTP — разрешён
	// адрес http:// (ослабление, DM-40).
	External        bool       `json:"external"`
	InsecureHTTP    bool       `json:"insecure_http"`
	CallTimeout     int        `json:"call_timeout"`
	Versions        []string   `json:"versions"`
	CredentialSet   bool       `json:"credential_set"`
	CredentialSetAt *time.Time `json:"credential_set_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	CreatedBy       string     `json:"created_by"`
	UpdatedAt       time.Time  `json:"updated_at"`
	UpdatedBy       string     `json:"updated_by"`
}

func mcpServerView(m agents.MCPServer) MCPServerView {
	v := MCPServerView{ID: m.ID, Slug: m.Slug, Name: m.Name, URL: m.URL, CAPEM: m.CAPEM, AuthHeader: m.AuthHeader,
		External: m.External, InsecureHTTP: m.InsecureHTTP, CallTimeout: m.CallTimeout, Versions: m.Versions,
		CredentialSet: m.Credential != nil, CreatedAt: m.CreatedAt.UTC(), CreatedBy: m.CreatedBy,
		UpdatedAt: m.UpdatedAt.UTC(), UpdatedBy: m.UpdatedBy}
	if v.CallTimeout == 0 {
		v.CallTimeout = agents.DefaultCallTimeout
	}
	if v.Versions == nil {
		v.Versions = []string{}
	}
	if m.Credential != nil {
		v.CredentialSetAt = optTime(m.Credential.SetAt)
	}
	return v
}

// MCPServerList — MCP-серверы (не больше 64).
type MCPServerList struct {
	Items []MCPServerView `json:"items"`
}

func (d Deps) listMCPServers(w http.ResponseWriter, r *http.Request) {
	owner, ok := ownerScope(r, auth.PermAgentsRead)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	list, err := d.Agents.ServersFor(r.Context(), owner)
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, mcpServerNotFound))
		return
	}
	out := MCPServerList{Items: make([]MCPServerView, 0, len(list))}
	for _, m := range list {
		out.Items = append(out.Items, mcpServerView(m))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (d Deps) getMCPServer(w http.ResponseWriter, r *http.Request) {
	owner, ok := ownerScope(r, auth.PermAgentsRead)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, mcpServerNotFound)
	if !ok {
		return
	}
	m, err := d.Agents.ServerFor(r.Context(), id, owner)
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, mcpServerNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, mcpServerView(m))
}

type mcpServerRequest struct {
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	CAPEM       string   `json:"ca_pem"`
	AuthHeader  string   `json:"auth_header"`
	CallTimeout int      `json:"call_timeout"`
	Versions    []string `json:"versions"`
	reauthFields
}

func (q mcpServerRequest) input() agents.ServerInput {
	return agents.ServerInput{Slug: q.Slug, Name: q.Name, URL: q.URL, CAPEM: q.CAPEM, AuthHeader: q.AuthHeader,
		CallTimeout: q.CallTimeout, Versions: q.Versions}
}

func (d Deps) createMCPServer(w http.ResponseWriter, r *http.Request) {
	var req mcpServerRequest
	if p := DecodeJSON(w, r, &req, mcpServerMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.agentsBy(r, req.reauthFields, "mcp_server.create")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	m, err := d.Agents.CreateServer(r.Context(), by, req.input())
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, mcpServerNotFound))
		return
	}
	w.Header().Set("Location", "/api/v1/mcp-servers/"+m.ID)
	WriteJSON(w, http.StatusCreated, mcpServerView(m))
}

func (d Deps) updateMCPServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, mcpServerNotFound)
	if !ok {
		return
	}
	var req mcpServerRequest
	if p := DecodeJSON(w, r, &req, mcpServerMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.agentsBy(r, req.reauthFields, "mcp_server.update")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	m, err := d.Agents.UpdateServer(r.Context(), by, id, req.input())
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, mcpServerNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, mcpServerView(m))
}

func (d Deps) deleteMCPServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, mcpServerNotFound)
	if !ok {
		return
	}
	by, ok := d.agentsBy(r, reauthFields{}, "mcp_server.delete")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	if _, err := d.Agents.DeleteServer(r.Context(), by, id); err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, mcpServerNotFound))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) setMCPCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, mcpServerNotFound)
	if !ok {
		return
	}
	var req credentialRequest
	if p := DecodeJSON(w, r, &req, mcpCredentialMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.agentsBy(r, reauthFields{}, "mcp_server.credentials_set")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	cred := []byte(req.Credential)
	m, err := d.Agents.SetServerCredential(r.Context(), by, id, cred)
	clear(cred)
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, mcpServerNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, mcpServerView(m))
}

type mcpSecurityRequest struct {
	External     *bool  `json:"external"`
	InsecureHTTP *bool  `json:"insecure_http"`
	Reason       string `json:"reason"`
	reauthFields
}

func (d Deps) setMCPSecurity(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, mcpServerNotFound)
	if !ok {
		return
	}
	var req mcpSecurityRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.agentsBy(r, req.reauthFields, "mcp_server.security_changed")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	m, err := d.Agents.SetServerSecurity(r.Context(), by, id,
		agents.SecurityInput{External: req.External, InsecureHTTP: req.InsecureHTTP, Reason: req.Reason})
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, mcpServerNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, mcpServerView(m))
}

// --- Инструменты ---

// AgentToolView — инструмент реестра в списке: без описаний.
type AgentToolView struct {
	ID string `json:"id"`
	// MCPServerID — MCP-сервер; для функций агента пусто, задан AgentID.
	MCPServerID string `json:"mcp_server_id,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
	Name        string `json:"name"`
	// Status — new, approved, changed, suspicious или revoked (DM-25).
	Status string `json:"status"`
	Risk   string `json:"risk"`
	// Hash и ApprovedHash — хеши последнего увиденного и одобренного
	// описаний (hex), HashAlg — алгоритм криптопрофиля.
	Hash         string     `json:"hash"`
	ApprovedHash string     `json:"approved_hash,omitempty"`
	HashAlg      string     `json:"hash_alg"`
	FirstSeen    time.Time  `json:"first_seen"`
	LastSeen     time.Time  `json:"last_seen"`
	DecidedBy    string     `json:"decided_by,omitempty"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	Comment      string     `json:"comment,omitempty"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// AgentToolDetail — инструмент с увиденным и одобренным описаниями
// (каноническая форма): консоль показывает разницу перед повторным
// одобрением (ADR-0023, раздел 1).
type AgentToolDetail struct {
	AgentToolView
	Descriptor         json.RawMessage `json:"descriptor"`
	ApprovedDescriptor json.RawMessage `json:"approved_descriptor,omitempty"`
}

func agentToolView(t agents.Tool) AgentToolView {
	v := AgentToolView{ID: t.ID, MCPServerID: t.ServerID, AgentID: t.AgentID, Name: t.Name, Status: string(t.Status),
		Risk: string(t.Risk), Hash: hex.EncodeToString(t.Hash), HashAlg: t.HashAlg, FirstSeen: t.FirstSeen.UTC(),
		LastSeen: t.LastSeen.UTC(), DecidedBy: t.DecidedBy, DecidedAt: optTime(t.DecidedAt), Comment: t.Comment,
		UpdatedAt: t.UpdatedAt.UTC()}
	if t.ServerID != "" {
		v.AgentID = ""
	}
	if len(t.ApprovedHash) > 0 {
		v.ApprovedHash = hex.EncodeToString(t.ApprovedHash)
	}
	return v
}

func agentToolDetail(t agents.Tool) AgentToolDetail {
	out := AgentToolDetail{AgentToolView: agentToolView(t), Descriptor: json.RawMessage(t.Descriptor)}
	if len(t.ApprovedDescriptor) > 0 {
		out.ApprovedDescriptor = json.RawMessage(t.ApprovedDescriptor)
	}
	return out
}

// AgentToolList — инструменты по отбору (не больше 2 000).
type AgentToolList struct {
	Items []AgentToolView `json:"items"`
}

func (d Deps) listAgentTools(w http.ResponseWriter, r *http.Request) {
	owner, ok := ownerScope(r, auth.PermAgentsRead)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var f agents.ToolFilter
	q := r.URL.Query()
	for _, p := range []struct {
		name string
		dst  *string
	}{{"mcp_server_id", &f.ServerID}, {"agent_id", &f.AgentID}} {
		vs, ok := q[p.name]
		if !ok {
			continue
		}
		id, err := store.ParseUUID(vs[0])
		if len(vs) != 1 || err != nil {
			WriteProblem(w, Invalid("Параметры выборки заданы неверно.", FieldError{p.name, "ID объекта."}))
			return
		}
		*p.dst = string(id)
	}
	if vs, ok := q["status"]; ok {
		st := policy.ToolStatus(vs[0])
		switch {
		case len(vs) != 1:
		case st == policy.ToolNew, st == policy.ToolApproved, st == policy.ToolChanged, st == policy.ToolSuspicious,
			st == policy.ToolRevoked:
			f.Status = st
		}
		if f.Status == "" {
			WriteProblem(w, Invalid("Параметры выборки заданы неверно.",
				FieldError{"status", "new, approved, changed, suspicious или revoked."}))
			return
		}
	}
	list, err := d.Agents.Tools(r.Context(), f, owner)
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, agentToolNotFound))
		return
	}
	out := AgentToolList{Items: make([]AgentToolView, 0, len(list))}
	for _, t := range list {
		out.Items = append(out.Items, agentToolView(t))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (d Deps) getAgentTool(w http.ResponseWriter, r *http.Request) {
	owner, ok := ownerScope(r, auth.PermAgentsRead)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, agentToolNotFound)
	if !ok {
		return
	}
	t, err := d.Agents.Tool(r.Context(), id, owner)
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, agentToolNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, agentToolDetail(t))
}

type approveToolRequest struct {
	Risk policy.ToolRisk `json:"risk"`
	// Hash — хеш описания, которое видел администратор (hex).
	Hash    string `json:"hash"`
	Comment string `json:"comment"`
	reauthFields
}

func (d Deps) approveAgentTool(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, agentToolNotFound)
	if !ok {
		return
	}
	var req approveToolRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.agentsBy(r, req.reauthFields, "agent_tool.approve")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	t, err := d.Agents.Approve(r.Context(), by, id, agents.ApproveInput{Risk: req.Risk, Hash: req.Hash, Comment: req.Comment})
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, agentToolNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, agentToolView(t))
}

type revokeToolRequest struct {
	Comment string `json:"comment"`
}

func (d Deps) revokeAgentTool(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, agentToolNotFound)
	if !ok {
		return
	}
	var req revokeToolRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.agentsBy(r, reauthFields{}, "agent_tool.revoke")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	t, err := d.Agents.Revoke(r.Context(), by, id, req.Comment)
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, agentToolNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, agentToolView(t))
}

type toolRiskRequest struct {
	Risk    policy.ToolRisk `json:"risk"`
	Comment string          `json:"comment"`
	reauthFields
}

func (d Deps) setAgentToolRisk(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, agentToolNotFound)
	if !ok {
		return
	}
	var req toolRiskRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by, ok := d.agentsBy(r, req.reauthFields, "agent_tool.risk")
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	t, err := d.Agents.SetRisk(r.Context(), by, id, req.Risk, req.Comment)
	if err != nil {
		WriteProblem(w, agentsProblem(d.Logger, err, agentToolNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, agentToolView(t))
}
