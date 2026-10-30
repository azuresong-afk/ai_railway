//go:build e2e

package e2e

// Сценарий S5 этапа 4 (задача 4.30): опасное действие агента. Агент идёт
// через MCP-прокси шлюза к mock-mcp (internal/mockmcp); политика вызовов
// пускает чтение отчётов только в своём каталоге и с ограничением частоты,
// а удаление файлов отдаёт человеку. Тесты на живой PostgreSQL с настоящими
// сервером и шлюзом. Строки матрицы покрыты и модульными тестами с ID
// строки; здесь — сквозной путь от вызова агента до решения человека в
// API консоли, события и оповещения.

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/mockmcp"
)

// s4Agents — стенд агента: сервер, шлюз, mock-mcp, приложение с агентом и
// ключом агента; одобренные инструменты уже видны агенту.
type s4Agents struct {
	st    *s3Stack
	mcp   *s4MCP
	app   s3App
	key   string
	tools map[string]s4AgentTool
}

// s4AgentsOpts — настройка стенда агента.
type s4AgentsOpts struct {
	// tools — раздел tools политики.
	tools map[string]any
	// rules — правила политики сверх инъекции на входе (она нужна для
	// результатов инструментов, DM-07).
	rules []map[string]any
	// approve — инструменты, которые одобряет администратор, и их риск.
	approve map[string]string
	// stack — параметры сервера и mock-llm.
	stack s3Opts
}

// s4NewAgents поднимает стенд агента: политика, MCP-сервер с учётными
// данными, агент, ключ агента, одобрение инструментов approve и ожидание
// пакета, в котором агент видит одобренные инструменты.
func s4NewAgents(t *testing.T, o s4AgentsOpts) *s4Agents {
	t.Helper()
	ip := s4HostIP(t)
	st := s3NewStack(t, o.stack)
	a := &s4Agents{st: st, mcp: s4StartMCP(t, ip), tools: map[string]s4AgentTool{}}

	rules := append([]map[string]any{
		{"id": "injection", "detector": "injection.heuristic", "directions": []string{"input"}, "action": "block", "severity": "high"},
	}, o.rules...)
	spec := map[string]any{"name": "Агенты e2e", "mode": "enforce", "rules": rules, "tools": o.tools}
	if r := st.admin.do("POST", "/api/v1/policies", map[string]any{"id": "agents-e2e", "spec": spec}); r.code != http.StatusCreated {
		t.Fatalf("политика: %s", r)
	}
	a.app = st.app("agents", "agents-e2e")

	r := st.admin.do("POST", "/api/v1/mcp-servers", map[string]any{"slug": "files", "name": "Файлы e2e",
		"url": "https://" + a.mcp.addr + mockmcp.Path, "ca_pem": string(a.mcp.caPEM), "versions": []string{"2026-07-28", "2025-11-25"}})
	if r.code != http.StatusCreated {
		t.Fatalf("MCP-сервер: %s", r)
	}
	var srv struct{ ID string }
	r.json(t, &srv)
	if r := st.admin.do("PUT", "/api/v1/mcp-servers/"+srv.ID+"/credentials", map[string]any{"credential": s4MCPToken}); r.code != http.StatusOK &&
		r.code != http.StatusNoContent {
		t.Fatalf("учётные данные MCP-сервера: %s", r)
	}
	r = st.admin.do("POST", "/api/v1/agents", map[string]any{"application_id": a.app.id, "slug": "report-bot", "name": "Отчёты",
		"mcp_servers": []string{srv.ID}, "password": s2AdminPass})
	if r.code != http.StatusCreated {
		t.Fatalf("агент: %s", r)
	}
	var agent struct{ ID string }
	r.json(t, &agent)
	r = st.admin.do("POST", "/api/v1/applications/"+a.app.id+"/keys", map[string]any{"name": "агент", "expires_in_days": 30,
		"agent_id": agent.ID})
	if r.code != http.StatusCreated {
		t.Fatalf("ключ агента: %s", r)
	}
	var k struct{ Key string }
	r.json(t, &k)
	a.key = k.Key
	st.startGateway()

	// Первый tools/list передаёт описания реестру (tools:observe).
	s4MCPCall(t, st, a.key, "tools/list", "", "")
	if !s2WaitFor(60*time.Second, func() bool {
		r := st.admin.do("GET", "/api/v1/agent-tools", nil)
		var page struct{ Items []s4AgentTool }
		r.json(t, &page)
		for _, tl := range page.Items {
			a.tools[tl.Name] = tl
		}
		return len(a.tools) >= 6
	}) {
		t.Fatalf("описания не дошли до реестра: %+v", a.tools)
	}
	for name, risk := range o.approve {
		tl, ok := a.tools[name]
		if !ok {
			t.Fatalf("нет инструмента %s в реестре", name)
		}
		r := st.admin.do("POST", "/api/v1/agent-tools/"+tl.ID+"/approve", map[string]any{"risk": risk, "hash": tl.Hash,
			"password": s2AdminPass})
		if r.code != http.StatusOK {
			t.Fatalf("одобрение %s: %s", name, r)
		}
	}
	if !s2WaitFor(90*time.Second, func() bool {
		_, body := s4MCPCall(t, st, a.key, "tools/list", "", "")
		return len(s4ToolNames(t, body)) == len(o.approve)
	}) {
		t.Fatalf("одобренные инструменты не появились у агента\n%s", st.gw.log())
	}
	return a
}

// call — вызов инструмента агентом: код и тело ответа шлюза.
func (a *s4Agents) call(tool, args string) (int, string) {
	a.st.t.Helper()
	return s4MCPCall(a.st.t, a.st, a.key, "tools/call", tool, `"name":"`+tool+`","arguments":`+args)
}

// s4CallResult — ответ шлюза на вызов, выполненный в горутине.
type s4CallResult struct {
	code int
	body string
}

// callAsync — вызов, который может ждать решения человека: ответ приходит в
// канал, ожидание — не дольше wait.
func (a *s4Agents) callAsync(tool, args string, wait time.Duration) <-chan s4CallResult {
	ch := make(chan s4CallResult, 1)
	st := a.st
	go func() {
		code, body := s4MCPCallWait(st.t, st, a.key, "tools/call", tool, `"name":"`+tool+`","arguments":`+args, wait)
		ch <- s4CallResult{code, body}
	}()
	return ch
}

// await ждёт ответ на асинхронный вызов.
func (a *s4Agents) await(ch <-chan s4CallResult, d time.Duration) s4CallResult {
	a.st.t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(d):
		a.st.t.Fatalf("шлюз не ответил на вызов за %v\n%s", d, a.st.gw.log())
		return s4CallResult{}
	}
}

// s4Approval — запрос подтверждения из API консоли.
type s4Approval struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	Server    string `json:"server"`
	Tool      string `json:"tool"`
	Agent     string `json:"agent"`
	Risk      string `json:"risk"`
	Rule      string `json:"rule"`
	Args      string `json:"args"`
	ArgsHash  string `json:"args_hash"`
	DecidedBy string `json:"decided_by"`
	Comment   string `json:"comment"`
}

// waitPending ждёт новый запрос в очереди подтверждений (его нет в seen) и
// возвращает карточку с аргументами и хешем привязки решения.
func (a *s4Agents) waitPending(seen map[string]bool) s4Approval {
	a.st.t.Helper()
	t := a.st.t
	var id string
	if !s2WaitFor(60*time.Second, func() bool {
		r := a.st.admin.do("GET", "/api/v1/approvals?state=pending&agent=report-bot&limit=20", nil)
		if r.code != http.StatusOK {
			t.Fatalf("очередь подтверждений: %s", r)
		}
		var page struct{ Items []s4Approval }
		r.json(t, &page)
		for _, it := range page.Items {
			if !seen[it.ID] {
				id, seen[it.ID] = it.ID, true
				return true
			}
		}
		return false
	}) {
		t.Fatalf("вызов не встал в очередь подтверждений\n%s", a.st.gw.log())
	}
	return a.approval(id)
}

// approval — карточка запроса подтверждения.
func (a *s4Agents) approval(id string) s4Approval {
	a.st.t.Helper()
	r := a.st.admin.do("GET", "/api/v1/approvals/"+id, nil)
	if r.code != http.StatusOK {
		a.st.t.Fatalf("запрос подтверждения %s: %s", id, r)
	}
	var ap s4Approval
	r.json(a.st.t, &ap)
	return ap
}

// s4ToolEvent — событие вызова инструмента: решение и итог подтверждения.
type s4ToolEvent struct {
	ID      string   `json:"id"`
	Action  string   `json:"action"`
	Rule    string   `json:"rule"`
	Threats []string `json:"threats"`
	Details struct {
		Agent struct {
			Tool     string
			Approval *struct {
				ID        string
				State     string
				DecidedBy string `json:"decided_by"`
			}
		}
	}
}

// toolEvent ждёт новое событие agent_tool_call по фильтру filter и
// возвращает его карточку.
func (a *s4Agents) toolEvent(filter string, seen map[string]bool) s4ToolEvent {
	a.st.t.Helper()
	ev := s3LastEvent(a.st.t, a.st.admin, `type = "agent_tool_call" and `+filter, seen)
	r := a.st.admin.do("GET", "/api/v1/events/"+ev.ID, nil)
	if r.code != http.StatusOK {
		a.st.t.Fatalf("событие %s: %s", ev.ID, r)
	}
	var out s4ToolEvent
	r.json(a.st.t, &out)
	return out
}

// approvalEvent ждёт событие вызова инструмента tool с итогом подтверждения
// state: события доходят до сервера пачками, порядок их появления в списке
// не гарантирован.
func (a *s4Agents) approvalEvent(tool, state string) s4ToolEvent {
	a.st.t.Helper()
	t := a.st.t
	filter := `type = "agent_tool_call" and threat = "DM-22" and tool = "` + tool + `"`
	var found s4ToolEvent
	if !s2WaitFor(60*time.Second, func() bool {
		r := a.st.admin.do("GET", "/api/v1/events?limit=50&filter="+url.QueryEscape(filter), nil)
		if r.code != http.StatusOK {
			t.Fatalf("события: %s", r)
		}
		var page struct{ Items []s3Event }
		r.json(t, &page)
		for _, it := range page.Items {
			c := a.st.admin.do("GET", "/api/v1/events/"+it.ID, nil)
			var ev s4ToolEvent
			c.json(t, &ev)
			if ap := ev.Details.Agent.Approval; ap != nil && ap.State == state {
				found = ev
				return true
			}
		}
		return false
	}) {
		t.Fatalf("нет события вызова %s с итогом подтверждения %s", tool, state)
	}
	return found
}

// reachedServer — дошёл ли до mock-mcp последний вызов с этим фрагментом.
func (a *s4Agents) reachedServer(fragment string) bool {
	_, body := a.mcp.last()
	return strings.Contains(body, fragment)
}

func isToolError(body string) bool { return strings.Contains(body, `"isError":true`) }

// S5: агент читает отчёты и просит удалить файл. Чтение вне каталога
// отчётов и сверх частоты блокируется с оповещением (DM-20, DM-21, DM-23);
// удаление ждёт человека в очереди (DM-22): одобрение выполняет ровно
// показанный вызов, отказ и таймаут не пускают его к серверу. Решать может
// только администратор безопасности, каждое решение пишет аудит.
func TestE2EStage4_S5_AgentDangerousAction(t *testing.T) {
	a := s4NewAgents(t, s4AgentsOpts{
		tools: map[string]any{"unapproved": "block", "default": "block", "approval_timeout": "1m", "rules": []map[string]any{
			{"id": "read-reports", "tool": "files/read_file", "risk": []string{"low"}, "action": "allow", "severity": "medium",
				"message": "Чтение разрешено только из каталога отчётов",
				"args": map[string]any{"type": "object", "required": []string{"path"}, "properties": map[string]any{
					"path": map[string]any{"type": "string", "maxLength": 512, "x-aisec-path-prefix": []string{"/data/reports/"}}}},
				"rate": map[string]any{"per_minute": 6}},
			{"id": "delete-approval", "tool": "files/delete_file", "risk": []string{"high"}, "action": "require_approval",
				"severity": "high", "message": "Удаление файлов подтверждает человек"},
		}},
		approve: map[string]string{"read_file": "low", "delete_file": "high"},
	})
	st := a.st
	seen := map[string]bool{}

	// Чтение отчёта разрешено; пути вне каталога отчётов — нет (DM-21):
	// «..» не нормализуется, соседний каталог с общим началом имени не
	// проходит по границе каталога.
	code, body := a.call("read_file", `{"path":"/data/reports/q3.txt"}`)
	if code != http.StatusOK || isToolError(body) || !strings.Contains(body, "отчёт") {
		t.Fatalf("чтение отчёта: %d %s", code, body)
	}
	for _, bad := range []string{"/etc/passwd", "/data/reports/../../etc/shadow", "/data/reports-old/q1.txt"} {
		code, body = a.call("read_file", `{"path":"`+bad+`"}`)
		if code != http.StatusOK || !isToolError(body) {
			t.Fatalf("чтение %s не заблокировано: %d %s", bad, code, body)
		}
		if a.reachedServer(bad) {
			t.Fatalf("запрещённый вызов %s дошёл до сервера MCP", bad)
		}
	}
	// Частота (DM-23): с пятого вызова правила в минуту (первый, три
	// запрещённых — тоже считаются) и до шестого — разрешены, седьмой — нет.
	for range 2 {
		if code, body = a.call("read_file", `{"path":"/data/reports/q3.txt"}`); code != http.StatusOK || isToolError(body) {
			t.Fatalf("чтение в пределах частоты: %d %s", code, body)
		}
	}
	if code, body = a.call("read_file", `{"path":"/data/reports/q3.txt"}`); code != http.StatusOK || !isToolError(body) {
		t.Fatalf("превышение частоты не заблокировано: %d %s", code, body)
	}

	// События: по строке на причину, без аргументов в списке.
	argsEv := a.toolEvent(`action = "block" and threat = "DM-21"`, seen)
	if argsEv.Rule != "read-reports" || argsEv.Details.Agent.Tool != "read_file" {
		t.Fatalf("событие DM-21: %+v", argsEv)
	}
	rateEv := a.toolEvent(`action = "block" and threat = "DM-23"`, seen)
	if rateEv.Rule != "read-reports" || !slices.Contains(rateEv.Threats, "DM-23") {
		t.Fatalf("событие DM-23: %+v", rateEv)
	}
	// Серия блокировок одного инструмента одним агентом — оповещение.
	al := st.waitAlert(alerting.BuiltinToolBlocked, 90*time.Second)
	if al.Severity != "high" || al.Group["agent"] != "report-bot" || al.Group["tool"] != "read_file" {
		t.Fatalf("оповещение agents.tool_blocked: %+v", al)
	}
	if r := st.admin.do("GET", "/api/v1/alerts/"+al.ID, nil); strings.Contains(string(r.body), "/etc/passwd") {
		t.Fatalf("аргументы вызова в оповещении: %s", r.body)
	}

	// DM-22. Вызов без решения ждёт в очереди и до сервера не доходит.
	pending := map[string]bool{}
	first := a.callAsync("delete_file", `{"path":"/data/reports/old.txt"}`, 3*time.Minute)
	ap := a.waitPending(pending)
	if ap.State != "pending" || ap.Tool != "delete_file" || ap.Server != "files" || ap.Risk != "high" || ap.Rule != "delete-approval" ||
		ap.Agent != "report-bot" || ap.ArgsHash == "" || !strings.Contains(ap.Args, "/data/reports/old.txt") {
		t.Fatalf("запрос подтверждения: %+v", ap)
	}
	if a.reachedServer("delete_file") {
		t.Fatal("вызов дошёл до сервера MCP до решения человека")
	}
	select {
	case r := <-first:
		t.Fatalf("вызов вернулся до решения: %d %s", r.code, r.body)
	case <-time.After(2 * time.Second):
	}
	// Решение привязано к показанным аргументам: чужой хеш — 409.
	if r := st.admin.do("POST", "/api/v1/approvals/"+ap.ID+"/approve", map[string]any{"args_hash": strings.Repeat("0", 64)}); r.code != http.StatusConflict {
		t.Fatalf("одобрение с чужим хешем аргументов: %s", r)
	}
	// Решает человек с правом approvals.decide (администратор безопасности,
	// аналитик, ADR-0023): администратору системы — 403, аудитор читает
	// очередь, но не видит ни аргументов, ни хеша привязки решения.
	sysadmin := st.admin.createUser("sysadmin-s5", auth.RoleSystemAdmin)
	sc := st.s.client("198.51.100.41")
	sc.signIn(sysadmin)
	for _, act := range []string{"approve", "deny"} {
		if r := sc.do("POST", "/api/v1/approvals/"+ap.ID+"/"+act, map[string]any{"args_hash": ap.ArgsHash}); r.code != http.StatusForbidden {
			t.Fatalf("%s администратором системы: %s", act, r)
		}
	}
	auditor := st.admin.createUser("auditor-s5", auth.RoleAuditor)
	au := st.s.client("198.51.100.42")
	au.signIn(auditor)
	r := au.do("GET", "/api/v1/approvals/"+ap.ID, nil)
	var seenByAuditor s4Approval
	r.json(t, &seenByAuditor)
	if r.code != http.StatusOK || seenByAuditor.State != "pending" || seenByAuditor.ArgsHash != "" || seenByAuditor.Args != "" {
		t.Fatalf("карточка запроса у аудитора: %s", r)
	}
	if r := au.do("POST", "/api/v1/approvals/"+ap.ID+"/approve", map[string]any{"args_hash": ap.ArgsHash}); r.code != http.StatusForbidden {
		t.Fatalf("одобрение аудитором: %s", r)
	}
	if got := a.approval(ap.ID); got.State != "pending" {
		t.Fatalf("после отказов в доступе запрос %s", got.State)
	}
	// Одобрение: шлюз передаёт серверу ровно проверенный вызов.
	if r := st.admin.do("POST", "/api/v1/approvals/"+ap.ID+"/approve", map[string]any{"args_hash": ap.ArgsHash,
		"comment": "Старый отчёт, удаление согласовано"}); r.code != http.StatusOK {
		t.Fatalf("одобрение: %s", r)
	}
	res := a.await(first, 30*time.Second)
	if res.code != http.StatusOK || isToolError(res.body) || !strings.Contains(res.body, "удалён") {
		t.Fatalf("одобренный вызов: %d %s", res.code, res.body)
	}
	if !a.reachedServer("/data/reports/old.txt") || !a.reachedServer("delete_file") {
		_, up := a.mcp.last()
		t.Fatalf("до сервера MCP дошёл не одобренный вызов: %s", up)
	}
	done := a.approval(ap.ID)
	if done.State != "approved" || done.DecidedBy != s2AdminLogin || !strings.Contains(done.Comment, "согласовано") {
		t.Fatalf("итог одобрения: %+v", done)
	}
	// Повторное решение по закрытому запросу — 409.
	if r := st.admin.do("POST", "/api/v1/approvals/"+ap.ID+"/deny", map[string]any{}); r.code != http.StatusConflict {
		t.Fatalf("повторное решение: %s", r)
	}
	appr := a.approvalEvent("delete_file", "approved")
	if appr.Action == "block" || appr.Details.Agent.Approval.DecidedBy != s2AdminLogin {
		t.Fatalf("событие одобренного вызова: %+v", appr)
	}

	// Отказ: агент получает ошибку без комментария дежурного, сервер вызова не видит.
	second := a.callAsync("delete_file", `{"path":"/data/reports/keep.txt"}`, 3*time.Minute)
	dn := a.waitPending(pending)
	if r := st.admin.do("POST", "/api/v1/approvals/"+dn.ID+"/deny", map[string]any{"comment": "Файл нужен аудиторам"}); r.code != http.StatusOK {
		t.Fatalf("отказ: %s", r)
	}
	res = a.await(second, 30*time.Second)
	if res.code != http.StatusOK || !isToolError(res.body) || strings.Contains(res.body, "аудиторам") {
		t.Fatalf("отклонённый вызов: %d %s", res.code, res.body)
	}
	if a.reachedServer("keep.txt") {
		t.Fatal("отклонённый вызов дошёл до сервера MCP")
	}
	if got := a.approval(dn.ID); got.State != "denied" || got.DecidedBy != s2AdminLogin {
		t.Fatalf("итог отказа: %+v", got)
	}

	// Таймаут (approval_timeout — 1 минута): без решения — отказ.
	third := a.callAsync("delete_file", `{"path":"/data/reports/tmp.txt"}`, 3*time.Minute)
	to := a.waitPending(pending)
	res = a.await(third, 2*time.Minute+30*time.Second)
	if res.code != http.StatusOK || !isToolError(res.body) {
		t.Fatalf("вызов без решения: %d %s", res.code, res.body)
	}
	if a.reachedServer("tmp.txt") {
		t.Fatal("вызов по таймауту дошёл до сервера MCP")
	}
	if got := a.approval(to.ID); got.State != "timeout" {
		t.Fatalf("итог таймаута: %+v", got)
	}
	if r := st.admin.do("POST", "/api/v1/approvals/"+to.ID+"/approve", map[string]any{"args_hash": to.ArgsHash}); r.code != http.StatusConflict {
		t.Fatalf("одобрение после таймаута: %s", r)
	}
	timedOut := a.approvalEvent("delete_file", "timeout")
	if timedOut.Action != "block" {
		t.Fatalf("событие вызова по таймауту: %+v", timedOut)
	}
	if denied := a.approvalEvent("delete_file", "denied"); denied.Action != "block" {
		t.Fatalf("событие отклонённого вызова: %+v", denied)
	}

	// Журнал аудита: каждое решение — запись; отказы в доступе решениями не стали.
	if n := st.s.auditCount("agent.approval.approve"); n != 1 {
		t.Fatalf("записей agent.approval.approve: %d", n)
	}
	if n := st.s.auditCount("agent.approval.deny"); n != 1 {
		t.Fatalf("записей agent.approval.deny: %d", n)
	}
	// Очередь в консоли: все три запроса закрыты, ожидающих нет.
	r = st.admin.do("GET", "/api/v1/approvals?state=pending&limit=20", nil)
	var left struct{ Items []s4Approval }
	r.json(t, &left)
	if r.code != http.StatusOK || len(left.Items) != 0 {
		t.Fatalf("в очереди остались запросы: %s", r)
	}
}
