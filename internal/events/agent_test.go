package events_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

const agentSession = "0123456789abcdef0123456789abcdef"

func agentEvent(id string, now time.Time) events.Event {
	return events.Event{
		ID: id, Time: now, Type: events.TypeAgentToolCall, App: "support-bot", Env: "prod", PolicyMode: events.ModeEnforce,
		Storage:  events.StorageNone,
		Decision: &events.Decision{Action: "block", Applied: []string{"block"}, Rule: "tools.default", Severity: "medium"},
		Threats:  []string{"DM-20"},
		Agent: &events.Agent{Path: events.AgentPathMCP, Agent: "report-bot", Server: "files", Method: "tools/call",
			Protocol: "2026-07-28", Tool: "read_file", Risk: "high", ToolStatus: "approved", Session: agentSession,
			Approval: &events.Approval{ID: "0192d6e0-0000-7000-8000-000000000001", State: "denied", DecidedBy: "duty", WaitedMS: 1500}},
	}
}

func TestAgentEventValidate(t *testing.T) {
	now := time.Now().UTC()
	ok := agentEvent("0192d6e0-0000-7000-8000-000000000002", now)
	if err := ok.Validate(); err != nil {
		t.Fatalf("верное событие: %v", err)
	}
	mcp := ok
	mcp.Type, mcp.Agent = events.TypeAgentMCP, &events.Agent{Agent: "report-bot", Server: "files", Method: "tools/list",
		Items: 3, Hidden: []string{"rm"}, Poisoned: []string{"rm"}}
	if err := mcp.Validate(); err != nil {
		t.Fatalf("agent_mcp: %v", err)
	}
	bad := []func(e *events.Event){
		func(e *events.Event) { e.Agent = nil },
		func(e *events.Event) { e.Agent.Path = "other" },
		func(e *events.Event) { e.Agent.Tool = "bad name" },
		func(e *events.Event) { e.Agent.Session = "x" },
		func(e *events.Event) { e.Agent.Risk = "extreme" },
		func(e *events.Event) { e.Agent.Approval.State = "maybe" },
		func(e *events.Event) { e.Agent.Hidden = []string{"плохое имя"} },
		func(e *events.Event) { e.Decision = nil },
		func(e *events.Event) { e.Session = &events.Session{ID: agentSession, Source: events.SessionHeader} },
		func(e *events.Event) { e.Response = &events.Response{Mode: events.ResponseBuffered} },
		func(e *events.Event) { e.Content = &events.Content{Request: "x"} }, // storage none
	}
	for i, f := range bad {
		e := agentEvent("0192d6e0-0000-7000-8000-000000000003", now)
		a := *e.Agent
		ap := *a.Approval
		a.Approval = &ap
		e.Agent = &a
		f(&e)
		if err := e.Validate(); err == nil {
			t.Errorf("случай %d принят", i)
		}
	}
	req := events.Event{ID: ok.ID, Time: now, Type: events.TypeGatewayRequest, App: "a", PolicyMode: events.ModeEnforce,
		Decision: &events.Decision{Action: "allow"}, Agent: &events.Agent{}}
	if err := req.Validate(); err == nil {
		t.Error("раздел agent у gateway_request принят")
	}
}

// Фильтр событий агентов: тип, агент, сервер, инструмент и сессия из
// details.agent (хронология сессии 4.12, правило agents.tool_blocked).
func TestAgentEventFilter(t *testing.T) {
	e := agentEvent("0192d6e0-0000-7000-8000-000000000004", time.Now().UTC())
	rec := events.RecordOf("gw", &e)
	for _, q := range []string{`type = "agent_tool_call"`, `agent = "report-bot"`, `mcp_server = "files"`, `tool = "read_file"`,
		`session = "` + agentSession + `"`, `tool != "other"`} {
		f, err := events.ParseFilter(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if !f.Match(&rec) {
			t.Errorf("%s: не подошло", q)
		}
	}
	for _, q := range []string{`tool = "плохое"`, `agent = "Bad"`} {
		if _, err := events.ParseFilter(q); err == nil {
			t.Errorf("%s принят", q)
		}
	}
	f, _ := events.ParseFilter(`tool = "read_file"`)
	var b bytes.Buffer
	b.WriteString(f.String())
	if !strings.Contains(b.String(), "read_file") {
		t.Errorf("каноническая запись: %s", b.String())
	}
}

func TestPGAgentEvents(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	if _, err := e.st.EnsurePartitions(ctx); err != nil {
		t.Fatal(err)
	}
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	ev := agentEvent(u.String(), u.Time().Add(-time.Millisecond))
	ev.Storage, ev.Content = events.StorageFull, &events.Content{Request: `{"path":"/data/a"}`, Response: "ok"}
	res, err := e.st.Insert(ctx, events.Ingest{GatewayID: testGateway, ReceivedAt: time.Now(), Events: []events.Event{ev}})
	if err != nil || res.Accepted != 1 {
		t.Fatalf("запись: %+v %v", res, err)
	}
	for _, q := range []string{`type = "agent_tool_call" and tool = "read_file"`, `session = "` + agentSession + `"`,
		`mcp_server = "files" and agent = "report-bot"`} {
		f, err := events.ParseFilter(q)
		if err != nil {
			t.Fatal(err)
		}
		recs, err := e.st.List(ctx, events.Query{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour), Filter: f, Limit: 10,
			WithDetails: true})
		if err != nil || len(recs) != 1 || recs[0].Details.Agent == nil || recs[0].Details.Agent.Approval.State != "denied" {
			t.Fatalf("%s: %d %v", q, len(recs), err)
		}
	}
	f, _ := events.ParseFilter(`tool != "read_file"`)
	if recs, err := e.st.List(ctx, events.Query{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour), Filter: f, Limit: 10}); err != nil || len(recs) != 0 {
		t.Fatalf("отрицание: %d %v", len(recs), err)
	}
	var details string
	if err := e.owner.QueryRow(ctx, "SELECT details::text FROM events WHERE id = $1", ev.ID).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, "/data/a") {
		t.Fatalf("аргументы в метаданных: %s", details)
	}
}
