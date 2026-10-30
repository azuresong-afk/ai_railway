package alerting

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// agentCall — событие agent_tool_call шлюза (синтетические имена).
func (e *env) agentCall(t *testing.T, agent, tool, action string, threats ...string) *events.Event {
	t.Helper()
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	return &events.Event{ID: u.String(), Time: e.clock.t, Type: events.TypeAgentToolCall, App: "support-bot", Env: "prod",
		PolicyMode: events.ModeEnforce, Storage: events.StorageNone, Threats: threats,
		Decision: &events.Decision{Action: action, Applied: []string{action}, Rule: "tools.default", Severity: "high"},
		Agent: &events.Agent{Path: events.AgentPathMCP, Agent: agent, Server: "files", Method: "tools/call",
			Protocol: "2026-07-28", Tool: tool, ToolStatus: "approved"}}
}

// DM-20, DM-21, DM-23 (оповещение): серия блокировок вызовов одного
// инструмента одним агентом за 10 минут — оповещение agents.tool_blocked с
// ключом «агент, сервер, инструмент»; разрешённые вызовы и блокировки
// других агентов в счёт не идут, содержимого в оповещении нет.
func TestDM20_ToolBlockedSeriesAlert(t *testing.T) {
	e := newEnv(t)
	e.ingest(t, e.agentCall(t, "report-bot", "delete_file", "block", "DM-20"),
		e.agentCall(t, "report-bot", "delete_file", "block", "DM-21"),
		e.agentCall(t, "report-bot", "delete_file", "allow"),
		e.agentCall(t, "other-bot", "delete_file", "block", "DM-20"),
		e.agentCall(t, "report-bot", "delete_file", "block", "DM-07"))
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinToolBlocked); len(got) != 0 {
		t.Fatalf("2 блокировки из 3 — оповещение: %+v", got)
	}
	e.tick(time.Minute)
	e.ingest(t, e.agentCall(t, "report-bot", "delete_file", "block", "DM-23"))
	e.tick(time.Minute)
	e.periodic(t, nil)
	got := e.alerts(t, BuiltinToolBlocked)
	if len(got) != 1 {
		t.Fatalf("ожидалось одно оповещение: %+v", got)
	}
	a := got[0]
	if a.Count != 3 || a.Kind != KindFrequency || a.Severity != "high" || a.Values["agent"] != "report-bot" ||
		a.Values["mcp_server"] != "files" || a.Values["tool"] != "delete_file" {
		t.Fatalf("оповещение: %+v", a)
	}
	card, err := e.svc.Alert(context.Background(), a.ID)
	if err != nil || len(card.Events) != 3 {
		t.Fatalf("ссылки на события: %+v %v", card, err)
	}
	// Имя инструмента в событии без сервера — не повод для agents.tool_new:
	// его поднимает сервер по tools:observe.
	if got := e.alerts(t, BuiltinToolNew); len(got) != 0 {
		t.Fatalf("agents.tool_new по событиям: %+v", got)
	}
}

// DM-24 (оповещение): событие agent_mcp с отравленными описаниями —
// оповещение agents.tool_poisoning на сервер и инструмент в транзакции
// приёма, в том числе в режиме monitor; повтор дополняет открытое.
func TestDM24_ToolPoisoningAlert(t *testing.T) {
	e := newEnv(t)
	list := func(mode string, poisoned ...string) *events.Event {
		u, err := e.ids.New()
		if err != nil {
			t.Fatal(err)
		}
		return &events.Event{ID: u.String(), Time: e.clock.t, Type: events.TypeAgentMCP, App: "support-bot", PolicyMode: mode,
			Storage: events.StorageNone, Threats: []string{"DM-24"}, Decision: &events.Decision{Action: "allow"},
			Agent: &events.Agent{Agent: "report-bot", Server: "files", Method: "tools/list", Items: 4, Poisoned: poisoned,
				Hidden: poisoned}}
	}
	e.ingest(t, list(events.ModeEnforce))
	if got := e.alerts(t, BuiltinToolPoisoning); len(got) != 0 {
		t.Fatalf("оповещение без находок: %+v", got)
	}
	e.ingest(t, list(events.ModeMonitor, "rm", "exfil"))
	got := e.alerts(t, BuiltinToolPoisoning)
	if len(got) != 2 {
		t.Fatalf("ожидалось 2 оповещения (по инструменту): %+v", got)
	}
	for _, a := range got {
		if a.Kind != KindSecurity || a.Severity != "high" || a.Values["mcp_server"] != "files" ||
			(a.Values["tool"] != "rm" && a.Values["tool"] != "exfil") {
			t.Fatalf("оповещение: %+v", a)
		}
		if s := fmt.Sprintf("%+v", a); strings.Contains(s, "description") {
			t.Fatalf("описание в оповещении: %s", s)
		}
	}
	e.ingest(t, list(events.ModeEnforce, "rm"))
	if got := e.alerts(t, BuiltinToolPoisoning); len(got) != 2 {
		t.Fatalf("дедупликация: %+v", got)
	}
	// Ревью 4.r1 (остаток для G3): описание из служебного tools/list шлюза
	// перед вызовом — событие agent_tool_call — тоже поднимает оповещение.
	u, err := e.ids.New()
	if err != nil {
		t.Fatal(err)
	}
	e.ingest(t, &events.Event{ID: u.String(), Time: e.clock.t, Type: events.TypeAgentToolCall, App: "support-bot",
		PolicyMode: events.ModeEnforce, Storage: events.StorageNone, Threats: []string{"DM-24"},
		Decision: &events.Decision{Action: "block"}, Agent: &events.Agent{Agent: "report-bot", Server: "files", Path: events.AgentPathMCP,
			Tool: "steal", Poisoned: []string{"steal"}}})
	if got := e.alerts(t, BuiltinToolPoisoning); len(got) != 3 {
		t.Fatalf("оповещение по вызову: %+v", got)
	}
}

func TestAgentGroupFields(t *testing.T) {
	ev := events.Event{Type: events.TypeAgentToolCall, Agent: &events.Agent{Agent: "a", Server: "s", Tool: "t"}}
	rec := events.RecordOf("gw", &ev)
	for f, want := range map[string]string{"agent": "a", "mcp_server": "s", "tool": "t"} {
		if got := fieldValue(&rec, f); got != want {
			t.Errorf("%s: %q", f, got)
		}
	}
	plain := events.RecordOf("gw", &events.Event{Type: events.TypeGatewayRequest})
	if fieldValue(&plain, "agent") != "" {
		t.Error("поле агента у gateway_request")
	}
}
