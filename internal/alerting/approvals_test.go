package alerting

import (
	"fmt"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

func approvalDetails(agent string) map[string]any {
	return map[string]any{"app": "crm", "agent": agent, "server": "files", "tool": "delete_file", "risk": "high",
		"rule": "tools-approve", "path": "mcp", "args_hash": strings.Repeat("a", 64), "deadline": "2026-10-27T12:10:00Z"}
}

// TestDM22_ApprovalRequestedAlert — запись agent.approval.requested от
// шлюза даёт одно оповещение на запрос; запись не от шлюза — ничего;
// больше 20 запросов за 10 минут объединяются в одно оповещение.
// Аргументов вызова в оповещении нет. Покрывает: DM-22.
func TestDM22_ApprovalRequestedAlert(t *testing.T) {
	e := newEnv(t)
	obj := func(i int) audit.Object {
		return audit.Object{Type: "approval", ID: fmt.Sprintf("01900000-0000-7000-8000-%012d", i)}
	}
	e.audit(t, e.rec(t, tUser, "", "agent.approval.requested", obj(0), audit.ResultSuccess, approvalDetails("support-bot")))
	if got := e.alerts(t, BuiltinApprovalRequested); len(got) != 0 {
		t.Fatalf("оповещение не от шлюза: %+v", got)
	}
	e = newEnv(t)
	for i := 1; i <= ApprovalBurst+5; i++ {
		e.audit(t, e.rec(t, tGateway, "", "agent.approval.requested", obj(i), audit.ResultSuccess, approvalDetails("support-bot")))
	}
	got := e.alerts(t, BuiltinApprovalRequested)
	if len(got) != ApprovalBurst+1 {
		t.Fatalf("оповещений %d, ожидалось %d", len(got), ApprovalBurst+1)
	}
	var burst *Alert
	for i := range got {
		a := &got[i]
		if a.Severity != "high" || a.Kind != KindSystem {
			t.Fatalf("оповещение: %+v", a)
		}
		if strings.Contains(fmt.Sprint(a.Details), "args_hash") || strings.Contains(fmt.Sprint(a.Details), "/tmp") {
			t.Fatalf("лишнее в оповещении: %+v", a.Details)
		}
		if a.Count > 1 {
			burst = a
		} else if a.Values[ToolField] != "files/delete_file" {
			t.Fatalf("значения: %+v", a.Values)
		}
	}
	if burst == nil || burst.Count != 5 {
		t.Fatalf("объединённое оповещение: %+v", burst)
	}
}

// Переполнение очереди — одно оповещение на шлюз и агента.
func TestDM22_ApprovalQueueFullAlert(t *testing.T) {
	e := newEnv(t)
	gw := audit.Object{Type: "gateway", ID: testGateway}
	for _, agent := range []string{"support-bot", "support-bot", "other-bot"} {
		d := approvalDetails(agent)
		d["scope"], d["limit"] = "agent", 16
		e.audit(t, e.rec(t, tGateway, "", "agent.approval.queue_full", gw, audit.ResultFailure, d))
	}
	got := e.alerts(t, BuiltinApprovalQueueFull)
	if len(got) != 2 {
		t.Fatalf("оповещений %d: %+v", len(got), got)
	}
	for _, a := range got {
		if a.Values["gateway"] != testGateway || !strings.HasPrefix(a.Values["agent"], "crm/") {
			t.Fatalf("значения: %+v", a.Values)
		}
	}
}
