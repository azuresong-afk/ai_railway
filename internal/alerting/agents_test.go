package alerting

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

const (
	tToolID  = "01900000-0000-7000-8000-0000000000e1"
	tToolID2 = "01900000-0000-7000-8000-0000000000e2"
)

func toolDetails(name, status string) map[string]any {
	return map[string]any{"name": name, "mcp_server": "files", "hash": strings.Repeat("a", 64), "hash_alg": "sha-256",
		"status": status, "approved_hash": strings.Repeat("b", 64)}
}

// TestDM25_ToolChangedAlert — запись аудита agent_tool.changed от шлюза
// даёт оповещение правила безопасности «Изменилось описание одобренного
// инструмента» высокой серьёзности, по одному на инструмент; запись не от
// шлюза или неуспешная оповещения не даёт; описаний в оповещении нет,
// только хеши. Покрывает: DM-25.
func TestDM25_ToolChangedAlert(t *testing.T) {
	e := newEnv(t)
	obj := audit.Object{Type: "agent_tool", ID: tToolID}
	e.audit(t, e.rec(t, tUser, "", "agent_tool.changed", obj, audit.ResultSuccess, toolDetails("read_file", "changed")))
	e.audit(t, e.rec(t, tGateway, "", "agent_tool.changed", obj, audit.ResultFailure, toolDetails("read_file", "changed")))
	if got := e.alerts(t, BuiltinToolChanged); len(got) != 0 {
		t.Fatalf("оповещение не от шлюза: %+v", got)
	}
	e.audit(t, e.rec(t, tGateway, "", "agent_tool.changed", obj, audit.ResultSuccess, toolDetails("read_file", "changed")))
	e.audit(t, e.rec(t, tGateway, "", "agent_tool.changed", obj, audit.ResultSuccess, toolDetails("read_file", "changed")))
	e.audit(t, e.rec(t, tGateway, "", "agent_tool.changed", audit.Object{Type: "agent_tool", ID: tToolID2}, audit.ResultSuccess,
		toolDetails("write_file", "changed")))
	got := e.alerts(t, BuiltinToolChanged)
	if len(got) != 2 {
		t.Fatalf("оповещений %d: %+v", len(got), got)
	}
	for _, a := range got {
		if a.Severity != "high" || a.Kind != KindSecurity {
			t.Fatalf("оповещение: %+v", a)
		}
		if a.Values[ToolField] != "files/read_file" && a.Values[ToolField] != "files/write_file" {
			t.Fatalf("значение tool: %+v", a.Values)
		}
	}
	if r := e.rule(t, BuiltinToolChanged); !Locked(r.Kind) {
		t.Fatal("правило DM-25 не защищено от отключения")
	}
}

// Новый инструмент — оповещение вида «новое» с полем tool; функция агента
// (без MCP-сервера) называется по агенту; правило можно отключить.
func TestToolNewAlert(t *testing.T) {
	e := newEnv(t)
	d := toolDetails("read_file", "new")
	delete(d, "approved_hash")
	e.audit(t, e.rec(t, tGateway, "", "agent_tool.discovered", audit.Object{Type: "agent_tool", ID: tToolID}, audit.ResultSuccess, d))
	fn := map[string]any{"name": "lookup", "agent": "support-bot", "hash": strings.Repeat("c", 64), "status": "new"}
	e.audit(t, e.rec(t, tGateway, "", "agent_tool.discovered", audit.Object{Type: "agent_tool", ID: tToolID2}, audit.ResultSuccess, fn))
	got := e.alerts(t, BuiltinToolNew)
	if len(got) != 2 || got[0].Kind != KindNew {
		t.Fatalf("оповещения: %+v", got)
	}
	tools := []string{got[0].Values[ToolField], got[1].Values[ToolField]}
	if !slices.Contains(tools, "files/read_file") || !slices.Contains(tools, "function@support-bot/lookup") {
		t.Fatalf("значения tool: %v", tools)
	}
	r := e.rule(t, BuiltinToolNew)
	off := false
	in := RuleInput{Name: r.Name, Description: r.Description, Enabled: &off, Severity: r.Severity, Condition: r.Condition,
		SuppressMinutes: &r.SuppressMinutes, Recipients: r.Recipients, Version: r.Version}
	if _, err := e.svc.UpdateRule(context.Background(), e.admin, r.ID, in); err != nil {
		t.Fatal(err)
	}
}

// Поле tool — только у встроенного правила: создать правило «новое» по tool
// нельзя, сменить поле встроенного или перевести своё правило на tool —
// тоже.
func TestToolFieldOnlyBuiltin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var ie *InputError
	if _, err := e.svc.CreateRule(ctx, e.admin, RuleInput{Kind: KindNew, Name: "Свои инструменты",
		Condition: Condition{Field: ToolField}}); !errors.As(err, &ie) {
		t.Fatalf("создание по tool: %v", err)
	}
	r := e.rule(t, BuiltinToolNew)
	in := RuleInput{Name: r.Name, Description: r.Description, Severity: r.Severity, Condition: Condition{Field: "model"},
		SuppressMinutes: &r.SuppressMinutes, Recipients: r.Recipients, Version: r.Version}
	if _, err := e.svc.UpdateRule(ctx, e.admin, r.ID, in); !errors.As(err, &ie) {
		t.Fatalf("смена поля встроенного: %v", err)
	}
	own, err := e.svc.CreateRule(ctx, e.admin, RuleInput{Kind: KindNew, Name: "Новые модели", Condition: Condition{Field: "model"}})
	if err != nil {
		t.Fatal(err)
	}
	in = RuleInput{Name: own.Name, Severity: own.Severity, Condition: Condition{Field: ToolField}, SuppressMinutes: &own.SuppressMinutes,
		Recipients: own.Recipients, Version: own.Version}
	if _, err := e.svc.UpdateRule(ctx, e.admin, own.ID, in); !errors.As(err, &ie) {
		t.Fatalf("перевод своего правила на tool: %v", err)
	}
}
