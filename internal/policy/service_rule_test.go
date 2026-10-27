package policy

import (
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/session"
)

// sessionCatalog — встроенные детекторы-заглушки и детекторы уровня сессии.
func sessionCatalog(t *testing.T) *detect.Registry {
	t.Helper()
	ds := registryDetectors(catalog(t))
	ds = append(ds, session.All()...)
	r, err := detect.NewRegistry(ds...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func registryDetectors(r *detect.Registry) []detect.Detector {
	var out []detect.Detector
	for _, id := range r.IDs() {
		d, _ := r.Get(id)
		out = append(out, d)
	}
	return out
}

// Детектор с ограниченным набором действий (detect.ActionLimiter):
// history.integrity не блокирует — проверка идёт после ответа.
func TestCompileChecksAllowedActions(t *testing.T) {
	c := sessionCatalog(t)
	s, _ := Template(TemplateBase)
	s.ID = "x"
	s.Rules = append(s.Rules, RuleSpec{ID: "hist", Detector: session.HistoryID, Action: Block, Severity: High})
	if _, err := Compile(s, c); err == nil || !strings.Contains(err.Error(), "допускает действия allow, log") {
		t.Fatalf("block для history.integrity: %v", err)
	}
	s.Rules[len(s.Rules)-1].Action = Log
	if _, err := Compile(s, c); err != nil {
		t.Fatal(err)
	}
	// Маскировать у находки уровня сессии нечего.
	s.Rules[len(s.Rules)-1] = RuleSpec{ID: "risk", Detector: session.RiskID, Action: Redact, Severity: High}
	if _, err := Compile(s, c); err == nil {
		t.Fatal("redact для session.risk принят")
	}
}

// Покрывает: DM-26
// Служебное правило приложения: ID с точкой (в спецификации политики такого
// быть не может), проверки как у Compile; правило в копии, исходная
// политика не меняется; решение по находке — правило с самым сильным
// действием.
func TestDM26_WithRuleAndRuleFor(t *testing.T) {
	c := sessionCatalog(t)
	p, err := TemplatePolicy(TemplateBase, c)
	if err != nil {
		t.Fatal(err)
	}
	r := RuleSpec{ID: "app.prompt_integrity", Detector: session.PromptID, Directions: []detect.Direction{detect.Input}, Action: Block, Severity: High}
	q, err := p.WithRule(c, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := p.RuleFor(session.PromptID, detect.Input); ok {
		t.Fatal("WithRule изменила исходную политику")
	}
	if rule, action, sev, ok := q.RuleFor(session.PromptID, detect.Input); !ok || rule != r.ID || action != Block || sev != High {
		t.Fatalf("RuleFor: %s %s %s %v", rule, action, sev, ok)
	}
	if _, _, _, ok := q.RuleFor(session.PromptID, detect.Output); ok {
		t.Fatal("правило входа найдено для ответа")
	}
	d := q.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Mode: Enforce,
		Hits: []Hit{hit(session.PromptID, session.CatPromptChanged, 1, detect.SourceUser)}})
	if !d.Block || d.Rule != r.ID {
		t.Fatalf("решение: %+v", d)
	}
	for name, bad := range map[string]RuleSpec{
		"id без точки":          {ID: "prompt", Detector: session.PromptID, Action: Log, Severity: High},
		"id как у спецификации": {ID: "app-prompt", Detector: session.PromptID, Action: Log, Severity: High},
		"нет детектора":         {ID: "app.x", Detector: "nope", Action: Log, Severity: High},
		"направление":           {ID: "app.x", Detector: session.PromptID, Directions: []detect.Direction{detect.Output}, Action: Log, Severity: High},
		"действие":              {ID: "app.x", Detector: session.PromptID, Action: Pseudonymize, Severity: High},
		"повтор":                {ID: r.ID, Detector: session.PromptID, Action: Log, Severity: High},
		"серьёзность":           {ID: "app.x", Detector: session.PromptID, Action: Log, Severity: "fatal"},
	} {
		if _, err := q.WithRule(c, bad); err == nil {
			t.Errorf("%s: правило принято", name)
		}
	}
}
