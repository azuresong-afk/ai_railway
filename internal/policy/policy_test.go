package policy

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
)

// fakeDetector — детектор с ID и направлениями; находок не выдаёт:
// политике нужны только ID и направления.
type fakeDetector struct {
	id   string
	dirs []detect.Direction
}

func (d fakeDetector) ID() string                     { return d.id }
func (fakeDetector) Version() string                  { return "1.0.0" }
func (d fakeDetector) Directions() []detect.Direction { return d.dirs }
func (fakeDetector) Detect(context.Context, detect.Text) ([]detect.Finding, error) {
	return nil, nil
}

func catalog(t *testing.T, ids ...string) *detect.Registry {
	t.Helper()
	all := map[string][]detect.Direction{
		detPII: {detect.Input, detect.Output}, detSecrets: {detect.Input, detect.Output},
		detInjection: {detect.Input}, detUnicode: {detect.Input},
		detCanary: {detect.Output}, detExfil: {detect.Output}, detLists: {detect.Input, detect.Output},
	}
	if len(ids) == 0 {
		for id := range all {
			ids = append(ids, id)
		}
		slices.Sort(ids)
	}
	var ds []detect.Detector
	for _, id := range ids {
		ds = append(ds, fakeDetector{id: id, dirs: all[id]})
	}
	r, err := detect.NewRegistry(ds...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hit(det, cat string, score float64, src detect.Source) Hit {
	return Hit{Finding: detect.Finding{Detector: det, Category: cat, Score: score}, Source: src}
}

var (
	pii    = hit(detPII, "pii.card", 0.97, detect.SourceUser)
	inj    = hit(detInjection, "injection.override", 0.9, detect.SourceUser)
	secret = hit(detSecrets, "secret.api_key", 0.95, detect.SourceUser)
)

func compile(t *testing.T, s *Spec) *Policy {
	t.Helper()
	p, err := Compile(s, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func base(t *testing.T) *Policy {
	t.Helper()
	p, err := TemplatePolicy(TemplateBase, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Таблица приоритетов (ТЗ, 5.3) зафиксирована в
// docs/cert/security-functions.md: менять только вместе.
func TestPriorityTable(t *testing.T) {
	order := []Action{Allow, Log, Pseudonymize, Redact, RequireApproval, Block}
	for i := 1; i < len(order); i++ {
		if !Stronger(order[i], order[i-1]) || Stronger(order[i-1], order[i]) {
			t.Fatalf("%s должно быть сильнее %s", order[i], order[i-1])
		}
	}
	if len(priority) != len(order) || Priority("unknown") != 0 || Stronger("unknown", Allow) {
		t.Fatal("неизвестное действие не должно иметь приоритета")
	}
}

func TestConflictStrongestWins(t *testing.T) {
	s := &Spec{ID: "p", Name: "П", Version: 1, Mode: Enforce, Rules: []RuleSpec{
		{ID: "allow-card", Detector: detPII, Directions: in, Categories: []string{"pii.card"}, Action: Allow, Severity: Info},
		{ID: "pseudo", Detector: detPII, Directions: in, Action: Pseudonymize, Severity: Low},
		{ID: "redact", Detector: detPII, Directions: in, Action: Redact, Severity: Medium},
		{ID: "redact-again", Detector: detPII, Directions: in, Action: Redact, Severity: High},
	}}
	d := compile(t, s).Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Hits: []Hit{pii}})
	m := d.Matches[0]
	// allow выше по списку не ослабляет; при равенстве — первое правило;
	// серьёзность — наибольшая среди совпавших.
	if d.Action != Redact || d.Rule != "redact" || m.Apply != Redact || m.ProtectRule != "redact" || d.Severity != High {
		t.Fatalf("решение: %+v", d)
	}
	// block сильнее всего, но защита данных по той же находке остаётся.
	s.Rules = append(s.Rules, RuleSpec{ID: "block", Detector: detPII, Directions: in, Action: Block, Severity: High})
	d = compile(t, s).Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Hits: []Hit{pii}})
	if d.Action != Block || d.Rule != "block" || !d.Block || d.Matches[0].Protect != Redact {
		t.Fatalf("решение с block: %+v", d)
	}
}

func TestDM01_InjectionBlockedInEnforceLoggedInMonitor(t *testing.T) {
	p := base(t)
	d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Mode: Enforce, External: true, Hits: []Hit{inj}})
	if !d.Block || d.Action != Block || d.Rule != "injection" || d.Message != DefaultBlockMessage || d.Severity != High {
		t.Fatalf("enforce: %+v", d)
	}
	if got := d.Applied(); !slices.Equal(got, []Action{Block}) {
		t.Fatalf("applied: %v", got)
	}
	d = p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, External: true, Hits: []Hit{inj}})
	if d.Mode != Monitor || d.Block || d.Action != Block || len(d.Applied()) != 0 || d.Message != "" {
		t.Fatalf("monitor: решение должно только журналироваться: %+v", d)
	}
}

// Критерий приёмки этапа 1: в monitor ПДн в запросе к внешнему провайдеру
// псевдонимизируются, в том числе когда в запросе есть инъекция; в решении
// видно и применённое, и то, что было бы в enforce.
func TestDM31_MonitorProtectsDataForExternalProvider(t *testing.T) {
	p := base(t)
	req := Request{Endpoint: EndpointChat, Direction: detect.Input, External: true, Hits: []Hit{inj, pii, secret}}
	d := p.Evaluate(req)
	if d.Block || d.Action != Block || d.Rule != "injection" {
		t.Fatalf("итог: %+v", d)
	}
	if got := d.Applied(); !slices.Equal(got, []Action{Redact, Pseudonymize}) {
		t.Fatalf("applied: %v", got)
	}
	apply := map[int]Action{}
	for _, m := range d.Matches {
		apply[m.Hit] = m.Apply
	}
	if apply[0] != "" || apply[1] != Pseudonymize || apply[2] != Redact {
		t.Fatalf("действия по находкам: %v", apply)
	}
	// Внутренний провайдер: monitor ничего не применяет.
	req.External = false
	if d := p.Evaluate(req); len(d.Applied()) != 0 || d.Action != Block {
		t.Fatalf("внутренний провайдер: %+v", d)
	}
}

func TestDM32_SecretsRedacted(t *testing.T) {
	d := base(t).Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, External: true, Hits: []Hit{secret}})
	if d.Action != Redact || d.Matches[0].Apply != Redact || d.Severity != High {
		t.Fatalf("секрет: %+v", d)
	}
}

func TestMonitorOutputNotApplied(t *testing.T) {
	p := base(t)
	out := hit(detPII, "pii.phone", 0.9, detect.SourceOutput)
	d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Output, External: true, Hits: []Hit{out}})
	if d.Action != Redact || len(d.Applied()) != 0 {
		t.Fatalf("monitor, ответ: %+v", d)
	}
	d = p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Output, Mode: Enforce, Hits: []Hit{out}})
	if d.Matches[0].Apply != Redact || d.Block {
		t.Fatalf("enforce, ответ: %+v", d)
	}
}

// ТЗ, 5.1: для эмбеддингов pseudonymize выполняется как redact, это видно
// в решении.
func TestEmbeddingsPseudonymizeAsRedact(t *testing.T) {
	d := base(t).Evaluate(Request{Endpoint: EndpointEmbeddings, Direction: detect.Input, Mode: Enforce, Hits: []Hit{pii}})
	m := d.Matches[0]
	if m.Action != Redact || m.Apply != Redact || !m.AsRedact || m.Rule != "pii-input" || d.Action != Redact {
		t.Fatalf("эмбеддинги: %+v", d)
	}
	if got := d.Applied(); !slices.Equal(got, []Action{Redact}) {
		t.Fatalf("applied: %v", got)
	}
}

func TestDM14_NonText(t *testing.T) {
	img := []MediaPart{{Kind: "image"}}
	url := []MediaPart{{Kind: "image", URL: true}}
	cases := []struct {
		nonText   NonText
		mode      Mode
		media     []MediaPart
		block     bool
		action    Action
		unchecked bool
	}{
		{"", Enforce, img, false, Allow, true},
		{NonTextAllowUnchecked, Enforce, url, false, Allow, true},
		{NonTextBlock, Enforce, img, true, Block, false},
		{NonTextBlock, Monitor, img, false, Block, true},
		{NonTextAllowInline, Enforce, img, false, Allow, true},
		{NonTextAllowInline, Enforce, append(img, url...), true, Block, false},
		{NonTextBlock, Enforce, nil, false, Allow, false},
	}
	for i, c := range cases {
		p := compile(t, &Spec{ID: "p", Name: "П", Version: 1, Mode: c.mode, NonText: c.nonText})
		d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Media: c.media})
		if d.Block != c.block || d.Action != c.action || d.NonTextUnchecked != c.unchecked {
			t.Fatalf("случай %d: %+v", i, d)
		}
		if c.action == Block && (d.Rule != NonTextRule || d.Severity != Medium) {
			t.Fatalf("случай %d: правило %q, серьёзность %q", i, d.Rule, d.Severity)
		}
	}
	// Блокировка правилом не заменяется на non_text в трассировке.
	p, err := TemplatePolicy(TemplatePIIStrict, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Hits: []Hit{inj}, Media: img})
	if !d.Block || d.Rule != "injection" {
		t.Fatalf("инъекция и медиа: %+v", d)
	}
}

func TestRuleConditions(t *testing.T) {
	half, high := 0.5, 0.9
	p := compile(t, &Spec{ID: "p", Name: "П", Version: 1, Mode: Enforce, Rules: []RuleSpec{
		{ID: "rag", Detector: detInjection, Sources: []detect.Source{detect.SourceRAG, detect.SourceTool}, Threshold: &half, Action: Block, Severity: High},
		{ID: "user", Detector: detInjection, Threshold: &high, Action: Log, Severity: Low},
		{ID: "card", Detector: detPII, Directions: in, Categories: []string{"pii.card"}, Action: Redact, Severity: Low},
	}})
	cases := []struct {
		h    Hit
		rule string
	}{
		{hit(detInjection, "injection.role", 0.5, detect.SourceRAG), "rag"},
		{hit(detInjection, "injection.role", 0.49, detect.SourceRAG), ""},
		{hit(detInjection, "injection.role", 0.6, detect.SourceUser), ""},
		{hit(detInjection, "injection.role", 0.95, detect.SourceUser), "user"},
		{hit(detInjection, "injection.role", 0.95, detect.SourceTool), "rag"},
		{hit(detPII, "pii.card", 0.6, detect.SourceUser), "card"},
		{hit(detPII, "pii.phone", 0.9, detect.SourceUser), ""},
		{hit("unknown.det", "pii.card", 0.9, detect.SourceUser), ""},
	}
	for i, c := range cases {
		d := p.Evaluate(Request{Endpoint: EndpointCheck, Direction: detect.Input, Hits: []Hit{c.h}})
		if d.Rule != c.rule || (c.rule == "") != (len(d.Matches) == 0) {
			t.Fatalf("случай %d: %+v", i, d)
		}
	}
	// Правило входа не срабатывает на ответе.
	if d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Output, Hits: []Hit{pii}}); len(d.Matches) != 0 {
		t.Fatalf("направление: %+v", d)
	}
}

func TestModeResolution(t *testing.T) {
	p := base(t) // monitor
	for mode, want := range map[Mode]Mode{"": Monitor, Monitor: Monitor, Enforce: Enforce, "audit": Enforce} {
		if d := p.Evaluate(Request{Direction: detect.Input, Mode: mode, Hits: []Hit{inj}}); d.Mode != want || d.Block != (want == Enforce) {
			t.Fatalf("режим %q: %+v", mode, d)
		}
	}
}

func TestBlockMessage(t *testing.T) {
	s := &Spec{ID: "p", Name: "П", Version: 1, Mode: Enforce, BlockMessage: "Обратитесь в поддержку.", Rules: []RuleSpec{
		{ID: "inj", Detector: detInjection, Action: Block, Severity: High, Message: "Запрос нарушает правила."},
		{ID: "secret", Detector: detSecrets, Action: Block, Severity: High},
	}}
	p := compile(t, s)
	if d := p.Evaluate(Request{Direction: detect.Input, Hits: []Hit{inj}}); d.Message != "Запрос нарушает правила." {
		t.Fatalf("сообщение правила: %q", d.Message)
	}
	if d := p.Evaluate(Request{Direction: detect.Input, Hits: []Hit{secret}}); d.Message != "Обратитесь в поддержку." {
		t.Fatalf("сообщение политики: %q", d.Message)
	}
	if d := p.Evaluate(Request{Direction: detect.Input}); d.Action != Allow || d.Rule != "" || d.Severity != "" || d.Matches != nil {
		t.Fatalf("без находок: %+v", d)
	}
}

func TestCompileChecksDetectors(t *testing.T) {
	c := catalog(t)
	s := &Spec{ID: "p", Name: "П", Version: 1, Mode: Enforce, Rules: []RuleSpec{
		{ID: "a", Detector: "canary2", Action: Block, Severity: High},
		{ID: "b", Detector: detInjection, Directions: out, Action: Block, Severity: High},
	}}
	_, err := Compile(s, c)
	if err == nil || !strings.Contains(err.Error(), "не зарегистрирован") || !strings.Contains(err.Error(), "не проверяет направление") {
		t.Fatalf("ожидались ошибки детекторов: %v", err)
	}
	p := compile(t, &Spec{ID: "p", Name: "П", Version: 1, Mode: Monitor, Rules: []RuleSpec{
		{ID: "a", Detector: detSecrets, Action: Log, Severity: Info},
		{ID: "b", Detector: detInjection, Action: Log, Severity: Info},
		{ID: "c", Detector: detSecrets, Directions: out, Action: Redact, Severity: Info},
	}})
	if got := p.Detectors(detect.Input); !slices.Equal(got, []string{detSecrets, detInjection}) {
		t.Fatalf("детекторы входа: %v", got)
	}
	if got := p.Detectors(detect.Output); !slices.Equal(got, []string{detSecrets}) {
		t.Fatalf("детекторы выхода: %v", got)
	}
	if p.NonText != NonTextAllowUnchecked || p.ResponseCheck != ResponseIncremental || p.BlockMessage != DefaultBlockMessage {
		t.Fatalf("значения по умолчанию: %+v", p)
	}
}

func TestTemplates(t *testing.T) {
	for _, id := range TemplateIDs() {
		s, ok := Template(id)
		if !ok || !IsTemplate(id) {
			t.Fatalf("шаблон %s", id)
		}
		if _, err := Compile(s, catalog(t)); err != nil {
			t.Fatalf("шаблон %s со всеми детекторами ТЗ: %v", id, err)
		}
		// Встроенных детекторов пока меньше: правила остальных опускаются.
		reg, err := detect.NewRegistry(builtin.All()...)
		if err != nil {
			t.Fatal(err)
		}
		p, err := TemplatePolicy(id, reg)
		if err != nil {
			t.Fatalf("шаблон %s со встроенными детекторами: %v", id, err)
		}
		for _, det := range append(p.Detectors(detect.Input), p.Detectors(detect.Output)...) {
			if _, ok := reg.Get(det); !ok {
				t.Fatalf("шаблон %s: детектор %s не встроен", id, det)
			}
		}
	}
	if IsTemplate("custom") {
		t.Fatal("custom — не шаблон")
	}
	if _, err := TemplatePolicy("custom", catalog(t)); err == nil {
		t.Fatal("неизвестный шаблон")
	}
	// Решение Р7: по умолчанию — «Базовая защита» в monitor.
	p, err := Resolve("", nil, catalog(t))
	if err != nil || p.ID != TemplateBase || p.Mode != Monitor || p.ResponseCheck != ResponseIncremental {
		t.Fatalf("политика по умолчанию: %+v, %v", p, err)
	}
	// Изменение копии не меняет шаблон.
	s, _ := Template(TemplateBase)
	s.Rules[0].Directions[0] = detect.Output
	s.Rules[0].Categories[0] = "pii.card"
	s.Mode = Enforce
	if again, _ := Template(TemplateBase); again.Rules[0].Directions[0] != detect.Input || again.Rules[0].Categories[0] != hidden[0] || again.Mode != Monitor {
		t.Fatal("шаблон изменился через копию")
	}
}

func TestTemplateOmitsMissingDetectors(t *testing.T) {
	// Реестр без canary и с lists только на входе — правило lists остаётся
	// только для входа.
	r, err := detect.NewRegistry(fakeDetector{id: detInjection, dirs: in}, fakeDetector{id: detLists, dirs: in})
	if err != nil {
		t.Fatal(err)
	}
	p, err := TemplatePolicy(TemplateBase, r)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Detectors(detect.Input); !slices.Equal(got, []string{detInjection, detLists}) {
		t.Fatalf("вход: %v", got)
	}
	if got := p.Detectors(detect.Output); len(got) != 0 {
		t.Fatalf("выход: %v", got)
	}
}

// «ПДн — строго» в monitor: block только журналируется, но ПДн и секреты
// к внешнему провайдеру маскируются правилами *-protect.
func TestPIIStrictInMonitorStillProtects(t *testing.T) {
	p, err := TemplatePolicy(TemplatePIIStrict, catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Mode: Monitor, External: true, Hits: []Hit{pii, secret}})
	if d.Block || d.Action != Block || !slices.Equal(d.Applied(), []Action{Redact}) {
		t.Fatalf("решение: %+v", d)
	}
	d = p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Hits: []Hit{pii}})
	if !d.Block || d.Rule != "pii-input" || d.Severity != High {
		t.Fatalf("enforce: %+v", d)
	}
}

func TestResolve(t *testing.T) {
	c := catalog(t)
	specs := []Spec{{ID: "custom", Name: "Своя", Version: 3, Mode: Enforce, Rules: []RuleSpec{
		{ID: "x", Detector: detInjection, Action: Block, Severity: High},
	}}}
	p, err := Resolve("custom", specs, c)
	if err != nil || p.Version != 3 || p.Mode != Enforce {
		t.Fatalf("политика заказчика: %+v, %v", p, err)
	}
	if _, err := Resolve("missing", specs, c); err == nil {
		t.Fatal("неизвестная политика")
	}
	specs[0].Rules[0].Detector = "canary2"
	if _, err := Resolve("custom", specs, c); err == nil {
		t.Fatal("политика заказчика проверяется строго")
	}
}

// Check API: ответа модели, где можно подставить исходные значения, нет —
// pseudonymize выполняется как redact, как и для эмбеддингов.
func TestCheckPseudonymizeAsRedact(t *testing.T) {
	d := base(t).Evaluate(Request{Endpoint: EndpointCheck, Direction: detect.Input, Mode: Enforce, Hits: []Hit{pii}})
	m := d.Matches[0]
	if m.Action != Redact || m.Apply != Redact || !m.AsRedact || d.Action != Redact {
		t.Fatalf("check: %+v", d)
	}
}
