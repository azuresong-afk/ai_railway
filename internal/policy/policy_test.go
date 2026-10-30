package policy

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
)

// fakeDetector — детектор с ID, направлениями и категориями; находок не
// выдаёт: политике нужны только они.
type fakeDetector struct {
	id   string
	dirs []detect.Direction
	cats []string
}

func (d fakeDetector) ID() string                     { return d.id }
func (fakeDetector) Version() string                  { return "1.0.0" }
func (d fakeDetector) Directions() []detect.Direction { return d.dirs }
func (d fakeDetector) Categories() []string           { return d.cats }
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
	// Категории — как у встроенных детекторов.
	cats := map[string][]string{}
	for _, d := range builtin.All() {
		cats[d.ID()] = d.(detect.Categorizer).Categories()
	}
	var ds []detect.Detector
	for _, id := range ids {
		ds = append(ds, fakeDetector{id: id, dirs: all[id], cats: cats[id]})
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

// mlFake — ML-детектор с признаком связи с aisec-ml (заглушка без связи —
// connected = false).
type mlFake struct {
	fakeDetector
	connected bool
}

func (d mlFake) MLConnected() bool { return d.connected }

// ML-правила шаблонов (задачи 4.19 и 4.20, DM-01, DM-18, DM-31): только на шлюзе с
// aisec-ml, только журнал (мониторинг до замера Р4), с порогом в правиле.
// Без aisec-ml шаблон их не содержит: иначе каждое событие получало бы
// ml_unavailable. Template (копия для политики заказчика) их не содержит.
func TestTemplateMLRulesOnlyWithAisecML(t *testing.T) {
	both := []detect.Direction{detect.Input, detect.Output}
	reg := func(connected bool) *detect.Registry {
		r, err := detect.NewRegistry(fakeDetector{id: detInjection, dirs: in},
			mlFake{fakeDetector{id: detInjML, dirs: in, cats: []string{"injection.ml"}}, connected},
			mlFake{fakeDetector{id: detToxML, dirs: both, cats: []string{"toxicity.insult"}}, connected},
			mlFake{fakeDetector{id: detNER, dirs: both, cats: []string{"pii.person"}}, connected})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, id := range TemplateIDs() {
		raw, _ := Template(id)
		for _, r := range raw.Rules {
			if r.Detector == detInjML || r.Detector == detToxML || r.Detector == detNER {
				t.Fatalf("%s: ML-правило в Template", id)
			}
		}
		if s, _ := TemplateFor(id, reg(false)); slices.ContainsFunc(s.Rules, func(r RuleSpec) bool { return r.Detector != detInjection }) {
			t.Fatalf("%s без aisec-ml: %+v", id, s.Rules)
		}
		s, _ := TemplateFor(id, reg(true))
		var ml []RuleSpec
		for _, r := range s.Rules {
			if r.Detector == detInjML || r.Detector == detToxML || r.Detector == detNER {
				ml = append(ml, r)
			}
		}
		if len(ml) != 3 {
			t.Fatalf("%s с aisec-ml: правил ML %d", id, len(ml))
		}
		for _, r := range ml {
			if r.Action != Log || r.Threshold == nil || *r.Threshold < 0.5 {
				t.Fatalf("%s: правило %+v", id, r)
			}
		}
		if _, err := TemplatePolicy(id, reg(true)); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	// Находка ML в enforce только журналируется; ниже порога правила — нет.
	p, err := TemplatePolicy(TemplatePIIStrict, reg(true))
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input,
		Hits: []Hit{hit(detInjML, "injection.ml", 0.95, detect.SourceUser)}})
	if d.Block || d.Action != Log || d.Rule != "injection-ml" {
		t.Fatalf("находка ML: %+v", d)
	}
	d = p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input,
		Hits: []Hit{hit(detInjML, "injection.ml", 0.6, detect.SourceUser)}})
	if d.Rule != "" {
		t.Fatalf("ниже порога: %+v", d)
	}
	// Изменение порога в копии не меняет шаблон.
	s, _ := TemplateFor(TemplateBase, reg(true))
	*s.Rules[len(s.Rules)-1].Threshold = 0.1
	again, _ := TemplateFor(TemplateBase, reg(true))
	if *again.Rules[len(again.Rules)-1].Threshold != thrNER {
		t.Fatal("порог шаблона изменился через копию")
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
	// Скрытые символы в monitor тоже вырезаются, а не уходят провайдеру
	// (ревью 1.17–1.21, п. 15).
	tag := hit(detUnicode, "unicode.tag", 0.95, detect.SourceUser)
	d = p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Mode: Monitor, External: true, Hits: []Hit{tag}})
	if d.Block || !slices.Equal(d.Applied(), []Action{Redact}) {
		t.Fatalf("скрытые символы в monitor: %+v", d)
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

// TestCompileRejectsUnknownCategory — опечатка в категории правила (ревью
// 1.17–1.21, п. 7) не даёт правила, которое молча никогда не срабатывает.
func TestCompileRejectsUnknownCategory(t *testing.T) {
	rule := func(det string, cats ...string) *Spec {
		return &Spec{ID: "p", Name: "p", Version: 1, Mode: Enforce, Rules: []RuleSpec{
			{ID: "r", Detector: det, Categories: cats, Action: Block, Severity: High},
		}}
	}
	if _, err := Compile(rule(detPII, "pii.passport", "pii.card"), catalog(t)); err != nil {
		t.Fatalf("верные категории: %v", err)
	}
	_, err := Compile(rule(detPII, "pii.card", "pii.pasport"), catalog(t))
	if err == nil || !strings.Contains(err.Error(), `"pii.pasport"`) {
		t.Fatalf("опечатка в категории: %v", err)
	}
	// Категория другого детектора — тоже ошибка.
	if _, err := Compile(rule(detPII, "secret.api_key"), catalog(t)); err == nil {
		t.Fatal("категория чужого детектора принята")
	}
	// Без categories проверять нечего.
	if _, err := Compile(rule(detPII), catalog(t)); err != nil {
		t.Fatal(err)
	}
	// Детектор, который не сообщает категории, — правило с categories
	// отвергается: проверить его нельзя.
	r, err := detect.NewRegistry(silentDetector{fakeDetector{id: "custom.det", dirs: in}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(rule("custom.det", "custom.x"), r); err == nil {
		t.Fatal("правило с categories у детектора без Categories() принято")
	}
	if _, err := Compile(rule("custom.det"), r); err != nil {
		t.Fatal(err)
	}
}

// silentDetector — детектор без Categories() (поле, а не встраивание, чтобы
// метод fakeDetector не перешёл к нему).
type silentDetector struct{ d fakeDetector }

func (s silentDetector) ID() string                     { return s.d.ID() }
func (s silentDetector) Version() string                { return s.d.Version() }
func (s silentDetector) Directions() []detect.Direction { return s.d.Directions() }
func (s silentDetector) Detect(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	return s.d.Detect(ctx, t)
}

// TestCompileListsCategories — категории lists берутся из списков
// приложения: lists.topic есть только у детектора с таким списком.
func TestCompileListsCategories(t *testing.T) {
	spec := &Spec{ID: "p", Name: "p", Version: 1, Mode: Enforce, Rules: []RuleSpec{
		{ID: "r", Detector: detLists, Categories: []string{"lists.topic"}, Action: Block, Severity: High},
	}}
	def, err := detect.NewRegistry(lists.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(spec, def); err == nil {
		t.Fatal("lists.topic принята без такого списка")
	}
	ld, err := lists.Compile(lists.WithDefaults([]lists.Spec{{ID: "topics", Category: "topic", Threat: "DM-32", Score: 0.8, Words: []string{"взрывчатка"}}}))
	if err != nil {
		t.Fatal(err)
	}
	app, err := detect.NewRegistry(ld)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(spec, app); err != nil {
		t.Fatalf("lists.topic у детектора приложения: %v", err)
	}
	spec.Rules[0].Categories = []string{"lists.marker", "lists.topik"}
	if _, err := Compile(spec, app); err == nil {
		t.Fatal("опечатка в категории lists принята")
	}
}
