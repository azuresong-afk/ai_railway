package versions_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

type env struct {
	svc *versions.Service
	mem *versions.Memory
	by  versions.By
	now time.Time
}

func registry(t testing.TB) *detect.Registry {
	t.Helper()
	r, err := detect.NewRegistry(builtin.All()...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newEnv(t testing.TB) *env {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{mem: versions.NewMemory(), now: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC),
		by: versions.By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-00000000a001", Name: "admin"}}}
	e.svc, err = versions.New(versions.Options{Store: e.mem, Provider: p, Catalog: registry(t), Clock: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func spec(id string, mode policy.Mode, rules ...policy.RuleSpec) *policy.Spec {
	return &policy.Spec{ID: id, Name: "Политика " + id, Mode: mode, Rules: rules}
}

var (
	ruleInjection = policy.RuleSpec{ID: "injection", Detector: "injection.heuristic", Directions: []detect.Direction{detect.Input},
		Action: policy.Block, Severity: policy.High}
	rulePII = policy.RuleSpec{ID: "pii", Detector: "pii.ru", Directions: []detect.Direction{detect.Input},
		Action: policy.Redact, Severity: policy.Medium}
)

func (e *env) last(t *testing.T, action string) audit.Entry {
	t.Helper()
	recs := e.mem.Records()
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i].Action == action {
			if _, err := audit.CanonicalDetails(recs[i].Details); err != nil {
				t.Fatalf("%s: подробности не проходят проверку журнала: %v", action, err)
			}
			return recs[i]
		}
	}
	t.Fatalf("нет записи %s", action)
	return audit.Entry{}
}

func inputErr(t *testing.T, err error, want string) {
	t.Helper()
	var ie *versions.InputError
	if !errors.As(err, &ie) || !strings.Contains(err.Error(), want) {
		t.Fatalf("ожидалась ошибка ввода про %q, получено %v", want, err)
	}
}

func TestCreateAndVersions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	d, err := e.svc.Create(ctx, e.by, spec("crm-strict", policy.Enforce, ruleInjection, rulePII), versions.SourceAPI, "первая", versions.ConsoleDefaults)
	if err != nil {
		t.Fatal(err)
	}
	// Решение 1.19: пустые поля сохраняются явно, non_text в консоли — allow_inline.
	if d.Version.Version != 1 || d.Spec.NonText != policy.NonTextAllowInline || d.Spec.ResponseCheck != policy.ResponseIncremental ||
		!bytes.Contains(d.Version.YAML, []byte("non_text: allow_inline")) || len(d.Version.Hash) != 32 {
		t.Fatalf("версия 1: %+v %s", d.Version, d.Version.YAML)
	}
	if r := e.last(t, "policy.create"); r.Object.ID != d.Policy.ID {
		t.Fatalf("аудит: %+v", r)
	}
	if _, err := e.svc.Create(ctx, e.by, spec("crm-strict", policy.Monitor), versions.SourceAPI, "", versions.ConsoleDefaults); !errors.Is(err, versions.ErrExists) {
		t.Fatalf("повторный ID: %v", err)
	}
	for _, id := range policy.TemplateIDs() {
		if _, err := e.svc.Create(ctx, e.by, spec(id, policy.Monitor), versions.SourceAPI, "", versions.ConsoleDefaults); !errors.Is(err, versions.ErrTemplate) {
			t.Fatalf("ID шаблона %s: %v", id, err)
		}
	}
	// Неизвестный детектор и направление, которого детектор не проверяет, — отказ (строгая компиляция).
	_, err = e.svc.Create(ctx, e.by, spec("bad", policy.Monitor, policy.RuleSpec{ID: "x", Detector: "no.such", Action: policy.Log, Severity: policy.Low}),
		versions.SourceAPI, "", versions.ConsoleDefaults)
	inputErr(t, err, "no.such")
	_, err = e.svc.Create(ctx, e.by, spec("bad", policy.Monitor, policy.RuleSpec{ID: "x", Detector: "canary",
		Directions: []detect.Direction{detect.Input}, Action: policy.Log, Severity: policy.Low}), versions.SourceAPI, "", versions.ConsoleDefaults)
	inputErr(t, err, "canary")
	_, err = e.svc.Create(ctx, e.by, spec("Bad_ID", policy.Monitor), versions.SourceAPI, "", versions.ConsoleDefaults)
	inputErr(t, err, "id")
	_, err = e.svc.Create(ctx, e.by, spec("c1", policy.Monitor), versions.SourceAPI, strings.Repeat("я", versions.MaxComment+1), versions.ConsoleDefaults)
	inputErr(t, err, "comment")
	if _, err := e.svc.Create(ctx, e.by, spec("c1", policy.Monitor), versions.SourceAPI, strings.Repeat("я", versions.MaxComment), versions.ConsoleDefaults); err != nil {
		t.Fatalf("граница комментария: %v", err)
	}

	// Новая версия поверх текущей; устаревшая base_version — конфликт.
	e.now = e.now.Add(time.Hour)
	weaker := spec("crm-strict", policy.Monitor, rulePII)
	d2, err := e.svc.Update(ctx, e.by, "crm-strict", 1, weaker, versions.SourceAPI, "вторая", versions.ConsoleDefaults)
	if err != nil || d2.Version.Version != 2 || d2.Policy.Current != 2 || d2.Policy.Mode != "monitor" || !d2.Policy.UpdatedAt.Equal(e.now) {
		t.Fatalf("версия 2: %+v %v", d2.Policy, err)
	}
	if _, err := e.svc.Update(ctx, e.by, "crm-strict", 1, spec("", policy.Enforce), versions.SourceAPI, "", versions.ConsoleDefaults); !errors.Is(err, versions.ErrConflict) {
		t.Fatalf("устаревшая base_version: %v", err)
	}
	if _, err := e.svc.Update(ctx, e.by, "crm-strict", 2, spec("other", policy.Enforce), versions.SourceAPI, "", versions.ConsoleDefaults); err == nil {
		t.Fatal("смена ID политики принята")
	}
	if _, err := e.svc.Update(ctx, e.by, "base", 1, spec("", policy.Enforce), versions.SourceAPI, "", versions.ConsoleDefaults); !errors.Is(err, versions.ErrTemplate) {
		t.Fatalf("изменение шаблона: %v", err)
	}
	if _, err := e.svc.Update(ctx, e.by, "nope", 1, spec("", policy.Enforce), versions.SourceAPI, "", versions.ConsoleDefaults); !errors.Is(err, versions.ErrNotFound) {
		t.Fatalf("нет политики: %v", err)
	}
	r := e.last(t, "policy.update")
	det := r.Details.(map[string]any)
	if det["weakening"] != true || det["from_version"] != 1 || det["to_version"] != 2 {
		t.Fatalf("аудит новой версии: %v", det)
	}

	// Версия 1 не изменилась; список — новые первыми.
	v1, err := e.svc.Get(ctx, "crm-strict", 1)
	if err != nil || v1.Spec.Mode != policy.Enforce || len(v1.Spec.Rules) != 2 || v1.Spec.Version != 1 {
		t.Fatalf("версия 1 после изменения: %+v %v", v1.Spec, err)
	}
	vs, err := e.svc.Versions(ctx, "crm-strict", 0, 0)
	if err != nil || len(vs) != 2 || vs[0].Version != 2 || vs[0].YAML != nil || vs[1].Comment != "первая" {
		t.Fatalf("список версий: %+v %v", vs, err)
	}
	if vs, err := e.svc.Versions(ctx, "crm-strict", 2, 10); err != nil || len(vs) != 1 || vs[0].Version != 1 {
		t.Fatalf("страница версий: %+v %v", vs, err)
	}
	if _, err := e.svc.Get(ctx, "crm-strict", 3); !errors.Is(err, versions.ErrNotFound) {
		t.Fatalf("нет версии 3: %v", err)
	}
}

func TestRollback(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.svc.Create(ctx, e.by, spec("p", policy.Enforce, ruleInjection), versions.SourceAPI, "", versions.ConsoleDefaults); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Update(ctx, e.by, "p", 1, spec("p", policy.Monitor), versions.SourceAPI, "", versions.ConsoleDefaults); err != nil {
		t.Fatal(err)
	}
	d, err := e.svc.Rollback(ctx, e.by, "p", 1, 2, "вернуть блокировку")
	if err != nil || d.Version.Version != 3 || d.Version.RolledBackFrom != 1 || d.Version.Source != versions.SourceRollback ||
		d.Spec.Mode != policy.Enforce || len(d.Spec.Rules) != 1 {
		t.Fatalf("откат: %+v %v", d.Version, err)
	}
	v1, err := e.svc.Get(ctx, "p", 1)
	if err != nil {
		t.Fatal(err)
	}
	v3, err := e.svc.Get(ctx, "p", 3)
	if err != nil {
		t.Fatal(err)
	}
	if diff := versions.Compare(v1.Spec, v3.Spec); !diff.Empty() {
		t.Fatalf("откат не вернул содержимое: %+v", diff)
	}
	if det := e.last(t, "policy.rollback").Details.(map[string]any); det["rolled_back_from"] != 1 || det["weakening"] != false {
		t.Fatalf("аудит отката: %v", det)
	}
	for _, c := range []struct{ to, base int }{{3, 3}, {0, 3}, {4, 3}} {
		if _, err := e.svc.Rollback(ctx, e.by, "p", c.to, c.base, ""); err == nil {
			t.Errorf("откат к %d поверх %d принят", c.to, c.base)
		}
	}
	if _, err := e.svc.Rollback(ctx, e.by, "p", 1, 2, ""); !errors.Is(err, versions.ErrConflict) {
		t.Fatalf("откат поверх устаревшей версии: %v", err)
	}
}

func TestImportExport(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	y := "id: imported\nname: Импорт\nversion: 7\nmode: enforce\nrules:\n  - id: injection\n    detector: injection.heuristic\n    directions: [input]\n    action: block\n    severity: high\n"
	d, created, err := e.svc.Import(ctx, e.by, strings.NewReader(y), 0, "")
	// Файл этапа 1 без non_text значит allow_unchecked — так и сохраняется.
	if err != nil || !created || d.Version.Version != 1 || d.Spec.NonText != policy.NonTextAllowUnchecked || d.Version.Source != versions.SourceImport {
		t.Fatalf("импорт: %+v %v", d.Version, err)
	}
	e.last(t, "policy.import")
	out, _, err := e.svc.Export(ctx, "imported", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Экспорт → импорт поверх текущей версии: политика та же.
	d2, created, err := e.svc.Import(ctx, e.by, bytes.NewReader(out), 1, "повтор")
	if err != nil || created || d2.Version.Version != 2 {
		t.Fatalf("повторный импорт: %+v %v", d2.Version, err)
	}
	diff, err := e.svc.Diff(ctx, "imported", 1, 2)
	if err != nil || !diff.Empty() {
		t.Fatalf("экспорт и импорт разошлись: %+v %v", diff, err)
	}
	if _, _, err := e.svc.Import(ctx, e.by, bytes.NewReader(out), 0, ""); !errors.Is(err, versions.ErrConflict) {
		t.Fatalf("импорт поверх без base_version: %v", err)
	}
	for name, bad := range map[string]string{
		"неизвестное поле":      y + "extra: 1\n",
		"второй документ":       y + "---\n" + y,
		"неизвестное в правиле": strings.Replace(y, "severity: high", "severity: high\n    weight: 2", 1),
		"шаблон":               strings.Replace(y, "id: imported", "id: base", 1),
		"больше 1 МиБ":         y + "# " + strings.Repeat("x", policy.MaxSpecSize) + "\n",
		"неизвестный детектор": strings.Replace(y, "injection.heuristic", "no.such", 1),
	} {
		if _, _, err := e.svc.Import(ctx, e.by, strings.NewReader(bad), 0, ""); err == nil {
			t.Errorf("%s: импорт принят", name)
		}
	}
	// Шаблон выгружается, но не имеет версий.
	tpl, td, err := e.svc.Export(ctx, "pii-strict", 0)
	if err != nil || !td.Template || !bytes.Contains(tpl, []byte("id: pii-strict")) {
		t.Fatalf("экспорт шаблона: %v", err)
	}
	if _, _, err := e.svc.Export(ctx, "pii-strict", 1); !errors.Is(err, versions.ErrNotFound) {
		t.Fatalf("версия шаблона: %v", err)
	}
}

func TestFromTemplateAndList(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	s, err := e.svc.FromTemplate("pii-strict", "pii-crm", "ПДн CRM")
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.svc.Create(ctx, e.by, s, versions.SourceTemplate, "", versions.ConsoleDefaults)
	// Копия шаблона сохраняет его non_text (block), а не умолчание консоли.
	if err != nil || d.Spec.NonText != policy.NonTextBlock || d.Spec.Name != "ПДн CRM" {
		t.Fatalf("копия шаблона: %+v %v", d.Spec, err)
	}
	if _, err := e.svc.FromTemplate("nope", "x", ""); err == nil {
		t.Fatal("неизвестный шаблон принят")
	}
	list, err := e.svc.List(ctx)
	if err != nil || len(list) != len(policy.TemplateIDs())+1 || !list[0].Template || list[len(list)-1].Slug != "pii-crm" || list[len(list)-1].Current != 1 {
		t.Fatalf("список: %+v %v", list, err)
	}
	for _, c := range []struct {
		id, mode string
		ok       bool
	}{{"base", "monitor", true}, {"pii-strict", "enforce", true}, {"pii-crm", "enforce", true}, {"nope", "", false}} {
		mode, ok, err := e.svc.PolicyMode(ctx, "", c.id)
		if err != nil || ok != c.ok || mode != c.mode {
			t.Errorf("PolicyMode(%s) = %s %v %v", c.id, mode, ok, err)
		}
	}
}

// Категории lists.* задают словари приложения: политика в сервере их
// принимает, а опечатка в категории другого детектора — ошибка.
func TestListsCategoriesLenient(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	s := spec("lists", policy.Enforce, policy.RuleSpec{ID: "codename", Detector: "lists", Categories: []string{"lists.codename"},
		Action: policy.Block, Severity: policy.High})
	if _, err := e.svc.Create(ctx, e.by, s, versions.SourceAPI, "", versions.ConsoleDefaults); err != nil {
		t.Fatal(err)
	}
	bad := spec("typo", policy.Enforce, policy.RuleSpec{ID: "pii", Detector: "pii.ru", Categories: []string{"pii.pasport"},
		Action: policy.Block, Severity: policy.High})
	_, err := e.svc.Create(ctx, e.by, bad, versions.SourceAPI, "", versions.ConsoleDefaults)
	inputErr(t, err, "pii.pasport")
	odd := spec("odd", policy.Enforce, policy.RuleSpec{ID: "x", Detector: "lists", Categories: []string{"pii.card"},
		Action: policy.Block, Severity: policy.High})
	_, err = e.svc.Create(ctx, e.by, odd, versions.SourceAPI, "", versions.ConsoleDefaults)
	inputErr(t, err, "pii.card")
}
