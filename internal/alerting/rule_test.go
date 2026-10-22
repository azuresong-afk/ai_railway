package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

func ptr[T any](v T) *T { return &v }

// Разбор правила из запроса: умолчания, каноническая форма, отказы.
func TestParseRuleInput(t *testing.T) {
	r, err := ParseRuleInput(RuleInput{Kind: KindThreshold, Name: "  Блокировки  ",
		Condition: Condition{Filter: `action="block"  and  app in ("b","a")`}, GroupBy: []string{"app", "user"},
		Recipients: Recipients{Roles: []string{"analyst", "security_admin", "analyst"},
			Users: []string{"01900000-0000-7000-8000-0000000000b1"}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "Блокировки" || !r.Enabled || r.Severity != "high" || r.SuppressMinutes != DefaultSuppressMinutes ||
		r.Condition.Filter != `action = "block" and app in ("b", "a")` || !slices.Equal(r.GroupBy, []string{"app", "user"}) ||
		!slices.Equal(r.Recipients.Roles, []string{"analyst"}) || len(r.Recipients.Users) != 1 {
		t.Fatalf("правило: %+v", r)
	}
	if got := r.Recipients.EffectiveRoles(); !slices.Equal(got, []string{"analyst", "auditor", "security_admin"}) {
		t.Fatalf("получатели: %v", got)
	}
	n, err := ParseRuleInput(RuleInput{Kind: KindNew, Name: "Новая модель", Condition: Condition{Field: "model"}}, "")
	if err != nil || n.Severity != "medium" || !slices.Equal(n.GroupBy, []string{"model"}) {
		t.Fatalf("новое: %+v %v", n, err)
	}
	for name, in := range map[string]RuleInput{
		"вид frequency":         {Kind: KindFrequency, Name: "x", Condition: Condition{MinSeverity: "high"}},
		"вид security":          {Kind: KindSecurity, Name: "x"},
		"без вида":              {Name: "x", Condition: Condition{MinSeverity: "high"}},
		"пустое имя":            {Kind: KindThreshold, Name: " ", Condition: Condition{MinSeverity: "high"}},
		"длинное имя":           {Kind: KindThreshold, Name: strings.Repeat("я", MaxName+1), Condition: Condition{MinSeverity: "high"}},
		"управляющий символ":    {Kind: KindThreshold, Name: "a\x00b", Condition: Condition{MinSeverity: "high"}},
		"порог без условия":     {Kind: KindThreshold, Name: "x"},
		"неверный фильтр":       {Kind: KindThreshold, Name: "x", Condition: Condition{Filter: `app ~ "x"`}},
		"неизвестное поле":      {Kind: KindThreshold, Name: "x", Condition: Condition{Filter: `content = "x"`}},
		"серьёзность":           {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "urgent"}},
		"серьёзность правила":   {Kind: KindThreshold, Name: "x", Severity: "warn", Condition: Condition{MinSeverity: "high"}},
		"field у порога":        {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high", Field: "model"}},
		"группировка по угрозе": {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high"}, GroupBy: []string{"threat"}},
		"повтор группировки":    {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high"}, GroupBy: []string{"app", "app"}},
		"пять полей": {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high"},
			GroupBy: []string{"app", "env", "user", "model", "provider"}},
		"новое без поля":       {Kind: KindNew, Name: "x"},
		"новое по угрозе":      {Kind: KindNew, Name: "x", Condition: Condition{Field: "threat"}},
		"новое с группировкой": {Kind: KindNew, Name: "x", Condition: Condition{Field: "model"}, GroupBy: []string{"app"}},
		"окно подавления":      {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high"}, SuppressMinutes: ptr(MaxSuppressMinutes + 1)},
		"отрицательное окно":   {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high"}, SuppressMinutes: ptr(-1)},
		"роль":                 {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high"}, Recipients: Recipients{Roles: []string{"Admin"}}},
		"пользователь":         {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high"}, Recipients: Recipients{Users: []string{"admin"}}},
		"много ролей": {Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high"},
			Recipients: Recipients{Roles: slices.Repeat([]string{"analyst"}, MaxRecipientRoles+1)}},
	} {
		if _, err := ParseRuleInput(in, ""); !isInput(err) {
			t.Errorf("%s: ожидалась ошибка ввода, получено %v", name, err)
		}
	}
	// Граница: ровно 4 поля группировки и окно 7 суток.
	if _, err := ParseRuleInput(RuleInput{Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high"},
		GroupBy: []string{"app", "env", "user", "model"}, SuppressMinutes: ptr(MaxSuppressMinutes)}, ""); err != nil {
		t.Fatalf("граница: %v", err)
	}
	// Вид не меняется при изменении.
	if _, err := ParseRuleInput(RuleInput{Kind: KindNew, Name: "x", Condition: Condition{Field: "model"}}, KindThreshold); !isInput(err) {
		t.Fatalf("смена вида: %v", err)
	}
	// Сообщение не повторяет длинный ввод целиком.
	_, err = ParseRuleInput(RuleInput{Kind: KindThreshold, Name: "x", Condition: Condition{MinSeverity: "high"},
		GroupBy: []string{strings.Repeat("z", 1000)}}, "")
	if err == nil || len(err.Error()) > 400 {
		t.Fatalf("сообщение: %v", err)
	}
}

// DM-40: ослабление правила определяется по каждому признаку; изменения
// выключенного правила ослаблением не считаются.
func TestWeakening(t *testing.T) {
	base := Rule{Enabled: true, Severity: "high", Condition: Condition{Filter: `app = "a"`, MinSeverity: "medium"},
		GroupBy: []string{"app"}, SuppressMinutes: 60, Recipients: Recipients{Roles: []string{"analyst"}, Users: []string{}}}
	for name, tc := range map[string]struct {
		mod  func(*Rule)
		want []string
	}{
		"без изменений":    {func(*Rule) {}, nil},
		"выключение":       {func(r *Rule) { r.Enabled = false }, []string{WeakDisabled}},
		"фильтр":           {func(r *Rule) { r.Condition.Filter = `app = "b"` }, []string{WeakConditionChanged}},
		"порог выше":       {func(r *Rule) { r.Condition.MinSeverity = "high" }, []string{WeakMinSeverityRaised}},
		"порог ниже":       {func(r *Rule) { r.Condition.MinSeverity = "low" }, nil},
		"группировка":      {func(r *Rule) { r.GroupBy = []string{"user"} }, []string{WeakGroupByChanged}},
		"серьёзность":      {func(r *Rule) { r.Severity = "low" }, []string{WeakSeverityLowered}},
		"серьёзность выше": {func(r *Rule) { r.Severity = "critical" }, nil},
		"окно больше":      {func(r *Rule) { r.SuppressMinutes = 120 }, []string{WeakSuppressIncreased}},
		"окно меньше":      {func(r *Rule) { r.SuppressMinutes = 0 }, nil},
		"убрана роль":      {func(r *Rule) { r.Recipients.Roles = []string{} }, []string{WeakRecipientRemoved}},
		"добавлен пользователь": {func(r *Rule) {
			r.Recipients.Users = []string{"01900000-0000-7000-8000-0000000000b1"}
		}, nil},
	} {
		next := base.clone()
		tc.mod(&next)
		if got := Weakening(&base, &next); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, ожидалось %v", name, got, tc.want)
		}
	}
	off := base.clone()
	off.Enabled = false
	next := off.clone()
	next.Condition.Filter = ""
	if got := Weakening(&off, &next); got != nil {
		t.Fatalf("выключенное правило: %v", got)
	}
}

// Изменение правила: версия, ослабление с повторной проверкой, правила
// безопасности не отключаются, изменение получателей порождает оповещение
// с группировкой по автору за 10 минут (ТЗ 5.6).
func TestUpdateRule(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	r, err := e.svc.CreateRule(ctx, e.admin, RuleInput{Kind: KindThreshold, Name: "Утечка ПДн",
		Condition: Condition{Filter: `threat = "DM-09"`}, GroupBy: []string{"app"}})
	if err != nil || r.Version != 1 || r.CreatedBy != "user:"+e.admin.UserID {
		t.Fatalf("создание: %+v %v", r, err)
	}
	in := RuleInput{Name: r.Name, Condition: r.Condition, GroupBy: r.GroupBy, Severity: r.Severity, Version: r.Version,
		Enabled: ptr(false)}
	// Ослабление без повторной проверки — отказ.
	noConfirm := e.admin
	noConfirm.Confirm = nil
	if _, err := e.svc.UpdateRule(ctx, noConfirm, r.ID, in); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("ослабление без проверки: %v", err)
	}
	failed := e.admin
	errReauth := errors.New("неверный пароль")
	failed.Confirm = func(context.Context) error { return errReauth }
	if _, err := e.svc.UpdateRule(ctx, failed, r.ID, in); !errors.Is(err, errReauth) {
		t.Fatalf("неверная проверка: %v", err)
	}
	got, err := e.svc.UpdateRule(ctx, e.admin, r.ID, in)
	if err != nil || got.Enabled || got.Version != 2 {
		t.Fatalf("выключение: %+v %v", got, err)
	}
	last := lastRecord(t, e.mem, "alert_rule.update")
	d := last.Details.(map[string]any)
	if d["weakening"] != true || !slices.Equal(d["weakening_reasons"].([]string), []string{WeakDisabled}) || d["recipients_changed"] != false {
		t.Fatalf("аудит ослабления: %+v", d)
	}
	// Устаревшая версия — конфликт; без изменений — без записи.
	if _, err := e.svc.UpdateRule(ctx, e.admin, r.ID, in); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("версия: %v", err)
	}
	in.Version = 2
	before := len(e.mem.Records())
	if got, err := e.svc.UpdateRule(ctx, e.admin, r.ID, in); err != nil || got.Version != 2 || len(e.mem.Records()) != before {
		t.Fatalf("без изменений: %+v %v", got, err)
	}
	// Правило безопасности: отключить нельзя, получателей менять можно.
	sec := e.rule(t, BuiltinRecipientsChanged)
	if _, err := e.svc.UpdateRule(ctx, e.admin, sec.ID, RuleInput{Enabled: ptr(false), Version: sec.Version}); !errors.Is(err, ErrLocked) {
		t.Fatalf("отключение правила безопасности: %v", err)
	}
	if _, err := e.svc.UpdateRule(ctx, e.admin, sec.ID, RuleInput{Severity: "low", Version: sec.Version}); !errors.Is(err, ErrLocked) {
		t.Fatalf("серьёзность правила безопасности: %v", err)
	}
	upd, err := e.svc.UpdateRule(ctx, e.admin, sec.ID, RuleInput{Name: sec.Name, Version: sec.Version,
		Recipients: Recipients{Roles: []string{"analyst"}}})
	if err != nil || !upd.Enabled || !slices.Equal(upd.Recipients.Roles, []string{"analyst"}) {
		t.Fatalf("получатели правила безопасности: %+v %v", upd, err)
	}
	// Изменение получателей двух правил одним пользователем за 10 минут — одно
	// оповещение со списком; через 10 минут — второе.
	in.Recipients = Recipients{Users: []string{"01900000-0000-7000-8000-0000000000c1"}}
	if _, err := e.svc.UpdateRule(ctx, e.admin, r.ID, in); err != nil {
		t.Fatal(err)
	}
	alerts := e.alerts(t, BuiltinRecipientsChanged)
	if len(alerts) != 1 || alerts[0].Count != 2 || alerts[0].Severity != "high" || alerts[0].Kind != KindSecurity ||
		len(alerts[0].Details["items"].([]any)) != 2 || alerts[0].Title != "Изменены получатели оповещений — admin" {
		t.Fatalf("оповещение об изменении получателей: %+v", alerts)
	}
	e.clock.t = e.clock.t.Add(11 * time.Minute)
	in.Version = 3
	in.Recipients = Recipients{}
	if _, err := e.svc.UpdateRule(ctx, e.admin, r.ID, in); err != nil {
		t.Fatal(err)
	}
	if alerts := e.alerts(t, BuiltinRecipientsChanged); len(alerts) != 2 {
		t.Fatalf("после окна группировки: %+v", alerts)
	}
	// Подробности не содержат ничего, кроме правил и получателей.
	if b, err := json.Marshal(alerts[0].Details); err != nil || strings.Contains(string(b), "password") {
		t.Fatalf("подробности: %s %v", b, err)
	}
	// Предел числа правил.
	for range MaxRules - 1 {
		if _, err := e.svc.CreateRule(ctx, e.admin, RuleInput{Kind: KindNew, Name: "n", Condition: Condition{Field: "app"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.CreateRule(ctx, e.admin, RuleInput{Kind: KindNew, Name: "n", Condition: Condition{Field: "app"}}); !errors.Is(err, ErrTooMany) {
		t.Fatalf("предел правил: %v", err)
	}
}

func lastRecord(t *testing.T, m *Memory, action string) audit.Entry {
	t.Helper()
	var last audit.Entry
	found := false
	for _, r := range m.Records() {
		if r.Action == action {
			last, found = r, true
		}
	}
	if !found {
		t.Fatalf("нет записи %s", action)
	}
	return last
}

// Получатели проверяются по существующим ролям и пользователям.
func TestRecipientsChecked(t *testing.T) {
	e := newEnv(t)
	e.svc.roleCheck = func(_ context.Context, id string) error {
		if id != "analyst" {
			return ErrNotFound
		}
		return nil
	}
	e.svc.userCheck = func(context.Context, string) error { return ErrNotFound }
	_, err := e.svc.CreateRule(context.Background(), e.admin, RuleInput{Kind: KindNew, Name: "x", Condition: Condition{Field: "model"},
		Recipients: Recipients{Roles: []string{"ghost_role"}, Users: []string{"01900000-0000-7000-8000-0000000000c1"}}})
	if !isInput(err) || !strings.Contains(err.Error(), "ghost_role") || !strings.Contains(err.Error(), "не найден") {
		t.Fatalf("получатели: %v", err)
	}
}
