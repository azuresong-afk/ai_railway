package alerting

import (
	"errors"
	"strings"
	"testing"
)

// storedInput — правило в виде, в каком оно хранится и попадает в копию.
func storedInput(r Rule) RuleInput {
	return RuleInput{Kind: r.Kind, Name: r.Name, Description: r.Description, Enabled: ptr(r.Enabled), Severity: r.Severity,
		Condition: r.Condition, GroupBy: r.GroupBy, SuppressMinutes: ptr(r.SuppressMinutes), Recipients: r.Recipients}
}

// Каждое встроенное правило этого выпуска проходит проверку сохранённого
// правила; неизвестный ключ, чужой вид, изменённое условие правила
// безопасности и поле правила «новое» — отказ (остаток 5.8, остатки волны A
// этапа 5).
func TestCheckStoredRule(t *testing.T) {
	var locked, newTool Rule
	for _, r := range builtinRules() {
		if err := CheckStoredRule(r.BuiltinKey, storedInput(r)); err != nil {
			t.Errorf("%s: %v", r.BuiltinKey, err)
		}
		if Locked(r.Kind) && locked.BuiltinKey == "" {
			locked = r
		}
		if r.BuiltinKey == BuiltinToolNew {
			newTool = r
		}
	}
	if locked.BuiltinKey == "" || newTool.BuiltinKey == "" {
		t.Fatal("нет встроенных правил для проверки")
	}
	withRecipients := locked
	withRecipients.Recipients = Recipients{Roles: []string{"duty_analyst"}, Users: []string{}}
	if err := CheckStoredRule(locked.BuiltinKey, storedInput(withRecipients)); err != nil {
		t.Fatalf("получатели правила безопасности: %v", err)
	}
	if err := CheckStoredRule("", RuleInput{Kind: KindThreshold, Name: "Блокировки", Condition: Condition{MinSeverity: "high"},
		Recipients: Recipients{Roles: []string{}, Users: []string{}}}); err != nil {
		t.Fatalf("своё правило: %v", err)
	}
	// Своё правило «новое» хранится с ключом группировки — полем условия.
	if err := CheckStoredRule("", RuleInput{Kind: KindNew, Name: "Новые модели", Condition: Condition{Field: "model"},
		GroupBy: []string{"model"}, Recipients: Recipients{Roles: []string{}, Users: []string{}}}); err != nil {
		t.Fatalf("своё правило «новое»: %v", err)
	}
	changed := locked
	changed.Condition.Filter = `action = "allow"`
	field := newTool
	field.Condition.Field = "model"
	field.GroupBy = []string{"model"}
	for _, tc := range []struct {
		name, key, want string
		in              RuleInput
	}{
		{"неизвестный ключ", "threshold.removed", "builtin_key", storedInput(locked)},
		{"чужой вид", locked.BuiltinKey, "kind", func() RuleInput { in := storedInput(locked); in.Kind = KindThreshold; return in }()},
		{"условие правила безопасности", locked.BuiltinKey, "condition", storedInput(changed)},
		{"получатель не роль", locked.BuiltinKey, "recipients.roles",
			func() RuleInput {
				in := storedInput(locked)
				in.Recipients.Roles = []string{"Не роль"}
				return in
			}()},
		{"поле правила «новое»", newTool.BuiltinKey, "condition.field", storedInput(field)},
		{"своё правило без условия", "", "condition", RuleInput{Kind: KindThreshold, Name: "Всё"}},
	} {
		err := CheckStoredRule(tc.key, tc.in)
		var ie *InputError
		if !errors.As(err, &ie) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
