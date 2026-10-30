package alerting

import (
	"errors"
	"fmt"
	"slices"
)

// CheckStoredRule проверяет сохранённое правило оповещений правилами API.
// Правило администратора (builtinKey пустой) — как при создании
// (ParseRuleInput). Встроенное: ключ известен этому выпуску и вид — тот
// же; у системных правил и правил безопасности условие и группировка —
// как у встроенного правила (через API у них меняются только получатели),
// получатели — по правилам API; у остальных — как при изменении через API,
// поле правила «новое» — то же, что у встроенного. Существование ролей и
// пользователей проверяет вызывающий. Ошибка — *InputError. Вызывает
// восстановление копии конфигурации до записи в БД (остаток 5.8, остатки
// волны A этапа 5).
func CheckStoredRule(builtinKey string, in RuleInput) error {
	// Правило «новое» хранит ключ группировки — поле условия; через API
	// группировка у него не задаётся.
	if in.Kind == KindNew && slices.Equal(in.GroupBy, []string{in.Condition.Field}) {
		in.GroupBy = nil
	}
	if builtinKey == "" {
		_, err := ParseRuleInput(in, "")
		return err
	}
	rules := builtinRules()
	i := slices.IndexFunc(rules, func(r Rule) bool { return r.BuiltinKey == builtinKey })
	if i < 0 {
		return &InputError{Errs: []error{fmt.Errorf("builtin_key: встроенного правила %q в этом выпуске нет", short(builtinKey))}}
	}
	b := rules[i]
	if in.Kind != b.Kind {
		return &InputError{Errs: []error{fmt.Errorf("kind: у встроенного правила %s вид %s", b.BuiltinKey, b.Kind)}}
	}
	if Locked(b.Kind) {
		_, errs := parseRecipients(in.Recipients)
		if in.Condition != b.Condition || !slices.Equal(in.GroupBy, b.GroupBy) {
			errs = append(errs, errors.New("condition: у системных правил и правил безопасности условие и группировку задаёт сервер"))
		}
		if len(errs) > 0 {
			return &InputError{Errs: errs}
		}
		return nil
	}
	r, err := ParseRuleInput(in, b.Kind)
	if err != nil {
		return err
	}
	if r.Condition.Field != b.Condition.Field {
		return &InputError{Errs: []error{errors.New("condition.field: у встроенного правила поле не меняется")}}
	}
	return nil
}
