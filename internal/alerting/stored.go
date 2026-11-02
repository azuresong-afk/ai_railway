package alerting

import (
	"errors"
	"fmt"
	"slices"
)

// ErrUnknownBuiltin — встроенного правила с ключом из копии в этом выпуске
// нет (правило сняли): восстановление пропускает его со строкой отчёта, а
// не отклоняет копию (5В1 ревью 5.r1 этапа 5).
var ErrUnknownBuiltin = errors.New("builtin_key: встроенного правила с этим ключом в этом выпуске нет")

// CheckStoredRule проверяет сохранённое правило оповещений правилами API.
// Правило администратора (builtinKey пустой) — как при создании
// (ParseRuleInput). Встроенное: ключ известен этому выпуску (иначе
// ErrUnknownBuiltin) и вид — тот же; у системных правил и правил
// безопасности проверяются только получатели — по правилам API, остальные
// поля восстановление берёт у встроенного правила этого выпуска
// (StoredBuiltin; через API у них меняются только получатели, 5В1 ревью
// 5.r1); у остальных — как при изменении через API, поле правила «новое» —
// то же, что у встроенного. Существование ролей и пользователей проверяет
// вызывающий. Ошибка, кроме ErrUnknownBuiltin, — *InputError. Вызывает
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
	b, ok := StoredBuiltin(builtinKey)
	if !ok {
		return ErrUnknownBuiltin
	}
	if in.Kind != b.Kind {
		return &InputError{Errs: []error{fmt.Errorf("kind: у встроенного правила %s вид %s", b.BuiltinKey, b.Kind)}}
	}
	if Locked(b.Kind) {
		if _, errs := parseRecipients(in.Recipients); len(errs) > 0 {
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

// StoredBuiltin — встроенное правило этого выпуска с ключом key (копия).
// Восстановление копии конфигурации берёт у системных правил и правил
// безопасности из копии только получателей, остальные поля — отсюда: иначе
// копия выключала бы их или меняла важность без возможности вернуть через
// API (5В1 ревью 5.r1 этапа 5).
func StoredBuiltin(key string) (Rule, bool) {
	rules := builtinRules()
	i := slices.IndexFunc(rules, func(r Rule) bool { return r.BuiltinKey == key })
	if i < 0 || key == "" {
		return Rule{}, false
	}
	return rules[i].clone(), true
}
