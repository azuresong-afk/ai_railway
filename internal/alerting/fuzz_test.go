package alerting

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

// Разбор правила из тела запроса (ADR-0020, п. 10): строгий JSON, затем
// ParseRuleInput. Без паники; принятое правило — в канонической форме:
// повторный разбор его же полей даёт то же правило.
func FuzzParseRuleInput(f *testing.F) {
	for _, s := range []string{
		`{"kind":"threshold","name":"Инъекции","condition":{"filter":"threat = \"DM-01\" and action = \"block\""},"group_by":["app"]}`,
		`{"kind":"new","name":"Новая модель","condition":{"field":"model","min_severity":"high"}}`,
		`{"kind":"threshold","name":"x","condition":{"min_severity":"critical"},"suppress_minutes":0,"recipients":{"roles":["analyst"],"users":["01900000-0000-7000-8000-0000000000b1"]}}`,
		`{"kind":"threshold","name":"x","condition":{"filter":"app in (\"a\", \"b\") and stream = true"},"enabled":false,"severity":"low"}`,
		`{"kind":"new","name":"","condition":{"field":"threat"}}`,
		`{"kind":"anomaly"}`,
		`{"kind":"threshold","name":"x","condition":{"filter":"app = \"\\\"\""}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxRuleBody {
			return
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		var in RuleInput
		if err := dec.Decode(&in); err != nil {
			return
		}
		r, err := ParseRuleInput(in, "")
		if err != nil {
			if !isInput(err) {
				t.Fatalf("ошибка не ввода: %v", err)
			}
			return
		}
		again, err := ParseRuleInput(RuleInput{Kind: r.Kind, Name: r.Name, Description: r.Description, Enabled: &r.Enabled,
			Severity: r.Severity, Condition: r.Condition, GroupBy: groupInput(&r), SuppressMinutes: &r.SuppressMinutes,
			Recipients: r.Recipients}, r.Kind)
		if err != nil {
			t.Fatalf("каноническое правило не разбирается: %+v: %v", r, err)
		}
		if !sameSettings(&r, &again) || !again.Recipients.equal(r.Recipients) || r.Kind != again.Kind {
			t.Fatalf("разбор не идемпотентен:\n%+v\n%+v", r, again)
		}
		if severityRank(r.Severity) == 0 || len(r.GroupBy) > MaxGroupBy || r.SuppressMinutes < 0 || r.SuppressMinutes > MaxSuppressMinutes {
			t.Fatalf("правило вне пределов: %+v", r)
		}
		if _, err := compile(r); err != nil {
			t.Fatalf("правило не компилируется: %v", err)
		}
		if b, err := json.Marshal(r.Condition); err != nil || len(b) > 8192 {
			t.Fatalf("условие больше ограничения БД: %d %v", len(b), err)
		}
	})
}

// groupInput — группировка в виде запроса: у «нового» она задаётся полем.
func groupInput(r *Rule) []string {
	if r.Kind == KindNew {
		return nil
	}
	return slices.Clone(r.GroupBy)
}
