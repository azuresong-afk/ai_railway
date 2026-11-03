package api

import (
	"reflect"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Раздел judge и подраздел judge правила (ADR-0030) проходят через API без
// потерь: JSON → спецификация → JSON.
func TestPolicyJudgeJSONRoundTrip(t *testing.T) {
	s, err := policy.Parse(strings.NewReader(`id: support
name: Поддержка
version: 1
mode: enforce
judge: {provider: local-llm, model: qwen3-14b, max_calls_per_minute: 30}
rules:
  - id: no-refunds
    detector: judge.llm
    directions: [output]
    action: block
    severity: high
    judge: {kind: business, criterion: "Ассистент не обещает возврат денег.", mode: sync, timeout_ms: 3000, on_failure: block}
`))
	if err != nil {
		t.Fatal(err)
	}
	j := specJSON(s)
	if j.Judge == nil || j.Rules[0].Judge == nil || j.Rules[0].Judge.OnFailure != "block" {
		t.Fatalf("в JSON нет раздела judge: %+v", j)
	}
	back, err := j.spec(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	back.Version = s.Version
	back.Exceptions = s.Exceptions
	if !reflect.DeepEqual(back.Judge, s.Judge) || !reflect.DeepEqual(back.Rules[0].Judge, s.Rules[0].Judge) {
		t.Fatalf("раздел judge изменился: %+v %+v", back.Judge, back.Rules[0].Judge)
	}
}
