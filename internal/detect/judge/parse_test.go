package judge

import (
	"errors"
	"strings"
	"testing"
)

var parseRules = []Criterion{{Rule: "a", Kind: KindBusiness, Text: "правило а"}, {Rule: "b", Kind: KindContent, Text: "правило б"}}

func TestParseVerdicts(t *testing.T) {
	ok := `  {"verdicts":[{"rule":"b","violated":true,"confidence":1},{"rule":"a","violated":false,"confidence":0}]}` + "\n"
	vs, err := ParseVerdicts([]byte(ok), parseRules)
	if err != nil || len(vs) != 2 || vs[0].Rule != "a" || vs[1].Rule != "b" || !vs[1].Violated || vs[1].Confidence != 1 {
		t.Fatalf("разбор: %+v, %v", vs, err)
	}
	bad := map[string]string{
		"пусто":            "",
		"массив":           `[{"rule":"a","violated":true,"confidence":1}]`,
		"лишнее после":     `{"verdicts":[{"rule":"a","violated":true,"confidence":1},{"rule":"b","violated":true,"confidence":1}]} {}`,
		"неизвестное поле": `{"verdicts":[{"rule":"a","violated":true,"confidence":1,"why":"x"},{"rule":"b","violated":true,"confidence":1}]}`,
		"поле верхнего уровня": `{"verdicts":[{"rule":"a","violated":true,"confidence":1},{"rule":"b","violated":true,"confidence":1}],` +
			`"note":"x"}`,
		"меньше вердиктов": `{"verdicts":[{"rule":"a","violated":true,"confidence":1}]}`,
		"повтор":           `{"verdicts":[{"rule":"a","violated":true,"confidence":1},{"rule":"a","violated":true,"confidence":1}]}`,
		"чужое правило":    `{"verdicts":[{"rule":"a","violated":true,"confidence":1},{"rule":"c","violated":true,"confidence":1}]}`,
		"нет violated":     `{"verdicts":[{"rule":"a","confidence":1},{"rule":"b","violated":true,"confidence":1}]}`,
		"нет confidence":   `{"verdicts":[{"rule":"a","violated":true},{"rule":"b","violated":true,"confidence":1}]}`,
		"confidence > 1":   `{"verdicts":[{"rule":"a","violated":true,"confidence":1.5},{"rule":"b","violated":true,"confidence":1}]}`,
		"confidence < 0":   `{"verdicts":[{"rule":"a","violated":true,"confidence":-0.1},{"rule":"b","violated":true,"confidence":1}]}`,
		"строка вместо bool": `{"verdicts":[{"rule":"a","violated":"true","confidence":1},` +
			`{"rule":"b","violated":true,"confidence":1}]}`,
		"не UTF-8": "{\"verdicts\":[{\"rule\":\"\xff\",\"violated\":true,\"confidence\":1}]}",
	}
	for name, s := range bad {
		if _, err := ParseVerdicts([]byte(s), parseRules); err == nil {
			t.Errorf("%s: принят ответ %q", name, s)
		}
	}
	big := `{"verdicts":[]}` + strings.Repeat(" ", MaxReply)
	if _, err := ParseVerdicts([]byte(big), nil); !errors.Is(err, ErrReplyTooLarge) {
		t.Fatalf("ответ сверх предела: %v", err)
	}
}

// FuzzParseVerdicts — разбор ответа оценщика (недоверенный ввод, ADR-0030,
// раздел 5): без паники; принятый ответ — ровно по вердикту на правило в
// порядке правил, уверенность в 0–1.
func FuzzParseVerdicts(f *testing.F) {
	f.Add([]byte(`{"verdicts":[{"rule":"a","violated":true,"confidence":0.9},{"rule":"b","violated":false,"confidence":0.1}]}`))
	f.Add([]byte(`{"verdicts":[{"rule":"a","violated":true,"confidence":1e-3},{"rule":"b","violated":false,"confidence":0}]} `))
	f.Add([]byte(`{"verdicts":null}`))
	f.Add([]byte(`{"VERDICTS":[{"RULE":"a","violated":true,"confidence":1}]}`))
	f.Add([]byte(`{"verdicts":[{"rule":"a","violated":true,"confidence":1,"rule":"b"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		vs, err := ParseVerdicts(data, parseRules)
		if err != nil {
			return
		}
		if len(data) > MaxReply || len(vs) != len(parseRules) {
			t.Fatalf("принят ответ: %d байт, %d вердиктов", len(data), len(vs))
		}
		for i, v := range vs {
			if v.Rule != parseRules[i].Rule || v.Confidence < 0 || v.Confidence > 1 {
				t.Fatalf("вердикт %d: %+v", i, v)
			}
		}
	})
}
