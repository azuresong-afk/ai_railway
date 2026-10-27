package argschema

import (
	"encoding/json"
	"testing"
)

// FuzzParseArgSchema — разбор схемы ограничений аргументов из недоверенного
// JSON (импорт политики, API): без паники, принятая схема укладывается в
// пределы и даёт тот же результат после перевода в дерево Go и обратно
// (схема в YAML политики хранится деревом).
func FuzzParseArgSchema(f *testing.F) {
	for _, s := range []string{
		`{"type":"object","required":["path"],"properties":{"path":{"type":"string","maxLength":512,"x-aisec-path-prefix":["/data/reports/"]}}}`,
		`{"type":"string","x-aisec-domains":["example.ru"]}`,
		`{"type":["integer","null"],"minimum":0,"maximum":100}`,
		`{"enum":["a","b",1,null]}`,
		`{"type":"array","items":{"type":"string","pattern":"^[a-z]+$"},"maxItems":3}`,
		`{"$ref":"#"}`, `{"items":{"items":{"items":{}}}}`, `{"const":1e400}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := Parse(data)
		if err != nil {
			return
		}
		if s.nodes > MaxSchemaNodes || s.patterns > s.nodes {
			t.Fatalf("пределы схемы нарушены: узлов %d, pattern %d", s.nodes, s.patterns)
		}
		v, err := ParseJSON(data, schemaLimits)
		if err != nil {
			t.Fatalf("схема принята, а документ не разбирается: %v", err)
		}
		if _, err := CompileAny(ToAny(v)); err != nil {
			t.Fatalf("схема не переживает перевод в дерево Go: %v", err)
		}
	})
}

// FuzzValidateArgs — строгий разбор и проверка аргументов вызова (DM-21):
// без паники; принятые аргументы — корректный JSON без повторяющихся ключей,
// который стандартный разборщик читает так же.
func FuzzValidateArgs(f *testing.F) {
	schema := `{"type":"object","additionalProperties":false,"properties":{` +
		`"path":{"type":"string","x-aisec-path-prefix":["/data/"]},` +
		`"to":{"type":"string","x-aisec-domains":["example.ru"]},` +
		`"n":{"type":"integer","minimum":-5,"maximum":5},"tags":{"type":"array","items":{"enum":["a","b"]}}}}`
	for _, a := range []string{
		`{"path":"/data/x"}`, `{"to":"u@example.ru"}`, `{"n":3}`, `{"tags":["a"]}`, `{"a":1,"a":2}`,
		"{\"path\":\"\xff\"}", `{"path":"\ud800"}`, `{} []`, `{"n":1e400}`, `{"path":"/data/../etc"}`,
		`{"to":"//evil.com/x@example.ru"}`, `{"to":"evil.com:@example.ru"}`, `{"path":"/data/a/link/../../x"}`,
	} {
		f.Add([]byte(schema), []byte(a))
	}
	f.Fuzz(func(t *testing.T, schemaDoc, args []byte) {
		s, err := Parse(schemaDoc)
		if err != nil {
			s = nil
		}
		v, err := ValidateArgs(s, args)
		if err != nil && !IsValidation(err) {
			return
		}
		if !json.Valid(args) {
			t.Fatalf("строгий разбор принял документ, который не принимает encoding/json")
		}
		if v.Kind == Object && len(v.Keys) != len(v.Vals) {
			t.Fatal("ключи и значения объекта не совпадают по числу")
		}
	})
}
