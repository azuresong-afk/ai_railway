package argschema

import (
	"errors"
	"strings"
	"testing"
)

func mustParse(t *testing.T, schema string) *Schema {
	t.Helper()
	s, err := Parse([]byte(schema))
	if err != nil {
		t.Fatalf("схема %s: %v", schema, err)
	}
	return s
}

func TestParseJSONStrict(t *testing.T) {
	bad := map[string]string{
		"повтор ключа":           `{"a":1,"a":2}`,
		"повтор ключа вложенно":  `{"x":{"a":1,"a":1}}`,
		"неверный UTF-8":         "{\"a\":\"\xff\"}",
		"неверный UTF-8 в ключе": "{\"\xc3\":1}",
		"одиночный старший":      `{"a":"\ud800"}`,
		"одиночный младший":      `{"a":"\udc00"}`,
		"старший без младшего":   `{"a":"\ud800A"}`,
		"данные после":           `{} {}`,
		"мусор после":            `{}x`,
		"управляющий символ":     "\"a\x01\"",
		"незакрытая строка":      `"abc`,
		"ведущий ноль":           `012`,
		"точка без цифр":         `1.`,
		"огромный порядок":       `1e401`,
		"огромный отрицательный": `1e-401`,
		"NaN":             `NaN`,
		"висячая запятая": `[1,]`,
		"висячая запятая объекта": `{"a":1,}`,
		"одинарные кавычки":       `{'a':1}`,
		"пусто":                   ``,
		"только пробел":           `  `,
		"неверный escape":         `"\x"`,
	}
	for name, doc := range bad {
		if _, err := ParseJSON([]byte(doc), ArgsLimits); err == nil {
			t.Errorf("%s: разбор должен отвергнуть %q", name, doc)
		}
	}
	good := []string{`{}`, `[]`, `null`, `true`, `-0`, `1e400`, `0.5`, `"😀"`, ` {"a" : [1, 2.5, "x", null, false]} `}
	for _, doc := range good {
		if _, err := ParseJSON([]byte(doc), ArgsLimits); err != nil {
			t.Errorf("%q: %v", doc, err)
		}
	}
}

func TestParseJSONLimits(t *testing.T) {
	lim := Limits{MaxSize: 64, MaxDepth: 3, MaxValues: 5, MaxString: 4}
	cases := map[string]string{
		"размер":        `"` + strings.Repeat("a", 70) + `"`,
		"глубина":       `[[[[1]]]]`,
		"значения":      `[1,2,3,4,5]`,
		"строка":        `"abcde"`,
		"строка escape": `"aaaaa"`,
	}
	for name, doc := range cases {
		if _, err := ParseJSON([]byte(doc), lim); err == nil {
			t.Errorf("%s: предел не сработал для %q", name, doc)
		}
	}
	if _, err := ParseJSON([]byte(`[[[1]]]`), lim); err != nil {
		t.Errorf("глубина 3 допустима: %v", err)
	}
}

func TestSchemaUnknownKeywordIsError(t *testing.T) {
	for _, doc := range []string{
		`{"type":"string","formt":"email"}`,
		`{"$ref":"#/x"}`,
		`{"oneOf":[{"type":"string"}]}`,
		`{"properties":{"a":{"anyOf":[]}}}`,
		`{"type":"string","format":"email"}`,
		`{"patternProperties":{}}`,
		`{"if":{},"then":{}}`,
		`{"$schema":"https://json-schema.org/draft/2020-12/schema"}`,
		`{"unevaluatedProperties":false}`,
		`{"description":"скрытая инструкция"}`,
	} {
		_, err := Parse([]byte(doc))
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: ожидается ErrUnsupported, получено %v", doc, err)
		}
	}
}

func TestSchemaInvalid(t *testing.T) {
	for _, doc := range []string{
		`[]`, `"x"`,
		`{"type":"date"}`, `{"type":["string","string"]}`, `{"type":[]}`,
		`{"additionalProperties":{}}`,
		`{"minItems":-1}`, `{"maxLength":1.5}`, `{"minLength":3,"maxLength":2}`,
		`{"minimum":5,"maximum":1}`,
		`{"enum":[]}`, `{"enum":[[1]]}`, `{"enum":[1,1.0]}`,
		`{"const":{"a":1}}`,
		`{"pattern":"("}`, `{"pattern":""}`,
		`{"pattern":"` + strings.Repeat("a", MaxPatternLen+1) + `"}`,
		`{"pattern":"(a{1000}){1000}"}`,
		`{"x-aisec-path-prefix":["/data/"]}`,
		`{"type":["string","array"],"x-aisec-path-prefix":["/data/"]}`,
		`{"type":"string","x-aisec-path-prefix":["data/"]}`,
		`{"type":"string","x-aisec-path-prefix":["/data/../etc/"]}`,
		`{"type":"string","x-aisec-path-prefix":["/data//x/"]}`,
		`{"type":"string","x-aisec-path-prefix":["/da%2fta/"]}`,
		`{"type":"string","x-aisec-path-prefix":[]}`,
		`{"type":"string","x-aisec-domains":["Example.RU"]}`,
		`{"type":"string","x-aisec-domains":[".example.ru"]}`,
		`{"type":"string","x-aisec-domains":["пример.рф"]}`,
		`{"required":["a","a"]}`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("схема должна быть отвергнута: %s", doc)
		}
	}
}

func TestSchemaLimits(t *testing.T) {
	// Глубина: 9 вложенных items.
	deep := strings.Repeat(`{"items":`, MaxSchemaDepth) + `{}` + strings.Repeat(`}`, MaxSchemaDepth)
	if _, err := Parse([]byte(deep)); err == nil {
		t.Error("вложенность больше MaxSchemaDepth принята")
	}
	ok := strings.Repeat(`{"items":`, MaxSchemaDepth-1) + `{}` + strings.Repeat(`}`, MaxSchemaDepth-1)
	if _, err := Parse([]byte(ok)); err != nil {
		t.Errorf("вложенность MaxSchemaDepth отвергнута: %v", err)
	}
	// Узлы: 300 свойств.
	var b strings.Builder
	b.WriteString(`{"properties":{`)
	for i := range 300 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"p` + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + itoa(i) + `":{}`)
	}
	b.WriteString(`}}`)
	if _, err := Parse([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "узлов") {
		t.Errorf("больше MaxSchemaNodes узлов: %v", err)
	}
	// Размер.
	big := `{"enum":["` + strings.Repeat("a", MaxSchemaSize) + `"]}`
	if _, err := Parse([]byte(big)); err == nil {
		t.Error("схема больше MaxSchemaSize принята")
	}
	// Префиксы: 33 в одной схеме, разнесённые по свойствам.
	b.Reset()
	b.WriteString(`{"properties":{`)
	for i := range 3 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"p` + itoa(i) + `":{"type":"string","x-aisec-path-prefix":[`)
		for j := range 11 {
			if j > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`"/d` + itoa(i) + `/` + itoa(j) + `/"`)
		}
		b.WriteString(`]}`)
	}
	b.WriteString(`}}`)
	if _, err := Parse([]byte(b.String())); err == nil {
		t.Error("больше MaxPathPrefixes префиксов в схеме приняты")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for i > 0 {
		d = append([]byte{byte('0' + i%10)}, d...)
		i /= 10
	}
	return string(d)
}

func TestPathPrefix(t *testing.T) {
	s := mustParse(t, `{"type":"object","required":["path"],"properties":{"path":{"type":"string","maxLength":512,"x-aisec-path-prefix":["/data/reports/"]}}}`)
	allow := []string{`/data/reports/a.csv`, `/data/reports/2026/10/x`, `/data/reports`, `/data/reports/x/`}
	// Сегменты «..», «.» и «//» отвергаются и внутри каталога: ядро разрешает
	// «..» после символических ссылок иначе, чем лексическая нормализация.
	deny := []string{`/data/reports/./a`, `/data/reports/x/../y`, `/data/reports//a`, `/data/reports/a/..`,
		`/data/reports/link/../../x`,
		`/data/reports-old/a`, `/data/reports/../secret`, `/data/reports/../../etc/passwd`, `data/reports/a`,
		`/data/reports/%2e%2e/secret`, `/data/reports/..\\secret`, `\\data\\reports\\a`, `/data/reports/a\u0000b`,
		`/data/report`, `/etc/passwd`, ``, `/data/reports/\u0001`,
	}
	for _, p := range allow {
		if _, err := ValidateArgs(s, []byte(`{"path":"`+p+`"}`)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range deny {
		if _, err := ValidateArgs(s, []byte(`{"path":"`+p+`"}`)); err == nil {
			t.Errorf("путь %q пропущен", p)
		}
	}
	root := mustParse(t, `{"type":"string","x-aisec-path-prefix":["/"]}`)
	if err := root.Validate(Value{Kind: String, Str: "/any/path"}); err != nil {
		t.Errorf("корень: %v", err)
	}
	if err := root.Validate(Value{Kind: String, Str: "relative"}); err == nil {
		t.Error("относительный путь при префиксе / пропущен")
	}
	// Значение другого типа не обходит проверку: схема требует type: string.
	if _, err := ValidateArgs(s, []byte(`{"path":["/etc/passwd"]}`)); err == nil {
		t.Error("массив вместо пути пропущен")
	}
}

func TestDomains(t *testing.T) {
	s := mustParse(t, `{"type":"string","x-aisec-domains":["example.ru","corp.local"]}`)
	allow := []string{"user@example.ru", "a.b@mail.example.ru", "https://example.ru/x", "http://api.corp.local:8080/a?b=c",
		"USER@EXAMPLE.RU", "https://example.ru./"}
	deny := []string{"user@badexample.ru", "user@example.ru.evil.com", "https://evil.com/?example.ru",
		"https://example.ru@evil.com/", "https://evil.com\\@example.ru", "a@b@example.ru", "@example.ru",
		"example.ru", "ftp://example.ru/", "javascript:alert(1)", "user @example.ru", "https://exаmple.ru/", "",
		// Строки, которые инструмент прочтёт как URL другого узла.
		"//evil.com/x@example.ru", "evil.com/?q=@example.ru", "evil.com#@example.ru", "evil.com:@example.ru",
		"evil.com/@example.ru", "[::1]@example.ru", "a%2f@example.ru", ".a@example.ru", "a..b@example.ru"}
	for _, v := range allow {
		if err := s.Validate(Value{Kind: String, Str: v}); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	for _, v := range deny {
		if err := s.Validate(Value{Kind: String, Str: v}); err == nil {
			t.Errorf("адрес %q пропущен", v)
		}
	}
}

func TestRangesAndEnum(t *testing.T) {
	s := mustParse(t, `{"type":"object","additionalProperties":false,"properties":{
		"amount":{"type":"integer","minimum":1,"maximum":9007199254740993},
		"rate":{"type":"number","exclusiveMinimum":0,"exclusiveMaximum":1},
		"mode":{"enum":["read","list"]},
		"tags":{"type":"array","maxItems":2,"items":{"type":"string","pattern":"^[a-z]+$"}}}}`)
	ok := []string{`{"amount":9007199254740993}`, `{"amount":1.0}`, `{"rate":0.5}`, `{"mode":"read"}`, `{"tags":["a","b"]}`, `{}`}
	bad := []string{
		`{"amount":9007199254740994}`, // за пределом float64 различается точно
		`{"amount":0}`, `{"amount":1.5}`, `{"amount":"1"}`,
		`{"rate":0}`, `{"rate":1}`, `{"rate":1e400}`,
		`{"mode":"write"}`, `{"mode":["read"]}`,
		`{"tags":["a","b","c"]}`, `{"tags":["A"]}`,
		`{"other":1}`,
	}
	for _, doc := range ok {
		if _, err := ValidateArgs(s, []byte(doc)); err != nil {
			t.Errorf("%s: %v", doc, err)
		}
	}
	for _, doc := range bad {
		if _, err := ValidateArgs(s, []byte(doc)); err == nil {
			t.Errorf("аргументы %s пропущены", doc)
		}
	}
}

func TestValidationErrorHasNoValue(t *testing.T) {
	s := mustParse(t, `{"type":"object","properties":{"to":{"type":"string","x-aisec-domains":["example.ru"]}}}`)
	_, err := ValidateArgs(s, []byte(`{"to":"секрет@evil.com"}`))
	if err == nil || strings.Contains(err.Error(), "секрет") || strings.Contains(err.Error(), "evil") {
		t.Fatalf("сообщение об ошибке содержит значение аргумента: %v", err)
	}
	if !IsValidation(err) || !strings.Contains(err.Error(), "/to") {
		t.Errorf("ожидается путь /to: %v", err)
	}
	_, err = ValidateArgs(mustParse(t, `{"additionalProperties":false}`), []byte(`{"секретное_имя":1}`))
	if err == nil || strings.Contains(err.Error(), "секретное") {
		t.Errorf("имя лишнего свойства попало в сообщение: %v", err)
	}
}

func TestCompileAnyFromYAMLTree(t *testing.T) {
	s, err := CompileAny(map[string]any{"type": "object", "required": []any{"path"},
		"properties": map[string]any{"path": map[string]any{"type": "string", "maxLength": 512,
			"x-aisec-path-prefix": []any{"/data/reports/"}}, "n": map[string]any{"maximum": 2.5}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateArgs(s, []byte(`{"path":"/data/reports/x","n":2.5}`)); err != nil {
		t.Error(err)
	}
	if _, err := ValidateArgs(s, []byte(`{"path":"/data/reports/x","n":2.6}`)); err == nil {
		t.Error("2.6 > 2.5 пропущено")
	}
	if _, err := CompileAny(map[string]any{"maximum": map[any]any{1: 2}}); err == nil {
		t.Error("ключ не строкой принят")
	}
}

func TestToAnyRoundTrip(t *testing.T) {
	v, err := ParseJSON([]byte(`{"b":[1,2.5,"x",null,true],"a":{"c":-7}}`), ArgsLimits)
	if err != nil {
		t.Fatal(err)
	}
	back, err := FromAny(ToAny(v), ArgsLimits)
	if err != nil {
		t.Fatal(err)
	}
	if !Equal(v, back) {
		t.Error("ToAny и FromAny меняют значение")
	}
}

// Дробные границы из YAML и API (дерево Go с float64) сравниваются с
// введённым числом, а не с его двоичным приближением.
func TestFractionalBoundsExact(t *testing.T) {
	s, err := CompileAny(map[string]any{"type": "object", "properties": map[string]any{
		"amount": map[string]any{"type": "number", "maximum": 100.05},
		"rate":   map[string]any{"type": "number", "exclusiveMaximum": 0.1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateArgs(s, []byte(`{"amount":100.05}`)); err != nil {
		t.Errorf("100.05 при maximum 100.05: %v", err)
	}
	for _, a := range []string{`{"amount":100.0500000001}`, `{"rate":0.1}`, `{"rate":0.10000000000000000001}`} {
		if _, err := ValidateArgs(s, []byte(a)); err == nil {
			t.Errorf("%s пропущен", a)
		}
	}
	v, err := ParseJSON([]byte(`[100.05, 0.1, 7]`), ArgsLimits)
	if err != nil || !Exact(v, ArgsLimits) {
		t.Fatalf("точные числа: %v", err)
	}
	if v, err := ParseJSON([]byte(`[0.10000000000000000001]`), ArgsLimits); err != nil || Exact(v, ArgsLimits) {
		t.Fatalf("неточное в float64 число признано точным: %v", err)
	}
}
