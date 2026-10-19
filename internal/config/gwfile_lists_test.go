package config

import (
	"strings"
	"testing"
)

// Разделы lists и quotas приложения (задача 1.18, DM-15, DM-35, DM-36).
const listsYAML = `    quotas:
      requests_per_minute: 600
      requests_per_minute_per_user: 20
      requests_per_minute_per_key: 300
      tokens_per_minute: 100000
      tokens_per_day: 1000000
      max_input_bytes: 200000
      max_messages: 64
      max_tokens: 4096
    lists:
      - id: topics
        category: topic
        threat: DM-35
        score: 0.8
        direction: input
        words: ["взрывчат*", "как взломать"]
      - id: codenames
        threat: DM-32
        words: ["проект Орион"]
        regex: ['\bORN-\d{4}\b']
`

func withLists(t *testing.T, repl string) string {
	t.Helper()
	base := readFixture(t)
	a := strings.Index(base, "    quotas:")
	b := strings.Index(base, "    keys:")
	if a < 0 || b < a {
		t.Fatal("фикстура без quotas")
	}
	return base[:a] + repl + base[b:]
}

func TestParseListsAndQuotas(t *testing.T) {
	f, err := ParseGatewayFile(strings.NewReader(withLists(t, listsYAML)))
	if err != nil {
		t.Fatal(err)
	}
	a := f.Applications[0]
	if a.Quotas.RequestsPerMinutePerKey != 300 || a.Quotas.MaxInputBytes != 200000 || a.Quotas.TokensPerMinute != 100000 {
		t.Fatalf("квоты: %+v", a.Quotas)
	}
	if len(a.Lists) != 2 || a.Lists[0].Score != 0.8 || a.Lists[1].Regex[0] != `\bORN-\d{4}\b` || len(a.Lists[0].Words) != 2 {
		t.Fatalf("списки: %+v", a.Lists)
	}
}

// Ошибки в правилах заказчика находятся при загрузке файла, а не при первом
// запросе; неизвестные поля — ошибка.
func TestParseListsErrors(t *testing.T) {
	for name, c := range map[string][2]string{
		"неизвестное поле списка": {"        threat: DM-35\n", "        threat: DM-35\n        action: block\n"},
		"threat не из DM-35":      {"threat: DM-35", "threat: DM-01"},
		"выражение не RE2":        {`'\bORN-\d{4}\b'`, `'(a)\1'`},
		"пустое совпадение":       {`'\bORN-\d{4}\b'`, `'a*'`},
		"дубль списка":            {"id: codenames", "id: topics"},
		"слово без букв":          {`"как взломать"`, `"!!!"`},
		"звёздочка в середине":    {`"взрывчат*"`, `"взр*ывчат"`},
		"квота ниже нуля":         {"max_input_bytes: 200000", "max_input_bytes: -1"},
		"квота на ключ":           {"requests_per_minute_per_key: 300", "requests_per_minute_per_key: 2000000000"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(listsYAML, c[0]) {
				t.Fatalf("образец не содержит %q", c[0])
			}
			if _, err := ParseGatewayFile(strings.NewReader(withLists(t, strings.Replace(listsYAML, c[0], c[1], 1)))); err == nil {
				t.Fatal("конфигурация принята")
			}
		})
	}
}
