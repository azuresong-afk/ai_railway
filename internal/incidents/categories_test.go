package incidents_test

import (
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/incidents"
)

// ТЗ 5.7, 5.16: каждая строка матрицы обнаружения относится ровно к одной
// категории, и колонка «Категория инцидента» в docs/taxonomy.md совпадает
// со справочником в коде.
func TestTaxonomyIncidentCategories(t *testing.T) {
	spec, err := os.ReadFile("../../docs/SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`(?m)^\| (DM-\d{2}) \|`).FindAllStringSubmatch(string(spec), -1)
	if len(rows) < 50 {
		t.Fatalf("строк матрицы в ТЗ: %d", len(rows))
	}
	tax, err := os.ReadFile("../../docs/taxonomy.md")
	if err != nil {
		t.Fatal(err)
	}
	inDoc := map[string]string{}
	for _, m := range regexp.MustCompile("(?m)^\\| (DM-\\d{2}) \\|.*\\(`([a-z_]+)`\\) \\|$").FindAllStringSubmatch(string(tax), -1) {
		inDoc[m[1]] = m[2]
	}
	for _, r := range rows {
		id := r[1]
		got := incidents.CategoryOfRow(id)
		c, _ := incidents.LookupCategory(got)
		if !slices.Contains(c.Rows, id) {
			t.Errorf("%s: нет в справочнике категорий", id)
		}
		if inDoc[id] != got {
			t.Errorf("%s: в docs/taxonomy.md %q, в коде %q", id, inDoc[id], got)
		}
	}
	for _, c := range incidents.Categories() {
		if c.Title == "" || c.Instructions == "" || utf8.RuneCountInString(c.Instructions) > incidents.MaxInstructions {
			t.Errorf("категория %s: название или инструкция", c.ID)
		}
	}
}

// Категория инцидента из оповещения: по признаку правила, по строке
// матрицы в условии, по виду правила.
func TestCategoryOfAlert(t *testing.T) {
	for _, tc := range []struct {
		rule alerting.Rule
		want string
	}{
		{alerting.Rule{BuiltinKey: alerting.BuiltinCanaryLeak, Kind: alerting.KindThreshold}, incidents.CategorySystemPromptLeak},
		{alerting.Rule{Kind: alerting.KindThreshold, Condition: alerting.Condition{Filter: `threat = "DM-01" and action = "block"`}}, incidents.CategoryPromptInjection},
		{alerting.Rule{Kind: alerting.KindThreshold, Condition: alerting.Condition{Filter: `threat in ("DM-31", "DM-09")`}}, incidents.CategoryPIILeak},
		{alerting.Rule{Kind: alerting.KindThreshold, Condition: alerting.Condition{Filter: `threat != "DM-01"`}}, incidents.CategoryOther},
		{alerting.Rule{Kind: alerting.KindSecurity}, incidents.CategoryPlatformAccess},
		{alerting.Rule{Kind: alerting.KindNew, Condition: alerting.Condition{Field: "model"}}, incidents.CategoryOther},
		{alerting.Rule{Kind: alerting.KindThreshold, Condition: alerting.Condition{Filter: "битый (("}}, incidents.CategoryOther},
	} {
		if got := incidents.CategoryOfAlert(tc.rule); got != tc.want {
			t.Errorf("%+v: %s, ожидалось %s", tc.rule, got, tc.want)
		}
	}
}

// Фильтры списка: значения из перечней, каждый параметр не больше раза.
func TestParseQuery(t *testing.T) {
	q, err := incidents.ParseQuery(url.Values{"status": {"open"}, "severity": {"high"}, "category": {"pii_leak"},
		"assignee_id": {"01900000-0000-7000-8000-0000000000b1"}, "source": {"auto"}, "limit": {"10"}})
	if err != nil || q.Status != "open" || q.Severity != "high" || q.Category != "pii_leak" || q.Source != "auto" {
		t.Fatalf("%+v %v", q, err)
	}
	for _, v := range []url.Values{
		{"status": {"reopened"}}, {"status": {"new", "closed"}}, {"severity": {"urgent"}}, {"category": {"phishing"}},
		{"assignee_id": {"me"}}, {"source": {"api"}}, {"status": {""}},
	} {
		if _, err := incidents.ParseQuery(v); err == nil {
			t.Errorf("%v: ожидалась ошибка", v)
		}
	}
}

// Разбор фильтров не паникует, а принятый фильтр состоит из допустимых значений.
func FuzzParseQuery(f *testing.F) {
	for _, s := range []string{"status=open", "status=new&severity=high", "category=pii_leak&source=auto",
		"assignee_id=01900000-0000-7000-8000-0000000000b1", "status=%00", "status=new&status=closed", "x=1&limit=5"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		v, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		q, err := incidents.ParseQuery(v)
		if err != nil {
			return
		}
		if q.Status != "" && q.Status != incidents.StatusOpen && !slices.Contains(incidents.Statuses(), q.Status) {
			t.Fatalf("статус %q", q.Status)
		}
		if q.Category != "" {
			if _, ok := incidents.LookupCategory(q.Category); !ok {
				t.Fatalf("категория %q", q.Category)
			}
		}
		if q.Severity != "" && !slices.Contains(alerting.Severities(), q.Severity) {
			t.Fatalf("серьёзность %q", q.Severity)
		}
		if strings.ContainsAny(q.AssigneeID, "\x00 ") {
			t.Fatalf("ответственный %q", q.AssigneeID)
		}
	})
}

// Разбор тела смены статуса: принятое тело всегда задаёт допустимый
// статус, резолюция есть ровно при закрытии, комментарий в пределе.
func FuzzStatusInput(f *testing.F) {
	for _, s := range []string{`{"status":"closed","resolution":"resolved"}`, `{"status":"in_progress"}`,
		`{"status":"contained","comment":"Локализовано"}`, `{"status":"closed"}`, `{"status":"new"}`,
		`{"status":"in_progress","resolution":"risk_accepted"}`, `{"status":"closed","resolution":"false_positive","comment":"\u0000"}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var in incidents.StatusInput
		if json.Unmarshal(raw, &in) != nil {
			return
		}
		if incidents.ParseStatusInput(in) != nil {
			return
		}
		if !slices.Contains([]string{"in_progress", "contained", "closed"}, in.Status) {
			t.Fatalf("статус %q", in.Status)
		}
		if (in.Status == "closed") != (in.Resolution != "") || in.Resolution != "" && !slices.Contains(incidents.Resolutions(), in.Resolution) {
			t.Fatalf("резолюция %q при статусе %q", in.Resolution, in.Status)
		}
		if !utf8.ValidString(in.Comment) || utf8.RuneCountInString(in.Comment) > incidents.MaxResolutionComment ||
			strings.ContainsRune(in.Comment, 0) {
			t.Fatalf("комментарий %q", in.Comment)
		}
	})
}
