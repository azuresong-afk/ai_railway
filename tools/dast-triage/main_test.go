package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const report = `{"site":[{"alerts":[
 {"pluginid":"10038","alert":"CSP Header Not Set","riskcode":"2","count":"3"},
 {"pluginid":"10049","alert":"Non-Storable Content","riskcode":"0","count":"1"},
 {"pluginid":"10021","alert":"X-Content-Type-Options Missing","riskcode":"1","count":"2"}]}]}`

const rules = "# комментарий\n10021\tFAIL\t(X-Content-Type-Options)\n10049\tIGNORE\t(x)\nмусор\n"

func TestParseRules(t *testing.T) {
	r := ParseRules([]byte(rules))
	if r["10021"] != "FAIL" || r["10049"] != "IGNORE" || len(r) != 2 {
		t.Fatalf("%v", r)
	}
}

func TestCompare(t *testing.T) {
	alerts, err := ParseReport("console", []byte(report))
	if err != nil || len(alerts) != 3 {
		t.Fatalf("%v %v", alerts, err)
	}
	res := Compare(alerts, ParseRules([]byte(rules)), nil)
	if len(res.Problems) != 2 { // Medium и правило FAIL; 10049 игнорируется
		t.Fatalf("%v", res.Problems)
	}
	fp := func(id string) Entry {
		return Entry{Target: "console", PluginID: id, Alert: map[string]string{"10038": "CSP Header Not Set", "10021": "X-Content-Type-Options Missing"}[id], MaxRisk: 3, Verdict: FalsePositive, Justification: "обоснование не короче двадцати символов", Author: "a", Date: "2026-10-22"}
	}
	res = Compare(alerts, ParseRules([]byte(rules)), []Entry{fp("10038"), fp("10021"), fp("99999")})
	if len(res.Problems) != 0 || res.MarkedAbove != 2 || len(res.Stale) != 1 {
		t.Fatalf("%+v", res)
	}
	// accepted_risk выше порога не принимается.
	acc := fp("10038")
	acc.Verdict = AcceptedRisk
	if res = Compare(alerts, ParseRules([]byte(rules)), []Entry{acc, fp("10021")}); len(res.Problems) != 1 {
		t.Fatalf("%+v", res)
	}
	// Запись другой цели не покрывает находку.
	other := fp("10038")
	other.Target = "gateway"
	if res = Compare(alerts, ParseRules([]byte(rules)), []Entry{other, fp("10021")}); len(res.Problems) != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestEmptyReportFails(t *testing.T) {
	for _, bad := range []string{`{}`, `{"site":[]}`} {
		if _, err := ParseReport("t", []byte(bad)); err == nil {
			t.Errorf("%s: пустой отчёт не должен проходить", bad)
		}
	}
}

func TestIgnoreDoesNotHideMedium(t *testing.T) {
	alerts, _ := ParseReport("console", []byte(report)) //nolint:gosec // G104: отчёт заведомо корректен
	res := Compare(alerts, map[string]string{"10038": "IGNORE", "10021": "FAIL"}, nil)
	if len(res.Problems) != 2 || len(res.Ignored) != 0 {
		t.Fatalf("Medium под IGNORE обязан требовать разметки: %+v", res)
	}
}

func TestEntryScope(t *testing.T) {
	alerts, _ := ParseReport("console", []byte(report)) //nolint:gosec // G104: отчёт заведомо корректен
	e := Entry{Target: "console", PluginID: "10038", Alert: "CSP Header Not Set", MaxRisk: 1, Verdict: FalsePositive, Justification: "обоснование не короче двадцати символов", Author: "a", Date: "2026-10-22"}
	res := Compare(alerts, map[string]string{}, []Entry{e})
	if len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "CSP") {
		t.Fatalf("риск выше max_risk не покрывается: %+v", res.Problems)
	}
	e.MaxRisk = 2
	e.Alert = "Другая находка"
	if res = Compare(alerts, map[string]string{}, []Entry{e}); len(res.Problems) != 1 {
		t.Fatalf("другое имя находки не покрывается: %+v", res.Problems)
	}
}

func TestParseReportInvalid(t *testing.T) {
	for _, bad := range []string{`{`, `{"site":[{"alerts":[{"pluginid":"1","alert":"x","riskcode":"9"}]}]}`, `{"site":[{"alerts":[{"alert":"x","riskcode":"1"}]}]}`} {
		if _, err := ParseReport("t", []byte(bad)); err == nil {
			t.Errorf("%s: ожидалась ошибка", bad)
		}
	}
}

func TestParseTriageInvalid(t *testing.T) {
	ok := "schema_version: 1\nentries:\n  - {target: console, plugin_id: '1', alert: a, max_risk: 3, verdict: false_positive, justification: обоснование не короче двадцати символов, author: a, date: 2026-10-22}\n"
	if _, err := ParseTriage([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"версия":      "schema_version: 2\n",
		"вердикт":     strings.Replace(ok, "false_positive", "ok", 1),
		"обоснование": strings.Replace(ok, "justification: обоснование не короче двадцати символов", "justification: коротко", 1),
		"поле":        ok + "    extra: 1\n",
		"повтор":      ok + strings.SplitN(ok, "\n", 3)[2],
		"цель":        strings.Replace(ok, "target: console", "target: consol", 1),
		"дата":        strings.Replace(ok, "date: 2026-10-22", "date: вчера", 1),
		"max_risk":    strings.Replace(ok, "max_risk: 3", "max_risk: 7", 1),
	} {
		if _, err := ParseTriage([]byte(bad)); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	w := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	r, rep := w("rules.conf", rules), w("console.json", report)
	empty := w("t.yaml", "schema_version: 1\nentries: []\n")
	var out, errb bytes.Buffer
	if err := run(r, empty, filepath.Join(dir, "o.md"), []string{"console=" + rep}, &out, &errb); err == nil {
		t.Fatal("ожидался провал: находки выше порога без разметки")
	}
	full := w("full.yaml", "schema_version: 1\nentries:\n"+
		"  - {target: console, plugin_id: '10038', alert: CSP Header Not Set, max_risk: 3, verdict: false_positive, justification: обоснование не короче двадцати символов, author: a, date: 2026-10-22}\n"+
		"  - {target: console, plugin_id: '10021', alert: X-Content-Type-Options Missing, max_risk: 3, verdict: false_positive, justification: обоснование не короче двадцати символов, author: a, date: 2026-10-22}\n")
	if err := run(r, full, "", []string{"console=" + rep}, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if err := run(r, full, "", nil, &out, &errb); err == nil {
		t.Fatal("без отчётов должна быть ошибка")
	}
	if err := run(r, full, "", []string{"console"}, &out, &errb); err == nil {
		t.Fatal("отчёт без цели должен отклоняться")
	}
}

func FuzzParseReport(f *testing.F) {
	f.Add([]byte(report))
	f.Add([]byte(`{"site":null}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseReport("t", b) }) //nolint:gosec // G104: проверяется только отсутствие паники
}

func FuzzParseTriage(f *testing.F) {
	f.Add([]byte("schema_version: 1\nentries: []\n"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseTriage(b) }) //nolint:gosec // G104: проверяется только отсутствие паники
}

func FuzzParseRules(f *testing.F) {
	f.Add([]byte(rules))
	f.Fuzz(func(t *testing.T, b []byte) { _ = ParseRules(b) })
}
