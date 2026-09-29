package main

import (
	"strings"
	"testing"
	"testing/fstest"
)

const sarifSample = `{"version":"2.1.0","runs":[{"results":[
 {"ruleId":"gosec","message":{"text":"G104: Errors unhandled"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a/b.go"},"region":{"startLine":2}}}]},
 {"ruleId":"errcheck","message":{"text":"Error return value"},
  "locations":[{"physicalLocation":{"artifactLocation":{"uri":"file://c.go"},"region":{"startLine":1}}}]}]}]}`

func TestParseSARIF(t *testing.T) {
	got, err := ParseSARIF([]byte(sarifSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Rule != "gosec/G104" || got[0].File != "a/b.go" || got[0].Line != 2 ||
		got[1].Rule != "errcheck" || got[1].File != "c.go" {
		t.Fatalf("неверный разбор: %+v", got)
	}
	empty, err := ParseSARIF([]byte(`{"version":"2.1.0","runs":[{"results":[]}]}`))
	if err != nil || len(empty) != 0 {
		t.Fatalf("пустой отчёт: %v %v", empty, err)
	}
}

func TestParseSARIFErrors(t *testing.T) {
	for _, doc := range []string{
		`не json`,
		`{"version":"2.0.0","runs":[]}`,
		`{"version":"2.1.0","runs":[{"results":[{"ruleId":"","locations":[]}]}]}`,
		`{"version":"2.1.0","runs":[{"results":[{"ruleId":"x","locations":[{"physicalLocation":{"artifactLocation":{"uri":""},"region":{"startLine":1}}}]}]}]}`,
		`{"version":"2.1.0","runs":[{"results":[{"ruleId":"x","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a"},"region":{"startLine":0}}}]}]}]}`,
	} {
		if _, err := ParseSARIF([]byte(doc)); err == nil {
			t.Errorf("ожидалась ошибка для %s", doc)
		}
	}
	if _, err := ParseSARIF(make([]byte, maxSARIF+1)); err == nil {
		t.Error("ожидалась ошибка размера")
	}
}

const triageSample = `schema_version: 1
entries:
  - rule: gosec/G104
    file: a/b.go
    snippet: "_ = f.Close()"
    verdict: false_positive
    justification: файл открыт только для чтения
    author: владелец
    date: 2026-09-29
`

func TestParseTriage(t *testing.T) {
	tr, err := ParseTriage([]byte(triageSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Entries) != 1 || tr.Entries[0].Verdict != FalsePositive {
		t.Fatalf("неверный разбор: %+v", tr)
	}
	for name, doc := range map[string]string{
		"версия":        strings.Replace(triageSample, "schema_version: 1", "schema_version: 3", 1),
		"вердикт":       strings.Replace(triageSample, "false_positive", "maybe", 1),
		"обоснование":   strings.Replace(triageSample, "    justification: файл открыт только для чтения\n", "", 1),
		"дата":          strings.Replace(triageSample, "2026-09-29", "вчера", 1),
		"лишнее поле":   triageSample + "extra: 1\n",
		"два документа": triageSample + "---\nschema_version: 1\n",
		"испорченный":   "schema_version: [",
	} {
		if _, err := ParseTriage([]byte(doc)); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestCompare(t *testing.T) {
	findings := []Finding{
		{Rule: "gosec/G104", File: "a/b.go", Line: 2, Snippet: "_ = f.Close()"},  // размечено
		{Rule: "gosec/G304", File: "a/b.go", Line: 3, Snippet: "os.ReadFile(p)"}, // не размечено
		{Rule: "gosec/G401", File: "c.go", Line: 1, Snippet: "md5.New()"},        // истинное
	}
	entries := []Entry{
		{Rule: "gosec/G104", File: "a/b.go", Snippet: "  _ = f.Close()  ", Verdict: FalsePositive},
		{Rule: "gosec/G401", File: "c.go", Snippet: "md5.New()", Verdict: TruePositive},
		{Rule: "gosec/G101", File: "d.go", Snippet: "x", Verdict: FalsePositive}, // устарело
	}
	problems, stale := Compare(findings, entries)
	joined := strings.Join(problems, "\n")
	if len(problems) != 2 || !strings.Contains(joined, "G304: не размечено") || !strings.Contains(joined, "G401: истинное") {
		t.Fatalf("неверные нарушения: %q", problems)
	}
	if len(stale) != 1 || !strings.Contains(stale[0], "gosec/G101") {
		t.Fatalf("неверные устаревшие записи: %q", stale)
	}
}

func TestSourceLineAndSuppressions(t *testing.T) {
	fsys := fstest.MapFS{
		"a/b.go": {Data: []byte("package a\n\n\tvar _ = 1  \n")},
		"a/s.go": {Data: []byte("package a\n\n// Упоминание //nolint:gosec в тексте не считается.\n" +
			"var x = 1 //nolint:gosec // обоснование\n" +
			"var y = \"//nolint:gosec\" //nolint:errcheck,gosec // два\n" +
			"var z = 3 //nolint:errcheck // не gosec\n")},
		"vendor/v/v.go":   {Data: []byte("package v //nolint:gosec\n")},
		"a/testdata/t.go": {Data: []byte("package t //nolint:gosec\n")},
		"README.md":       {Data: []byte("//nolint:gosec\n")},
	}
	if got := sourceLine(fsys, "a/b.go", 3); got != "var _ = 1" {
		t.Fatalf("sourceLine = %q", got)
	}
	if got := sourceLine(fsys, "a/b.go", 9); got != "" {
		t.Fatalf("строки нет, получено %q", got)
	}
	if got := sourceLine(fsys, "нет.go", 1); got != "" {
		t.Fatalf("файла нет, получено %q", got)
	}
	s, err := CollectSuppressions(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 || s[0].File != "a/s.go" || s[0].Line != 4 || s[1].Line != 5 {
		t.Fatalf("неверные подавления: %+v", s)
	}
}

func TestSuppressesGosec(t *testing.T) {
	cases := map[string]bool{
		"//nolint:gosec": true,
		"//nolint:gosec // обоснование":  true,
		"//nolint:errcheck,gosec // два": true,
		"//nolint // всё":                true,
		"//nolint":                       true,
		"//nolint:errcheck // нет":       false,
		"//nolint:gosecx":                false,
		"// nolint:gosec":                false,
		"// Упоминание //nolint:gosec":   false,
		"//nolintgosec":                  false,
	}
	for c, want := range cases {
		if got := suppressesGosec(c); got != want {
			t.Errorf("suppressesGosec(%q) = %v, ожидалось %v", c, got, want)
		}
	}
}

func TestCollectSuppressionsSyntaxError(t *testing.T) {
	if _, err := CollectSuppressions(fstest.MapFS{"a.go": {Data: []byte("package")}}); err == nil {
		t.Fatal("ожидалась ошибка разбора")
	}
}

func FuzzParseSARIF(f *testing.F) {
	f.Add([]byte(sarifSample))
	f.Add([]byte(`{"version":"2.1.0"}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseSARIF(data)
		if err != nil {
			return
		}
		for _, fd := range got {
			if fd.Rule == "" || fd.File == "" || fd.Line < 1 {
				t.Fatalf("принято некорректное срабатывание %+v", fd)
			}
		}
	})
}

func FuzzParseTriage(f *testing.F) {
	f.Add([]byte(triageSample))
	f.Add([]byte("schema_version: 1\nentries: []\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		tr, err := ParseTriage(data)
		if err != nil {
			return
		}
		for _, e := range tr.Entries {
			if e.Verdict != FalsePositive && e.Verdict != TruePositive {
				t.Fatalf("принят вердикт %q", e.Verdict)
			}
		}
	})
}
