package events

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var eventsT0 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func TestCSVCell(t *testing.T) {
	for in, want := range map[string]string{
		"":             "",
		"crm":          "crm",
		"=1+2":         "'=1+2",
		"+7 999":       "'+7 999",
		"-5":           "'-5",
		"@SUM(A1)":     "'@SUM(A1)",
		"\tcmd":        "'\tcmd",
		"\rcmd":        "'\rcmd",
		"a=1":          "a=1",
		"'уже":         "'уже",
		"=HYPERLINK()": "'=HYPERLINK()",
		// После разделителя русской локали и других (В12 ревью 2.r3a).
		"x;=cmd|' /C calc'!A0": "x;'=cmd|' /C calc'!A0",
		"gpt;=1+2":             "gpt;'=1+2",
		"a,=1":                 "a,'=1",
		"a\n=1":                "a\n'=1",
		"a\t@x":                "a\t'@x",
		"a; \"=1\"":            "a; \"'=1\"",
		"a;-1;+2":              "a;'-1;'+2",
		"DM-05;DM-13":          "DM-05;DM-13",
		"2026-10-21T12:00:00Z": "2026-10-21T12:00:00Z",
		"a-b=c":                "a-b=c",
		// Полноширинные знаки формулы (ревью 4.r1, остаток).
		"\uff1d1+2":     "'\uff1d1+2",
		"\uff0b7":       "'\uff0b7",
		"a;\uff0d1":     "a;'\uff0d1",
		"\uff20SUM(A1)": "'\uff20SUM(A1)",
		"a\uff1d1":      "a\uff1d1",
		"\uff1e\uff0c":  "\uff1e\uff0c",
	} {
		if got := CSVCell(in); got != want {
			t.Errorf("%q → %q, ожидалось %q", in, got, want)
		}
	}
}

func exportRecord() *Record {
	return &Record{
		ID: "01900000-0000-7000-8000-000000000001", Time: eventsT0, ReceivedAt: eventsT0, GatewayID: "gw",
		Type: TypeGatewayRequest, App: `=cmd|' /C calc'!A0`, Env: "prod,\"кавычки\"\nстрока", Action: "-block",
		Storage: StorageFull, Threats: []string{"DM-05", "DM-13"}, HasContent: true,
		Details: &Details{Findings: []Finding{{Detector: "pii.inn"}}},
	}
}

func TestExportCSV(t *testing.T) {
	var buf bytes.Buffer
	ex, err := NewExporter(&buf, FormatCSV, DelimSemicolon)
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.Write(exportRecord()); err != nil {
		t.Fatal(err)
	}
	if err := ex.Close(); err != nil {
		t.Fatal(err)
	}
	body, ok := strings.CutPrefix(buf.String(), utf8BOM)
	if !ok {
		t.Fatal("нет BOM UTF-8")
	}
	cr := csv.NewReader(strings.NewReader(body))
	cr.Comma = DelimSemicolon
	rows, err := cr.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || len(rows[0]) != len(csvHeader) || len(rows[1]) != len(csvHeader) || ex.Rows() != 1 {
		t.Fatalf("строки %v", rows)
	}
	col := func(name string) string {
		for i, h := range rows[0] {
			if h == name {
				return rows[1][i]
			}
		}
		t.Fatalf("нет столбца %s", name)
		return ""
	}
	if col("app") != `'=cmd|' /C calc'!A0` || col("action") != "'-block" || col("env") != "prod,\"кавычки\"\nстрока" ||
		col("threats") != "DM-05;DM-13" || col("has_content") != "true" {
		t.Fatalf("ячейки %v", rows[1])
	}
	// В CSV нет столбцов содержимого и подробностей.
	for _, h := range rows[0] {
		if h == "content" || h == "request" || h == "response" || h == "details" {
			t.Fatalf("столбец %s в выгрузке", h)
		}
	}
}

// excelRuPieces режет строку файла так, как Excel в русской локали режет
// чужой CSV: по «;», «,», табуляции и переводам строк без учёта кавычек.
// Ведущие пробелы и кавычки куска Excel тоже отбрасывает.
func excelRuPieces(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(";,\t\r\n", r) }) {
		out = append(out, strings.TrimLeft(p, " \""))
	}
	return out
}

// Ни один кусок выгрузки после деления по любому разделителю не начинается с
// символа формулы (В12 ревью 2.r3a): значения model, app, env, rule задаёт
// клиент LLM-приложения.
func TestExportCSVRussianLocale(t *testing.T) {
	attacks := []string{`x;=cmd|' /C calc'!A0`, "gpt;=1+2", "a,=1", "a\n=1", `a; "=1"`, "a;\t+1", "a\r\n@SUM(1)", `";=1;"`, "=1", "-2;-3"}
	for _, a := range attacks {
		r := exportRecord()
		r.App, r.Env, r.Model, r.Rule = a, a, a, a
		var buf bytes.Buffer
		ex, err := NewExporter(&buf, FormatCSV, DelimSemicolon)
		if err != nil {
			t.Fatal(err)
		}
		if err := ex.Write(r); err != nil {
			t.Fatal(err)
		}
		if err := ex.Close(); err != nil {
			t.Fatal(err)
		}
		for _, p := range excelRuPieces(strings.TrimPrefix(buf.String(), utf8BOM)) {
			if p != "" && (strings.ContainsRune("=+-@", rune(p[0])) || fullwidthFormula(p)) {
				t.Fatalf("%q: кусок %q начинается с формулы", a, p)
			}
		}
		// Разбор по RFC 4180 возвращает значение с апострофами, без потерь
		// (encoding/csv заменяет \r\n внутри поля на \n).
		cr := csv.NewReader(strings.NewReader(strings.TrimPrefix(buf.String(), utf8BOM)))
		cr.Comma = DelimSemicolon
		rows, err := cr.ReadAll()
		if err != nil || len(rows) != 2 || rows[1][5] != strings.ReplaceAll(CSVCell(a), "\r\n", "\n") {
			t.Fatalf("%q: разбор %v %v", a, rows, err)
		}
	}
}

func FuzzCSVCell(f *testing.F) {
	for _, s := range []string{"", "=1", "a;=1", "a; \"@x", "\t-1", "обычный текст", "a;\uff1d1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := CSVCell(s)
		if strings.ReplaceAll(out, "'", "") != strings.ReplaceAll(s, "'", "") {
			t.Fatalf("CSVCell изменил не только апострофы: %q → %q", s, out)
		}
		for _, p := range excelRuPieces(out) {
			if p != "" && (strings.ContainsRune("=+-@", rune(p[0])) || fullwidthFormula(p)) {
				t.Fatalf("%q: кусок %q начинается с формулы", s, p)
			}
		}
	})
}

func TestExportJSON(t *testing.T) {
	for _, n := range []int{0, 1, 3} {
		var buf bytes.Buffer
		ex, err := NewExporter(&buf, FormatJSON, DelimSemicolon)
		if err != nil {
			t.Fatal(err)
		}
		for range n {
			if err := ex.Write(exportRecord()); err != nil {
				t.Fatal(err)
			}
		}
		if err := ex.Close(); err != nil {
			t.Fatal(err)
		}
		var out []map[string]any
		if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
			t.Fatalf("%d: не JSON: %v\n%s", n, err, buf.String())
		}
		if len(out) != n {
			t.Fatalf("записей %d", len(out))
		}
		if n > 0 {
			if _, ok := out[0]["details"]; !ok {
				t.Fatal("нет details в выгрузке JSON")
			}
			if strings.Contains(buf.String(), `"content"`) {
				t.Fatal("содержимое в выгрузке")
			}
		}
	}
	if _, err := NewExporter(&bytes.Buffer{}, "xml", DelimSemicolon); err == nil {
		t.Fatal("неизвестный формат принят")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("клиент ушёл") }

func TestExportWriteError(t *testing.T) {
	ex, err := NewExporter(failWriter{}, FormatCSV, DelimSemicolon)
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.Write(exportRecord()); err != nil {
		t.Fatal(err) // буфер ещё не сброшен
	}
	if err := ex.Close(); err == nil {
		t.Fatal("ошибка записи не возвращена")
	}
}

func TestQueryValidate(t *testing.T) {
	ok := Query{From: eventsT0, To: eventsT0.Add(MaxQueryRange)}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, q := range []Query{
		{}, {From: eventsT0}, {To: eventsT0}, {From: eventsT0, To: eventsT0},
		{From: eventsT0.Add(time.Hour), To: eventsT0},
		{From: eventsT0, To: eventsT0.Add(MaxQueryRange + time.Nanosecond)},
		{From: eventsT0, To: eventsT0.Add(time.Hour), Limit: -1},
	} {
		if err := q.Validate(); err == nil {
			t.Errorf("принят %+v", q)
		}
	}
}

func TestRetentionValidate(t *testing.T) {
	for _, r := range []Retention{{MetadataDays: 30, ContentDays: 7}, {MetadataDays: 3650, ContentDays: 3650}, {MetadataDays: 365, ContentDays: 90}} {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	for _, r := range []Retention{{MetadataDays: 29, ContentDays: 7}, {MetadataDays: 30, ContentDays: 6}, {MetadataDays: 3651, ContentDays: 7},
		{MetadataDays: 30, ContentDays: 31}, {}} {
		if err := r.Validate(); err == nil {
			t.Errorf("%+v принят", r)
		}
	}
}

func TestValidFilterName(t *testing.T) {
	for _, s := range []string{"Блокировки", "a", strings.Repeat("я", MaxFilterNameRunes), "high и critical"} {
		if !ValidFilterName(s) {
			t.Errorf("%q отклонено", s)
		}
	}
	for _, s := range []string{"", " a", "a ", "a\nb", "a\x00", "\u0085x", strings.Repeat("я", MaxFilterNameRunes+1), "\xff"} {
		if ValidFilterName(s) {
			t.Errorf("%q принято", s)
		}
	}
}

func TestStatsQueryValidate(t *testing.T) {
	for _, q := range []StatsQuery{
		{Interval: IntervalMinute, From: eventsT0, To: eventsT0.Add(MaxMinuteRange)},
		{Interval: IntervalHour, From: eventsT0, To: eventsT0.Add(MaxHourRange), App: "crm"},
	} {
		if err := q.Validate(); err != nil {
			t.Errorf("%+v: %v", q, err)
		}
	}
	for _, q := range []StatsQuery{
		{Interval: "day", From: eventsT0, To: eventsT0.Add(time.Hour)},
		{Interval: IntervalMinute, From: eventsT0, To: eventsT0.Add(MaxMinuteRange + time.Second)},
		{Interval: IntervalHour, From: eventsT0, To: eventsT0},
		{Interval: IntervalHour, From: eventsT0, To: eventsT0.Add(time.Hour), App: strings.Repeat("a", MaxFilterValue+1)},
	} {
		if err := q.Validate(); err == nil {
			t.Errorf("%+v принят", q)
		}
	}
}

// Разделитель CSV: «;» по умолчанию, «,» по запросу; значения с «;» и «,»
// не ломают столбцы при обоих разделителях (задача 4.6).
func TestExportCSVDelimiter(t *testing.T) {
	for _, delim := range []rune{DelimSemicolon, DelimComma} {
		var buf bytes.Buffer
		ex, err := NewExporter(&buf, FormatCSV, delim)
		if err != nil {
			t.Fatal(err)
		}
		r := exportRecord()
		r.Model = "a;b,c"
		if err := ex.Write(r); err != nil {
			t.Fatal(err)
		}
		if err := ex.Close(); err != nil {
			t.Fatal(err)
		}
		cr := csv.NewReader(strings.NewReader(strings.TrimPrefix(buf.String(), utf8BOM)))
		cr.Comma = delim
		rows, err := cr.ReadAll()
		if err != nil || len(rows) != 2 || len(rows[1]) != len(csvHeader) || rows[1][9] != "a;b,c" {
			t.Fatalf("разделитель %q: %v %v", delim, rows, err)
		}
		first := strings.SplitN(strings.TrimPrefix(buf.String(), utf8BOM), "\r\n", 2)[0]
		if !strings.HasPrefix(first, `"id"`+string(delim)+`"time"`) {
			t.Fatalf("разделитель %q: заголовок %q", delim, first)
		}
	}
	if _, err := NewExporter(&bytes.Buffer{}, FormatCSV, '|'); err == nil {
		t.Fatal("чужой разделитель принят")
	}
}

func TestParseDelimiter(t *testing.T) {
	for in, want := range map[string]rune{"": DelimSemicolon, "semicolon": DelimSemicolon, "comma": DelimComma} {
		if got, ok := ParseDelimiter(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{";", ",", "tab", "Comma", "semicolon "} {
		if _, ok := ParseDelimiter(in); ok {
			t.Errorf("%q принят", in)
		}
	}
}
