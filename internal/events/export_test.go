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
	ex, err := NewExporter(&buf, FormatCSV)
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.Write(exportRecord()); err != nil {
		t.Fatal(err)
	}
	if err := ex.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
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

func TestExportJSON(t *testing.T) {
	for _, n := range []int{0, 1, 3} {
		var buf bytes.Buffer
		ex, err := NewExporter(&buf, FormatJSON)
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
	if _, err := NewExporter(&bytes.Buffer{}, "xml"); err == nil {
		t.Fatal("неизвестный формат принят")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("клиент ушёл") }

func TestExportWriteError(t *testing.T) {
	ex, err := NewExporter(failWriter{}, FormatCSV)
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
