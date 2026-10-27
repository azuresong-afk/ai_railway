package reports

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"
)

func sampleDoc() Doc {
	return Doc{Kind: KindSummary, Title: "Сводный отчёт", Meta: [][2]string{{"Период", "01.10.2026 — 31.10.2026"}},
		Sections: []Section{
			{Title: "Итоги", Header: []string{"Показатель", "Значение"}, Rows: [][]Cell{
				{T("Запросов"), N(-5)}, {T("Стоимость, ₽"), D("12.30")}, {T(`=HYPERLINK("http://evil","x")`), N(1)},
			}},
			{Title: "Пусто", Header: []string{"A"}},
		}}
}

// CSV: защита от формул — префикс ' для = + - @, табуляции и перевода каретки
// в начале значения и после разделителей; числа префикса не получают.
func TestCSVFormulaInjection(t *testing.T) {
	for _, p := range []string{"=", "+", "-", "@", "\t", "\r"} {
		d := Doc{Title: "t", Sections: []Section{{Title: "s", Header: []string{"h"}, Rows: [][]Cell{{T(p + "cmd|' /C calc'!A0")}}}}}
		var b bytes.Buffer
		if err := WriteCSV(&b, d, events.DelimSemicolon); err != nil {
			t.Fatal(err)
		}
		out := strings.TrimPrefix(b.String(), utf8BOM)
		if strings.Contains(out, `"`+p+"cmd") {
			t.Errorf("префикс %q без защиты: %q", p, out)
		}
		if !strings.Contains(out, `"'`+p+"cmd") {
			t.Errorf("префикс %q: нет апострофа в %q", p, out)
		}
	}
	// После «;» внутри значения — Excel в русской локали делит по «;».
	d := Doc{Title: "t", Sections: []Section{{Title: "s", Rows: [][]Cell{{T("a;=1+1")}}}}}
	var b bytes.Buffer
	if err := WriteCSV(&b, d, events.DelimSemicolon); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `a;'=1+1`) {
		t.Errorf("значение после ';': %q", b.String())
	}
}

func TestCSVLayout(t *testing.T) {
	var b bytes.Buffer
	if err := WriteCSV(&b, sampleDoc(), events.DelimSemicolon); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "\xef\xbb\xbf") {
		t.Fatal("нет BOM UTF-8")
	}
	if strings.Count(b.String(), "\xef\xbb\xbf") != 1 {
		t.Error("BOM встречается не один раз")
	}
	// Разный состав строк (разделы разной ширины): читаем без проверки ширины.
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(b.String(), "\xef\xbb\xbf")))
	r.Comma = events.DelimSemicolon
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, row := range rows {
		if len(row) == 2 && row[0] == "Запросов" {
			found[row[1]] = true // число без апострофа
		}
	}
	if !found["-5"] {
		t.Errorf("число -5 испорчено: %v", rows)
	}
	if !strings.Contains(b.String(), `"'=HYPERLINK(""http://evil"",""x"")"`) {
		t.Errorf("формула в тексте не защищена: %q", b.String())
	}
	if !strings.HasSuffix(b.String(), "\r\n") {
		t.Error("конец строки не CRLF")
	}
}

func unzipAll(t *testing.T, data []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close() //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = string(b)
	}
	return out
}

func wellFormed(t *testing.T, name, s string) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(s))
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatalf("%s: XML неверен: %v", name, err)
		}
	}
}

// XLSX: структура архива, корректный XML, экранирование, нет формул.
func TestXLSXStructure(t *testing.T) {
	d := sampleDoc()
	d.Sections[0].Rows = append(d.Sections[0].Rows, []Cell{T("<b>&\"'</b>\x00\x01 ok"), D("0.5")})
	var b bytes.Buffer
	if err := WriteXLSX(&b, d); err != nil {
		t.Fatal(err)
	}
	parts := unzipAll(t, b.Bytes())
	for _, name := range []string{"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/worksheets/sheet1.xml"} {
		s, ok := parts[name]
		if !ok {
			t.Fatalf("нет части %s", name)
		}
		wellFormed(t, name, s)
	}
	if len(parts) != 6 {
		t.Errorf("частей %d, ожидалось 6: лишних файлов (макросов, связей) быть не должно", len(parts))
	}
	zr, _ := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len())) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	if zr.File[0].Name != "[Content_Types].xml" {
		t.Errorf("первым идёт %s", zr.File[0].Name)
	}
	sheet := parts["xl/worksheets/sheet1.xml"]
	if strings.Contains(sheet, "<f>") || strings.Contains(sheet, "<f ") {
		t.Error("в листе есть формулы")
	}
	if !strings.Contains(sheet, `t="inlineStr"`) || !strings.Contains(sheet, "&lt;b&gt;&amp;&#34;&#39;&lt;/b&gt;") {
		t.Errorf("текст не экранирован: %s", sheet)
	}
	if strings.ContainsAny(sheet, "\x00\x01") {
		t.Error("управляющие символы в XML")
	}
	if !strings.Contains(sheet, "<v>-5</v>") || !strings.Contains(sheet, "<v>12.30</v>") {
		t.Errorf("числа записаны не числами: %s", sheet)
	}
	// Макросов и внешних связей нет.
	for name := range parts {
		if strings.Contains(name, "vba") || strings.Contains(name, "externalLinks") || strings.HasSuffix(name, ".bin") {
			t.Errorf("лишняя часть %s", name)
		}
	}
	if strings.Contains(parts["[Content_Types].xml"], "macro") {
		t.Error("тип содержимого с макросами")
	}
}

func TestXLSXDeterministicAndEmpty(t *testing.T) {
	var a, b bytes.Buffer
	if err := WriteXLSX(&a, sampleDoc()); err != nil {
		t.Fatal(err)
	}
	if err := WriteXLSX(&b, sampleDoc()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("один и тот же отчёт даёт разные файлы")
	}
	var e bytes.Buffer
	if err := WriteXLSX(&e, Doc{}); err != nil {
		t.Fatal(err)
	}
	wellFormed(t, "sheet1", unzipAll(t, e.Bytes())["xl/worksheets/sheet1.xml"])
	if xlsxCol(0) != "A" || xlsxCol(25) != "Z" || xlsxCol(26) != "AA" || xlsxCol(701) != "ZZ" || xlsxCol(702) != "AAA" {
		t.Error("имена столбцов")
	}
}

func TestXLSXTextLimit(t *testing.T) {
	long := strings.Repeat("я", xlsxMaxCell+50)
	if n := len([]rune(xlsxText(long))); n != xlsxMaxCell {
		t.Errorf("длина ячейки %d", n)
	}
}

func FuzzWriteXLSX(f *testing.F) {
	f.Add("=1+1", "a\x00b")
	f.Add("<>&\"'", "\xff\xfe")
	f.Fuzz(func(t *testing.T, a, b string) {
		d := Doc{Title: a, Meta: [][2]string{{a, b}}, Sections: []Section{{Title: b, Header: []string{a}, Rows: [][]Cell{{T(a), T(b)}}}}}
		var buf bytes.Buffer
		if err := WriteXLSX(&buf, d); err != nil {
			t.Fatal(err)
		}
		wellFormed(t, "sheet", unzipAll(t, buf.Bytes())["xl/worksheets/sheet1.xml"])
		var c bytes.Buffer
		if err := WriteCSV(&c, d, events.DelimSemicolon); err != nil {
			t.Fatal(err)
		}
	})
}

// HTML: нет скриптов и внешних ресурсов, значения экранированы.
func TestHTMLSafe(t *testing.T) {
	d := sampleDoc()
	d.Title = `<script>alert(1)</script>`
	d.Sections[0].Rows = append(d.Sections[0].Rows, []Cell{T(`<img src=x onerror=alert(1)>`), N(2)})
	var b bytes.Buffer
	if err := WriteHTML(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	// Разметка — только из разрешённого набора тегов: значения ячеек, даже с
	// «<img onerror=…>», остаются текстом.
	allowed := map[string]bool{"html": true, "head": true, "meta": true, "title": true, "style": true, "body": true, "h1": true,
		"h2": true, "dl": true, "dt": true, "dd": true, "section": true, "p": true, "table": true, "thead": true, "tbody": true,
		"tr": true, "th": true, "td": true, "footer": true}
	for _, m := range regexp.MustCompile(`</?([a-zA-Z][a-zA-Z0-9]*)`).FindAllStringSubmatch(out, -1) {
		if !allowed[m[1]] {
			t.Errorf("в странице тег <%s>", m[1])
		}
	}
	for _, bad := range []string{"<script", "<link", "<iframe", "<a ", "<img", "@import", "url("} {
		if strings.Contains(strings.ToLower(out), bad) {
			t.Errorf("в странице есть %q", bad)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("заголовок не экранирован")
	}
	if !strings.Contains(out, `<html lang="ru">`) || !strings.Contains(out, "@media print") || !strings.Contains(out, "Нет данных за период.") {
		t.Error("вёрстка для печати или пустой раздел")
	}
}

// Разделитель CSV отчёта: «;» и «,»; значения с обоими знаками — в кавычках,
// столбцы не смещаются; защита от формул действует при обоих (задача 4.6).
func TestCSVDelimiter(t *testing.T) {
	d := Doc{Title: "t", Sections: []Section{{Title: "s", Header: []string{"h1", "h2"},
		Rows: [][]Cell{{T("a;b,c"), T("x;=1+1")}}}}}
	for _, delim := range []rune{events.DelimSemicolon, events.DelimComma} {
		var b bytes.Buffer
		if err := WriteCSV(&b, d, delim); err != nil {
			t.Fatal(err)
		}
		r := csv.NewReader(strings.NewReader(strings.TrimPrefix(b.String(), "\xef\xbb\xbf")))
		r.Comma = delim
		r.FieldsPerRecord = -1
		rows, err := r.ReadAll()
		if err != nil {
			t.Fatalf("%q: %v", delim, err)
		}
		var data []string
		for _, row := range rows {
			if len(row) == 2 && row[0] == "a;b,c" {
				data = row
			}
		}
		if data == nil || data[1] != "x;'=1+1" {
			t.Errorf("%q: строки %v", delim, rows)
		}
	}
}

func TestParseParamsDelimiter(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	p, err := ParseParams(KindSummary, map[string][]string{"format": {"csv"}}, loc, now)
	if err != nil || p.Delimiter != events.DelimSemicolon {
		t.Fatalf("по умолчанию: %v %q", err, p.Delimiter)
	}
	p, err = ParseParams(KindSummary, map[string][]string{"format": {"csv"}, "delimiter": {"comma"}}, loc, now)
	if err != nil || p.Delimiter != events.DelimComma {
		t.Fatalf("comma: %v %q", err, p.Delimiter)
	}
	for _, q := range []map[string][]string{
		{"format": {"csv"}, "delimiter": {"tab"}},
		{"format": {"xlsx"}, "delimiter": {"comma"}},
		{"delimiter": {"comma"}},
		{"format": {"csv"}, "delimiter": {"comma", "semicolon"}},
	} {
		if _, err := ParseParams(KindSummary, q, loc, now); err == nil {
			t.Errorf("%v принят", q)
		}
	}
}
