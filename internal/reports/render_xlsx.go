package reports

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Минимальная запись SpreadsheetML (Р5): один лист, строки и числа, без
// формул, макросов, внешних связей и общих строк. Текст хранится как
// inlineStr: Excel и LibreOffice не исполняют его, даже если он начинается
// с «=». Файл строится только на стандартной библиотеке (archive/zip,
// encoding/xml).

// Пределы XLSX (спецификация Excel).
const (
	xlsxMaxCell = 32767
	xlsxMaxRows = 1_048_576
	xlsxMaxCols = 16384
	xlsxMaxWide = 60
)

// xlsxEpoch — фиксированное время записей архива: файл не зависит от часов.
var xlsxEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	xlsxNS    = `http://schemas.openxmlformats.org/spreadsheetml/2006/main`
	xlsxRelNS = `http://schemas.openxmlformats.org/officeDocument/2006/relationships`
	xmlHead   = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"
)

const xlsxContentTypes = xmlHead + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
	`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
	`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` +
	`</Types>`

const xlsxRootRels = xmlHead + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
	`</Relationships>`

const xlsxWorkbook = xmlHead + `<workbook xmlns="` + xlsxNS + `" xmlns:r="` + xlsxRelNS + `">` +
	`<sheets><sheet name="Отчёт" sheetId="1" r:id="rId1"/></sheets></workbook>`

const xlsxWorkbookRels = xmlHead + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
	`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
	`</Relationships>`

// Стили: 0 — обычный, 1 — полужирный (заголовки и названия разделов).
const xlsxStyles = xmlHead + `<styleSheet xmlns="` + xlsxNS + `">` +
	`<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>` +
	`<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>` +
	`<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>` +
	`<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
	`<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
	`<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>` +
	`<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`

// xlsxText приводит текст к допустимому в XML 1.0: недопустимые символы
// заменяются пробелом, длина — не больше предела ячейки.
func xlsxText(s string) string {
	s = strings.ToValidUTF8(s, " ")
	if utf8.RuneCountInString(s) > xlsxMaxCell {
		s = string([]rune(s)[:xlsxMaxCell])
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case r < 0x20, r == 0xFFFE, r == 0xFFFF, r >= 0xD800 && r <= 0xDFFF:
			return ' '
		}
		return r
	}, s)
}

// xlsxCol — буквенное имя столбца по номеру с нуля.
func xlsxCol(i int) string {
	var b []byte
	for i++; i > 0; i = (i - 1) / 26 {
		b = append([]byte{byte('A' + (i-1)%26)}, b...)
	}
	return string(b)
}

type sheetRow struct {
	cells []Cell
	bold  bool
}

// WriteXLSX пишет отчёт в XLSX. Строка с названием раздела и заголовок
// таблицы — полужирные; ширина столбцов по длине текста.
func WriteXLSX(w io.Writer, d Doc) error {
	var rows []sheetRow
	add := func(bold bool, cells ...Cell) { rows = append(rows, sheetRow{cells: cells, bold: bold}) }
	add(true, T(d.Title))
	for _, m := range d.Meta {
		add(false, T(m[0]), T(m[1]))
	}
	for _, s := range d.Sections {
		add(false)
		add(true, T(s.Title))
		if s.Note != "" {
			add(false, T(s.Note))
		}
		if len(s.Header) > 0 {
			hs := make([]Cell, len(s.Header))
			for i, h := range s.Header {
				hs[i] = T(h)
			}
			add(true, hs...)
		}
		for _, r := range s.Rows {
			add(false, r...)
		}
	}
	if len(rows) > xlsxMaxRows {
		return ErrTooLarge
	}
	widths := map[int]int{}
	var sheet bytes.Buffer
	sheet.WriteString(xmlHead + `<worksheet xmlns="` + xlsxNS + `">`)
	var body bytes.Buffer
	body.WriteString(`<sheetData>`)
	for i, r := range rows {
		if len(r.cells) > xlsxMaxCols {
			return ErrTooLarge
		}
		body.WriteString(`<row r="` + strconv.Itoa(i+1) + `">`)
		for j, c := range r.cells {
			ref := xlsxCol(j) + strconv.Itoa(i+1)
			style := ""
			if r.bold {
				style = ` s="1"`
			}
			switch c.Kind {
			case CellInt, CellDec:
				body.WriteString(`<c r="` + ref + `"` + style + `><v>` + c.Text + `</v></c>`)
				widths[j] = max(widths[j], len(c.Text))
			default:
				t := xlsxText(c.Text)
				body.WriteString(`<c r="` + ref + `"` + style + ` t="inlineStr"><is><t xml:space="preserve">`)
				if err := xml.EscapeText(&body, []byte(t)); err != nil {
					return err
				}
				body.WriteString(`</t></is></c>`)
				// Длинные строки (название, пояснение) ширину столбца не растят.
				if len(r.cells) > 1 {
					widths[j] = max(widths[j], utf8.RuneCountInString(t))
				}
			}
		}
		body.WriteString(`</row>`)
	}
	body.WriteString(`</sheetData></worksheet>`)
	cols := 0
	for j := range widths {
		cols = max(cols, j+1)
	}
	if cols > 0 {
		sheet.WriteString(`<cols>`)
	}
	for j := 0; j < cols; j++ {
		sheet.WriteString(`<col min="` + strconv.Itoa(j+1) + `" max="` + strconv.Itoa(j+1) + `" width="` +
			strconv.Itoa(min(max(widths[j]+2, 8), xlsxMaxWide)) + `" customWidth="1"/>`)
	}
	if cols > 0 {
		sheet.WriteString(`</cols>`)
	}
	sheet.Write(body.Bytes())

	zw := zip.NewWriter(w)
	parts := []struct{ name, data string }{
		{"[Content_Types].xml", xlsxContentTypes},
		{"_rels/.rels", xlsxRootRels},
		{"xl/workbook.xml", xlsxWorkbook},
		{"xl/_rels/workbook.xml.rels", xlsxWorkbookRels},
		{"xl/styles.xml", xlsxStyles},
		{"xl/worksheets/sheet1.xml", sheet.String()},
	}
	for _, p := range parts {
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: p.name, Method: zip.Deflate, Modified: xlsxEpoch})
		if err != nil {
			return err
		}
		if _, err := io.WriteString(fw, p.data); err != nil {
			return err
		}
	}
	return zw.Close()
}
