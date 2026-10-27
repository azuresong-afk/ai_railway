package reports

import (
	"bufio"
	"io"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// utf8BOM — метка порядка байтов: без неё Excel открывает кириллицу в Windows-1251.
const utf8BOM = "\xef\xbb\xbf"

// WriteCSV пишет отчёт в CSV (RFC 4180, UTF-8 с BOM; delim — «;» или «,»): каждое поле в
// кавычках, конец строки CRLF. Текст проходит events.CSVCell — защита от
// исполнения формул в Excel (префикс ' перед = + - @ и табуляцией в начале
// значения и после «,», «;»). Числа префикса не получают: «-5» остаётся числом.
// Разделы идут друг за другом, между ними пустая строка.
func WriteCSV(w io.Writer, d Doc, delim rune) error {
	bw := bufio.NewWriterSize(w, 32<<10)
	if _, err := bw.WriteString(utf8BOM); err != nil {
		return err
	}
	row := func(cells ...Cell) error {
		for i, c := range cells {
			if i > 0 {
				if err := bw.WriteByte(byte(delim)); err != nil {
					return err
				}
			}
			v := c.Text
			if c.Kind == CellText {
				v = events.CSVCell(v)
			}
			if _, err := bw.WriteString(`"` + strings.ReplaceAll(v, `"`, `""`) + `"`); err != nil {
				return err
			}
		}
		_, err := bw.WriteString("\r\n")
		return err
	}
	blank := func() error { _, err := bw.WriteString("\r\n"); return err }
	if err := row(T(d.Title)); err != nil {
		return err
	}
	for _, m := range d.Meta {
		if err := row(T(m[0]), T(m[1])); err != nil {
			return err
		}
	}
	for _, s := range d.Sections {
		if err := blank(); err != nil {
			return err
		}
		if err := row(T(s.Title)); err != nil {
			return err
		}
		if s.Note != "" {
			if err := row(T(s.Note)); err != nil {
				return err
			}
		}
		hs := make([]Cell, len(s.Header))
		for i, h := range s.Header {
			hs[i] = T(h)
		}
		if len(hs) > 0 {
			if err := row(hs...); err != nil {
				return err
			}
		}
		for _, r := range s.Rows {
			if err := row(r...); err != nil {
				return err
			}
		}
	}
	return bw.Flush()
}
