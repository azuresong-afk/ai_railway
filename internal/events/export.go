package events

import (
	"bufio"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
)

// Выгрузка событий (ТЗ 5.5, задача 2.16): CSV и JSON, только метаданные —
// содержимого запросов и ответов в выгрузке нет. Запись data.export в
// журнал аудита делает вызывающий до начала выгрузки.

// Форматы выгрузки.
const (
	FormatCSV  = "csv"
	FormatJSON = "json"
)

// View — событие в ответах API и выгрузке JSON. Details есть в карточке и
// выгрузке JSON, в списке — нет.
type View struct {
	ID               string    `json:"id"`
	Time             time.Time `json:"time"`
	ReceivedAt       time.Time `json:"received_at"`
	GatewayID        string    `json:"gateway_id"`
	Type             string    `json:"type"`
	App              string    `json:"app,omitempty"`
	Env              string    `json:"env,omitempty"`
	User             string    `json:"user,omitempty"`
	Provider         string    `json:"provider,omitempty"`
	Model            string    `json:"model,omitempty"`
	Source           string    `json:"source,omitempty"`
	PolicyMode       string    `json:"policy_mode,omitempty"`
	Action           string    `json:"action,omitempty"`
	Rule             string    `json:"rule,omitempty"`
	Severity         string    `json:"severity,omitempty"`
	Storage          string    `json:"storage"`
	Threats          []string  `json:"threats"`
	Stream           bool      `json:"stream"`
	NonTextUnchecked bool      `json:"non_text_unchecked"`
	HasContent       bool      `json:"has_content"`
	// Mark — отметка аналитика (задача 3.22); нет — поле отсутствует.
	Mark    *Mark    `json:"mark,omitempty"`
	Details *Details `json:"details,omitempty"`
}

// View — представление записи для API.
func (r *Record) View() View {
	threats := r.Threats
	if threats == nil {
		threats = []string{}
	}
	return View{
		ID: r.ID, Time: r.Time.UTC(), ReceivedAt: r.ReceivedAt.UTC(), GatewayID: r.GatewayID, Type: r.Type,
		App: r.App, Env: r.Env, User: r.User, Provider: r.Provider, Model: r.Model, Source: r.Source,
		PolicyMode: r.PolicyMode, Action: r.Action, Rule: r.Rule, Severity: r.Severity, Storage: r.Storage,
		Threats: threats, Stream: r.Stream, NonTextUnchecked: r.NonTextUnchecked, HasContent: r.HasContent,
		Mark: r.Mark, Details: r.Details,
	}
}

// Разделители полей CSV. По умолчанию «;»: Excel с русской локалью делит по
// нему на столбцы, запятая в такой локали оставляла строку в одном столбце
// (решение владельца по пилоту, задача 4.6).
const (
	DelimSemicolon = ';'
	DelimComma     = ','
)

// ParseDelimiter разбирает параметр delimiter: semicolon (по умолчанию, если
// пусто) или comma.
func ParseDelimiter(s string) (rune, bool) {
	switch s {
	case "", "semicolon":
		return DelimSemicolon, true
	case "comma":
		return DelimComma, true
	}
	return 0, false
}

// csvHeader — столбцы CSV; порядок совпадает с csvRow.
var csvHeader = []string{"id", "time", "received_at", "gateway_id", "type", "app", "env", "user", "provider",
	"model", "source", "policy_mode", "action", "rule", "severity", "storage", "threats", "stream",
	"non_text_unchecked", "has_content"}

// CSVCell защищает ячейку от исполнения как формулы в табличных
// редакторах (CSV injection). Апостроф ставится перед «=», «+», «-», «@»
// в начале значения и после любого из «,», «;», табуляции, «\r», «\n»,
// если между ними только пробелы и кавычки: Excel в русской локали делит
// строку по «;», и такой кусок стал бы отдельной ячейкой-формулой (В12
// ревью 2.r3a). Табуляция и «\r» в начале значения тоже получают апостроф.
// Полноширинные «＝», «＋», «－», «＠» — тоже: табличный редактор с
// азиатской локалью или нормализацией NFKC читает их как обычные знаки
// (ревью 4.r1, остаток).
func CSVCell(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 1)
	if s != "" && (s[0] == '\t' || s[0] == '\r') {
		b.WriteByte('\'')
	}
	start := true // начало значения или куска после разделителя
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ',' || c == ';' || c == '\t' || c == '\r' || c == '\n':
			start = true
		case start && (c == ' ' || c == '"'):
		case start && (c == '=' || c == '+' || c == '-' || c == '@' || fullwidthFormula(s[i:])):
			b.WriteByte('\'')
			start = false
		default:
			start = false
		}
		b.WriteByte(c)
	}
	return b.String()
}

// fullwidthFormula — s начинается с полноширинного знака формулы
// (U+FF1D, U+FF0B, U+FF0D, U+FF20).
func fullwidthFormula(s string) bool {
	for _, p := range [...]string{"\uff1d", "\uff0b", "\uff0d", "\uff20"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func csvRow(r *Record) []string {
	return []string{r.ID, r.Time.UTC().Format(time.RFC3339Nano), r.ReceivedAt.UTC().Format(time.RFC3339Nano),
		r.GatewayID, r.Type, r.App, r.Env, r.User, r.Provider, r.Model, r.Source, r.PolicyMode, r.Action, r.Rule,
		r.Severity, r.Storage, strings.Join(r.Threats, ";"), strconv.FormatBool(r.Stream),
		strconv.FormatBool(r.NonTextUnchecked), strconv.FormatBool(r.HasContent)}
}

// utf8BOM — метка порядка байтов в начале CSV: без неё Excel открывает
// кириллицу в кодировке Windows-1251.
const utf8BOM = "\ufeff"

// writeCSVRow пишет строку CSV (RFC 4180): каждое поле в кавычках, кавычки
// внутри удваиваются, значения проходят CSVCell, конец строки — CRLF.
// encoding/csv берёт в кавычки не каждое поле, и «;» оставался бы вне
// кавычек (В12 ревью 2.r3a).
func writeCSVRow(w *bufio.Writer, row []string, delim rune) error {
	for i, f := range row {
		if i > 0 {
			if err := w.WriteByte(byte(delim)); err != nil { //nolint:gosec // разделитель из белого списка ParseDelimiter (ASCII)
				return err
			}
		}
		if err := w.WriteByte('"'); err != nil {
			return err
		}
		if _, err := w.WriteString(strings.ReplaceAll(CSVCell(f), `"`, `""`)); err != nil {
			return err
		}
		if err := w.WriteByte('"'); err != nil {
			return err
		}
	}
	_, err := w.WriteString("\r\n")
	return err
}

// Exporter пишет выгрузку в w: Write — по записи, Close — завершение.
type Exporter struct {
	format string
	delim  rune
	bw     *bufio.Writer
	rows   int
}

// NewExporter начинает выгрузку в формате format (FormatCSV, FormatJSON);
// delim — разделитель CSV (DelimSemicolon или DelimComma), для JSON не нужен.
func NewExporter(w io.Writer, format string, delim rune) (*Exporter, error) {
	if delim != DelimSemicolon && delim != DelimComma {
		return nil, strconv.ErrSyntax
	}
	e := &Exporter{format: format, delim: delim, bw: bufio.NewWriterSize(w, 64<<10)}
	switch format {
	case FormatCSV:
		if _, err := e.bw.WriteString(utf8BOM); err != nil {
			return nil, err
		}
		if err := writeCSVRow(e.bw, csvHeader, delim); err != nil {
			return nil, err
		}
	case FormatJSON:
		if _, err := e.bw.WriteString("["); err != nil {
			return nil, err
		}
	default:
		return nil, strconv.ErrSyntax
	}
	return e, nil
}

// Write добавляет запись.
func (e *Exporter) Write(r *Record) error {
	e.rows++
	if e.format == FormatCSV {
		return writeCSVRow(e.bw, csvRow(r), e.delim)
	}
	b, err := json.Marshal(r.View())
	if err != nil {
		return err
	}
	if e.rows > 1 {
		if _, err := e.bw.WriteString(","); err != nil {
			return err
		}
	}
	if _, err := e.bw.WriteString("\n"); err != nil {
		return err
	}
	_, err = e.bw.Write(b)
	return err
}

// Rows — число записанных записей.
func (e *Exporter) Rows() int { return e.rows }

// Close завершает выгрузку и сбрасывает буфер.
func (e *Exporter) Close() error {
	if e.format == FormatJSON {
		if _, err := e.bw.WriteString("\n]\n"); err != nil {
			return err
		}
	}
	return e.bw.Flush()
}
