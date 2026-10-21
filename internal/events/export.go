package events

import (
	"bufio"
	"encoding/csv"
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
	Details          *Details  `json:"details,omitempty"`
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
		Details: r.Details,
	}
}

// csvHeader — столбцы CSV; порядок совпадает с csvRow.
var csvHeader = []string{"id", "time", "received_at", "gateway_id", "type", "app", "env", "user", "provider",
	"model", "source", "policy_mode", "action", "rule", "severity", "storage", "threats", "stream",
	"non_text_unchecked", "has_content"}

// CSVCell защищает ячейку от исполнения как формулы в табличных
// редакторах (CSV injection): значение, начинающееся с «=», «+», «-», «@»,
// табуляции или возврата каретки, получает в начале апостроф.
func CSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func csvRow(r *Record) []string {
	row := []string{r.ID, r.Time.UTC().Format(time.RFC3339Nano), r.ReceivedAt.UTC().Format(time.RFC3339Nano),
		r.GatewayID, r.Type, r.App, r.Env, r.User, r.Provider, r.Model, r.Source, r.PolicyMode, r.Action, r.Rule,
		r.Severity, r.Storage, strings.Join(r.Threats, ";"), strconv.FormatBool(r.Stream),
		strconv.FormatBool(r.NonTextUnchecked), strconv.FormatBool(r.HasContent)}
	for i := range row {
		row[i] = CSVCell(row[i])
	}
	return row
}

// Exporter пишет выгрузку в w: Write — по записи, Close — завершение.
type Exporter struct {
	format string
	bw     *bufio.Writer
	cw     *csv.Writer
	rows   int
}

// NewExporter начинает выгрузку в формате format (FormatCSV, FormatJSON).
func NewExporter(w io.Writer, format string) (*Exporter, error) {
	e := &Exporter{format: format, bw: bufio.NewWriterSize(w, 64<<10)}
	switch format {
	case FormatCSV:
		e.cw = csv.NewWriter(e.bw)
		if err := e.cw.Write(csvHeader); err != nil {
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
	if e.cw != nil {
		return e.cw.Write(csvRow(r))
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
	if e.cw != nil {
		e.cw.Flush()
		if err := e.cw.Error(); err != nil {
			return err
		}
	} else if _, err := e.bw.WriteString("\n]\n"); err != nil {
		return err
	}
	return e.bw.Flush()
}
