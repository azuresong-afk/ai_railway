package reports

import (
	"errors"
	"fmt"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Виды отчётов (ТЗ 5.8).
const (
	KindSummary   = "summary"   // сводный за период
	KindIncidents = "incidents" // по инцидентам
	KindPilot     = "pilot"     // «Итоги пилота» (S10)
	// KindCompliance — «Соответствие требованиям» для аттестационных
	// испытаний и аудита ИСПДн (S7, ТЗ 5.9; задача 4.25).
	KindCompliance = "compliance"
)

// Kinds — виды отчётов в порядке показа.
func Kinds() []string { return []string{KindSummary, KindIncidents, KindPilot, KindCompliance} }

// Title — название вида отчёта для людей.
func Title(kind string) string {
	switch kind {
	case KindSummary:
		return "Сводный отчёт за период"
	case KindIncidents:
		return "Отчёт по инцидентам"
	case KindPilot:
		return "Итоги пилота"
	case KindCompliance:
		return "Соответствие требованиям"
	}
	return kind
}

// ValidKind — известный вид отчёта.
func ValidKind(kind string) bool { return Title(kind) != kind }

// Форматы выгрузки (Р5).
const (
	FormatHTML = "html"
	FormatCSV  = "csv"
	FormatXLSX = "xlsx"
)

// ValidFormat — известный формат.
func ValidFormat(f string) bool { return f == FormatHTML || f == FormatCSV || f == FormatXLSX }

// ContentType и Extension — тип содержимого и расширение файла формата.
func ContentType(f string) string {
	switch f {
	case FormatCSV:
		return "text/csv; charset=utf-8"
	case FormatXLSX:
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	}
	return "text/html; charset=utf-8"
}

// Пределы отчётов.
const (
	// MaxPeriodDays — наибольший период отчёта, суток (как у дашбордов).
	MaxPeriodDays = 366
	// MaxIncidentRows — строк инцидентов в отчёте; сверх предела в конце
	// отчёта стоит пометка, а итоги считаются по всем.
	MaxIncidentRows = 2000
	// MaxScan — записей инцидентов или оповещений, просматриваемых за период.
	MaxScan = 20000
	// TopRows — строк в списках «топ».
	TopRows = 20
	// MaxSlug — длина slug приложения.
	MaxSlug = 64
)

// CellKind — вид ячейки таблицы.
type CellKind uint8

const (
	// CellText — текст.
	CellText CellKind = iota
	// CellInt — целое число.
	CellInt
	// CellDec — десятичное число (рубли): значение — каноническая строка.
	CellDec
)

// Cell — ячейка таблицы отчёта.
type Cell struct {
	Kind CellKind
	// Text — текст или каноническая запись числа.
	Text string
}

// T — текстовая ячейка.
func T(s string) Cell { return Cell{Kind: CellText, Text: s} }

// N — целое число.
func N(n int64) Cell { return Cell{Kind: CellInt, Text: strconv.FormatInt(n, 10)} }

var decimalRe = regexp.MustCompile(`^-?[0-9]{1,18}(\.[0-9]{1,9})?$`)

// D — десятичное число; строка не по формату превращается в текст.
func D(s string) Cell {
	if !decimalRe.MatchString(s) {
		return T(s)
	}
	return Cell{Kind: CellDec, Text: s}
}

// Section — раздел отчёта: таблица с заголовком и пояснением.
type Section struct {
	Title  string
	Note   string
	Header []string
	Rows   [][]Cell
}

// Doc — отчёт: заголовок, сведения о периоде и разделы.
type Doc struct {
	Kind  string
	Title string
	// Meta — пары «название — значение» под заголовком: период, приложение,
	// время формирования.
	Meta     [][2]string
	Sections []Section
}

// Rows — число строк данных во всех разделах (для записи data.export).
func (d Doc) Rows() int {
	n := 0
	for _, s := range d.Sections {
		n += len(s.Rows)
	}
	return n
}

// Period — период отчёта: целые сутки часового пояса установки.
type Period struct {
	// From и To — границы [From, To) в UTC.
	From, To time.Time
	// First и Last — первый и последний день периода, YYYY-MM-DD.
	First, Last string
	Days        int
	Loc         *time.Location
}

// Label — период для людей: «01.10.2026 — 31.10.2026».
func (p Period) Label() string {
	f, _ := time.Parse(dateLayout, p.First) //nolint:gosec // G104: день проверен при построении периода
	l, _ := time.Parse(dateLayout, p.Last)  //nolint:gosec // G104: день проверен при построении периода
	if p.First == p.Last {
		return f.Format("02.01.2006")
	}
	return f.Format("02.01.2006") + " — " + l.Format("02.01.2006")
}

const dateLayout = "2006-01-02"

// Ошибки разбора параметров.
var (
	ErrPeriod = errors.New("отчёты: период задан неверно")
)

// ParseDay разбирает день YYYY-MM-DD строго: только цифры и дефисы.
func ParseDay(s string) (time.Time, error) {
	if len(s) != len(dateLayout) {
		return time.Time{}, ErrPeriod
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (i == 4 || i == 7) != (c == '-') || (c != '-' && (c < '0' || c > '9')) {
			return time.Time{}, ErrPeriod
		}
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return time.Time{}, ErrPeriod
	}
	return t, nil
}

// NewPeriod строит период из дней first..last включительно в поясе loc.
// Начало не в будущем; конец после «сейчас» урезается до сегодняшнего дня,
// длина — не больше MaxPeriodDays суток (и 366*24 часов, как у дашбордов).
func NewPeriod(first, last string, loc *time.Location, now time.Time) (Period, error) {
	f, err := ParseDay(first)
	if err != nil {
		return Period{}, fmt.Errorf("%w: начало", ErrPeriod)
	}
	l, err := ParseDay(last)
	if err != nil {
		return Period{}, fmt.Errorf("%w: конец", ErrPeriod)
	}
	if loc == nil {
		loc = time.UTC
	}
	today := now.In(loc)
	td := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	if f.After(td) {
		return Period{}, fmt.Errorf("%w: начало в будущем", ErrPeriod)
	}
	if l.After(td) {
		l = td
	}
	if l.Before(f) {
		return Period{}, fmt.Errorf("%w: конец раньше начала", ErrPeriod)
	}
	days := int(l.Sub(f)/(24*time.Hour)) + 1
	if days > MaxPeriodDays {
		return Period{}, fmt.Errorf("%w: больше %d суток", ErrPeriod, MaxPeriodDays)
	}
	from := time.Date(f.Year(), f.Month(), f.Day(), 0, 0, 0, 0, loc).UTC()
	to := time.Date(l.Year(), l.Month(), l.Day()+1, 0, 0, 0, 0, loc).UTC()
	if to.Sub(from) > MaxPeriodDays*24*time.Hour {
		return Period{}, fmt.Errorf("%w: больше %d суток", ErrPeriod, MaxPeriodDays)
	}
	return Period{From: from, To: to, First: f.Format(dateLayout), Last: l.Format(dateLayout), Days: days, Loc: loc}, nil
}

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ValidSlug — slug приложения допустим для условия отчёта.
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// Params — разобранные параметры запроса отчёта.
type Params struct {
	Kind   string
	Format string
	// Delimiter — разделитель CSV; для других форматов не используется.
	Delimiter rune
	Period    Period
	// App — slug приложения; пусто — все приложения.
	App string
}

// ParseParams разбирает параметры GET /reports/{kind}: format, from, to, app.
// Неизвестные и повторные параметры отклоняются.
func ParseParams(kind string, q map[string][]string, loc *time.Location, now time.Time) (Params, error) {
	if !ValidKind(kind) {
		return Params{}, errors.New("отчёты: неизвестный вид отчёта")
	}
	get := func(k string) (string, error) {
		vs := q[k]
		switch len(vs) {
		case 0:
			return "", nil
		case 1:
			if !utf8.ValidString(vs[0]) || len(vs[0]) > 128 {
				return "", fmt.Errorf("отчёты: параметр %s задан неверно", k)
			}
			return vs[0], nil
		}
		return "", fmt.Errorf("отчёты: параметр %s указан несколько раз", k)
	}
	for k := range q {
		switch k {
		case "format", "delimiter", "from", "to", "app":
		default:
			return Params{}, fmt.Errorf("отчёты: неизвестный параметр %q", truncate(k, 32))
		}
	}
	var p Params
	p.Kind = kind
	var err error
	if p.Format, err = get("format"); err != nil {
		return p, err
	}
	if p.Format == "" {
		p.Format = FormatHTML
	}
	if !ValidFormat(p.Format) {
		return p, errors.New("отчёты: формат — html, csv или xlsx")
	}
	ds, err := get("delimiter")
	if err != nil {
		return p, err
	}
	var okd bool
	if p.Delimiter, okd = events.ParseDelimiter(ds); !okd {
		return p, errors.New("отчёты: разделитель — semicolon или comma")
	}
	if ds != "" && p.Format != FormatCSV {
		return p, errors.New("отчёты: разделитель задаётся только для csv")
	}
	from, err := get("from")
	if err != nil {
		return p, err
	}
	to, err := get("to")
	if err != nil {
		return p, err
	}
	if p.App, err = get("app"); err != nil {
		return p, err
	}
	if p.App != "" && !ValidSlug(p.App) {
		return p, errors.New("отчёты: приложение задано неверно")
	}
	// По одному приложению строится только сводный: «Итоги пилота» и «По
	// инцидентам» считаются по всей установке (3Н47 ревью 3.r4).
	if p.App != "" && p.Kind != KindSummary {
		return p, errors.New("отчёты: приложение задаётся только для сводного отчёта")
	}
	// Без обеих дат — последние 30 суток по сегодняшний день (3Н46 ревью
	// 3.r4: так обещает консоль); одна дата без другой — ошибка.
	if from == "" && to == "" {
		today := now.In(loc)
		from, to = today.AddDate(0, 0, -(DefaultPeriodDays-1)).Format(dateLayout), today.Format(dateLayout)
	}
	if from == "" || to == "" {
		return p, fmt.Errorf("%w: нужны from и to", ErrPeriod)
	}
	p.Period, err = NewPeriod(from, to, loc, now)
	return p, err
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return strings.ToValidUTF8(s, "?")
	}
	r := []rune(strings.ToValidUTF8(s, "?"))
	return string(r[:n])
}

// DefaultPeriodDays — период отчёта без дат: последние 30 суток.
const DefaultPeriodDays = 30

// ErrTooLarge — отчёт не помещается в формат.
var ErrTooLarge = errors.New("отчёты: отчёт слишком велик для формата")
