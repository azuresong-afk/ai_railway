package redteam

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/reports"
)

// Отчёт тестирования устойчивости (ТЗ 5.13; задача 5.33 этапа 5, ADR-0031,
// раздел 7). Документ строится в общей модели internal/reports (HTML, CSV,
// XLSX — как у остальных отчётов). Промптов атак в нём нет никогда. Выдержки
// ответов (цель endpoint, режим masked, только удавшиеся атаки) — только по
// явному запросу и с правом events.content.read: право проверяет API.

// KindReport — вид отчёта в записи аудита data.export.
const KindReport = "redteam"

// Report — отчёт по запуску; withExamples — включить выдержки ответов.
func (s *Service) Report(ctx context.Context, runID string, withExamples bool) (reports.Doc, error) {
	run, res, err := s.Run(ctx, runID)
	if err != nil {
		return reports.Doc{}, err
	}
	loc, err := s.location(ctx)
	if err != nil {
		return reports.Doc{}, err
	}
	// Названия сценариев — из действующей базы, только если это та же версия,
	// что и в запуске: иначе под тем же ID может лежать другой сценарий.
	titles := map[string]string{}
	if v, err := s.scenarios.Active(ctx); err == nil && v != nil {
		if b, ok := v.Content.Value.(*Base); ok && b.Version == run.DBVersion {
			for _, sc := range b.Scenarios {
				titles[sc.ID] = sc.Title
			}
		}
	}
	storage := StorageNone
	if run.TargetID != "" {
		if t, err := s.Target(ctx, run.TargetID); err == nil {
			storage = t.Storage
		}
	}
	return BuildReport(run, res, ReportOptions{Titles: titles, Examples: withExamples && storage == StorageMasked, Loc: loc}), nil
}

// ReportOptions — параметры построения отчёта.
type ReportOptions struct {
	// Titles — названия сценариев по ID (может быть пусто).
	Titles map[string]string
	// Examples — выдержки ответов в таблице удавшихся атак.
	Examples bool
	// Loc — часовой пояс для времени; nil — UTC.
	Loc *time.Location
}

// VerdictTitle — итог сценария для людей.
func VerdictTitle(v string) string {
	switch v {
	case VerdictSucceeded:
		return "Атака удалась"
	case VerdictBlocked:
		return "Заблокировано защитой"
	case VerdictDefended:
		return "Отражено"
	case VerdictUnchecked:
		return "Не проверено"
	case VerdictError:
		return "Ошибка"
	case VerdictSkipped:
		return "Пропущено"
	}
	return v
}

// RunStatusTitle — состояние запуска для людей.
func RunStatusTitle(st, reason string) string {
	var t string
	switch st {
	case RunQueued:
		t = "в очереди"
	case RunRunning:
		t = "идёт"
	case RunDone:
		t = "завершён"
	case RunFailed:
		t = "не удался"
	case RunCancelled:
		t = "отменён"
	default:
		t = st
	}
	if reason == "" {
		return t
	}
	return t + " (" + ReasonTitle(reason) + ")"
}

// ReasonTitle — причина неуспешного запуска для людей.
func ReasonTitle(r string) string {
	switch r {
	case ReasonInterrupted:
		return "сервер был перезапущен"
	case ReasonDeadline:
		return "истёк срок запуска"
	case ReasonKeyNotDelivered:
		return "шлюз не принял ключ запуска"
	case ReasonNoScenarios:
		return "нет сценариев"
	case ReasonInternal:
		return "внутренняя ошибка"
	}
	return r
}

// ErrorTitle — код ошибки шага для людей.
func ErrorTitle(c string) string {
	switch c {
	case ErrCodeBlockedAddr:
		return "адрес запрещён правилом адресов"
	case ErrCodeDial:
		return "нет соединения"
	case ErrCodeTimeout:
		return "срок запроса истёк"
	case ErrCodeRedirect:
		return "перенаправление (не выполняется)"
	case ErrCodeHTTP:
		return "ответ с кодом ошибки"
	case ErrCodeTooLarge:
		return "ответ больше 1 МиБ"
	case ErrCodeBadResponse:
		return "ответ не по пути из цели"
	case ErrCodeRequest:
		return "запрос не построен"
	}
	return c
}

// CoverageRow — строка матрицы обнаружения и итоги сценариев по ней.
type CoverageRow struct {
	Threat string
	Total  int
	Counts Counts
}

// Coverage — итоги сценариев запуска по строкам матрицы DM-NN, по номеру.
func Coverage(res []Result) []CoverageRow {
	by := map[string]*CoverageRow{}
	for _, r := range res {
		row := by[r.Threat]
		if row == nil {
			row = &CoverageRow{Threat: r.Threat, Counts: Counts{}}
			by[r.Threat] = row
		}
		row.Total++
		row.Counts[r.Verdict]++
	}
	out := make([]CoverageRow, 0, len(by))
	for _, r := range by {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Threat < out[j].Threat })
	return out
}

func stamp(t time.Time, loc *time.Location) string {
	if loc == nil {
		loc = time.UTC
	}
	return t.In(loc).Format("02.01.2006 15:04 MST")
}

func findingList(fs []Finding) string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if !seen[f.Category] {
			seen[f.Category] = true
			out = append(out, f.Category)
		}
	}
	return strings.Join(out, ", ")
}

// BuildReport строит документ отчёта по запуску и его итогам.
func BuildReport(run Run, res []Result, o ReportOptions) reports.Doc {
	results := append([]Result(nil), res...)
	sort.Slice(results, func(i, j int) bool { return results[i].ScenarioID < results[j].ScenarioID })
	d := reports.Doc{Kind: KindReport, Title: "Тестирование устойчивости: отчёт по запуску"}
	kind := "приложение продукта (через шлюз)"
	if run.TargetKind == KindEndpoint {
		kind = "адрес приложения заказчика"
	}
	d.Meta = [][2]string{
		{"Цель", run.TargetName},
		{"Вид цели", kind},
		{"Запуск", run.ID},
		{"Состояние", RunStatusTitle(run.Status, run.Reason)},
		{"Начат", stamp(run.StartedAt, o.Loc) + ", запустил: " + run.StartedBy},
		{"База сценариев", "версия " + strconv.FormatUint(run.DBVersion, 10)},
		{"Сценариев в запуске", strconv.Itoa(run.Scenarios)},
	}
	if run.FinishedAt != nil {
		d.Meta = append(d.Meta, [2]string{"Завершён", stamp(*run.FinishedAt, o.Loc)})
	}
	examples := "не включены"
	if o.Examples {
		examples = "включены (ответ цели, ПДн и секреты заменены категорией)"
	}
	d.Meta = append(d.Meta, [2]string{"Выдержки ответов", examples})

	sum := reports.Section{Title: "Итоги", Header: []string{"Итог", "Сценариев"},
		Note: "«Атака удалась» — уязвимость: условие успеха сценария выполнено. «Заблокировано защитой» — продукт остановил запрос или ответ."}
	for _, v := range Verdicts {
		sum.Rows = append(sum.Rows, []reports.Cell{reports.T(VerdictTitle(v)), reports.N(int64(run.Counts[v]))})
	}
	d.Sections = append(d.Sections, sum)

	cov := reports.Section{Title: "Покрытие строк матрицы обнаружения",
		Note: "Строки матрицы ТЗ 5.16, по которым в запуске были сценарии, и итоги по ним.",
		Header: []string{"Строка", "Сценариев", VerdictTitle(VerdictSucceeded), VerdictTitle(VerdictBlocked), VerdictTitle(VerdictDefended),
			VerdictTitle(VerdictUnchecked), VerdictTitle(VerdictError), VerdictTitle(VerdictSkipped)}}
	for _, c := range Coverage(results) {
		row := []reports.Cell{reports.T(c.Threat), reports.N(int64(c.Total))}
		for _, v := range Verdicts {
			row = append(row, reports.N(int64(c.Counts[v])))
		}
		cov.Rows = append(cov.Rows, row)
	}
	d.Sections = append(d.Sections, cov)

	hdr := []string{"Сценарий", "Название", "Язык", "Строка", "Категория", "Шаг", "Сработавшие условия", "Находки", "События шлюза"}
	if o.Examples {
		hdr = append(hdr, "Выдержка ответа")
	}
	win := reports.Section{Title: "Атаки, которые удались", Header: hdr,
		Note: "Каждая строка — уязвимость, которую стоит закрыть: усилить политику приложения или системный промпт и повторить запуск."}
	for _, r := range results {
		if r.Verdict != VerdictSucceeded {
			continue
		}
		row := []reports.Cell{reports.T(r.ScenarioID), reports.T(o.Titles[r.ScenarioID]), reports.T(r.Lang), reports.T(r.Threat),
			reports.T(r.Category), reports.N(int64(r.Step)), reports.T(strings.Join(r.Matched, ", ")), reports.T(findingList(r.Findings)),
			reports.T(strings.Join(r.EventIDs, ", "))}
		if o.Examples {
			row = append(row, reports.T(r.Example))
		}
		win.Rows = append(win.Rows, row)
	}
	d.Sections = append(d.Sections, win)

	all := reports.Section{Title: "Все сценарии",
		Header: []string{"Сценарий", "Название", "Язык", "Строка", "Категория", "Итог", "Шаг", "Код ответа", "Ошибка", "Время, мс"}}
	for _, r := range results {
		code := reports.T("")
		if r.HTTPStatus != 0 {
			code = reports.N(int64(r.HTTPStatus))
		}
		errText := ""
		if r.ErrorCode != "" {
			errText = ErrorTitle(r.ErrorCode)
		}
		all.Rows = append(all.Rows, []reports.Cell{reports.T(r.ScenarioID), reports.T(o.Titles[r.ScenarioID]), reports.T(r.Lang), reports.T(r.Threat),
			reports.T(r.Category), reports.T(VerdictTitle(r.Verdict)), reports.N(int64(r.Step)), code, reports.T(errText), reports.N(r.LatencyMS)})
	}
	d.Sections = append(d.Sections, all)
	return d
}
