package reports

import (
	"context"
	"fmt"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/compliance"
)

// ComplianceSource — вычисление статусов соответствия (*compliance.Service).
type ComplianceSource interface {
	Evaluate(ctx context.Context, f compliance.Filter) (compliance.Overview, error)
}

// Отчёт «Соответствие требованиям» (ТЗ 5.9, сценарий S7; задача 4.25):
// для аттестационных испытаний и аудита ИСПДн. Пункты с источником,
// статусом, результатом проверок, доказательствами, ручными отметками и
// их датой; пункты из проектов документов — отдельным разделом и вне
// процента. Содержимого запросов и ответов в отчёте нет: только настройки,
// счётчики и ссылки на экраны консоли.
func (b *Builder) complianceReport(ctx context.Context, p Params) (Doc, error) {
	if b.Compliance == nil {
		return Doc{}, ErrNoSource
	}
	o, err := b.Compliance.Evaluate(ctx, compliance.Filter{})
	if err != nil {
		return Doc{}, err
	}
	tz := "UTC"
	if p.Period.Loc != nil {
		tz = p.Period.Loc.String()
	}
	origin := "встроенная"
	if o.Base.Origin == "uploaded" {
		origin = "загруженная подписанная"
	}
	percent := "нет пунктов для расчёта"
	if o.Summary.Percent != nil {
		percent = fmt.Sprintf("%d %% (учтено пунктов: %d; пункты из проектов документов и «не применимо» не входят)", *o.Summary.Percent, o.Summary.Counted)
	}
	d := Doc{Kind: KindCompliance, Title: Title(KindCompliance), Meta: [][2]string{
		{"Состояние на", fmtTime(o.GeneratedAt, p.Period.Loc)},
		{"Часовой пояс", tz},
		{"База требований", fmt.Sprintf("версия %d от %s, %s", o.Base.Version, o.Base.Date, origin)},
		{"Итог соответствия", percent},
	}}
	c := o.Summary.Counts
	d.Sections = append(d.Sections, Section{Title: "Сводка", Header: []string{"Показатель", "Пунктов"}, Rows: [][]Cell{
		{T(compliance.StatusTitle(compliance.StatusMet)), N(int64(c.Met))},
		{T(compliance.StatusTitle(compliance.StatusPartial)), N(int64(c.Partial))},
		{T(compliance.StatusTitle(compliance.StatusNotMet)), N(int64(c.NotMet))},
		{T(compliance.StatusTitle(compliance.StatusNotApplicable)), N(int64(c.NotApplicable))},
		{T(compliance.StatusTitle(compliance.StatusManual)), N(int64(c.Manual))},
		{T("Из проектов документов (отдельно, вне процента)"), N(int64(o.Summary.Drafts))},
	}})
	if len(o.Unavailable) > 0 {
		d.Sections[0].Note = "Часть сведений не удалось прочитать при формировании отчёта: " + strings.Join(o.Unavailable, ", ") +
			". Проверки, которым они нужны, не засчитаны."
	}
	header := []string{"ID", "Источник", "Пункт", "Требование", "Применимость", "Статус", "Результат проверок", "Ручная отметка", "Доказательства"}
	var regular, drafts [][]Cell
	for _, it := range o.Items {
		row := complianceRow(it, p)
		if it.Draft {
			drafts = append(drafts, row)
		} else {
			regular = append(regular, row)
		}
	}
	d.Sections = append(d.Sections, Section{Title: "Требования", Header: header, Rows: regular})
	d.Sections = append(d.Sections, Section{Title: "Требования из проектов документов",
		Note:   "Проекты не вступили в силу: пункты показаны для подготовки и в итоговый процент не входят.",
		Header: header, Rows: drafts})
	return d, nil
}

func complianceRow(it compliance.Item, p Params) []Cell {
	applies := make([]string, 0, len(it.Applies))
	for _, a := range it.Applies {
		applies = append(applies, compliance.ApplicabilityTitle(a))
	}
	checks := make([]string, 0, len(it.Checks))
	for _, ch := range it.Checks {
		checks = append(checks, ch.Detail)
	}
	check := strings.Join(checks, "; ")
	if check == "" {
		check = "автоматических проверок нет"
	}
	mark := "нет"
	if m := it.Mark; m != nil {
		mark = fmt.Sprintf("%s: %s", compliance.StatusTitle(m.Status), m.Comment)
		if m.Document != "" {
			mark += " (документ: " + m.Document + ")"
		}
		mark += " — " + fmtTime(m.SetAt, p.Period.Loc)
		if m.ReviewBy != "" {
			mark += ", пересмотр до " + m.ReviewBy
		}
		if it.MarkOverdue {
			mark += " — СРОК ПЕРЕСМОТРА ИСТЁК, отметка не засчитана"
		}
	}
	ev := make([]string, 0, len(it.Evidence))
	for _, e := range it.Evidence {
		s := e.Title + " [раздел консоли " + e.Path + "]"
		if e.Hint != "" {
			s += ", " + e.Hint
		}
		if f := e.Query["f"]; f != "" {
			s += ", фильтр событий: " + f
		}
		ev = append(ev, s)
	}
	return []Cell{T(it.ID), T(it.SourceTitle), T(it.Clause), T(it.Title), T(strings.Join(applies, ", ")),
		T(compliance.StatusTitle(it.Status)), T(check), T(mark), T(strings.Join(ev, "; "))}
}
