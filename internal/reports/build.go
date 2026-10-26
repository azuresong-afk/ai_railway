package reports

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/incidents"
)

// Dash — чтение агрегатов дашбордов (*events.DashStore). Других источников
// событий у отчётов нет: содержимого запросов и ответов они не читают.
type Dash interface {
	Totals(ctx context.Context, q events.DashQuery) (events.DashTotals, error)
	Latency(ctx context.Context, q events.DashQuery) (events.DashLatency, error)
	TopFindings(ctx context.Context, q events.DashQuery, dim, prefix string, limit int) ([]events.DashTop, error)
	PIIBreakdown(ctx context.Context, q events.DashQuery) ([]events.DashPIIRow, error)
	RequestsBy(ctx context.Context, q events.DashQuery, dim string, limit int) ([]events.DashRequestRow, error)
}

// IncidentSource — список инцидентов (*incidents.Service).
type IncidentSource interface {
	List(ctx context.Context, q incidents.Query) ([]incidents.Incident, error)
}

// AlertSource — список оповещений (*alerting.Service).
type AlertSource interface {
	Alerts(ctx context.Context, q alerting.AlertQuery) ([]alerting.Alert, error)
}

// MarkStats — отметки аналитиков за период (задача 3.22).
type MarkStats struct {
	FalsePositive int64
	Confirmed     int64
	// FalseByThreat — ложные срабатывания по строкам матрицы обнаружения.
	FalseByThreat []events.DashTop
}

// Inventory — что подключено.
type Inventory struct {
	Apps          int
	AppsByEnv     map[string]int
	Providers     int
	ExternalProvs int
	Gateways      int
	// ExceptionsActive и ExceptionsExpired — исключения текущих версий политик.
	ExceptionsActive  int
	ExceptionsExpired int
}

// BudgetLine — исполнение бюджета приложения за месяц.
type BudgetLine struct {
	App       string
	Mode      string
	Limit     string
	Spent     string
	Percent   int64
	Exhausted bool
}

// Facts — остальные сведения отчётов (отметки, состав установки, бюджеты).
type Facts interface {
	Marks(ctx context.Context, from, to time.Time, app string) (MarkStats, error)
	Inventory(ctx context.Context) (Inventory, error)
	// Budgets — бюджеты за месяц YYYY-MM часового пояса установки.
	Budgets(ctx context.Context, month string) ([]BudgetLine, error)
}

// Scope — что вызывающему можно увидеть в отчёте.
type Scope struct {
	// Budgets — разрешено читать бюджеты (budgets.read на все объекты).
	Budgets bool
}

// Builder собирает отчёты из источников.
type Builder struct {
	Dash      Dash
	Incidents IncidentSource
	Alerts    AlertSource
	Facts     Facts
	// Now — часы; nil — time.Now.
	Now func() time.Time
}

func (b *Builder) now() time.Time {
	if b.Now != nil {
		return b.Now().UTC()
	}
	return time.Now().UTC()
}

// ErrNoSource — источник данных отчёта не подключён.
var ErrNoSource = errors.New("отчёты: источник данных не подключён")

// Build строит отчёт вида p.Kind.
func (b *Builder) Build(ctx context.Context, p Params, sc Scope) (Doc, error) {
	if b.Dash == nil || b.Incidents == nil || b.Alerts == nil || b.Facts == nil {
		return Doc{}, ErrNoSource
	}
	meta := b.meta(p)
	switch p.Kind {
	case KindSummary:
		return b.summary(ctx, p, sc, meta)
	case KindIncidents:
		return b.incidentsReport(ctx, p, meta)
	case KindPilot:
		return b.pilot(ctx, p, meta)
	}
	return Doc{}, errors.New("отчёты: неизвестный вид отчёта")
}

func (b *Builder) meta(p Params) [][2]string {
	app := "все приложения"
	if p.App != "" {
		app = p.App
	}
	tz := "UTC"
	if p.Period.Loc != nil {
		tz = p.Period.Loc.String()
	}
	return [][2]string{
		{"Период", p.Period.Label()},
		{"Часовой пояс", tz},
		{"Приложения", app},
		{"Сформирован", fmtTime(b.now(), p.Period.Loc)},
	}
}

func fmtTime(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return ""
	}
	if loc == nil {
		loc = time.UTC
	}
	return t.In(loc).Format("02.01.2006 15:04")
}

func (p Params) query() events.DashQuery {
	tz := "UTC"
	if p.Period.Loc != nil {
		tz = p.Period.Loc.String()
	}
	return events.DashQuery{From: p.Period.From, To: p.Period.To, App: p.App, TZ: tz}
}

func tops(rows []events.DashTop) [][]Cell {
	out := make([][]Cell, 0, len(rows))
	for _, r := range rows {
		out = append(out, []Cell{T(r.Key), N(r.Value)})
	}
	return out
}

func requestRows(rows []events.DashRequestRow) [][]Cell {
	out := make([][]Cell, 0, len(rows))
	for _, r := range rows {
		out = append(out, []Cell{T(r.Key), N(r.Requests), N(r.WithFindings), N(r.Blocked), N(r.WouldBlock), N(r.Masked),
			N(r.TokensPrompt + r.TokensCompletion), D(apps.FormatCost(r.Cost))})
	}
	return out
}

var requestHeader = []string{"Ключ", "Запросов", "С находками", "Заблокировано", "Заблокировало бы (мониторинг)",
	"Замаскировано", "Токенов", "Стоимость, ₽"}

func with(h []string, first string) []string {
	out := append([]string(nil), h...)
	out[0] = first
	return out
}

func p95(l events.DashLatency) string {
	switch {
	case l.Total == 0:
		return "нет данных"
	case l.P95 == events.DashLatencyOverflow:
		return "больше " + strconv.Itoa(events.DashLatencyBounds[len(events.DashLatencyBounds)-1]) + " мс"
	}
	return strconv.Itoa(l.P95) + " мс"
}

func totalsRows(t events.DashTotals, l events.DashLatency) [][]Cell {
	return [][]Cell{
		{T("Запросов проверено"), N(t.Requests)},
		{T("Запросов с находками"), N(t.WithFindings)},
		{T("Заблокировано (режим защиты)"), N(t.Blocked)},
		{T("Было бы заблокировано (режим мониторинга)"), N(t.WouldBlock)},
		{T("Замаскировано"), N(t.Masked)},
		{T("С непроверенным нетекстовым содержимым"), N(t.NonTextUnchecked)},
		{T("Токенов во входе"), N(t.TokensPrompt)},
		{T("Токенов в ответах"), N(t.TokensCompletion)},
		{T("Оценка стоимости, ₽"), D(apps.FormatCost(t.Cost))},
		{T("Запросов моделей без цены"), N(t.UnpricedRequests)},
		{T("Задержка шлюза, 95-й процентиль"), T(p95(l))},
	}
}

// aggregates читает общие агрегаты периода.
type aggregates struct {
	totals  events.DashTotals
	latency events.DashLatency
}

func (b *Builder) aggregates(ctx context.Context, q events.DashQuery) (aggregates, error) {
	t, err := b.Dash.Totals(ctx, q)
	if err != nil {
		return aggregates{}, fmt.Errorf("отчёты: итоги периода: %w", err)
	}
	l, err := b.Dash.Latency(ctx, q)
	if err != nil {
		return aggregates{}, fmt.Errorf("отчёты: задержка: %w", err)
	}
	return aggregates{totals: t, latency: l}, nil
}

func (b *Builder) summary(ctx context.Context, p Params, sc Scope, meta [][2]string) (Doc, error) {
	q := p.query()
	ag, err := b.aggregates(ctx, q)
	if err != nil {
		return Doc{}, err
	}
	d := Doc{Kind: KindSummary, Title: Title(KindSummary), Meta: meta}
	d.Sections = append(d.Sections, Section{Title: "Итоги периода", Header: []string{"Показатель", "Значение"},
		Rows: totalsRows(ag.totals, ag.latency)})
	byApp, err := b.Dash.RequestsBy(ctx, q, events.DimApp, TopRows)
	if err != nil {
		return Doc{}, fmt.Errorf("отчёты: запросы по приложениям: %w", err)
	}
	d.Sections = append(d.Sections, Section{Title: "Запросы по приложениям", Header: with(requestHeader, "Приложение"), Rows: requestRows(byApp)})
	for _, f := range []struct{ title, dim string }{
		{"Находки по строкам матрицы обнаружения", events.DimThreat},
		{"Находки по категориям", events.DimCategory},
		{"Находки по детекторам", events.DimDetector},
	} {
		rows, err := b.Dash.TopFindings(ctx, q, f.dim, "", TopRows)
		if err != nil {
			return Doc{}, fmt.Errorf("отчёты: находки: %w", err)
		}
		d.Sections = append(d.Sections, Section{Title: f.title, Header: []string{"Ключ", "Находок"}, Rows: tops(rows)})
	}
	byModel, err := b.Dash.RequestsBy(ctx, q, events.DimModel, TopRows)
	if err != nil {
		return Doc{}, fmt.Errorf("отчёты: запросы по моделям: %w", err)
	}
	d.Sections = append(d.Sections, Section{Title: "Потребление по моделям", Header: with(requestHeader, "Модель"), Rows: requestRows(byModel)})
	if p.App != "" {
		d.Sections = append(d.Sections, Section{Title: "Инциденты, оповещения и бюджеты",
			Note: "Отчёт по одному приложению: инциденты, оповещения и бюджеты в нём не приводятся, они относятся ко всей установке."})
		return d, nil
	}
	inc, err := b.incidentStats(ctx, p.Period)
	if err != nil {
		return Doc{}, err
	}
	d.Sections = append(d.Sections, inc.section())
	al, err := b.alertSection(ctx, p.Period)
	if err != nil {
		return Doc{}, err
	}
	d.Sections = append(d.Sections, al)
	if sc.Budgets {
		bl, err := b.Facts.Budgets(ctx, monthOf(p.Period))
		if err != nil {
			return Doc{}, fmt.Errorf("отчёты: бюджеты: %w", err)
		}
		d.Sections = append(d.Sections, budgetSection(bl, monthOf(p.Period)))
	}
	return d, nil
}

// monthOf — месяц последнего дня периода, YYYY-MM.
func monthOf(p Period) string { return p.Last[:7] }

func budgetSection(bl []BudgetLine, month string) Section {
	s := Section{Title: "Исполнение бюджетов за " + month, Header: []string{"Приложение", "Режим", "Бюджет, ₽", "Расход, ₽", "Исполнено, %", "Исчерпан"}}
	for _, l := range bl {
		limit, mode := T("не задан"), T("—")
		if l.Limit != "" {
			limit, mode = D(l.Limit), T(budgetMode(l.Mode))
		}
		s.Rows = append(s.Rows, []Cell{T(l.App), mode, limit, D(l.Spent), N(l.Percent), T(yesNo(l.Exhausted))})
	}
	return s
}

func budgetMode(m string) string {
	switch m {
	case "hard":
		return "жёсткий"
	case "soft":
		return "мягкий"
	}
	return m
}

func yesNo(b bool) string {
	if b {
		return "да"
	}
	return "нет"
}

// Состав инцидентов периода.
type incidentStats struct {
	all       []incidents.Incident
	truncated bool
	loc       *time.Location
}

// scanIncidents читает инциденты, созданные в периоде [From, To): список идёт от
// новых к старым, чтение останавливается на первом старше периода.
func (b *Builder) scanIncidents(ctx context.Context, per Period) (incidentStats, error) {
	st := incidentStats{loc: per.Loc}
	var after *incidents.Position
	for {
		page, err := b.Incidents.List(ctx, incidents.Query{After: after, Limit: incidents.MaxListLimit})
		if err != nil {
			return st, fmt.Errorf("отчёты: инциденты: %w", err)
		}
		for _, in := range page {
			switch {
			case !in.CreatedAt.Before(per.To):
			case in.CreatedAt.Before(per.From):
				return st, nil
			default:
				if len(st.all) >= MaxScan {
					st.truncated = true
					return st, nil
				}
				st.all = append(st.all, in)
			}
		}
		if len(page) < incidents.MaxListLimit {
			return st, nil
		}
		last := page[len(page)-1]
		after = &incidents.Position{CreatedAt: last.CreatedAt, ID: last.ID}
	}
}

func (b *Builder) incidentStats(ctx context.Context, per Period) (incidentStats, error) {
	return b.scanIncidents(ctx, per)
}

var severityRu = map[string]string{"critical": "критическая", "high": "высокая", "medium": "средняя", "low": "низкая", "info": "информация"}

var severityOrder = []string{"critical", "high", "medium", "low", "info"}

var statusRu = map[string]string{incidents.StatusNew: "новый", incidents.StatusInProgress: "в работе",
	incidents.StatusContained: "локализован", incidents.StatusClosed: "закрыт"}

var resolutionRu = map[string]string{incidents.ResolutionResolved: "устранён", incidents.ResolutionFalsePositive: "ложное срабатывание",
	incidents.ResolutionRiskAccepted: "риск принят"}

func ru(m map[string]string, k string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return k
}

// section — краткая сводка инцидентов для сводного отчёта.
func (s incidentStats) section() Section {
	sec := Section{Title: "Инциденты за период", Header: []string{"Показатель", "Значение"}}
	bySev := map[string]int64{}
	byStatus := map[string]int64{}
	for _, in := range s.all {
		bySev[in.Severity]++
		byStatus[in.Status]++
	}
	sec.Rows = append(sec.Rows, []Cell{T("Создано инцидентов"), N(int64(len(s.all)))})
	for _, st := range incidents.Statuses() {
		sec.Rows = append(sec.Rows, []Cell{T("Статус: " + ru(statusRu, st)), N(byStatus[st])})
	}
	for _, sv := range severityOrder {
		sec.Rows = append(sec.Rows, []Cell{T("Серьёзность: " + ru(severityRu, sv)), N(bySev[sv])})
	}
	if s.truncated {
		sec.Note = fmt.Sprintf("Показаны первые %d инцидентов периода: сузьте период.", MaxScan)
	}
	return sec
}

func (b *Builder) incidentsReport(ctx context.Context, p Params, meta [][2]string) (Doc, error) {
	st, err := b.scanIncidents(ctx, p.Period)
	if err != nil {
		return Doc{}, err
	}
	d := Doc{Kind: KindIncidents, Title: Title(KindIncidents), Meta: meta}
	d.Sections = append(d.Sections, st.section())
	byCat := map[string]int64{}
	var reacted, reactedN int64
	var overdue int64
	for _, in := range st.all {
		byCat[in.Category]++
		if !in.ReactedAt.IsZero() {
			reacted += int64(in.ReactedAt.Sub(in.CreatedAt) / time.Minute)
			reactedN++
		}
		if in.Overdue(b.now()) || !in.ReactedAt.IsZero() && in.ReactedAt.After(in.ReactionDueAt) {
			overdue++
		}
	}
	cats := make([]events.DashTop, 0, len(byCat))
	for k, v := range byCat {
		cats = append(cats, events.DashTop{Key: k, Value: v})
	}
	sort.Slice(cats, func(i, j int) bool {
		if cats[i].Value != cats[j].Value {
			return cats[i].Value > cats[j].Value
		}
		return cats[i].Key < cats[j].Key
	})
	d.Sections = append(d.Sections, Section{Title: "Инциденты по категориям", Header: []string{"Категория", "Инцидентов"}, Rows: tops(cats)})
	react := "нет данных"
	if reactedN > 0 {
		react = strconv.FormatInt(reacted/reactedN, 10) + " мин"
	}
	d.Sections = append(d.Sections, Section{Title: "Реакция", Header: []string{"Показатель", "Значение"}, Rows: [][]Cell{
		{T("Среднее время до принятия в работу"), T(react)},
		{T("С нарушенным сроком реакции"), N(overdue)},
	}})
	list := Section{Title: "Список инцидентов", Header: []string{"№", "Название", "Серьёзность", "Категория", "Статус", "Резолюция",
		"Создан", "Принят в работу", "Закрыт"}}
	for i, in := range st.all {
		if i >= MaxIncidentRows {
			list.Note = fmt.Sprintf("Показаны первые %d инцидентов из %d: сузьте период.", MaxIncidentRows, len(st.all))
			break
		}
		list.Rows = append(list.Rows, []Cell{N(in.Number), T(in.Title), T(ru(severityRu, in.Severity)), T(in.Category),
			T(ru(statusRu, in.Status)), T(ru(resolutionRu, in.Resolution)), T(fmtTime(in.CreatedAt, p.Period.Loc)),
			T(fmtTime(in.ReactedAt, p.Period.Loc)), T(fmtTime(in.ClosedAt, p.Period.Loc))})
	}
	d.Sections = append(d.Sections, list)
	return d, nil
}

func (b *Builder) alertSection(ctx context.Context, per Period) (Section, error) {
	sec := Section{Title: "Оповещения за период", Header: []string{"Показатель", "Значение"}}
	bySev := map[string]int64{}
	var total int64
	var after *alerting.Position
	for {
		page, err := b.Alerts.Alerts(ctx, alerting.AlertQuery{From: per.From, To: per.To, After: after, Limit: 200})
		if err != nil {
			return sec, fmt.Errorf("отчёты: оповещения: %w", err)
		}
		for _, a := range page {
			total++
			bySev[a.Severity]++
		}
		if len(page) < 200 || total >= MaxScan {
			if total >= MaxScan {
				sec.Note = fmt.Sprintf("Учтены первые %d оповещений периода.", MaxScan)
			}
			break
		}
		last := page[len(page)-1]
		after = &alerting.Position{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	sec.Rows = append(sec.Rows, []Cell{T("Оповещений"), N(total)})
	for _, sv := range severityOrder {
		sec.Rows = append(sec.Rows, []Cell{T("Серьёзность: " + ru(severityRu, sv)), N(bySev[sv])})
	}
	return sec, nil
}

// pilot — «Итоги пилота» (сценарий S10): что подключено, сколько проверено,
// что найдено, ложные срабатывания и исключения, инциденты, стоимость,
// рекомендации по шаблону.
func (b *Builder) pilot(ctx context.Context, p Params, meta [][2]string) (Doc, error) {
	q := p.query()
	ag, err := b.aggregates(ctx, q)
	if err != nil {
		return Doc{}, err
	}
	inv, err := b.Facts.Inventory(ctx)
	if err != nil {
		return Doc{}, fmt.Errorf("отчёты: состав установки: %w", err)
	}
	d := Doc{Kind: KindPilot, Title: Title(KindPilot), Meta: meta}
	envs := ""
	for _, e := range sortedKeys(inv.AppsByEnv) {
		if envs != "" {
			envs += ", "
		}
		envs += e + " — " + strconv.Itoa(inv.AppsByEnv[e])
	}
	d.Sections = append(d.Sections, Section{Title: "Что подключено", Header: []string{"Показатель", "Значение"}, Rows: [][]Cell{
		{T("Приложений"), N(int64(inv.Apps))},
		{T("Приложения по средам"), T(envs)},
		{T("Провайдеров LLM (из них внешних)"), T(strconv.Itoa(inv.Providers) + " (" + strconv.Itoa(inv.ExternalProvs) + ")")},
		{T("Шлюзов"), N(int64(inv.Gateways))},
	}})
	d.Sections = append(d.Sections, Section{Title: "Сколько проверено", Header: []string{"Показатель", "Значение"}, Rows: totalsRows(ag.totals, ag.latency)})
	threats, err := b.Dash.TopFindings(ctx, q, events.DimThreat, "", events.DashMaxTop)
	if err != nil {
		return Doc{}, fmt.Errorf("отчёты: находки: %w", err)
	}
	d.Sections = append(d.Sections, Section{Title: "Что найдено по строкам матрицы обнаружения", Header: []string{"Строка матрицы", "Находок"}, Rows: tops(threats)})

	pii, err := b.Dash.PIIBreakdown(ctx, q)
	if err != nil {
		return Doc{}, fmt.Errorf("отчёты: ПДн: %w", err)
	}
	d.Sections = append(d.Sections, piiSection(pii))
	secrets, err := b.Dash.TopFindings(ctx, q, events.DimCategory, "secret.", events.DashMaxTop)
	if err != nil {
		return Doc{}, fmt.Errorf("отчёты: секреты: %w", err)
	}
	d.Sections = append(d.Sections, Section{Title: "Секреты в запросах", Note: "Ключи, токены и закрытые ключи, найденные в запросах и ответах.",
		Header: []string{"Категория", "Находок"}, Rows: tops(secrets)})
	attacks, err := b.Dash.TopFindings(ctx, q, events.DimCategory, "injection.", events.DashMaxTop)
	if err != nil {
		return Doc{}, fmt.Errorf("отчёты: атаки: %w", err)
	}
	d.Sections = append(d.Sections, Section{Title: "Обнаруженные атаки на модель", Header: []string{"Категория", "Находок"}, Rows: tops(attacks)})

	mk, err := b.Facts.Marks(ctx, p.Period.From, p.Period.To, p.App)
	if err != nil {
		return Doc{}, fmt.Errorf("отчёты: отметки: %w", err)
	}
	fpShare := "нет данных"
	if ag.totals.WithFindings > 0 {
		fpShare = strconv.FormatInt(mk.FalsePositive*100/ag.totals.WithFindings, 10) + " %"
	}
	d.Sections = append(d.Sections, Section{Title: "Ложные срабатывания и исключения", Header: []string{"Показатель", "Значение"}, Rows: [][]Cell{
		{T("События, отмеченные как ложное срабатывание"), N(mk.FalsePositive)},
		{T("События, подтверждённые аналитиком"), N(mk.Confirmed)},
		{T("Доля ложных срабатываний среди запросов с находками"), T(fpShare)},
		{T("Исключений в действующих политиках"), N(int64(inv.ExceptionsActive))},
		{T("Исключений с истёкшим сроком"), N(int64(inv.ExceptionsExpired))},
	}})
	if len(mk.FalseByThreat) > 0 {
		d.Sections = append(d.Sections, Section{Title: "Ложные срабатывания по строкам матрицы", Header: []string{"Строка матрицы", "Событий"}, Rows: tops(mk.FalseByThreat)})
	}

	st, err := b.scanIncidents(ctx, p.Period)
	if err != nil {
		return Doc{}, err
	}
	sec := st.section()
	sec.Title = "Инциденты"
	d.Sections = append(d.Sections, sec)

	byModel, err := b.Dash.RequestsBy(ctx, q, events.DimModel, TopRows)
	if err != nil {
		return Doc{}, fmt.Errorf("отчёты: запросы по моделям: %w", err)
	}
	d.Sections = append(d.Sections, Section{Title: "Стоимость по моделям",
		Note:   "Оценка по ценам моделей, которые заполнил администратор; запросы моделей без цены не оценены.",
		Header: with(requestHeader, "Модель"), Rows: requestRows(byModel)})

	d.Sections = append(d.Sections, Section{Title: "Рекомендации", Rows: recommendations(ag.totals, mk, inv, st)})
	return d, nil
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// piiSection — ПДн по типам: сколько найдено и сколько ушло бы провайдеру
// без защиты (действие allow или log).
func piiSection(rows []events.DashPIIRow) Section {
	type agg struct{ total, open int64 }
	m := map[string]*agg{}
	for _, r := range rows {
		a := m[r.Category]
		if a == nil {
			a = &agg{}
			m[r.Category] = a
		}
		a.total += r.Findings
		if r.Action == "allow" || r.Action == "log" {
			a.open += r.Findings
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]].total != m[keys[j]].total {
			return m[keys[i]].total > m[keys[j]].total
		}
		return keys[i] < keys[j]
	})
	s := Section{Title: "Персональные данные в запросах",
		Note:   "«Без защиты» — находки в запросах, которые были пропущены или только записаны (действие «разрешить» или «записать»): такие данные ушли бы провайдеру.",
		Header: []string{"Тип", "Находок", "Без защиты"}}
	for _, k := range keys {
		s.Rows = append(s.Rows, []Cell{T(k), N(m[k].total), N(m[k].open)})
	}
	return s
}

// recommendations — шаблонный текст по цифрам периода.
func recommendations(t events.DashTotals, mk MarkStats, inv Inventory, st incidentStats) [][]Cell {
	var out [][]Cell
	add := func(s string) { out = append(out, []Cell{T(s)}) }
	if t.Requests == 0 {
		add("За период нет проверенных запросов: проверьте, что приложения направляют трафик через шлюз.")
	}
	if t.WouldBlock > 0 {
		add(fmt.Sprintf("В режиме мониторинга %d запросов были бы заблокированы. Разберите их и переведите приложения в режим защиты, когда ложных срабатываний не останется.", t.WouldBlock))
	}
	if t.NonTextUnchecked > 0 {
		add(fmt.Sprintf("%d запросов содержали изображения или аудио, которые не проверялись: учитывайте это при оценке рисков.", t.NonTextUnchecked))
	}
	if mk.FalsePositive > 0 {
		add("Есть события, отмеченные как ложные срабатывания: добавьте исключения или уточните правила, чтобы они не повторялись.")
	}
	if inv.ExceptionsExpired > 0 {
		add("В политиках остались исключения с истёкшим сроком: продлите нужные и удалите лишние.")
	}
	if t.UnpricedRequests > 0 {
		add("Часть запросов относится к моделям без цены: заполните таблицу цен, чтобы стоимость была полной.")
	}
	open := 0
	for _, in := range st.all {
		if in.Status != incidents.StatusClosed {
			open++
		}
	}
	if open > 0 {
		add(fmt.Sprintf("Не закрыто инцидентов: %d. Назначьте ответственных и закройте их с резолюцией.", open))
	}
	if len(out) == 0 {
		add("Существенных замечаний по итогам периода нет: продолжайте наблюдение в режиме защиты.")
	}
	return out
}
