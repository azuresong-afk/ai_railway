package gateway

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	// База часовых поясов встроена в бинарник: в образе шлюза её нет, а
	// месяц расхода считается в часовом поясе установки.
	_ "time/tzdata"

	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Учёт расхода и жёсткие бюджеты приложений (ТЗ 5.8, 4.2; решение Р7
// этапа 3, задача 3.18). Шлюз считает расход каждого запроса, ушедшего
// провайдеру, по ценам раздела budgets пакета и хранит нарастающие
// счётчики процесса по месяцам в часовом поясе установки. Расход остальных
// процессов и шлюзов приходит в ответе heartbeat; запросы приложения с
// жёстким бюджетом отклоняются, когда свой расход и чужой вместе достигли
// бюджета. До первого ответа сервера после запуска чужой расход неизвестен
// и не учитывается: шлюз работает автономно (ТЗ 4.2), бюджет может быть
// превышен на расход, не дошедший до сервера.

const (
	// ruleBudget — правило отказа по исчерпанному жёсткому бюджету.
	ruleBudget = "budget.hard"
	// maxBudgetApps — приложений в месяце счётчиков (bundle.MaxApplications).
	maxBudgetApps = bundle.MaxApplications
	// maxBudgetCounter — предел счётчика в heartbeat (gwregistry).
	maxBudgetCounter = 1 << 62
)

// Budget — счётчики расхода процесса шлюза и жёсткие бюджеты. Безопасен
// для одновременного использования.
type Budget struct {
	now func() time.Time

	mu sync.Mutex
	// on — в пакете есть раздел budgets: расход считается и уходит в
	// heartbeat.
	on     bool
	loc    *time.Location
	prices map[priceKey]bundle.ModelPrice
	hard   map[string]int64
	// months — месяц «ГГГГ-ММ» → приложение → счётчики процесса.
	months map[string]map[string]*budgetUsage
	// others — расход остальных процессов за месяц othersMonth.
	others      map[string]int64
	othersMonth string
}

type priceKey struct{ provider, model string }

// budgetUsage — счётчики приложения за месяц (поля heartbeat).
type budgetUsage struct {
	App              string `json:"app"`
	Cost             int64  `json:"cost"`
	PricedTokens     int64  `json:"priced_tokens"`
	UnpricedTokens   int64  `json:"unpriced_tokens"`
	Requests         int64  `json:"requests"`
	UnpricedRequests int64  `json:"unpriced_requests"`
}

// budgetMonth и budgetReport — раздел budget heartbeat.
type budgetMonth struct {
	Month string        `json:"month"`
	Apps  []budgetUsage `json:"apps"`
}

type budgetReport struct {
	Months []budgetMonth `json:"months"`
}

// budgetState — раздел budget ответа heartbeat.
type budgetState struct {
	Month  string           `json:"month"`
	Others map[string]int64 `json:"others"`
}

// NewBudget — учёт расхода без раздела budgets: ничего не считается и не
// отклоняется до Reconfigure. now — часы; nil — time.Now.
func NewBudget(now func() time.Time) *Budget {
	if now == nil {
		now = time.Now
	}
	return &Budget{now: now, months: map[string]map[string]*budgetUsage{}}
}

// Reconfigure применяет раздел budgets нового пакета; nil — раздела нет:
// расход не считается, бюджеты не применяются. Счётчики процесса
// сохраняются: они нарастающие с запуска.
func (b *Budget) Reconfigure(sec *bundle.Budgets) error {
	if sec == nil {
		b.mu.Lock()
		b.on, b.prices, b.hard = false, nil, nil
		b.mu.Unlock()
		return nil
	}
	loc, err := bundle.LoadLocation(sec.Timezone)
	if err != nil {
		return errors.New("бюджеты: " + err.Error())
	}
	prices := make(map[priceKey]bundle.ModelPrice, len(sec.Prices))
	for _, p := range sec.Prices {
		prices[priceKey{p.Provider, p.Model}] = p
	}
	hard := make(map[string]int64, len(sec.Hard))
	for _, h := range sec.Hard {
		hard[h.App] = h.Limit
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.on, b.loc, b.prices, b.hard = true, loc, prices, hard
	return nil
}

// Exhausted сообщает, исчерпан ли жёсткий бюджет приложения в текущем
// месяце (расход не меньше бюджета: ровно 100 % — исчерпан), и сколько
// ждать начала следующего месяца.
func (b *Budget) Exhausted(app string) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit, ok := b.hard[app]
	if !b.on || !ok {
		return false, 0
	}
	now := b.now()
	month := bundle.Month(now, b.loc)
	spent := int64(0)
	if u := b.months[month][app]; u != nil {
		spent = u.Cost
	}
	if b.othersMonth == month {
		spent = bundle.AddCost(spent, b.others[app])
	}
	if spent < limit {
		return false, 0
	}
	return true, bundle.NextMonth(now, b.loc).Sub(now)
}

// Record учитывает запрос приложения, ушедший провайдеру: расход по цене
// модели или, если цены нет, токены и запрос «без цены» — стоимость не
// определена, запрос не отклоняется.
func (b *Budget) Record(app, provider, model string, input, output int64) {
	input, output = max(input, 0), max(output, 0)
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.on {
		return
	}
	month := bundle.Month(b.now(), b.loc)
	m := b.months[month]
	if m == nil {
		m = map[string]*budgetUsage{}
		b.months[month] = m
		b.prune(month)
	}
	u := m[app]
	if u == nil {
		if len(m) >= maxBudgetApps {
			return
		}
		u = &budgetUsage{App: app}
		m[app] = u
	}
	u.Requests = bundle.AddCost(u.Requests, 1)
	tokens := bundle.AddCost(input, output)
	p, ok := b.prices[priceKey{provider, model}]
	if !ok {
		u.UnpricedRequests = bundle.AddCost(u.UnpricedRequests, 1)
		u.UnpricedTokens = bundle.AddCost(u.UnpricedTokens, tokens)
		return
	}
	u.PricedTokens = bundle.AddCost(u.PricedTokens, tokens)
	u.Cost = bundle.AddCost(u.Cost, bundle.Cost(p, input, output))
}

// prune оставляет счётчики текущего месяца и предыдущего (он уходит на
// сервер, пока сервер не подтвердит его приём).
func (b *Budget) prune(current string) {
	months := make([]string, 0, len(b.months))
	for m := range b.months {
		months = append(months, m)
	}
	slices.Sort(months)
	for len(months) > 2 || len(months) > 0 && months[0] > current {
		delete(b.months, months[0])
		months = months[1:]
	}
}

// report — счётчики для heartbeat: месяцы по возрастанию, последний —
// текущий (может быть без приложений). nil — раздела budgets нет.
func (b *Budget) report() *budgetReport {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.on {
		return nil
	}
	current := bundle.Month(b.now(), b.loc)
	if b.months[current] == nil {
		b.months[current] = map[string]*budgetUsage{}
		b.prune(current)
	}
	months := make([]string, 0, len(b.months))
	for m := range b.months {
		months = append(months, m)
	}
	slices.Sort(months)
	rep := &budgetReport{Months: make([]budgetMonth, 0, len(months))}
	for _, m := range months {
		bm := budgetMonth{Month: m, Apps: make([]budgetUsage, 0, len(b.months[m]))}
		for _, u := range b.months[m] {
			c := *u
			for _, v := range []*int64{&c.Cost, &c.PricedTokens, &c.UnpricedTokens, &c.Requests, &c.UnpricedRequests} {
				*v = min(*v, maxBudgetCounter)
			}
			bm.Apps = append(bm.Apps, c)
		}
		slices.SortFunc(bm.Apps, func(x, y budgetUsage) int { return strings.Compare(x.App, y.App) })
		rep.Months = append(rep.Months, bm)
	}
	return rep
}

// apply принимает ответ сервера на heartbeat с отчётом rep: расход
// остальных процессов за месяц ответа. Месяцы отчёта раньше месяца ответа
// сервер сохранил — их счётчики больше не меняются и не отправляются.
func (b *Budget) apply(rep *budgetReport, st *budgetState) {
	if rep == nil || st == nil || !bundle.ValidMonth(st.Month) {
		return
	}
	others := make(map[string]int64, len(st.Others))
	for app, v := range st.Others {
		others[app] = max(v, 0)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.others, b.othersMonth = others, st.Month
	for _, m := range rep.Months {
		if m.Month < st.Month {
			delete(b.months, m.Month)
		}
	}
}
