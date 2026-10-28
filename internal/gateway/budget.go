package gateway

import (
	"context"
	"errors"
	"log/slog"
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
// превышен на расход, не дошедший до сервера. В режиме leased (ADR-0021,
// п. 4, задача 4.29) жёсткий бюджет берётся арендой у сервера: перед
// вызовом провайдера резервируется оценка стоимости (Reserve), после ответа
// резерв уточняется фактическим расходом; others не используется.

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
	now    func() time.Time
	logger *slog.Logger

	mu sync.Mutex
	// on — в пакете есть раздел budgets: расход считается и уходит в
	// heartbeat.
	on     bool
	loc    *time.Location
	prices map[priceKey]bundle.ModelPrice
	hard   map[string]int64
	// known — приложения текущего пакета (nil — неизвестны): при
	// переполнении месяца вытесняются счётчики приложений вне пакета.
	known map[string]bool
	// months — месяц «ГГГГ-ММ» → приложение → счётчики процесса.
	months map[string]map[string]*budgetUsage
	// others — расход остальных процессов за месяц othersMonth.
	others      map[string]int64
	othersMonth string
	// lease — аренда жёстких бюджетов у сервера (режим leased).
	lease *LeaseClient
}

// SetLeases подключает аренду бюджетов у сервера (задача 4.29); вызывается
// до начала работы.
func (b *Budget) SetLeases(c *LeaseClient) {
	b.mu.Lock()
	b.lease = c
	b.mu.Unlock()
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
	return &Budget{now: now, logger: slog.Default(), months: map[string]map[string]*budgetUsage{}}
}

// SetLogger задаёт технический журнал; вызывается до начала работы.
func (b *Budget) SetLogger(l *slog.Logger) {
	if l != nil {
		b.logger = l
	}
}

// Reconfigure применяет раздел budgets нового пакета; nil — раздела нет:
// расход не считается, бюджеты не применяются. Счётчики процесса
// сохраняются: они нарастающие с запуска. apps — ID приложений пакета: их
// счётчики не вытесняются при переполнении месяца (3В23 ревью 3.r3).
func (b *Budget) Reconfigure(sec *bundle.Budgets, apps ...string) error {
	var known map[string]bool
	if len(apps) > 0 {
		known = make(map[string]bool, len(apps))
		for _, a := range apps {
			known[a] = true
		}
	}
	b.mu.Lock()
	b.known = known
	b.mu.Unlock()
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
	b.on, b.loc, b.prices, b.hard = true, loc, prices, hard
	lease := b.lease
	b.mu.Unlock()
	lease.setLocation(loc)
	return nil
}

// Leased — жёсткий бюджет приложения берётся арендой у сервера: тогда
// Exhausted не применяется, а запрос резервирует оценку через Reserve.
func (b *Budget) Leased(app string) bool {
	b.mu.Lock()
	_, hard := b.hard[app]
	on, lease := b.on, b.lease
	b.mu.Unlock()
	return on && hard && lease.Enabled()
}

// Reserve резервирует в аренде бюджета оценку стоимости запроса: input и
// output токенов по цене модели, не меньше одной единицы (ADR-0021, п. 4).
// nil, nil — аренда не применяется (нет жёсткого бюджета или цены модели:
// стоимость не определена, запрос не отклоняется). *Exceeded с правилом
// budget.hard — бюджет исчерпан; ErrQuotaUnavailable — сервер недоступен.
func (b *Budget) Reserve(ctx context.Context, app, provider, model string, input, output int64) (*leaseHold, error) {
	b.mu.Lock()
	limit, hard := b.hard[app]
	p, priced := b.prices[priceKey{provider, model}]
	on, lease := b.on, b.lease
	b.mu.Unlock()
	if !on || !hard || !priced {
		return nil, nil
	}
	est := max(bundle.Cost(p, max(input, 0), max(output, 0)), 1)
	return lease.take(ctx, app, quotaBudget, est, limit)
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
	b.roll(month)
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
// определена, запрос не отклоняется. Возвращает стоимость запроса (0 —
// без цены или учёт выключен): ею уточняется резерв Reserve.
func (b *Budget) Record(app, provider, model string, input, output int64) int64 {
	input, output = max(input, 0), max(output, 0)
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.on {
		return 0
	}
	month := bundle.Month(b.now(), b.loc)
	b.roll(month)
	m := b.months[month]
	u := m[app]
	if u == nil {
		if len(m) >= maxBudgetApps && !b.evict(m, app) {
			// Счётчик месяца не заведён, но резерв аренды уточняется ценой.
			if p, ok := b.prices[priceKey{provider, model}]; ok {
				return bundle.Cost(p, input, output)
			}
			return 0
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
		return 0
	}
	cost := bundle.Cost(p, input, output)
	u.PricedTokens = bundle.AddCost(u.PricedTokens, tokens)
	u.Cost = bundle.AddCost(u.Cost, cost)
	return cost
}

// evict освобождает место в переполненном месяце m для приложения app:
// вытесняет счётчики приложения, которого нет в текущем пакете (удалено с
// сервера). Такого нет или пакет неизвестен — расход app не учитывается;
// и то и другое — в технический журнал.
func (b *Budget) evict(m map[string]*budgetUsage, app string) bool {
	if b.known != nil {
		for id := range m {
			if !b.known[id] {
				delete(m, id)
				b.logger.Warn("бюджеты: счётчики приложения вне пакета вытеснены — переполнен месяц", "app", id, "limit", maxBudgetApps)
				return true
			}
		}
	}
	b.logger.Warn("бюджеты: расход приложения не учтён — переполнен месяц", "app", app, "limit", maxBudgetApps)
	return false
}

// roll готовит счётчики к месяцу current: заводит его, переносит в него
// счётчики «будущих» месяцев (часы или пояс установки сдвинулись назад
// через границу месяца: расход в них сделан сейчас, а не в будущем) и
// оставляет кроме текущего только предыдущий (он уходит на сервер, пока
// сервер не подтвердит его приём). Без переноса текущий месяц не был бы
// последним в отчёте, сервер ответил бы «будущим» месяцем, и apply стирал
// бы счётчик, в который шлюз продолжает писать (3В23 ревью 3.r3).
func (b *Budget) roll(current string) {
	cur := b.months[current]
	if cur == nil {
		cur = map[string]*budgetUsage{}
		b.months[current] = cur
	}
	months := make([]string, 0, len(b.months))
	for m := range b.months {
		months = append(months, m)
	}
	slices.Sort(months)
	for _, m := range months {
		if m <= current {
			continue
		}
		for app, u := range b.months[m] {
			c := cur[app]
			if c == nil {
				if len(cur) >= maxBudgetApps && !b.evict(cur, app) {
					continue
				}
				c = &budgetUsage{App: app}
				cur[app] = c
			}
			c.Cost = bundle.AddCost(c.Cost, u.Cost)
			c.PricedTokens = bundle.AddCost(c.PricedTokens, u.PricedTokens)
			c.UnpricedTokens = bundle.AddCost(c.UnpricedTokens, u.UnpricedTokens)
			c.Requests = bundle.AddCost(c.Requests, u.Requests)
			c.UnpricedRequests = bundle.AddCost(c.UnpricedRequests, u.UnpricedRequests)
		}
		delete(b.months, m)
	}
	months = slices.DeleteFunc(months, func(m string) bool { return m > current })
	for len(months) > 2 {
		delete(b.months, months[0])
		months = months[1:]
	}
}

// report — счётчики для heartbeat: месяцы по возрастанию, последний —
// текущий (может быть без приложений), будущих нет. nil — раздела budgets
// нет.
func (b *Budget) report() *budgetReport {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.on {
		return nil
	}
	b.roll(bundle.Month(b.now(), b.loc))
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
// Текущий месяц шлюза не удаляется никогда: в него пишется расход.
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
	current := ""
	if b.on {
		current = bundle.Month(b.now(), b.loc)
	}
	for _, m := range rep.Months {
		if m.Month < st.Month && m.Month != current {
			delete(b.months, m.Month)
		}
	}
}
