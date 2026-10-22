package apps

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Цены моделей и бюджеты приложений (ТЗ 5.8, 4.2; решение Р7 этапа 3,
// задача 3.18). Цены администратор задаёт вручную: платформа не ходит за
// ценами в интернет. Бюджет — месячный на приложение: мягкий (оповещения
// 80 % и 100 %, задача 3.12) или жёсткий (шлюз отвечает 429
// budget_exceeded). Цены и жёсткие бюджеты уходят шлюзам в разделе budgets
// пакета конфигурации; расход шлюзы считают по usage ответов провайдера и
// присылают с heartbeat. Снятие или повышение жёсткого бюджета —
// не ослабление защиты (не DM-40), но пишется в аудит с отметкой relaxed.

// Режимы бюджета.
const (
	BudgetSoft = "soft"
	BudgetHard = "hard"
)

// MaxPrices — цен в организации (bundle.MaxPrices).
const MaxPrices = bundle.MaxPrices

// DefaultTimezone — часовой пояс месяца расхода без настроек установки.
const DefaultTimezone = "UTC"

// Ошибки цен и бюджетов.
var (
	ErrPriceExists = errors.New("цена этой модели провайдера уже задана")
	ErrNoBudget    = errors.New("бюджет не задан")
)

// Price — цена модели провайдера за 1 000 токенов, единицы 0,0001 ₽.
type Price struct {
	ID         string
	OrgID      string
	ProviderID string
	Model      string
	Input      int64
	Output     int64
	CreatedAt  time.Time
	CreatedBy  string
	UpdatedAt  time.Time
	UpdatedBy  string
}

// PriceInput — цена из запроса: рубли за 1 000 токенов десятичной строкой
// (до 4 знаков после точки). ProviderID и Model — только при создании.
type PriceInput struct {
	ProviderID string
	Model      string
	Input      string
	Output     string
}

// Budget — месячный бюджет приложения в копейках.
type Budget struct {
	AppID     string
	OrgID     string
	Mode      string
	Limit     int64
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
}

// BudgetInput — бюджет из запроса: режим и рубли в месяц десятичной
// строкой (до 2 знаков после точки).
type BudgetInput struct {
	Mode  string
	Limit string
}

// Usage — расход приложения за месяц: 1e-7 ₽, токены и запросы с
// известной и неизвестной ценой модели.
type Usage struct {
	Cost             int64
	PricedTokens     int64
	UnpricedTokens   int64
	Requests         int64
	UnpricedRequests int64
}

func (u Usage) add(o Usage) Usage {
	return Usage{Cost: bundle.AddCost(u.Cost, o.Cost), PricedTokens: bundle.AddCost(u.PricedTokens, o.PricedTokens),
		UnpricedTokens: bundle.AddCost(u.UnpricedTokens, o.UnpricedTokens), Requests: bundle.AddCost(u.Requests, o.Requests),
		UnpricedRequests: bundle.AddCost(u.UnpricedRequests, o.UnpricedRequests)}
}

// BudgetStatus — бюджет и расход приложения за месяц.
type BudgetStatus struct {
	App Application
	// Budget — nil, если бюджет не задан.
	Budget *Budget
	Month  string
	Usage
	// Percent — расход от бюджета в целых процентах (вниз); Exhausted —
	// расход достиг бюджета (ровно 100 % — исчерпан).
	Percent   int64
	Exhausted bool
}

// BudgetSection — данные раздела budgets пакета.
type BudgetSection struct {
	Timezone string
	Prices   []Price
	// Hard — жёсткие бюджеты; AnyBudget — задан хотя бы один бюджет.
	Hard      []Budget
	AnyBudget bool
}

// SetTimezone задаёт чтение часового пояса установки: по нему считается
// месяц расхода. Вызывается до начала обслуживания запросов; nil — UTC.
func (s *Service) SetTimezone(fn func(ctx context.Context) (string, error)) { s.timezone = fn }

func (s *Service) location(ctx context.Context) (string, *time.Location, error) {
	name := DefaultTimezone
	if s.timezone != nil {
		n, err := s.timezone(ctx)
		if err != nil {
			return "", nil, err
		}
		if n != "" {
			name = n
		}
	}
	loc, err := bundle.LoadLocation(name)
	if err != nil {
		return "", nil, fmt.Errorf("бюджеты: часовой пояс %q: %w", name, err)
	}
	return name, loc, nil
}

// CurrentMonth — текущий месяц «ГГГГ-ММ» в часовом поясе установки.
func (s *Service) CurrentMonth(ctx context.Context) (string, error) {
	_, loc, err := s.location(ctx)
	if err != nil {
		return "", err
	}
	return bundle.Month(s.now(), loc), nil
}

func priceDetails(p Price) map[string]any {
	return map[string]any{"provider_id": p.ProviderID, "model": p.Model,
		"input": FormatMoney(p.Input, PriceDigits), "output": FormatMoney(p.Output, PriceDigits)}
}

func (in PriceInput) parse() (input, output int64, err error) {
	var errs []error
	if input, err = ParseMoney(in.Input, PriceDigits, MaxPriceUnits); err != nil {
		errs = append(errs, errors.New("input_price — рубли за 1 000 токенов: от 0 до 1000000, до 4 знаков после точки, например 0.25"))
	}
	if output, err = ParseMoney(in.Output, PriceDigits, MaxPriceUnits); err != nil {
		errs = append(errs, errors.New("output_price — рубли за 1 000 токенов: от 0 до 1000000, до 4 знаков после точки, например 0.25"))
	}
	if len(errs) > 0 {
		return 0, 0, invalid(errs...)
	}
	return input, output, nil
}

// Prices — цены моделей организации по провайдеру и модели.
func (s *Service) Prices(ctx context.Context) ([]Price, error) { return s.store.Prices(ctx, s.orgID) }

// CreatePrice задаёт цену модели провайдера.
func (s *Service) CreatePrice(ctx context.Context, by By, in PriceInput) (Price, error) {
	var errs []error
	if !bundle.ValidModelName(in.Model) {
		errs = append(errs, errors.New("model — имя модели у провайдера, от 1 до 128 печатных символов"))
	}
	if _, err := store.ParseUUID(in.ProviderID); err != nil {
		errs = append(errs, errors.New("provider_id — ID провайдера (UUID)"))
	}
	input, output, err := in.parse()
	var ie *InputError
	if errors.As(err, &ie) {
		errs = append(errs, ie.Errs...)
	}
	if len(errs) > 0 {
		return Price{}, invalid(errs...)
	}
	if _, err := s.store.Provider(ctx, s.orgID, in.ProviderID); errors.Is(err, ErrNotFound) {
		return Price{}, ErrProviderNotFound
	} else if err != nil {
		return Price{}, err
	}
	all, err := s.store.Prices(ctx, s.orgID)
	if err != nil {
		return Price{}, err
	}
	if len(all) >= MaxPrices {
		return Price{}, ErrTooMany
	}
	id, err := s.newID()
	if err != nil {
		return Price{}, err
	}
	now := s.now()
	p := Price{ID: id, OrgID: s.orgID, ProviderID: in.ProviderID, Model: in.Model, Input: input, Output: output,
		CreatedAt: now, CreatedBy: by.ref(), UpdatedAt: now, UpdatedBy: by.ref()}
	rec := by.entry("model_price.create", "model_price", id, priceDetails(p))
	if err := s.store.CreatePrice(ctx, p, rec); err != nil {
		return Price{}, err
	}
	return p, nil
}

// UpdatePrice меняет цены входа и выхода; провайдер и модель неизменны.
func (s *Service) UpdatePrice(ctx context.Context, by By, id string, in PriceInput) (Price, error) {
	input, output, err := in.parse()
	if err != nil {
		return Price{}, err
	}
	return s.store.UpdatePrice(ctx, s.orgID, id, func(p *Price) (audit.Entry, error) {
		before := priceDetails(*p)
		old := *p
		p.Input, p.Output, p.UpdatedAt, p.UpdatedBy = input, output, s.now(), by.ref()
		// Снижение цены уменьшает учитываемый расход: жёсткий бюджет
		// срабатывает позже (relaxed, как у budget.set).
		rec := by.entry("model_price.update", "model_price", id, map[string]any{"before": before, "after": priceDetails(*p),
			"relaxed": input < old.Input || output < old.Output})
		return rec, nil
	})
}

// DeletePrice удаляет цену: стоимость запросов к модели становится «не
// определена».
func (s *Service) DeletePrice(ctx context.Context, by By, id string) (Price, error) {
	return s.store.DeletePrice(ctx, s.orgID, id, func(p Price) (audit.Entry, error) {
		// Модель без цены не расходует жёсткий бюджет: удаление — relaxed.
		d := priceDetails(p)
		d["relaxed"] = true
		rec := by.entry("model_price.delete", "model_price", id, d)
		return rec, nil
	})
}

func budgetDetails(b *Budget) any {
	if b == nil {
		return nil
	}
	return map[string]any{"mode": b.Mode, "limit": FormatMoney(b.Limit, BudgetDigits)}
}

// relaxed — новый бюджет next мягче прежнего prev: снят или повышен
// жёсткий бюджет. Это не ослабление защиты (не DM-40), но отмечается в
// аудите (решение Р7 этапа 3).
func relaxed(prev, next *Budget) bool {
	if prev == nil || prev.Mode != BudgetHard {
		return false
	}
	return next == nil || next.Mode != BudgetHard || next.Limit > prev.Limit
}

// SetBudget задаёт или заменяет месячный бюджет действующего приложения.
func (s *Service) SetBudget(ctx context.Context, by By, appID string, in BudgetInput) (Budget, error) {
	var errs []error
	if in.Mode != BudgetSoft && in.Mode != BudgetHard {
		errs = append(errs, errors.New("mode — soft (оповещения) или hard (запросы сверх бюджета отклоняются)"))
	}
	limit, err := ParseMoney(in.Limit, BudgetDigits, MaxBudgetKopecks)
	if err != nil || limit < 1 {
		errs = append(errs, errors.New("monthly_limit — рубли в месяц: от 0.01 до 1000000000, до 2 знаков после точки, например 15000.00"))
	}
	if len(errs) > 0 {
		return Budget{}, invalid(errs...)
	}
	return s.store.SetBudget(ctx, s.orgID, appID, func(a Application, prev *Budget) (Budget, audit.Entry, error) {
		if a.Archived() {
			return Budget{}, audit.Entry{}, ErrArchived
		}
		now := s.now()
		next := Budget{AppID: a.ID, OrgID: s.orgID, Mode: in.Mode, Limit: limit, CreatedAt: now, CreatedBy: by.ref(),
			UpdatedAt: now, UpdatedBy: by.ref()}
		if prev != nil {
			next.CreatedAt, next.CreatedBy = prev.CreatedAt, prev.CreatedBy
		}
		rec := by.entry("budget.set", "application", a.ID, map[string]any{"application": a.Slug,
			"before": budgetDetails(prev), "after": budgetDetails(&next), "relaxed": relaxed(prev, &next)})
		return next, rec, nil
	})
}

// DeleteBudget снимает бюджет приложения.
func (s *Service) DeleteBudget(ctx context.Context, by By, appID string) (Budget, error) {
	return s.store.DeleteBudget(ctx, s.orgID, appID, func(a Application, b Budget) (audit.Entry, error) {
		rec := by.entry("budget.delete", "application", a.ID, map[string]any{"application": a.Slug,
			"before": budgetDetails(&b), "relaxed": relaxed(&b, nil)})
		return rec, nil
	})
}

func status(a Application, b *Budget, month string, u Usage) BudgetStatus {
	st := BudgetStatus{App: a, Budget: b, Month: month, Usage: u}
	if b != nil {
		st.Percent = Percent(u.Cost, b.Limit)
		st.Exhausted = u.Cost >= bundle.KopecksToCost(b.Limit)
	}
	return st
}

// BudgetStatus — бюджет и расход приложения за месяц (пусто — текущий).
func (s *Service) BudgetStatus(ctx context.Context, appID, month string) (BudgetStatus, error) {
	month, err := s.month(ctx, month)
	if err != nil {
		return BudgetStatus{}, err
	}
	a, err := s.store.Application(ctx, s.orgID, appID)
	if err != nil {
		return BudgetStatus{}, err
	}
	var b *Budget
	switch got, err := s.store.Budget(ctx, s.orgID, appID); {
	case err == nil:
		b = &got
	case !errors.Is(err, ErrNoBudget):
		return BudgetStatus{}, err
	}
	use, err := s.store.Usage(ctx, s.orgID, month)
	if err != nil {
		return BudgetStatus{}, err
	}
	return status(a, b, month, use[a.Slug]), nil
}

// BudgetStatuses — приложения с бюджетом или с расходом за месяц (пусто —
// текущий), по ID приложения. Приложения с расходом по моделям без цены
// видны по UnpricedRequests.
func (s *Service) BudgetStatuses(ctx context.Context, month string) ([]BudgetStatus, string, error) {
	month, err := s.month(ctx, month)
	if err != nil {
		return nil, "", err
	}
	budgets, err := s.store.Budgets(ctx, s.orgID)
	if err != nil {
		return nil, "", err
	}
	byApp := make(map[string]*Budget, len(budgets))
	for i := range budgets {
		byApp[budgets[i].AppID] = &budgets[i]
	}
	use, err := s.store.Usage(ctx, s.orgID, month)
	if err != nil {
		return nil, "", err
	}
	var out []BudgetStatus
	var after *Cursor
	for {
		page, err := s.store.Applications(ctx, s.orgID, "", after, 500)
		if err != nil {
			return nil, "", err
		}
		for _, a := range page {
			b := byApp[a.ID]
			u, used := use[a.Slug]
			if b == nil && !used {
				continue
			}
			out = append(out, status(a, b, month, u))
		}
		if len(page) < 500 {
			break
		}
		last := page[len(page)-1]
		after = &Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	slices.SortFunc(out, func(x, y BudgetStatus) int { return strings.Compare(x.App.Slug, y.App.Slug) })
	return out, month, nil
}

// month — месяц запроса или текущий; неверный — InputError.
func (s *Service) month(ctx context.Context, month string) (string, error) {
	if month == "" {
		return s.CurrentMonth(ctx)
	}
	if !bundle.ValidMonth(month) {
		return "", invalidf("month — месяц в виде ГГГГ-ММ, например 2026-10")
	}
	return month, nil
}

// BudgetSection — данные раздела budgets пакета: часовой пояс, все цены
// и жёсткие бюджеты.
func (s *Service) BudgetSection(ctx context.Context) (BudgetSection, error) {
	tz, _, err := s.location(ctx)
	if err != nil {
		return BudgetSection{}, err
	}
	prices, err := s.store.Prices(ctx, s.orgID)
	if err != nil {
		return BudgetSection{}, err
	}
	budgets, err := s.store.Budgets(ctx, s.orgID)
	if err != nil {
		return BudgetSection{}, err
	}
	sec := BudgetSection{Timezone: tz, Prices: prices, AnyBudget: len(budgets) > 0}
	for _, b := range budgets {
		if b.Mode == BudgetHard {
			sec.Hard = append(sec.Hard, b)
		}
	}
	return sec, nil
}

// SyncBudget сохраняет счётчики процесса шлюза из heartbeat и возвращает
// расход остальных процессов за текущий месяц шлюза по приложениям с
// жёстким бюджетом (gwregistry.BudgetSync). Отчёт уже проверен
// HeartbeatInput.Validate.
func (s *Service) SyncBudget(ctx context.Context, gatewayID string, startedAt time.Time, rep gwregistry.BudgetReport) (gwregistry.BudgetState, error) {
	if len(rep.Months) == 0 {
		return gwregistry.BudgetState{}, errors.New("бюджеты: пустой отчёт шлюза")
	}
	if err := s.store.SaveUsage(ctx, s.orgID, gatewayID, startedAt.UTC(), rep.Months, s.now()); err != nil {
		return gwregistry.BudgetState{}, err
	}
	month := rep.Months[len(rep.Months)-1].Month
	others, err := s.store.HardUsageOthers(ctx, s.orgID, month, gatewayID, startedAt.UTC())
	if err != nil {
		return gwregistry.BudgetState{}, err
	}
	return gwregistry.BudgetState{Month: month, Others: others}, nil
}
