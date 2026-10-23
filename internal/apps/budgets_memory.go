package apps

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

// Цены, бюджеты и расход в памяти — правила PGStore и миграции 0031.

// CreatePrice — см. Store.
func (m *Memory) CreatePrice(_ context.Context, p Price, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pr, ok := m.providers[p.ProviderID]; !ok || pr.OrgID != p.OrgID {
		return ErrProviderNotFound
	}
	for _, o := range m.prices {
		if o.OrgID == p.OrgID && o.ProviderID == p.ProviderID && o.Model == p.Model {
			return ErrPriceExists
		}
	}
	m.prices[p.ID] = p
	m.records = append(m.records, rec)
	return nil
}

// UpdatePrice — см. Store.
func (m *Memory) UpdatePrice(_ context.Context, orgID, id string, fn func(*Price) (audit.Entry, error)) (Price, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.prices[id]
	if !ok || p.OrgID != orgID {
		return Price{}, ErrNotFound
	}
	next := p
	rec, err := fn(&next)
	if err != nil {
		return Price{}, err
	}
	if next.ID != p.ID || next.ProviderID != p.ProviderID || next.Model != p.Model {
		return Price{}, errImmutable
	}
	m.prices[id] = next
	m.records = append(m.records, rec)
	return next, nil
}

// DeletePrice — см. Store.
func (m *Memory) DeletePrice(_ context.Context, orgID, id string, fn func(Price) (audit.Entry, error)) (Price, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.prices[id]
	if !ok || p.OrgID != orgID {
		return Price{}, ErrNotFound
	}
	rec, err := fn(p)
	if err != nil {
		return Price{}, err
	}
	delete(m.prices, id)
	m.records = append(m.records, rec)
	return p, nil
}

// Prices — см. Store.
func (m *Memory) Prices(_ context.Context, orgID string) ([]Price, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Price{}
	for _, p := range m.prices {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b Price) int {
		if c := strings.Compare(a.ProviderID, b.ProviderID); c != 0 {
			return c
		}
		return strings.Compare(a.Model, b.Model)
	})
	return out, nil
}

// SetBudget — см. Store.
func (m *Memory) SetBudget(_ context.Context, orgID, appID string, fn func(a Application, prev *Budget) (Budget, audit.Entry, error)) (Budget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.apps[appID]
	if !ok || a.OrgID != orgID {
		return Budget{}, ErrNotFound
	}
	var prev *Budget
	if b, ok := m.budgets[appID]; ok {
		prev = &b
	}
	next, rec, err := fn(cloneApp(a), prev)
	if err != nil {
		return Budget{}, err
	}
	m.budgets[appID] = next
	m.records = append(m.records, rec)
	return next, nil
}

// DeleteBudget — см. Store.
func (m *Memory) DeleteBudget(_ context.Context, orgID, appID string, fn func(a Application, b Budget) (audit.Entry, error)) (Budget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.apps[appID]
	if !ok || a.OrgID != orgID {
		return Budget{}, ErrNotFound
	}
	b, ok := m.budgets[appID]
	if !ok {
		return Budget{}, ErrNoBudget
	}
	rec, err := fn(cloneApp(a), b)
	if err != nil {
		return Budget{}, err
	}
	delete(m.budgets, appID)
	m.records = append(m.records, rec)
	return b, nil
}

// Budget — см. Store.
func (m *Memory) Budget(_ context.Context, orgID, appID string) (Budget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.budgets[appID]
	if !ok || b.OrgID != orgID {
		return Budget{}, ErrNoBudget
	}
	return b, nil
}

// Budgets — см. Store.
func (m *Memory) Budgets(_ context.Context, orgID string) ([]Budget, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Budget{}
	for _, b := range m.budgets {
		if b.OrgID == orgID {
			out = append(out, b)
		}
	}
	slices.SortFunc(out, func(a, b Budget) int { return strings.Compare(a.AppID, b.AppID) })
	return out, nil
}

func (m *Memory) appBySlug(orgID, slug string) (Application, bool) {
	for _, a := range m.apps {
		if a.OrgID == orgID && a.Slug == slug {
			return a, true
		}
	}
	return Application{}, false
}

// SaveUsage — см. Store.
func (m *Memory) SaveUsage(_ context.Context, orgID, gatewayID string, startedAt time.Time, months []gwregistry.BudgetMonth, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, mo := range months {
		for _, u := range mo.Apps {
			if _, ok := m.appBySlug(orgID, u.App); !ok {
				continue
			}
			k := usageKey{org: orgID, month: mo.Month, app: u.App, gateway: gatewayID, started: startedAt.UTC()}
			cur := m.usage[k]
			m.usage[k] = Usage{Cost: max(cur.Cost, u.Cost), PricedTokens: max(cur.PricedTokens, u.PricedTokens),
				UnpricedTokens: max(cur.UnpricedTokens, u.UnpricedTokens), Requests: max(cur.Requests, u.Requests),
				UnpricedRequests: max(cur.UnpricedRequests, u.UnpricedRequests)}
		}
	}
	return nil
}

// HardUsageOthers — см. Store.
func (m *Memory) HardUsageOthers(_ context.Context, orgID, month, gatewayID string, startedAt time.Time) (map[string]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	hard := map[string]bool{}
	for _, b := range m.budgets {
		if a, ok := m.apps[b.AppID]; ok && b.OrgID == orgID && b.Mode == BudgetHard {
			hard[a.Slug] = true
		}
	}
	out := map[string]int64{}
	for k, u := range m.usage {
		if k.org != orgID || k.month != month || !hard[k.app] || k.gateway == gatewayID && k.started.Equal(startedAt.UTC()) {
			continue
		}
		out[k.app] = Usage{Cost: out[k.app]}.add(Usage{Cost: u.Cost}).Cost
	}
	for app := range hard {
		if _, ok := out[app]; !ok {
			out[app] = 0
		}
	}
	return out, nil
}

// Usage — см. Store.
func (m *Memory) Usage(_ context.Context, orgID, month string) (map[string]Usage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]Usage{}
	for k, u := range m.usage {
		if k.org == orgID && k.month == month {
			out[k.app] = out[k.app].add(u)
		}
	}
	return out, nil
}
