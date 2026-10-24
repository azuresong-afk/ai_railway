package apps

import (
	"bytes"
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Memory — Store в памяти для тестов без PostgreSQL. Повторяет правила
// PGStore и триггеров миграции 0014: ключи и приложения не удаляются,
// отзыв и архив окончательны, срок ключа только сокращается. Записи
// аудита изменений копятся в Records.
type Memory struct {
	mu        sync.Mutex
	providers map[string]Provider
	apps      map[string]Application
	keys      map[string]Key
	records   []audit.Entry
	// Цены, бюджеты и расход (задача 3.18).
	prices  map[string]Price
	budgets map[string]Budget
	usage   map[usageKey]Usage
	// gatewayTLS — сертификат заказчика по организации (задача 3.27).
	gatewayTLS map[string]GatewayTLS
}

// usageKey — строка budget_usage.
type usageKey struct {
	org, month, app, gateway string
	started                  time.Time
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory {
	return &Memory{providers: map[string]Provider{}, apps: map[string]Application{}, keys: map[string]Key{},
		prices: map[string]Price{}, budgets: map[string]Budget{}, usage: map[usageKey]Usage{},
		gatewayTLS: map[string]GatewayTLS{}}
}

// Records — копия записей аудита.
func (m *Memory) Records() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records)
}

func cloneProvider(p Provider) Provider {
	if p.Credential != nil {
		c := *p.Credential
		c.Data = bytes.Clone(c.Data)
		p.Credential = &c
	}
	return p
}

func cloneApp(a Application) Application {
	a.Models, a.Aliases = slices.Clone(a.Models), maps.Clone(a.Aliases)
	a.Lists, a.ExfilAllowDomains = slices.Clone(a.Lists), slices.Clone(a.ExfilAllowDomains)
	return a
}

func cloneKey(k Key) Key {
	k.Hash, k.AllowedCIDRs = bytes.Clone(k.Hash), slices.Clone(k.AllowedCIDRs)
	return k
}

// CreateProvider — см. Store.
func (m *Memory) CreateProvider(_ context.Context, p Provider, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.providers {
		if o.OrgID == p.OrgID && o.Slug == p.Slug {
			return ErrSlugTaken
		}
	}
	m.providers[p.ID] = cloneProvider(p)
	m.records = append(m.records, rec)
	return nil
}

// UpdateProvider — см. Store.
func (m *Memory) UpdateProvider(_ context.Context, orgID, id string, fn func(*Provider) (audit.Entry, error)) (Provider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.providers[id]
	if !ok || p.OrgID != orgID {
		return Provider{}, ErrNotFound
	}
	p = cloneProvider(p)
	slug, created := p.Slug, p.CreatedAt
	rec, err := fn(&p)
	if err != nil {
		return Provider{}, err
	}
	if p.Slug != slug || !p.CreatedAt.Equal(created) || p.ID != id {
		return Provider{}, errImmutable
	}
	m.providers[id] = cloneProvider(p)
	m.records = append(m.records, rec)
	return p, nil
}

// DeleteProvider — см. Store.
func (m *Memory) DeleteProvider(_ context.Context, orgID, id string, fn func(Provider) (audit.Entry, error)) (Provider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.providers[id]
	if !ok || p.OrgID != orgID {
		return Provider{}, ErrNotFound
	}
	for _, a := range m.apps {
		if a.ProviderID == id {
			return Provider{}, ErrProviderInUse
		}
	}
	rec, err := fn(p)
	if err != nil {
		return Provider{}, err
	}
	delete(m.providers, id)
	// Цены удалённого провайдера удаляются вместе с ним (ON DELETE CASCADE).
	for pid, pr := range m.prices {
		if pr.ProviderID == id {
			delete(m.prices, pid)
		}
	}
	m.records = append(m.records, rec)
	return p, nil
}

// Provider — см. Store.
func (m *Memory) Provider(_ context.Context, orgID, id string) (Provider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.providers[id]
	if !ok || p.OrgID != orgID {
		return Provider{}, ErrNotFound
	}
	return cloneProvider(p), nil
}

// Providers — см. Store.
func (m *Memory) Providers(_ context.Context, orgID string) ([]Provider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Provider{}
	for _, p := range m.providers {
		if p.OrgID == orgID {
			out = append(out, cloneProvider(p))
		}
	}
	slices.SortFunc(out, func(a, b Provider) int { return strings.Compare(a.Slug, b.Slug) })
	return out, nil
}

// CountProviders — см. Store.
func (m *Memory) CountProviders(ctx context.Context, orgID string) (int, error) {
	ps, err := m.Providers(ctx, orgID)
	return len(ps), err
}

// CreateApplication — см. Store.
func (m *Memory) CreateApplication(_ context.Context, a Application, rec audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.apps {
		if o.OrgID == a.OrgID && o.Slug == a.Slug {
			return ErrSlugTaken
		}
	}
	if p, ok := m.providers[a.ProviderID]; !ok || p.OrgID != a.OrgID {
		return ErrProviderNotFound
	}
	m.apps[a.ID] = cloneApp(a)
	m.records = append(m.records, rec)
	return nil
}

func (m *Memory) app(orgID, id string) (Application, error) {
	a, ok := m.apps[id]
	if !ok || a.OrgID != orgID {
		return Application{}, ErrNotFound
	}
	return cloneApp(a), nil
}

// UpdateApplication — см. Store.
func (m *Memory) UpdateApplication(_ context.Context, orgID, id string, fn func(*Application) (audit.Entry, error)) (Application, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, err := m.app(orgID, id)
	if err != nil {
		return Application{}, err
	}
	if a.Archived() {
		return Application{}, ErrArchived
	}
	slug, created := a.Slug, a.CreatedAt
	rec, err := fn(&a)
	if err != nil {
		return Application{}, err
	}
	if a.Slug != slug || !a.CreatedAt.Equal(created) || a.ID != id || a.Archived() {
		return Application{}, errImmutable
	}
	if p, ok := m.providers[a.ProviderID]; !ok || p.OrgID != orgID {
		return Application{}, ErrProviderNotFound
	}
	m.apps[id] = cloneApp(a)
	m.records = append(m.records, rec)
	return a, nil
}

func (m *Memory) activeKeys(appID string, now time.Time) []string {
	var out []string
	for id, k := range m.keys {
		if k.AppID == appID && k.Status(now) == KeyActive {
			out = append(out, id)
		}
	}
	return out
}

// ArchiveApplication — см. Store.
func (m *Memory) ArchiveApplication(_ context.Context, orgID, id string, fn func(*Application, int) (audit.Entry, error)) (Application, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, err := m.app(orgID, id)
	if err != nil {
		return Application{}, err
	}
	if a.Archived() {
		return Application{}, ErrArchived
	}
	// Отзываются ключи, ещё не отозванные: истёкшие тоже, чтобы архив был окончательным.
	var open []string
	for kid, k := range m.keys {
		if k.AppID == id && k.RevokedAt.IsZero() {
			open = append(open, kid)
		}
	}
	rec, err := fn(&a, len(open))
	if err != nil {
		return Application{}, err
	}
	if !a.Archived() {
		return Application{}, errImmutable
	}
	for _, kid := range open {
		k := m.keys[kid]
		k.RevokedAt, k.RevokedBy = a.ArchivedAt, a.UpdatedBy
		m.keys[kid] = k
	}
	m.apps[id] = cloneApp(a)
	m.records = append(m.records, rec)
	return a, nil
}

// Application — см. Store.
func (m *Memory) Application(_ context.Context, orgID, id string) (Application, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.app(orgID, id)
}

// Applications — см. Store.
func (m *Memory) Applications(_ context.Context, orgID, ownerID string, after *Cursor, limit int) ([]Application, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Application{}
	for _, a := range m.apps {
		if a.OrgID != orgID || (ownerID != "" && a.OwnerID != ownerID) {
			continue
		}
		if after != nil && (a.CreatedAt.Before(after.CreatedAt) || (a.CreatedAt.Equal(after.CreatedAt) && a.ID <= after.ID)) {
			continue
		}
		out = append(out, cloneApp(a))
	}
	slices.SortFunc(out, func(a, b Application) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// CreateKey — см. Store.
func (m *Memory) CreateKey(_ context.Context, orgID, appID string, now time.Time, fn func(Application, int) (Key, audit.Entry, error)) (Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, err := m.app(orgID, appID)
	if err != nil {
		return Key{}, err
	}
	k, rec, err := fn(a, len(m.activeKeys(appID, now)))
	if err != nil {
		return Key{}, err
	}
	if err := m.insertKey(k); err != nil {
		return Key{}, err
	}
	m.records = append(m.records, rec)
	return k, nil
}

func (m *Memory) insertKey(k Key) error {
	for _, o := range m.keys {
		if o.Prefix == k.Prefix {
			return ErrSlugTaken
		}
	}
	if k.ExpiresAt.Before(k.CreatedAt) || k.ExpiresAt.After(k.CreatedAt.Add(MaxKeyDays*24*time.Hour)) {
		return errImmutable
	}
	m.keys[k.ID] = cloneKey(k)
	return nil
}

// UpdateKey — см. Store.
func (m *Memory) UpdateKey(_ context.Context, orgID, id string, now time.Time, fn func(*Key, Application, int) (*Key, audit.Entry, error)) (Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok || k.OrgID != orgID {
		return Key{}, ErrNotFound
	}
	a, err := m.app(orgID, k.AppID)
	if err != nil {
		return Key{}, err
	}
	old := cloneKey(k)
	k = cloneKey(k)
	created, rec, err := fn(&k, a, len(m.activeKeys(k.AppID, now)))
	if err != nil {
		return Key{}, err
	}
	// Триггер app_keys_guard: отозванный не меняется, срок не продлевается,
	// остальные поля неизменны.
	if !old.RevokedAt.IsZero() || k.ExpiresAt.After(old.ExpiresAt) || k.Prefix != old.Prefix ||
		!bytes.Equal(k.Hash, old.Hash) || k.AppID != old.AppID || !slices.Equal(k.AllowedCIDRs, old.AllowedCIDRs) {
		return Key{}, errImmutable
	}
	if created != nil {
		if err := m.insertKey(*created); err != nil {
			return Key{}, err
		}
	}
	m.keys[id] = cloneKey(k)
	m.records = append(m.records, rec)
	return k, nil
}

// Key — см. Store.
func (m *Memory) Key(_ context.Context, orgID, id string) (Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok || k.OrgID != orgID {
		return Key{}, ErrNotFound
	}
	return cloneKey(k), nil
}

// ActiveKeys — см. Store.
func (m *Memory) ActiveKeys(_ context.Context, orgID string, now time.Time) ([]Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Key{}
	for _, k := range m.keys {
		if k.OrgID == orgID && k.RevokedAt.IsZero() && now.Before(k.ExpiresAt) {
			out = append(out, cloneKey(k))
		}
	}
	slices.SortFunc(out, func(a, b Key) int {
		if c := strings.Compare(a.AppID, b.AppID); c != 0 {
			return c
		}
		return strings.Compare(a.Prefix, b.Prefix)
	})
	return out, nil
}

// Keys — см. Store.
func (m *Memory) Keys(_ context.Context, orgID, appID string) ([]Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Key{}
	for _, k := range m.keys {
		if k.OrgID == orgID && k.AppID == appID {
			out = append(out, cloneKey(k))
		}
	}
	slices.SortFunc(out, func(a, b Key) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	})
	if len(out) > MaxKeysListed {
		out = out[:MaxKeysListed]
	}
	return out, nil
}
