package judge

import (
	"container/list"
	"context"
	"encoding/binary"
	"slices"
	"sync"
	"time"
)

// Пределы кэша (ADR-0030, раздел 6).
const (
	CacheEntries = 4096
	CacheTTL     = 10 * time.Minute
)

// Shared — состояние оценщиков шлюза, которое переживает смену пакета:
// кэш вердиктов, бюджеты политик, пределы одновременных вызовов.
type Shared struct {
	cache   *cache
	budgets *budgets
	sync    chan struct{}
	queue   chan struct{}
	workers chan struct{}
}

// NewShared — состояние с пределами ADR-0030.
func NewShared() *Shared {
	return &Shared{cache: newCache(CacheEntries, CacheTTL), budgets: &budgets{m: map[string]*budget{}},
		sync: make(chan struct{}, MaxSyncCalls), queue: make(chan struct{}, AsyncWorkers+AsyncQueue),
		workers: make(chan struct{}, AsyncWorkers)}
}

func (s *Shared) acquireSync() (func(), bool) {
	select {
	case s.sync <- struct{}{}:
		return func() { <-s.sync }, true
	default:
		return nil, false
	}
}

// AcquireAsync — место для асинхронной оценки: false — очередь заполнена
// (overloaded). Ждёт свободного исполнителя не дольше ctx; release
// освобождает место.
func (s *Shared) AcquireAsync(ctx context.Context) (release func(), ok bool) {
	select {
	case s.queue <- struct{}{}:
	default:
		return nil, false
	}
	select {
	case s.workers <- struct{}{}:
		return func() { <-s.workers; <-s.queue }, true
	case <-ctx.Done():
		<-s.queue
		return nil, false
	}
}

// cacheKey — хеш через криптопрофиль от версии шаблона, оценщика,
// направления, набора критериев и текста. Части разделены длиной: граница
// между ними однозначна.
func (e *Engine) cacheKey(req Request) string {
	h := e.cfg.Hasher.New()
	put := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(s))
	}
	put(PromptVersion)
	put(e.cfg.Provider)
	put(e.cfg.Model)
	put(string(req.Direction))
	for _, c := range req.Criteria {
		put(c.Rule)
		put(c.Kind)
		put(c.Text)
	}
	put(req.Text)
	return string(h.Sum(nil))
}

// cache — LRU вердиктов со сроком: только вердикты, без текста.
type cache struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	order *list.List
	m     map[string]*list.Element
}

type cacheEntry struct {
	key string
	vs  []Verdict
	at  time.Time
}

func newCache(n int, ttl time.Duration) *cache {
	return &cache{max: n, ttl: ttl, order: list.New(), m: map[string]*list.Element{}}
}

func (c *cache) get(key string, now time.Time) ([]Verdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if now.Sub(e.at) > c.ttl {
		c.order.Remove(el)
		delete(c.m, key)
		return nil, false
	}
	c.order.MoveToFront(el)
	return slices.Clone(e.vs), true
}

func (c *cache) put(key string, vs []Verdict, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		el.Value = &cacheEntry{key: key, vs: slices.Clone(vs), at: now}
		c.order.MoveToFront(el)
		return
	}
	c.m[key] = c.order.PushFront(&cacheEntry{key: key, vs: slices.Clone(vs), at: now})
	for c.order.Len() > c.max {
		old := c.order.Back()
		c.order.Remove(old)
		delete(c.m, old.Value.(*cacheEntry).key)
	}
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// budgets — счётчики бюджета по ID политики: вызовы за минуту и токены за
// час (окна по часам шлюза).
type budgets struct {
	mu sync.Mutex
	m  map[string]*budget
}

type budget struct {
	minute time.Time
	calls  int
	hour   time.Time
	tokens int
}

// maxBudgets — политик со счётчиками: больше политик в пакете не бывает
// (bundle.MaxPolicies), запас — на смену пакета.
const maxBudgets = 4096

func (b *budgets) get(key string, now time.Time) *budget {
	c, ok := b.m[key]
	if !ok {
		if len(b.m) >= maxBudgets {
			// Счётчики политик, которых давно нет, сбрасываются целиком:
			// бюджет — защита от расхода, а не учёт.
			clear(b.m)
		}
		c = &budget{}
		b.m[key] = c
	}
	if m := now.Truncate(time.Minute); !c.minute.Equal(m) {
		c.minute, c.calls = m, 0
	}
	if h := now.Truncate(time.Hour); !c.hour.Equal(h) {
		c.hour, c.tokens = h, 0
	}
	return c
}

// take — вызов в пределах бюджета (учитывается сразу).
func (b *budgets) take(key string, l Limits, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.get(key, now)
	if c.calls >= l.CallsPerMinute || c.tokens >= l.TokensPerHour {
		return false
	}
	c.calls++
	return true
}

// spend — расход токенов вызова.
func (b *budgets) spend(key string, tokens int, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.get(key, now).tokens += max(tokens, 0)
}
