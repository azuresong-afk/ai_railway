package media

import (
	"container/list"
	"slices"
	"sync"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// DefaultCacheEntries — предел записей кэша по умолчанию (около 1 МиБ).
const DefaultCacheEntries = 4096

// Cache — итоги анализа по хешу содержимого (ADR-0032, раздел 7): только
// статус, причина, формат, размеры и проверки, без извлечённого текста.
// Предел записей; при переполнении вытесняется давно не использованная.
// Безопасен для одновременного использования.
type Cache struct {
	mu    sync.Mutex
	limit int
	order *list.List // от недавней к давней; значения — *cacheEntry
	items map[string]*list.Element
}

type cacheEntry struct {
	key string
	res wire.Result
}

// NewCache — кэш на limit записей; limit < 1 — кэш выключен.
func NewCache(limit int) *Cache {
	return &Cache{limit: limit, order: list.New(), items: map[string]*list.Element{}}
}

// Get — итог по хешу; у найденного Cached = true.
func (c *Cache) Get(key []byte) (wire.Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[string(key)]
	if !ok {
		return wire.Result{}, false
	}
	c.order.MoveToFront(e)
	res := e.Value.(*cacheEntry).res
	res.Checks = slices.Clone(res.Checks)
	res.Cached = true
	return res, true
}

// Put запоминает итог.
func (c *Cache) Put(key []byte, res wire.Result) {
	if c.limit < 1 {
		return
	}
	res.Checks = slices.Clone(res.Checks)
	res.Cached = false
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[string(key)]; ok {
		e.Value.(*cacheEntry).res = res
		c.order.MoveToFront(e)
		return
	}
	c.items[string(key)] = c.order.PushFront(&cacheEntry{key: string(key), res: res})
	if c.order.Len() > c.limit {
		old := c.order.Back()
		c.order.Remove(old)
		delete(c.items, old.Value.(*cacheEntry).key)
	}
}

// Len — записей в кэше.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
