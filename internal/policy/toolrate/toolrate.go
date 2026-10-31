// Пакет toolrate — счётчики лимитов вызовов инструментов агентами в памяти
// шлюза (ТЗ 5.10; ADR-0023, раздел 4; DM-23). На пилоте один шлюз
// (ADR-0021), перенос на аренду у сервера — вместе с квотами (задача 4.29).
//
// Окно — скользящее приближённо: счёт текущего окна плюс доля прошлого
// по оставшемуся времени. Память ограничена: не больше MaxKeys ключей,
// при переполнении вытесняется давно не использованный ключ, его счётчик
// сбрасывается (fail-open по счётчику). Вытеснения считает Evictions,
// Maintain пишет о них предупреждение в журнал шлюза, а heartbeat передаёт
// число на «Состояние системы» (4Н11 ревью 4.r1, задача 5.9 этапа 5).
// Пакет без сети: его используют MCP-прокси и путь chat (задача 4.11).
package toolrate

import (
	"container/list"
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// SweepIdle — ключ без вызовов дольше двух самых длинных окон (24 ч,
// политика вызовов) уже ничего не считает и удаляется Maintain.
const SweepIdle = 48 * time.Hour

// DefaultMaxKeys — предел ключей по умолчанию (ADR-0023, раздел 4).
const DefaultMaxKeys = 100000

// Counters — счётчики по ключам. Безопасны для одновременного использования.
type Counters struct {
	mu        sync.Mutex
	max       int
	byKey     map[string]*list.Element
	lru       *list.List // от недавно использованного к давнему
	evictions atomic.Uint64
}

type entry struct {
	key      string
	window   time.Duration
	start    time.Time // начало текущего окна
	cur      int64
	prev     int64
	lastSeen time.Time
}

// New создаёт счётчики; maxKeys ≤ 0 — DefaultMaxKeys.
func New(maxKeys int) *Counters {
	if maxKeys <= 0 {
		maxKeys = DefaultMaxKeys
	}
	return &Counters{max: maxKeys, byKey: map[string]*list.Element{}, lru: list.New()}
}

// Hit учитывает вызов по ключу key в окне window и сообщает, превышен ли
// limit с учётом этого вызова (счёт больше limit). limit ≤ 0 — без предела:
// вызов не учитывается. Ключ включает окно: один ключ с разными окнами —
// разные счётчики (вызывающий добавляет окно в key).
func (c *Counters) Hit(key string, window time.Duration, limit int, now time.Time) bool {
	if limit <= 0 || window <= 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entry(key, window, now)
	e.roll(now)
	e.cur++
	e.lastSeen = now
	return e.count(now) > float64(limit)
}

// Count — текущая оценка счёта ключа (для тестов и «Состояния системы»).
func (c *Counters) Count(key string, now time.Time) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byKey[key]
	if !ok {
		return 0
	}
	e := el.Value.(*entry)
	e.roll(now)
	return e.count(now)
}

// Len — ключей сейчас.
func (c *Counters) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byKey)
}

// Evictions — сколько ключей вытеснено из-за предела.
func (c *Counters) Evictions() uint64 { return c.evictions.Load() }

// MaxKeys — предел ключей.
func (c *Counters) MaxKeys() int { return c.max }

func (c *Counters) entry(key string, window time.Duration, now time.Time) *entry {
	if el, ok := c.byKey[key]; ok {
		c.lru.MoveToFront(el)
		e := el.Value.(*entry)
		if e.window != window {
			*e = entry{key: key, window: window, start: now}
		}
		return e
	}
	for len(c.byKey) >= c.max {
		old := c.lru.Back()
		delete(c.byKey, old.Value.(*entry).key)
		c.lru.Remove(old)
		c.evictions.Add(1)
	}
	e := &entry{key: key, window: window, start: now}
	c.byKey[key] = c.lru.PushFront(e)
	return e
}

// roll сдвигает окна до now. Часы назад (перевод) — окно начинается заново.
func (e *entry) roll(now time.Time) {
	if now.Before(e.start) {
		e.start, e.cur, e.prev = now, 0, 0
		return
	}
	// n — число целых окон с начала текущего (безразмерное).
	n := int64(now.Sub(e.start) / e.window)
	switch n {
	case 0:
	case 1:
		e.prev, e.cur = e.cur, 0
		e.start = e.start.Add(e.window)
	default:
		e.prev, e.cur = 0, 0
		e.start = e.start.Add(time.Duration(n) * e.window)
	}
}

// count — счёт скользящего окна: текущее окно и доля прошлого.
func (e *entry) count(now time.Time) float64 {
	rest := 1 - float64(now.Sub(e.start))/float64(e.window)
	if rest < 0 {
		rest = 0
	}
	return float64(e.cur) + float64(e.prev)*rest
}

// Maintain раз в every удаляет ключи, не использованные дольше idle
// (Sweep), и пишет предупреждение, если с прошлого раза ключи вытеснялись
// пределом: их счётчики сброшены, лимиты по ним — fail-open (4Н11 ревью
// 4.r1). В журнал — только числа, без ключей (в них ID агентов и сессий).
// Возвращается при отмене ctx.
func (c *Counters) Maintain(ctx context.Context, every, idle time.Duration, logger *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	var seen uint64
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.Sweep(now, idle)
			if n := c.Evictions(); n > seen {
				logger.Warn("счётчики лимитов вызовов инструментов: ключи вытеснены пределом, их счёт начат заново",
					"evicted", n-seen, "max_keys", c.max)
				seen = n
			}
		}
	}
}

// Sweep удаляет ключи, не использованные дольше idle: память не держит
// счётчики давно ушедших сессий. Вызывается периодически (Maintain).
func (c *Counters) Sweep(now time.Time, idle time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for el := c.lru.Back(); el != nil; {
		e := el.Value.(*entry)
		if now.Sub(e.lastSeen) < idle {
			break
		}
		prev := el.Prev()
		delete(c.byKey, e.key)
		c.lru.Remove(el)
		el = prev
		n++
	}
	return n
}
