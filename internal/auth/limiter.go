package auth

import (
	"net/netip"
	"sync"
	"time"
)

// FailureLimiter ограничивает частоту неудачных попыток аутентификации с
// одного адреса (ТЗ, 5.1; DM-38). Адреса IPv6 группируются по сети /64:
// у одного клиента их обычно целая сеть. Пока адрес заблокирован, неудачи с
// него отклоняются без событий; действующий ключ проходит (см. RequireAppKey).
//
// Память ограничена: при переполнении сначала удаляются записи с истёкшим
// окном, затем — любая незаблокированная запись. Если места всё равно нет
// (таблицу заполнили блокировками, например, из множества сетей IPv6 /64),
// неудачи новых адресов учитываются в одном общем счётчике, который
// блокируется так же: ограничение не перестаёт действовать, а поток событий
// остаётся ограниченным. Ограничитель — средство против перебора и шума, а
// не единственная защита: ключ содержит 256 бит случайных данных.
type FailureLimiter struct {
	mu         sync.Mutex
	cfg        LimiterConfig
	entries    map[netip.Prefix]*limiterEntry
	overflow   limiterEntry // общий счётчик для адресов, не поместившихся в таблицу
	lastSweep  time.Time
	overflowed uint64
}

// LimiterConfig — параметры ограничителя.
type LimiterConfig struct {
	MaxFailures int           // неудач за окно до блокировки; по умолчанию 10
	Window      time.Duration // окно подсчёта; по умолчанию 1 мин
	Block       time.Duration // время блокировки; по умолчанию 15 мин
	MaxEntries  int           // число отслеживаемых адресов; по умолчанию 65 536
}

type limiterEntry struct {
	failures     int
	windowStart  time.Time
	blockedUntil time.Time
}

// NewFailureLimiter создаёт ограничитель; нулевые параметры — по умолчанию.
func NewFailureLimiter(cfg LimiterConfig) *FailureLimiter {
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = 10
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.Block <= 0 {
		cfg.Block = 15 * time.Minute
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 1 << 16
	}
	return &FailureLimiter{cfg: cfg, entries: map[netip.Prefix]*limiterEntry{}}
}

// clientKey — ключ учёта: адрес IPv4 целиком или сеть IPv6 /64.
func clientKey(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	p, err := a.Prefix(64)
	if err != nil {
		// Нулевой адрес (RemoteAddr не разобран; у TCP-соединения так не
		// бывает) — один общий ключ: такие клиенты делят один счётчик.
		return netip.Prefix{}
	}
	return p
}

// entry возвращает запись адреса; если её нет и места нет — общий счётчик.
// Вызывается под блокировкой.
func (l *FailureLimiter) entry(k netip.Prefix, now time.Time, create bool) *limiterEntry {
	if e, ok := l.entries[k]; ok {
		return e
	}
	if !create {
		if len(l.entries) >= l.cfg.MaxEntries {
			return &l.overflow
		}
		return nil
	}
	if !l.makeRoom(now) {
		l.overflowed++
		return &l.overflow
	}
	e := &limiterEntry{windowStart: now}
	l.entries[k] = e
	return e
}

// Blocked сообщает, заблокирован ли адрес, и до какого момента.
func (l *FailureLimiter) Blocked(a netip.Addr, now time.Time) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entry(clientKey(a), now, false)
	if e == nil || !now.Before(e.blockedUntil) {
		return false, time.Time{}
	}
	return true, e.blockedUntil
}

// Fail учитывает неудачу. Возвращает true, если эта неудача привела к
// блокировке адреса (о начале блокировки создаётся одно событие, а не по
// событию на каждый отклонённый запрос).
func (l *FailureLimiter) Fail(a netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entry(clientKey(a), now, true)
	if now.Before(e.blockedUntil) {
		return false
	}
	if now.Sub(e.windowStart) >= l.cfg.Window {
		e.failures, e.windowStart = 0, now
	}
	e.failures++
	if e.failures >= l.cfg.MaxFailures {
		e.blockedUntil = now.Add(l.cfg.Block)
		e.failures, e.windowStart = 0, now
		return true
	}
	return false
}

// Overflowed — сколько неудач учтено в общем счётчике из-за переполнения
// таблицы (метрика).
func (l *FailureLimiter) Overflowed() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.overflowed
}

// makeRoom освобождает место под новую запись. Вызывается под блокировкой.
func (l *FailureLimiter) makeRoom(now time.Time) bool {
	if len(l.entries) < l.cfg.MaxEntries {
		return true
	}
	// Полный проход — не чаще раза в секунду, чтобы поток неудач с разных
	// адресов не превращал каждую из них в обход всей таблицы.
	if now.Sub(l.lastSweep) >= time.Second {
		l.lastSweep = now
		for k, e := range l.entries {
			if !now.Before(e.blockedUntil) && now.Sub(e.windowStart) >= l.cfg.Window {
				delete(l.entries, k)
			}
		}
		if len(l.entries) < l.cfg.MaxEntries {
			return true
		}
	}
	// Вытесняется первая попавшаяся незаблокированная запись; блокировки
	// сохраняются. Просмотр ограничен, чтобы не обходить таблицу целиком.
	n := 0
	for k, e := range l.entries {
		if !now.Before(e.blockedUntil) {
			delete(l.entries, k)
			return true
		}
		if n++; n >= 64 {
			break
		}
	}
	return false
}
