package api

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateRule — предел запросов с одного клиента за окно для адресов с префиксом
// Prefix и, если задан Method, только для этого метода. Max = 0 — без предела.
type RateRule struct {
	Prefix string
	Method string
	Max    int
	Window time.Duration
}

// RateConfig — настройки ограничения частоты (ЗИ.6). Применяется правило с
// самым длинным совпавшим префиксом.
type RateConfig struct {
	Rules      []RateRule
	MaxEntries int // число отслеживаемых клиентов; по умолчанию 65 536
	Now        func() time.Time
}

// DefaultRateRules — значения по умолчанию. Строгий предел — только у
// запросов, которые проверяют пароль или код второго фактора (перебор):
// вход, первичная настройка, второй фактор, смена пароля. Выход, чтение
// состояния настройки и настроек входа идут по общему правилу: за NAT или
// прокси консоль офиса иначе упиралась бы в 429 (замечание В3 ревью 2.r1).
func DefaultRateRules() []RateRule {
	return []RateRule{
		{Prefix: "/", Max: 600, Window: time.Minute},
		{Prefix: "/api/v1/auth/login", Method: http.MethodPost, Max: 10, Window: time.Minute},
		{Prefix: "/api/v1/auth/setup", Method: http.MethodPost, Max: 10, Window: time.Minute},
		{Prefix: "/api/v1/auth/mfa/", Method: http.MethodPost, Max: 10, Window: time.Minute},
		{Prefix: "/api/v1/auth/password", Method: http.MethodPost, Max: 10, Window: time.Minute},
		{Prefix: "/api/v1/gateways/register", Max: 10, Window: time.Minute},
		// Проверка цепочки аудита читает весь журнал (задача 2.4a).
		{Prefix: "/api/v1/audit/verify", Method: http.MethodPost, Max: 5, Window: time.Minute},
		{Prefix: "/internal/", Max: 600, Window: time.Minute},
		{Prefix: "/healthz", Max: 60, Window: time.Minute},
		{Prefix: "/readyz", Max: 60, Window: time.Minute},
	}
}

type rateKey struct {
	rule   int
	client netip.Prefix
}

type rateEntry struct {
	count int
	start time.Time
}

// RateLimiter — счётчики с фиксированным окном. Память ограничена: при
// переполнении удаляются истёкшие окна, а если места всё равно нет, новые
// клиенты считаются в одном общем счётчике правила — ограничение не отключается.
type RateLimiter struct {
	mu       sync.Mutex
	cfg      RateConfig
	entries  map[rateKey]*rateEntry
	overflow map[int]*rateEntry
}

// NewRateLimiter создаёт ограничитель; пустые правила заменяются умолчаниями.
func NewRateLimiter(cfg RateConfig) *RateLimiter {
	if len(cfg.Rules) == 0 {
		cfg.Rules = DefaultRateRules()
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 1 << 16
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &RateLimiter{cfg: cfg, entries: map[rateKey]*rateEntry{}, overflow: map[int]*rateEntry{}}
}

func (l *RateLimiter) ruleFor(method, path string) int {
	best, bestLen := -1, -1
	for i, r := range l.cfg.Rules {
		if r.Method != "" && r.Method != method {
			continue
		}
		if strings.HasPrefix(path, r.Prefix) && len(r.Prefix) > bestLen {
			best, bestLen = i, len(r.Prefix)
		}
	}
	return best
}

// Allow учитывает запрос; при отказе возвращает время до сброса окна.
func (l *RateLimiter) Allow(method, path string, client netip.Prefix) (ok bool, retryAfter time.Duration) {
	i := l.ruleFor(method, path)
	if i < 0 || l.cfg.Rules[i].Max <= 0 {
		return true, 0
	}
	rule := l.cfg.Rules[i]
	window := rule.Window
	if window <= 0 {
		window = time.Minute
	}
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	key := rateKey{i, client}
	e := l.entries[key]
	if e == nil {
		if len(l.entries) >= l.cfg.MaxEntries {
			l.sweep(now)
		}
		if len(l.entries) >= l.cfg.MaxEntries {
			if l.overflow[i] == nil {
				l.overflow[i] = &rateEntry{start: now}
			}
			e = l.overflow[i]
		} else {
			e = &rateEntry{start: now}
			l.entries[key] = e
		}
	}
	if now.Sub(e.start) >= window {
		e.count, e.start = 0, now
	}
	e.count++
	if e.count > rule.Max {
		return false, e.start.Add(window).Sub(now)
	}
	return true, 0
}

// sweep удаляет записи с истёкшим окном.
func (l *RateLimiter) sweep(now time.Time) {
	for k, e := range l.entries {
		w := l.cfg.Rules[k.rule].Window
		if w <= 0 {
			w = time.Minute
		}
		if now.Sub(e.start) >= w {
			delete(l.entries, k)
		}
	}
}

// clientPrefix — клиент для счётчика: адрес IPv6 группируется по сети /64.
func clientPrefix(addr netip.Addr) netip.Prefix {
	if !addr.IsValid() {
		return netip.Prefix{}
	}
	addr = addr.Unmap()
	bits := 32
	if addr.Is6() {
		bits = 64
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return p
}

// Middleware отклоняет превышение предела ответом 429 с Retry-After.
func (l *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, wait := l.Allow(r.Method, r.URL.Path, clientPrefix(clientAddr(r)))
		if !ok {
			secs := int((wait + time.Second - 1) / time.Second)
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			WriteProblem(w, NewProblem(http.StatusTooManyRequests, CodeRateLimited,
				"Слишком много запросов. Повторите через "+strconv.Itoa(secs)+" с."))
			return
		}
		next.ServeHTTP(w, r)
	})
}
