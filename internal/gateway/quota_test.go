package gateway

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(q config.Quotas) (*Limiter, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	return newLimiter([]config.Application{{ID: "app", Quotas: q}, {ID: "other", Quotas: q}}, c.now), c
}

func exceeded(t *testing.T, err error, rule, threat string) Exceeded {
	t.Helper()
	var e *Exceeded
	if !errors.As(err, &e) || e.Rule != rule || e.Threat != threat {
		t.Fatalf("ждали превышение %s (%s), получили %v", rule, threat, err)
	}
	return *e
}

// TestDM36_RequestRate: частота запросов приложения, пользователя и ключа
// (DM-36) — отказ quota_exceeded, окно скользит, счётчики приложений
// независимы.
func TestDM36_RequestRate(t *testing.T) {
	l, clk := newTestLimiter(config.Quotas{RequestsPerMinute: 5, RequestsPerMinutePerUser: 2, RequestsPerMinutePerKey: 4})
	req := func(app, key, user string) error {
		_, err := l.Admit(QuotaRequest{App: app, Key: key, User: user})
		return err
	}
	// пользователь: 2 в минуту
	for range 2 {
		if err := req("app", "k1", "u1"); err != nil {
			t.Fatal(err)
		}
	}
	e := exceeded(t, req("app", "k1", "u1"), QuotaRequestsPerMinutePerUser, "DM-36")
	if e.RetryAfter <= 0 || e.RetryAfter > time.Minute {
		t.Errorf("RetryAfter %v", e.RetryAfter)
	}
	// другой пользователь того же ключа проходит; ключ: 4 в минуту
	for _, u := range []string{"u2", "u3"} {
		if err := req("app", "k1", u); err != nil {
			t.Fatal(err)
		}
	}
	exceeded(t, req("app", "k1", "u4"), QuotaRequestsPerMinutePerKey, "DM-36")
	// другой ключ: ещё один запрос — пятый в приложении, шестой отклонён
	if err := req("app", "k2", "u5"); err != nil {
		t.Fatal(err)
	}
	exceeded(t, req("app", "k2", "u6"), QuotaRequestsPerMinute, "DM-36")
	// другое приложение не затронуто
	if err := req("other", "k1", "u1"); err != nil {
		t.Fatal(err)
	}
	// отказ не потребляет квоту: через минуту окно пусто
	clk.advance(61 * time.Second)
	for range 2 {
		if err := req("app", "k1", "u1"); err != nil {
			t.Fatal(err)
		}
	}
}

// Окно скользит: запросы, сделанные в разное время, освобождаются по одному.
func TestDM36_SlidingWindow(t *testing.T) {
	l, clk := newTestLimiter(config.Quotas{RequestsPerMinute: 3})
	admit := func() error { _, err := l.Admit(QuotaRequest{App: "app"}); return err }
	for range 3 {
		if err := admit(); err != nil {
			t.Fatal(err)
		}
		clk.advance(10 * time.Second)
	}
	// прошло 30 с: окно полно, самый старый освободится через ~30 с
	e := exceeded(t, admit(), QuotaRequestsPerMinute, "DM-36")
	if e.RetryAfter < 29*time.Second || e.RetryAfter > 31*time.Second {
		t.Errorf("RetryAfter %v, ждали около 30 с", e.RetryAfter)
	}
	clk.advance(e.RetryAfter)
	if err := admit(); err != nil {
		t.Fatalf("после RetryAfter: %v", err)
	}
	exceeded(t, admit(), QuotaRequestsPerMinute, "DM-36")
}

// TestDM36_Tokens: токены в минуту и в сутки; резерв уточняется по факту.
func TestDM36_Tokens(t *testing.T) {
	l, clk := newTestLimiter(config.Quotas{TokensPerMinute: 1000, TokensPerDay: 2500})
	admit := func(tokens int) (*Reservation, error) { return l.Admit(QuotaRequest{App: "app", Tokens: tokens}) }

	r1, err := admit(600)
	if err != nil {
		t.Fatal(err)
	}
	exceeded(t, errOf(admit(600)), QuotaTPM, "DM-36")
	r1.Settle(100) // фактический расход меньше резерва — излишек возвращается
	r1.Settle(0)   // повторный вызов не действует
	if _, err := admit(800); err != nil {
		t.Fatalf("после возврата излишка: %v", err)
	}
	// запрос больше предела не пройдёт никогда: RetryAfter 0
	if e := exceeded(t, errOf(admit(1001)), QuotaTPM, "DM-36"); e.RetryAfter != 0 {
		t.Errorf("RetryAfter %v", e.RetryAfter)
	}
	// суточный предел: 100 + 800 уже учтено, минуты идут
	for i := range 2 {
		clk.advance(time.Minute + time.Second)
		r, err := admit(800)
		if err != nil {
			t.Fatalf("запрос %d: %v", i, err)
		}
		r.Settle(800)
	}
	clk.advance(time.Minute + time.Second)
	exceeded(t, errOf(admit(800)), QuotaTPD, "DM-36") // 100+800+800+800 > 2500
	// через сутки счётчик свободен
	clk.advance(25 * time.Hour)
	if _, err := admit(800); err != nil {
		t.Fatal(err)
	}
	// фактический расход больше резерва доплачивается
	r, err := admit(100)
	if err != nil {
		t.Fatal(err)
	}
	r.Settle(900)
	exceeded(t, errOf(admit(200)), QuotaTPM, "DM-36")
	// сбой запроса: Settle(0) возвращает весь резерв
	l2, _ := newTestLimiter(config.Quotas{TokensPerMinute: 100})
	r2, err := l2.Admit(QuotaRequest{App: "app", Tokens: 100})
	if err != nil {
		t.Fatal(err)
	}
	r2.Settle(0)
	if _, err := l2.Admit(QuotaRequest{App: "app", Tokens: 100}); err != nil {
		t.Fatal(err)
	}
}

func errOf(_ *Reservation, err error) error { return err }

// TestDM15_InputSize: слишком большой входной текст (DM-15).
func TestDM15_InputSize(t *testing.T) {
	l, _ := newTestLimiter(config.Quotas{MaxInputBytes: 1000})
	if _, err := l.Admit(QuotaRequest{App: "app", InputBytes: 1000}); err != nil {
		t.Fatal(err)
	}
	exceeded(t, errOf(l.Admit(QuotaRequest{App: "app", InputBytes: 1001})), QuotaMaxInputBytes, "DM-15")
}

// DM-15: отказ по размеру не потребляет остальные квоты.
func TestDM15_RejectionDoesNotConsume(t *testing.T) {
	l, _ := newTestLimiter(config.Quotas{MaxInputBytes: 10, RequestsPerMinute: 1})
	exceeded(t, errOf(l.Admit(QuotaRequest{App: "app", InputBytes: 11})), QuotaMaxInputBytes, "DM-15")
	if _, err := l.Admit(QuotaRequest{App: "app", InputBytes: 10}); err != nil {
		t.Fatalf("отказ израсходовал квоту запросов: %v", err)
	}
}

// Без лимитов (нули) квоты не действуют; неизвестное приложение — ошибка;
// отрицательные значения не ломают счётчики.
func TestEdgeCases(t *testing.T) {
	l, _ := newTestLimiter(config.Quotas{})
	for range 100 {
		r, err := l.Admit(QuotaRequest{App: "app", User: "u", Key: "k", InputBytes: 1 << 30, Tokens: 1 << 30})
		if err != nil {
			t.Fatal(err)
		}
		r.Settle(1 << 30)
	}
	if _, err := l.Admit(QuotaRequest{App: "nope"}); !errors.Is(err, ErrUnknownApp) {
		t.Errorf("ошибка %v", err)
	}
	l, _ = newTestLimiter(config.Quotas{TokensPerMinute: 10, RequestsPerMinute: 5})
	r, err := l.Admit(QuotaRequest{App: "app", Tokens: -5, InputBytes: -1})
	if err != nil {
		t.Fatal(err)
	}
	r.Settle(-100)
	var nilRes *Reservation
	nilRes.Settle(1)
}

// Пользователей больше предела: память ограничена, лишние делятся на
// OverflowBuckets корзин по хешу — новые пользователи не получают отказ все
// разом (ревью 1.17–1.21, п. 8), а их суммарная частота ограничена.
func TestUserTableBounded(t *testing.T) {
	l, clk := newTestLimiter(config.Quotas{RequestsPerMinutePerUser: 1})
	for i := range MaxTrackedPerApp {
		if _, err := l.Admit(QuotaRequest{App: "app", User: fmt.Sprint("u", i)}); err != nil {
			t.Fatalf("пользователь %d: %v", i, err)
		}
	}
	// Сверх предела: 1000 новых пользователей по одному запросу. С одной
	// общей корзиной прошёл бы один; с 4096 корзинами по хешу отказ — только
	// при совпадении корзины (в среднем около 11 %).
	const extra = 1000
	denied := 0
	for i := range extra {
		if _, err := l.Admit(QuotaRequest{App: "app", User: fmt.Sprint("x", i)}); err != nil {
			exceeded(t, err, QuotaRequestsPerMinutePerUser, "DM-36")
			denied++
		}
	}
	if denied > extra/4 {
		t.Fatalf("отказано %d из %d новых пользователей сверх предела", denied, extra)
	}
	u := l.apps["app"].users
	if len(u.m) > MaxTrackedPerApp || len(u.over) > OverflowBuckets {
		t.Fatalf("записей %d, корзин %d", len(u.m), len(u.over))
	}
	// Пользователь в корзине сверх предела ограничен её лимитом.
	if _, err := l.Admit(QuotaRequest{App: "app", User: "x0"}); err == nil {
		t.Fatal("повторный запрос пользователя сверх предела прошёл")
	}
	// через минуту устаревшие записи вычищаются и новые пользователи снова отслеживаются
	clk.advance(2 * time.Minute)
	if _, err := l.Admit(QuotaRequest{App: "app", User: "fresh"}); err != nil {
		t.Fatal(err)
	}
	if len(u.m) > 2 || len(u.over) != 0 {
		t.Fatalf("после чистки записей %d, корзин %d", len(u.m), len(u.over))
	}
}

// TestDM36_WindowFromStart — корзины считаются от запуска лимитера
// (now.Sub(start), монотонные часы), а не от UnixNano: перевод системных
// часов назад не обнуляет окна (ревью 1.17–1.21, п. 13). Запуск в 12:00:00,9:
// при корзинах по UnixNano запросы ушли бы из окна через 59,1 с.
func TestDM36_WindowFromStart(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 19, 12, 0, 0, 900_000_000, time.UTC)}
	l := newLimiter([]config.Application{{ID: "app", Quotas: config.Quotas{RequestsPerMinute: 2}}}, clk.now)
	for range 2 {
		if _, err := l.Admit(QuotaRequest{App: "app"}); err != nil {
			t.Fatal(err)
		}
	}
	clk.advance(59500 * time.Millisecond)
	e := exceeded(t, admitErr(l), QuotaRequestsPerMinute, "DM-36")
	if e.RetryAfter <= 0 || e.RetryAfter > time.Second {
		t.Fatalf("RetryAfter %v", e.RetryAfter)
	}
	clk.advance(e.RetryAfter)
	if err := admitErr(l); err != nil {
		t.Fatalf("после RetryAfter: %v", err)
	}
	// Время раньше запуска (часы без монотонной составляющей) — первая
	// корзина, а не отрицательный номер.
	w := newWindow(clk.t, time.Second, 60)
	if b := w.bucket(clk.t.Add(-time.Hour)); b != 1 {
		t.Fatalf("корзина до запуска: %d", b)
	}
}

func admitErr(l *Limiter) error {
	_, err := l.Admit(QuotaRequest{App: "app"})
	return err
}

// Параллельные запросы не проскакивают лимит (go test -race).
func TestConcurrentAdmit(t *testing.T) {
	l, _ := newTestLimiter(config.Quotas{RequestsPerMinute: 100, TokensPerMinute: 1000})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 400 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := l.Admit(QuotaRequest{App: "app", Tokens: 10})
			if err == nil {
				r.Settle(10)
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 100 {
		t.Fatalf("допущено %d, ждали 100", ok)
	}
}

// Цель фаззинга: последовательности вызовов не паникуют и не нарушают
// инварианты (счётчики не отрицательны, допущено не больше предела).
func FuzzAdmit(f *testing.F) {
	f.Add([]byte{1, 2, 3, 200, 7, 0, 255})
	f.Fuzz(func(t *testing.T, ops []byte) {
		l, clk := newTestLimiter(config.Quotas{RequestsPerMinute: 10, TokensPerMinute: 500, TokensPerDay: 2000, RequestsPerMinutePerUser: 3, MaxInputBytes: 1 << 10})
		admitted := 0
		for i := 0; i+1 < len(ops); i += 2 {
			switch ops[i] % 4 {
			case 0:
				clk.advance(time.Duration(ops[i+1]) * time.Second)
			default:
				r, err := l.Admit(QuotaRequest{App: "app", User: string(rune('a' + ops[i+1]%5)), Tokens: int(ops[i+1]) * 3, InputBytes: int(ops[i+1]) * 8})
				if err == nil {
					admitted++
					r.Settle(int(ops[i+1]))
				}
			}
		}
		_ = admitted
		a := l.apps["app"]
		for _, w := range []*window{a.rpm, a.tpm, a.tpd} {
			for _, c := range w.cnt {
				if c < 0 {
					t.Fatalf("отрицательный счётчик %d", c)
				}
			}
		}
	})
}

func BenchmarkAdmit(b *testing.B) {
	l := NewLimiter([]config.Application{{ID: "app", Quotas: config.Quotas{RequestsPerMinute: 1 << 30, TokensPerMinute: 1 << 30, TokensPerDay: 1 << 30, RequestsPerMinutePerUser: 1 << 30}}})
	b.ReportAllocs()
	for b.Loop() {
		r, err := l.Admit(QuotaRequest{App: "app", User: "u", Tokens: 100})
		if err != nil {
			b.Fatal(err)
		}
		r.Settle(80)
	}
}
