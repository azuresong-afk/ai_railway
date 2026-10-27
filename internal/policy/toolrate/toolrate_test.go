package toolrate

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func TestHitLimitAndWindow(t *testing.T) {
	c := New(0)
	for i := range 5 {
		if c.Hit("k", time.Minute, 5, t0.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("вызов %d превысил предел 5", i+1)
		}
	}
	if !c.Hit("k", time.Minute, 5, t0.Add(10*time.Second)) {
		t.Fatal("шестой вызов в окне не превысил предел")
	}
	// Скользящее окно: через полторы минуты доля прошлого окна — половина.
	if n := c.Count("k", t0.Add(90*time.Second)); n < 2.9 || n > 3.1 {
		t.Fatalf("счёт через 1,5 окна: %v", n)
	}
	// Через два окна счёт обнулён.
	if c.Hit("k", time.Minute, 5, t0.Add(3*time.Minute)) {
		t.Fatal("после двух окон вызов превысил предел")
	}
	// Без предела вызов не учитывается и ключ не создаётся.
	if c.Hit("free", time.Minute, 0, t0) || c.Len() != 1 {
		t.Fatalf("предел 0: ключей %d", c.Len())
	}
}

func TestClockBackwardsRestartsWindow(t *testing.T) {
	c := New(0)
	for range 3 {
		c.Hit("k", time.Minute, 10, t0)
	}
	if c.Hit("k", time.Minute, 1, t0.Add(-time.Hour)) {
		t.Fatal("после перевода часов назад окно не началось заново")
	}
}

// Память ограничена: при переполнении вытесняется давно не использованный
// ключ, его счётчик сбрасывается (fail-open), вытеснение считается.
func TestEvictionBoundsMemory(t *testing.T) {
	c := New(100)
	for i := range 1000 {
		c.Hit("k"+strconv.Itoa(i), time.Minute, 1, t0)
	}
	if c.Len() != 100 || c.Evictions() != 900 {
		t.Fatalf("ключей %d, вытеснено %d", c.Len(), c.Evictions())
	}
	// Недавно использованный ключ остаётся: k999 не вытеснен.
	if c.Count("k999", t0) != 1 || c.Count("k0", t0) != 0 {
		t.Fatal("вытеснен не самый давний ключ")
	}
	if n := c.Sweep(t0.Add(25*time.Hour), 24*time.Hour); n != 100 || c.Len() != 0 {
		t.Fatalf("очистка давних ключей: %d, осталось %d", n, c.Len())
	}
}

func TestConcurrentHits(t *testing.T) {
	c := New(10)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 1000 {
				c.Hit("k"+strconv.Itoa((g*1000+i)%20), time.Minute, 50, t0)
			}
		}()
	}
	wg.Wait()
	if c.Len() > 10 {
		t.Fatalf("ключей больше предела: %d", c.Len())
	}
}
