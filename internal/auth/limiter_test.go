package auth

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestDM38_LimiterBlocksAfterFailures(t *testing.T) {
	l := NewFailureLimiter(LimiterConfig{MaxFailures: 3, Window: time.Minute, Block: 10 * time.Minute})
	a := netip.MustParseAddr("203.0.113.7")
	// Граница: третья неудача в окне блокирует, вторая — нет.
	for i := range 2 {
		if l.Fail(a, now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("блокировка после %d неудач", i+1)
		}
	}
	if b, _ := l.Blocked(a, now); b {
		t.Fatal("заблокирован до порога")
	}
	if !l.Fail(a, now.Add(2*time.Second)) {
		t.Fatal("нет блокировки на пороге")
	}
	blocked, until := l.Blocked(a, now.Add(3*time.Second))
	if !blocked || !until.Equal(now.Add(2*time.Second+10*time.Minute)) {
		t.Fatalf("блокировка: %v до %v", blocked, until)
	}
	// Неудачи во время блокировки не продлевают её и не создают новых
	// сообщений о начале блокировки.
	if l.Fail(a, now.Add(time.Minute)) {
		t.Fatal("повторное начало блокировки")
	}
	if b, _ := l.Blocked(a, until); b {
		t.Fatal("блокировка не снялась в срок")
	}
	// Другой адрес не затронут.
	if b, _ := l.Blocked(netip.MustParseAddr("203.0.113.8"), now.Add(3*time.Second)); b {
		t.Fatal("заблокирован соседний адрес")
	}
}

func TestDM38_LimiterWindowResets(t *testing.T) {
	l := NewFailureLimiter(LimiterConfig{MaxFailures: 3, Window: time.Minute})
	a := netip.MustParseAddr("198.51.100.1")
	l.Fail(a, now)
	l.Fail(a, now.Add(30*time.Second))
	// Окно истекло: счёт начинается заново.
	if l.Fail(a, now.Add(time.Minute)) || l.Fail(a, now.Add(61*time.Second)) {
		t.Fatal("неудачи из прошлого окна учтены")
	}
	if !l.Fail(a, now.Add(62*time.Second)) {
		t.Fatal("нет блокировки в новом окне")
	}
}

func TestDM38_LimiterGroupsIPv6By64(t *testing.T) {
	l := NewFailureLimiter(LimiterConfig{MaxFailures: 2})
	l.Fail(netip.MustParseAddr("2001:db8:1:2::1"), now)
	if !l.Fail(netip.MustParseAddr("2001:db8:1:2:ffff::9"), now) {
		t.Fatal("адреса одной сети /64 учитываются раздельно")
	}
	if b, _ := l.Blocked(netip.MustParseAddr("2001:db8:1:3::1"), now); b {
		t.Fatal("заблокирована соседняя сеть /64")
	}
	// IPv4 в записи IPv6 — тот же адрес IPv4.
	l.Fail(netip.MustParseAddr("192.0.2.1"), now)
	if !l.Fail(netip.MustParseAddr("::ffff:192.0.2.1"), now) {
		t.Fatal("IPv4-in-IPv6 учтён отдельно от IPv4")
	}
}

func TestLimiterMemoryBounded(t *testing.T) {
	l := NewFailureLimiter(LimiterConfig{MaxFailures: 2, MaxEntries: 4, Window: time.Minute})
	addr := func(i uint16) netip.Addr {
		b := [4]byte{10, 0}
		binary.BigEndian.PutUint16(b[2:], i)
		return netip.AddrFrom4(b)
	}
	// Четыре адреса заблокированы — вытеснить нечего, новые не учитываются.
	for i := range uint16(4) {
		l.Fail(addr(i), now)
		l.Fail(addr(i), now)
	}
	l.Fail(addr(100), now)
	if l.Overflowed() != 1 || len(l.entries) != 4 {
		t.Fatalf("переполнение: %d, записей %d", l.Overflowed(), len(l.entries))
	}
	for i := range uint16(4) {
		if b, _ := l.Blocked(addr(i), now); !b {
			t.Fatalf("блокировка %d вытеснена", i)
		}
	}
	// После снятия блокировок старые записи вычищаются.
	later := now.Add(time.Hour)
	for i := uint16(200); i < 300; i++ {
		l.Fail(addr(i), later)
	}
	if len(l.entries) > 4 {
		t.Fatalf("записей %d при пределе 4", len(l.entries))
	}
}

func TestLimiterDefaults(t *testing.T) {
	l := NewFailureLimiter(LimiterConfig{})
	if l.cfg.MaxFailures != 10 || l.cfg.Window != time.Minute || l.cfg.Block != 15*time.Minute || l.cfg.MaxEntries != 1<<16 {
		t.Fatalf("%+v", l.cfg)
	}
	// Нулевой адрес учитывается, а не роняет ограничитель.
	l.Fail(netip.Addr{}, now)
}
