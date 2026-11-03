package providers

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// Оценщик judge.llm — только в частной сети (ADR-0030, раздел 1): адрес
// вне неё — отказ соединения при каждом соединении, после разрешения имени.
func TestPrivateDialerRefusesOutsidePrivateNetwork(t *testing.T) {
	answers := map[string][]netip.Addr{
		"public.example":   {netip.MustParseAddr("203.0.113.7")},
		"mixed.example":    {netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("8.8.8.8")},
		"meta.example":     {netip.MustParseAddr("169.254.169.254")},
		"loop.example":     {netip.MustParseAddr("127.0.0.1")},
		"ula-meta.example": {netip.MustParseAddr("fd00:ec2::254")},
	}
	d := &privateDialer{lookup: func(_ context.Context, _, host string) ([]netip.Addr, error) {
		return answers[host], nil
	}}
	for _, addr := range []string{"public.example:443", "mixed.example:443", "meta.example:443", "loop.example:443",
		"ula-meta.example:443", "203.0.113.7:443", "127.0.0.1:443", "[::1]:443", "localhost:443"} {
		if _, err := d.dial(context.Background(), "tcp", addr); !errors.Is(err, ErrNotPrivate) {
			t.Errorf("%s: %v, нужен отказ ErrNotPrivate", addr, err)
		}
	}
	if _, err := d.dial(context.Background(), "tcp", "nothing.example:443"); err == nil {
		t.Fatal("неразрешённое имя принято")
	}
	if _, err := d.dial(context.Background(), "tcp", "10.0.0.5:0"); err == nil {
		t.Fatal("порт 0 принят")
	}
}

// Частный адрес пропускается к соединению: ошибка — уже от самого
// соединения (адрес в тестовой среде недоступен), а не отказ правила.
func TestPrivateDialerAllowsPrivate(t *testing.T) {
	d := &privateDialer{lookup: func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.255.255.1")}, nil
	}}
	d.dialer.Timeout = 50 * time.Millisecond
	_, err := d.dial(context.Background(), "tcp", "llm.corp:443")
	if errors.Is(err, ErrNotPrivate) {
		t.Fatal("частный адрес отклонён правилом")
	}
}
