package netguard

import (
	"errors"
	"net/netip"
	"testing"
)

func TestBlocked(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "fe80::1", "fd00:ec2::254",
		"100.100.100.200", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "0.0.0.0", "::", "224.0.0.1", "ff02::1"} {
		if !Blocked(netip.MustParseAddr(ip)) {
			t.Errorf("%s не запрещён", ip)
		}
	}
	for _, ip := range []string{"10.1.2.3", "172.16.0.10", "192.168.1.5", "fc00::5", "203.0.113.7", "64:ff9b::cb00:7107"} {
		if Blocked(netip.MustParseAddr(ip)) {
			t.Errorf("%s запрещён", ip)
		}
	}
}

func TestPermittedAllowedNetworks(t *testing.T) {
	lo := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	if !Permitted(netip.MustParseAddr("127.0.0.1"), lo) || !Permitted(netip.MustParseAddr("::ffff:127.0.0.1"), lo) {
		t.Fatal("явно разрешённая сеть запрещена")
	}
	if Permitted(netip.MustParseAddr("169.254.169.254"), lo) {
		t.Fatal("метаданные разрешены вместе с loopback")
	}
}

func TestCheckHost(t *testing.T) {
	for _, h := range []string{"localhost", "LOCALHOST.", "api.localhost", "127.0.0.1", "[::1]", "::1", "169.254.169.254",
		"fe80::1%eth0", "0.0.0.0"} {
		if err := CheckHost(h, nil); !errors.Is(err, ErrBlockedHost) {
			t.Errorf("%s: %v", h, err)
		}
	}
	for _, h := range []string{"mcp.example.ru", "10.0.0.5", "[fc00::1]", "localhost.example.ru"} {
		if err := CheckHost(h, nil); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
	if err := CheckHost("127.0.0.1", []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}); err != nil {
		t.Errorf("разрешённая сеть: %v", err)
	}
}

// Адрес оценщика judge.llm — только частная сеть (ADR-0030, раздел 1).
func TestPrivate(t *testing.T) {
	for _, ip := range []string{"10.1.2.3", "172.16.0.10", "172.31.255.254", "192.168.1.5", "fc00::5", "fd12:3456::1",
		"::ffff:10.0.0.7"} {
		if !Private(netip.MustParseAddr(ip)) {
			t.Errorf("%s не считается частным", ip)
		}
	}
	for _, ip := range []string{"203.0.113.7", "8.8.8.8", "172.32.0.1", "100.64.0.1", "100.100.100.200", "127.0.0.1", "::1",
		"169.254.169.254", "fd00:ec2::254", "fe80::1", "64:ff9b::a01:203", "2001:db8::1", "0.0.0.0"} {
		if Private(netip.MustParseAddr(ip)) {
			t.Errorf("%s считается частным", ip)
		}
	}
}

func TestCheckPrivateHost(t *testing.T) {
	for _, h := range []string{"llm.corp.internal", "10.0.0.5", "[fd00::5]", "192.168.10.2"} {
		if err := CheckPrivateHost(h); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
	for _, h := range []string{"", "localhost", "a.localhost.", "127.0.0.1", "203.0.113.7", "[::1]", "169.254.169.254", "[fd00:ec2::254]"} {
		if err := CheckPrivateHost(h); err == nil {
			t.Errorf("%s принят", h)
		}
	}
	if !errors.Is(CheckPrivateHost("8.8.8.8"), ErrNotPrivateHost) {
		t.Fatal("внешний адрес — не ErrNotPrivateHost")
	}
}
