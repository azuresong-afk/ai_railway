package providers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/netguard"
)

// ErrNotPrivate — адрес провайдера-оценщика вне частной сети (ADR-0030,
// раздел 1): соединение не устанавливается.
var ErrNotPrivate = errors.New("провайдер-оценщик: адрес вне частной сети")

// NewPrivateTransport — транспорт к провайдеру-оценщику judge.llm: как
// NewTransport, но соединение устанавливается, только если все адреса
// узла после разрешения имени — в частной сети (netguard.Private). Проверка
// — при каждом соединении: имя, которое позже начало разрешаться во внешний
// адрес (DNS rebinding), текст за контур не выводит.
func NewPrivateTransport(tp aisecCrypto.TLSProvider, rootsPEM []byte, connectTimeout, headerTimeout time.Duration) (*http.Transport, error) {
	t, err := NewTransport(tp, rootsPEM, connectTimeout, headerTimeout)
	if err != nil {
		return nil, err
	}
	d := &privateDialer{dialer: net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}}
	t.DialContext = d.dial
	return t, nil
}

// privateDialer — соединение только с частными адресами.
type privateDialer struct {
	dialer net.Dialer
	// lookup — разрешение имени; nil — net.DefaultResolver (подмена в тестах).
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

func (d *privateDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, errors.New("провайдер-оценщик: неверный порт")
	}
	if err := netguard.CheckPrivateHost(host); err != nil {
		return nil, ErrNotPrivate
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip.WithZone("")}
	} else {
		lookup := d.lookup
		if lookup == nil {
			lookup = net.DefaultResolver.LookupNetIP
		}
		if ips, err = lookup(ctx, "ip", host); err != nil {
			return nil, err
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("провайдер-оценщик: имя не разрешилось")
	}
	// Хотя бы один внешний адрес среди ответов — отказ: иначе выбор адреса
	// зависел бы от порядка ответов DNS.
	for i, ip := range ips {
		ips[i] = ip.WithZone("")
		if !netguard.Private(ips[i]) {
			return nil, ErrNotPrivate
		}
	}
	var conn net.Conn
	for _, ip := range ips {
		if conn, err = d.dialer.DialContext(ctx, network, netip.AddrPortFrom(ip, uint16(p)).String()); err == nil {
			return conn, nil
		}
	}
	return nil, err
}
