package redteam

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

// Исходящие соединения исполнителя (ADR-0031, разделы 2 и 3): только адрес
// цели или шлюза, без прокси из окружения и без перенаправлений; к адресу
// цели endpoint — только если все адреса имени разрешены правилом
// internal/netguard, при каждом соединении и на проверенный адрес.

// errBlockedAddr — адрес цели запрещён правилом адресов.
var errBlockedAddr = errors.New("адрес цели запрещён: loopback, link-local, multicast и службы метаданных недоступны")

// Lookup — разрешение имени (подмена в тестах).
type Lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)

// Connect — соединение с проверенным адресом «IP:порт» (подмена в тестах).
type Connect func(ctx context.Context, network, addr string) (net.Conn, error)

// guardedDialer — соединение только с разрешёнными адресами.
type guardedDialer struct {
	dialer  net.Dialer
	lookup  Lookup
	connect Connect
}

func (d *guardedDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, errors.New("неверный порт")
	}
	if netguard.CheckHost(host, nil) != nil {
		return nil, errBlockedAddr
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
		return nil, errors.New("имя не разрешилось")
	}
	// Хотя бы один запрещённый адрес среди ответов — отказ: иначе выбор
	// адреса зависел бы от порядка ответов DNS.
	for i, ip := range ips {
		ips[i] = ip.WithZone("")
		if !netguard.Permitted(ips[i], nil) {
			return nil, errBlockedAddr
		}
	}
	connect := d.connect
	if connect == nil {
		connect = d.dialer.DialContext
	}
	var conn net.Conn
	for _, ip := range ips {
		if conn, err = connect(ctx, network, netip.AddrPortFrom(ip, uint16(p)).String()); err == nil {
			return conn, nil
		}
	}
	return nil, err
}

// noRedirect — перенаправления не выполняются: ответ 3xx возвращается как
// есть и становится ошибкой шага redirect.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// newClient — HTTP-клиент исполнителя. rootsPEM — корневые сертификаты для
// https (пусто — только http); guard — проверка адресов netguard при
// каждом соединении (цель endpoint); lookup и connect — разрешение имени
// и соединение с проверенным адресом (nil — системные).
func newClient(tp aisecCrypto.TLSProvider, rootsPEM []byte, timeout time.Duration, guard bool, lookup Lookup, connect Connect) (*http.Client, error) {
	t := &http.Transport{
		Proxy:                 nil,
		ResponseHeaderTimeout: timeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   MaxConcurrency,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	connectTimeout := 10 * time.Second
	if guard {
		d := &guardedDialer{dialer: net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}, lookup: lookup, connect: connect}
		t.DialContext = d.dial
	} else {
		t.DialContext = (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext
	}
	if len(rootsPEM) > 0 {
		if tp == nil {
			return nil, errors.New("TLS недоступен в криптопрофиле")
		}
		cfg, err := tp.ClientConfig(rootsPEM)
		if err != nil {
			return nil, err
		}
		t.TLSClientConfig = cfg
	}
	return &http.Client{Transport: t, CheckRedirect: noRedirect, Timeout: timeout}, nil
}
