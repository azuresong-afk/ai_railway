package ldap

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"
)

// errBlockedAddr — адрес каталога запрещён.
var errBlockedAddr = errors.New("LDAP: адрес каталога запрещён")

// errReadLimit — каталог прислал больше MaxRead байт за соединение.
var errReadLimit = errors.New("LDAP: превышен предел ответа каталога")

// metadataAddrs — адреса служб метаданных облака вне link-local: AWS
// IPv6 и Alibaba Cloud (169.254.169.254 — link-local). То же правило, что у
// OIDC и каналов уведомлений (3Н31 ревью 3.r2, ADR-0025, 2.6).
var metadataAddrs = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("100.100.100.200")}

// nat64 — префикс NAT64 (RFC 6052): адрес IPv4 в нём проверяется тоже.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// blockedAddr — адрес запрещён по умолчанию: loopback, link-local,
// групповые, неуказанные адреса и метаданные облака. Частные сети
// разрешены: каталог заказчика обычно в них.
func blockedAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if nat64.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte(b[12:]))
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || slices.Contains(metadataAddrs, ip)
}

func permitted(allowed []netip.Prefix, ip netip.Addr) bool {
	for _, p := range allowed {
		if p.Contains(ip.Unmap()) || p.Contains(ip) {
			return true
		}
	}
	return !blockedAddr(ip)
}

// dial — TCP-соединение с каталогом только на разрешённый адрес: имя
// разрешается здесь, и соединение идёт на уже проверенный адрес, поэтому
// повторное разрешение (DNS rebinding) проверку не обходит. Хотя бы один
// запрещённый адрес среди ответов — отказ.
func dial(ctx context.Context, allowed []netip.Prefix, timeout time.Duration, host string, port uint16) (net.Conn, error) {
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else if ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, err
	}
	for i, ip := range ips {
		ips[i] = ip.WithZone("")
		if !permitted(allowed, ips[i]) {
			return nil, errBlockedAddr
		}
	}
	d := net.Dialer{Timeout: timeout, KeepAlive: -1}
	var (
		conn net.Conn
		err  error
	)
	for _, ip := range ips {
		if conn, err = d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, port).String()); err == nil {
			return conn, nil
		}
	}
	if err == nil {
		err = errors.New("LDAP: имя узла не разрешено")
	}
	return nil, err
}

// limitedConn — соединение с пределом прочитанных байт: разборщик BER
// библиотеки читает пакеты без своего общего предела, а каталог —
// внешняя система (ADR-0025, 2.3).
type limitedConn struct {
	net.Conn
	left     atomic.Int64
	exceeded atomic.Bool
}

func newLimitedConn(c net.Conn, limit int64) *limitedConn {
	l := &limitedConn{Conn: c}
	l.left.Store(limit)
	return l
}

func (c *limitedConn) Read(p []byte) (int, error) {
	left := c.left.Load()
	if left <= 0 {
		c.exceeded.Store(true)
		return 0, errReadLimit
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, err := c.Conn.Read(p)
	c.left.Add(-int64(n))
	return n, err
}
