package oidc

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// errBlockedAddr — адрес IdP запрещён.
var errBlockedAddr = errors.New("OIDC: адрес IdP запрещён")

// metadataAddrs — адреса служб метаданных облака вне link-local: AWS
// IPv6 и Alibaba Cloud (169.254.169.254 — link-local). То же правило, что у
// каналов уведомлений (3Н31 ревью 3.r2).
var metadataAddrs = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("100.100.100.200")}

// nat64 — префикс NAT64 (RFC 6052): адрес IPv4 в нём проверяется тоже.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// blockedAddr — адрес запрещён по умолчанию: loopback, link-local,
// групповые, неуказанные адреса и метаданные облака. Частные сети
// разрешены: IdP заказчика обычно в них.
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

// dialer — соединение только с разрешёнными адресами: имя разрешается
// здесь, и соединение идёт на уже проверенный адрес, поэтому повторное
// разрешение (DNS rebinding) проверку не обходит. Хотя бы один
// запрещённый адрес среди ответов — отказ.
func dialer(allowed []netip.Prefix, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || p == 0 {
			return nil, errors.New("OIDC: неверный порт")
		}
		var ips []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			ips = []netip.Addr{ip.WithZone("")}
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
		var conn net.Conn
		for _, ip := range ips {
			if conn, err = d.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, uint16(p)).String()); err == nil {
				return conn, nil
			}
		}
		if err == nil {
			err = errors.New("OIDC: имя узла не разрешено")
		}
		return nil, err
	}
}
