// Пакет netguard — запрет исходящих соединений к адресам, через которые
// администратор консоли мог бы достать внутренние службы узла: loopback,
// link-local, multicast, неуказанный адрес и службы метаданных облака
// (3Н31 ревью 3.r2). Одно правило для каналов уведомлений (internal/notify)
// и MCP-серверов (internal/agents, ADR-0023, раздел 1): проверка при
// сохранении (литерал адреса и localhost) и при каждом соединении после
// разрешения имени. Частные сети разрешены: SIEM, почта и MCP-серверы
// заказчика обычно в них.
package netguard

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
)

// metadataAddrs — адреса служб метаданных облака вне link-local: AWS
// IPv6 и Alibaba Cloud (169.254.169.254 — link-local).
var metadataAddrs = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("100.100.100.200")}

// nat64 — префикс NAT64 (RFC 6052): адрес IPv4 в нём проверяется тоже.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// Blocked — адрес запрещён по умолчанию.
func Blocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	if nat64.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte(b[12:]))
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || slices.Contains(metadataAddrs, ip)
}

// Permitted — соединение с ip разрешено: адрес не запрещён или входит в
// явно разрешённые администратором сети (allowed).
func Permitted(ip netip.Addr, allowed []netip.Prefix) bool {
	for _, p := range allowed {
		if p.Contains(ip.Unmap()) || p.Contains(ip) {
			return true
		}
	}
	return !Blocked(ip)
}

// ErrBlockedHost — узел запрещён правилом адресов.
var ErrBlockedHost = errors.New("адрес запрещён: loopback, link-local, multicast и службы метаданных недоступны")

// CheckHost — проверка узла при сохранении: литерал запрещённого адреса и
// имена localhost запрещены (имя разрешается только при соединении, тогда
// проверяется каждый полученный адрес). host — без порта и скобок.
func CheckHost(host string, allowed []netip.Prefix) error {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return ErrBlockedHost
	}
	if ip, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil && !Permitted(ip.WithZone(""), allowed) {
		return ErrBlockedHost
	}
	return nil
}
