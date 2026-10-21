package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// maxForwardedHops — сколько адресов X-Forwarded-For разбирается справа:
// длиннее цепочки прокси не бывает, остальное задаёт сам клиент.
const maxForwardedHops = 16

// clientKey — ключ адреса клиента в контексте запроса.
type clientKey struct{}

// ClientAddrMiddleware определяет адрес клиента один раз на запрос: для
// ограничения частоты, аудита и сессий (РСБ.1 «откуда», ЗИ.6). Без
// доверенных прокси — адрес соединения. Если соединение пришло от
// доверенного прокси (TLS-шлюз ГОСТ и т. п., ТЗ 10.3), адрес берётся из
// X-Forwarded-For справа налево: первый адрес, который не входит в
// доверенные сети. Левые значения заголовка задаёт сам клиент, им не
// доверяем (замечание В3 ревью 2.r1).
func ClientAddrMiddleware(trusted []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := resolveClient(r, trusted)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientKey{}, a)))
	})
}

// resolveClient — адрес клиента запроса r.
func resolveClient(r *http.Request, trusted []netip.Prefix) netip.Addr {
	addr := peerAddr(r.RemoteAddr)
	if !inPrefixes(addr, trusted) {
		return addr
	}
	for _, hop := range lastHops(r.Header.Values("X-Forwarded-For"), maxForwardedHops) {
		a, err := netip.ParseAddr(strings.TrimSpace(hop))
		if err != nil || a.Zone() != "" {
			// Мусор в цепочке: дальше влево верить нельзя, клиент — последний
			// доверенный узел.
			return addr
		}
		addr = a.Unmap()
		if !inPrefixes(addr, trusted) {
			return addr
		}
	}
	return addr
}

// lastHops — до n последних адресов из заголовков X-Forwarded-For, справа
// налево. Остальная часть заголовка не разбирается.
func lastHops(values []string, n int) []string {
	out := make([]string, 0, n)
	for i := len(values) - 1; i >= 0 && len(out) < n; i-- {
		v := values[i]
		for len(out) < n {
			j := strings.LastIndexByte(v, ',')
			out = append(out, v[j+1:])
			if j < 0 {
				break
			}
			v = v[:j]
		}
	}
	return out
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// peerAddr — адрес соединения без порта и зоны.
func peerAddr(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.WithZone("").Unmap()
}

// clientAddr — адрес клиента: определённый ClientAddrMiddleware, иначе
// (внутренний порт, тесты обработчиков) — адрес соединения.
func clientAddr(r *http.Request) netip.Addr {
	if a, ok := r.Context().Value(clientKey{}).(netip.Addr); ok {
		return a
	}
	return peerAddr(r.RemoteAddr)
}
