// netwatch — ловушка сети для e2e пилота «без интернета» (задача 3.7, H-Р11).
// В поставку не входит: собирается целью make e2e-pilot-bin и запускается
// только наложением test/e2e/testdata/pilot/compose.e2e.yaml. Разборщики
// DNS и пакетов покрыты fuzz-тестами (docs/cert/fuzzing.md).
//
// Ловушка стоит во всех сетях compose пилота с фиксированными адресами, и
// каждый сервис получает её адрес как вышестоящий DNS (`dns:`). Встроенный
// DNS Docker сам отвечает на имена сервисов, а любое другое имя пересылает
// сюда. Ловушка:
//   - отвечает на запрос A своим адресом в сети спрашивающего и пишет имя;
//   - читает все пакеты, пришедшие на её адреса (AF_PACKET), и пишет каждую
//     попытку соединения: TCP SYN, UDP не на порт 53, ICMP.
//
// Так обращение по имени во внешнюю сеть видно дважды: запрос имени и
// попытка соединения с ловушкой. Обращение по IP-адресу без имени сюда не
// попадает: во внутренних сетях нет маршрута наружу, соединение не выходит
// из контейнера (ENETUNREACH), — его закрывает статическая проверка
// repocheck (сетевые клиенты только в NET_CLIENT_ALLOWED).
//
// Каждая запись — строка JSON на stdout; тест читает её через docker logs.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

// record — одна строка журнала ловушки.
type record struct {
	Kind  string   `json:"kind"`            // ready, dns, conn, error
	Src   string   `json:"src,omitempty"`   // адрес источника
	Name  string   `json:"name,omitempty"`  // dns: запрошенное имя
	Type  uint16   `json:"type,omitempty"`  // dns: тип запроса
	Proto string   `json:"proto,omitempty"` // conn: tcp, udp, icmp
	Port  uint16   `json:"port,omitempty"`  // conn: порт назначения
	Addrs []string `json:"addrs,omitempty"` // ready: адреса ловушки
	Error string   `json:"error,omitempty"`
}

// journal пишет записи без повторов: повторная передача SYN и повтор
// запроса имени — одна запись.
type journal struct {
	mu   sync.Mutex
	enc  *json.Encoder
	seen map[string]bool
}

func (j *journal) write(r record) {
	j.mu.Lock()
	defer j.mu.Unlock()
	key := fmt.Sprintf("%s|%s|%s|%d|%s|%d", r.Kind, r.Src, r.Name, r.Type, r.Proto, r.Port)
	if r.Kind != "ready" && r.Kind != "error" {
		if j.seen[key] {
			return
		}
		j.seen[key] = true
	}
	if err := j.enc.Encode(r); err != nil {
		// stdout недоступен — записать некуда; тест увидит пустой журнал.
		return
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	j := &journal{enc: json.NewEncoder(os.Stdout), seen: map[string]bool{}}
	nets, err := localNets()
	if err != nil {
		j.write(record{Kind: "error", Error: err.Error()})
		os.Exit(1)
	}
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", ":53")
	if err != nil {
		j.write(record{Kind: "error", Error: "DNS: " + err.Error()})
		os.Exit(1)
	}
	pf, err := packetSocket()
	if err != nil {
		j.write(record{Kind: "error", Error: "AF_PACKET: " + err.Error()})
		os.Exit(1)
	}
	go serveDNS(pc, nets, j)
	go sniff(pf, nets, j)
	addrs := make([]string, 0, len(nets))
	for _, n := range nets {
		addrs = append(addrs, n.IP.String())
	}
	j.write(record{Kind: "ready", Addrs: addrs})
	<-ctx.Done()
	_ = pc.Close() //nolint:gosec // G104: завершение по сигналу
}

// localNets — IPv4-адреса ловушки с масками сетей.
func localNets() ([]*net.IPNet, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []*net.IPNet
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			out = append(out, &net.IPNet{IP: n.IP.To4(), Mask: n.Mask})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("нет IPv4-адресов")
	}
	return out, nil
}

// own — свой адрес в сети источника src; nil — src не из сетей ловушки.
func own(nets []*net.IPNet, src net.IP) net.IP {
	for _, n := range nets {
		if n.Contains(src) {
			return n.IP
		}
	}
	return nil
}

func isOwn(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// serveDNS отвечает на каждый запрос A своим адресом, на остальные — пустым
// ответом без ошибки.
func serveDNS(pc net.PacketConn, nets []*net.IPNet, j *journal) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		name, qtype, qend, err := parseQuestion(buf[:n])
		if err != nil {
			j.write(record{Kind: "error", Src: ua.IP.String(), Error: "DNS: " + err.Error()})
			continue
		}
		j.write(record{Kind: "dns", Src: ua.IP.String(), Name: name, Type: qtype})
		resp := answer(buf[:qend], qtype, own(nets, ua.IP))
		if _, err := pc.WriteTo(resp, from); err != nil {
			j.write(record{Kind: "error", Src: ua.IP.String(), Error: "DNS: " + err.Error()})
		}
	}
}

// parseQuestion разбирает заголовок и единственный вопрос запроса DNS;
// qend — конец вопроса в msg.
func parseQuestion(msg []byte) (name string, qtype uint16, qend int, err error) {
	if len(msg) < 12 {
		return "", 0, 0, errors.New("короткий заголовок")
	}
	if msg[2]&0x80 != 0 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return "", 0, 0, errors.New("не запрос с одним вопросом")
	}
	var labels []string
	i := 12
	for {
		if i >= len(msg) {
			return "", 0, 0, errors.New("имя обрезано")
		}
		l := int(msg[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(msg) {
			return "", 0, 0, errors.New("неверная метка имени")
		}
		labels = append(labels, asciiLower(msg[i:i+l]))
		i += l
	}
	if i+4 > len(msg) {
		return "", 0, 0, errors.New("нет типа и класса")
	}
	return strings.Join(labels, "."), binary.BigEndian.Uint16(msg[i : i+2]), i + 4, nil
}

// asciiLower — метка в нижнем регистре только для ASCII: имена DNS
// сравниваются без учёта регистра ASCII, остальные байты остаются как есть.
func asciiLower(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// answer строит ответ на вопрос query (заголовок и вопрос): для A — одна
// запись с адресом ip.
func answer(query []byte, qtype uint16, ip net.IP) []byte {
	resp := append([]byte{}, query...)
	resp[2] = 0x84 | query[2]&0x01 // QR, AA, RD из запроса
	resp[3] = 0x80                 // RA, RCODE 0
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	if qtype != 1 || ip == nil {
		binary.BigEndian.PutUint16(resp[6:8], 0)
		return resp
	}
	binary.BigEndian.PutUint16(resp[6:8], 1)
	// Имя — ссылка на вопрос (0xC00C), A, IN, TTL 5 с, 4 байта адреса.
	resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4)
	return append(resp, ip.To4()...)
}

// Номера протоколов: EtherType IPv4 и протоколы IP.
const (
	ethPIPv4   = 0x0800
	protoICMP  = 1
	protoTCP   = 6
	protoUDP   = 17
	maxPacket  = 65536
	afPacketFD = "af_packet"
)

// packetSocket открывает AF_PACKET для IPv4 без заголовка канального уровня
// на всех интерфейсах ловушки (нужна возможность NET_RAW). В пакете Go нет
// сокетов AF_PACKET; ловушка — тестовый инструмент вне поставки, прямой
// вызов — только здесь (ADR-0004, дополнение от 22.10.2026).
func packetSocket() (*os.File, error) {
	proto := int(ethPIPv4>>8 | ethPIPv4&0xff<<8)                            // htons
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, proto) //nolint:forbidigo // ADR-0004, дополнение: AF_PACKET в тестовой ловушке вне поставки
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), afPacketFD), nil //nolint:gosec // G115: дескриптор от успешного socket(2) неотрицателен
}

// sniff пишет попытки соединения с адресами ловушки: TCP SYN без ACK, UDP
// не на порт 53 (запросы имён пишет serveDNS), ICMP. Свои исходящие пакеты
// отсекает attempt: у них источник — адрес ловушки.
func sniff(f *os.File, nets []*net.IPNet, j *journal) {
	buf := make([]byte, maxPacket)
	for {
		n, err := f.Read(buf)
		if err != nil {
			j.write(record{Kind: "error", Error: "AF_PACKET: " + err.Error()})
			return
		}
		if r, ok := attempt(buf[:n], nets); ok {
			j.write(r)
		}
	}
}

// attempt разбирает пакет IPv4 и решает, попытка ли это соединения с ловушкой.
func attempt(p []byte, nets []*net.IPNet) (record, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return record{}, false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl+4 {
		return record{}, false
	}
	src, dst := net.IP(p[12:16]), net.IP(p[16:20])
	if isOwn(nets, src) || !isOwn(nets, dst) {
		return record{}, false
	}
	l4 := p[ihl:]
	r := record{Kind: "conn", Src: src.String()}
	switch p[9] {
	case protoTCP:
		if len(l4) < 14 || l4[13]&0x12 != 0x02 { // SYN без ACK
			return record{}, false
		}
		r.Proto, r.Port = "tcp", binary.BigEndian.Uint16(l4[2:4])
	case protoUDP:
		r.Proto, r.Port = "udp", binary.BigEndian.Uint16(l4[2:4])
		if r.Port == 53 {
			return record{}, false
		}
	case protoICMP:
		r.Proto = "icmp"
	default:
		r.Proto = fmt.Sprintf("ip-%d", p[9])
	}
	return r, true
}
