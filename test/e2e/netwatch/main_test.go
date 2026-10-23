package main

import (
	"encoding/binary"
	"net"
	"testing"
)

// query собирает запрос DNS с одним вопросом.
func query(name string, qtype uint16) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			msg = append(msg, byte(i-start))
			msg = append(msg, name[start:i]...)
			start = i + 1
		}
	}
	msg = binary.BigEndian.AppendUint16(append(msg, 0), qtype)
	msg = append(msg, 0, 1)
	return msg
}

func TestParseQuestionAndAnswer(t *testing.T) {
	q := query("LLM-Canary.example.net", 1)
	name, qtype, end, err := parseQuestion(q)
	if err != nil || name != "llm-canary.example.net" || qtype != 1 || end != len(q) {
		t.Fatalf("разбор: %q %d %d %v", name, qtype, end, err)
	}
	nets := []*net.IPNet{{IP: net.IPv4(10, 231, 14, 53).To4(), Mask: net.CIDRMask(24, 32)}}
	resp := answer(q[:end], qtype, own(nets, net.IPv4(10, 231, 14, 20)))
	if resp[0] != 0x12 || resp[1] != 0x34 || resp[2]&0x80 == 0 || binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatalf("заголовок ответа: % x", resp[:12])
	}
	if got := net.IP(resp[len(resp)-4:]); !got.Equal(net.IPv4(10, 231, 14, 53)) {
		t.Fatalf("адрес в ответе %v", got)
	}
	// AAAA и источник вне сетей ловушки — пустой ответ без ошибки.
	if resp := answer(q[:end], 28, nets[0].IP); binary.BigEndian.Uint16(resp[6:8]) != 0 {
		t.Fatal("ответ на AAAA не пустой")
	}
	if own(nets, net.IPv4(192, 0, 2, 1)) != nil {
		t.Fatal("чужая сеть признана своей")
	}
}

func TestParseQuestionRejects(t *testing.T) {
	good := query("example.net", 1)
	resp := append([]byte{}, good...)
	resp[2] |= 0x80
	two := append([]byte{}, good...)
	two[5] = 2
	long := append([]byte{}, good...)
	long[12] = 64
	for name, msg := range map[string][]byte{
		"короткий": good[:11], "ответ": resp, "два вопроса": two, "метка длиннее 63": long,
		"обрезанное имя": good[:16], "без типа": good[:len(good)-3],
	} {
		if _, _, _, err := parseQuestion(msg); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
}

// packet собирает IPv4 с заголовком 20 байт и началом заголовка L4.
func packet(proto byte, src, dst net.IP, l4 []byte) []byte {
	p := make([]byte, 20, 20+len(l4))
	p[0], p[9] = 0x45, proto
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	return append(p, l4...)
}

func TestAttempt(t *testing.T) {
	nets := []*net.IPNet{{IP: net.IPv4(10, 231, 14, 53).To4(), Mask: net.CIDRMask(24, 32)}}
	gw, trap := net.IPv4(10, 231, 14, 20), net.IPv4(10, 231, 14, 53)
	tcp := func(flags byte) []byte {
		h := make([]byte, 20)
		binary.BigEndian.PutUint16(h[2:4], 443)
		h[13] = flags
		return h
	}
	udp := func(port uint16) []byte {
		h := make([]byte, 8)
		binary.BigEndian.PutUint16(h[2:4], port)
		return h
	}
	cases := []struct {
		name  string
		p     []byte
		want  bool
		proto string
	}{
		{"SYN", packet(6, gw, trap, tcp(0x02)), true, "tcp"},
		{"SYN+ACK", packet(6, gw, trap, tcp(0x12)), false, ""},
		{"ACK", packet(6, gw, trap, tcp(0x10)), false, ""},
		{"UDP 123", packet(17, gw, trap, udp(123)), true, "udp"},
		{"UDP 53 — пишет DNS", packet(17, gw, trap, udp(53)), false, ""},
		{"ICMP", packet(1, gw, trap, []byte{8, 0, 0, 0}), true, "icmp"},
		{"от себя", packet(6, trap, gw, tcp(0x02)), false, ""},
		{"не на ловушку", packet(6, gw, net.IPv4(10, 231, 14, 30), tcp(0x02)), false, ""},
		{"IPv6", append([]byte{0x60}, make([]byte, 40)...), false, ""},
		{"короткий", []byte{0x45, 0}, false, ""},
	}
	for _, c := range cases {
		r, ok := attempt(c.p, nets)
		if ok != c.want || ok && r.Proto != c.proto {
			t.Errorf("%s: %v %+v", c.name, ok, r)
		}
	}
	if r, _ := attempt(packet(6, gw, trap, tcp(0x02)), nets); r.Port != 443 || r.Src != gw.String() {
		t.Errorf("SYN: %+v", r)
	}
}

func FuzzParseQuestion(f *testing.F) {
	f.Add(query("llm-canary.example.net", 1))
	f.Add(query("a", 28))
	f.Add([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1})
	nets := []*net.IPNet{{IP: net.IPv4(10, 0, 0, 53).To4(), Mask: net.CIDRMask(8, 32)}}
	f.Fuzz(func(t *testing.T, msg []byte) {
		name, qtype, end, err := parseQuestion(msg)
		if err != nil {
			return
		}
		if end > len(msg) || end < 17 || len(name) > len(msg) {
			t.Fatalf("границы: %d из %d, имя %d", end, len(msg), len(name))
		}
		resp := answer(msg[:end], qtype, nets[0].IP)
		if len(resp) < end {
			t.Fatal("ответ короче вопроса")
		}
	})
}

func FuzzAttempt(f *testing.F) {
	nets := []*net.IPNet{{IP: net.IPv4(10, 231, 14, 53).To4(), Mask: net.CIDRMask(24, 32)}}
	f.Add(packet(6, net.IPv4(10, 231, 14, 20), net.IPv4(10, 231, 14, 53), make([]byte, 20)))
	f.Add(packet(17, net.IPv4(10, 231, 14, 20), net.IPv4(10, 231, 14, 53), make([]byte, 8)))
	f.Add([]byte{0x4f})
	f.Fuzz(func(t *testing.T, p []byte) {
		if r, ok := attempt(p, nets); ok && (r.Kind != "conn" || r.Proto == "") {
			t.Fatalf("запись без вида или протокола: %+v", r)
		}
	})
}
