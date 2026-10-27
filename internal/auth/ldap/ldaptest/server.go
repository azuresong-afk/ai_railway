// Пакет ldaptest — синтетический каталог LDAP для тестов входа через LDAP
// (ADR-0025, раздел 2): LDAPS или StartTLS на 127.0.0.1 с собственной
// цепочкой сертификатов, simple bind, поиск с фильтрами and/or/not,
// равенством, присутствием и правилом вложенных групп AD. Только для
// тестов (depguard test-doubles); внешних адресов нет.
package ldaptest

import (
	"bufio"
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

// Коды результата LDAP (RFC 4511, 4.1.9), которые отдаёт каталог.
const (
	resultSuccess        = 0
	resultSizeLimit      = 4
	resultProtocol       = 2
	resultNoSuchObject   = 32
	resultInvalidCreds   = 49
	resultUnwillingToRun = 53
)

const (
	startTLSOID  = "1.3.6.1.4.1.1466.20037"
	nestedRuleAD = "1.2.840.113556.1.4.1941"
)

// entry — запись каталога: атрибуты по имени в нижнем регистре.
type entry struct {
	dn       string
	attrs    map[string][][]byte
	names    map[string]string // нижний регистр → имя как задано
	password string
}

// Directory — каталог для тестов.
type Directory struct {
	// URL — ldaps://127.0.0.1:порт или ldap://127.0.0.1:порт (StartTLS).
	URL string
	// RootPEM — корень цепочки сертификата каталога.
	RootPEM []byte

	ln    net.Listener
	ldaps bool
	wrap  func(net.Conn) net.Conn

	mu      sync.Mutex
	entries []*entry
	binds   []string
	filters []string
	delay   time.Duration
	// noStartTLS — отказ в StartTLS (каталог без TLS).
	noStartTLS bool
	// filler — байт в каждом ответе поиска сверх записей (проверка предела).
	filler int
	wg     sync.WaitGroup
}

// New запускает каталог: ldaps — LDAPS, иначе StartTLS на ldap://.
func New(ldaps bool) (*Directory, error) {
	chain, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{"127.0.0.1", "localhost"}})
	if err != nil {
		return nil, err
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return nil, err
	}
	tp, err := p.TLS()
	if err != nil {
		return nil, err
	}
	cfg, err := tp.ServerConfig(append(append([]byte{}, chain.Leaf...), chain.Intermediate...), chain.Key)
	if err != nil {
		return nil, err
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d := &Directory{RootPEM: chain.Root, ln: ln, ldaps: ldaps,
		wrap: func(c net.Conn) net.Conn { return aisecCrypto.ServerTLS(c, cfg) }}
	scheme := "ldap://"
	if ldaps {
		scheme = "ldaps://"
	}
	d.URL = scheme + ln.Addr().String()
	d.wg.Add(1)
	go d.serve()
	return d, nil
}

// Close останавливает каталог.
func (d *Directory) Close() {
	_ = d.ln.Close()
	d.wg.Wait()
}

// Add добавляет запись с атрибутами (значения — строки) и паролем
// (пусто — bind этой записью невозможен).
func (d *Directory) Add(dn string, attrs map[string][]string, password string) {
	e := &entry{dn: dn, attrs: map[string][][]byte{}, names: map[string]string{}, password: password}
	for k, vs := range attrs {
		for _, v := range vs {
			e.put(k, []byte(v))
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries = append(d.entries, e)
}

// SetRaw задаёт двоичное значение атрибута записи dn (например, objectGUID).
func (d *Directory) SetRaw(dn, attr string, v []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.entries {
		if strings.EqualFold(e.dn, dn) {
			delete(e.attrs, strings.ToLower(attr))
			e.put(attr, v)
		}
	}
}

func (e *entry) put(attr string, v []byte) {
	k := strings.ToLower(attr)
	e.names[k] = attr
	e.attrs[k] = append(e.attrs[k], v)
}

// SetDelay задерживает каждый ответ (проверка срока).
func (d *Directory) SetDelay(v time.Duration) { d.mu.Lock(); d.delay = v; d.mu.Unlock() }

// RefuseStartTLS — каталог отвечает на StartTLS ошибкой.
func (d *Directory) RefuseStartTLS() { d.mu.Lock(); d.noStartTLS = true; d.mu.Unlock() }

// PadSearch добавляет к ответам поиска запись с n байт (проверка предела ответа).
func (d *Directory) PadSearch(n int) { d.mu.Lock(); d.filler = n; d.mu.Unlock() }

// Binds — DN всех попыток bind по порядку (с пустым паролем — тоже).
func (d *Directory) Binds() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.binds)
}

// Filters — фильтры поисков по порядку (в строковой форме библиотеки клиента не
// восстанавливаются: записываются значения равенств «атрибут=значение»).
func (d *Directory) Filters() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.filters)
}

func (d *Directory) serve() {
	defer d.wg.Done()
	for {
		c, err := d.ln.Accept()
		if err != nil {
			return
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.handle(c)
		}()
	}
}

func (d *Directory) handle(c net.Conn) {
	if d.ldaps {
		c = d.wrap(c)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(c)
	for {
		p, err := ber.ReadPacket(r)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		d.mu.Lock()
		delay := d.delay
		d.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		switch op.Tag {
		case 0: // BindRequest
			if !d.write(c, result(id, 1, d.bind(op))) {
				return
			}
		case 2: // UnbindRequest
			return
		case 3: // SearchRequest
			for _, pkt := range d.search(id, op) {
				if !d.write(c, pkt) {
					return
				}
			}
		case 23: // ExtendedRequest
			name := ""
			if len(op.Children) > 0 {
				name = op.Children[0].Data.String()
			}
			d.mu.Lock()
			refuse := d.noStartTLS
			d.mu.Unlock()
			if name != startTLSOID || d.ldaps || refuse {
				if !d.write(c, result(id, 24, resultProtocol)) {
					return
				}
				continue
			}
			if !d.write(c, result(id, 24, resultSuccess)) {
				return
			}
			c = d.wrap(c)
			r = bufio.NewReader(c)
		default:
			_ = d.write(c, result(id, 1, resultUnwillingToRun))
			return
		}
	}
}

func (d *Directory) write(c net.Conn, p *ber.Packet) bool {
	_, err := c.Write(p.Bytes())
	return err == nil
}

// result — LDAPResult с кодом code в операции ответа tag.
func result(id int64, tag ber.Tag, code int) *ber.Packet {
	p := envelope(id)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "result")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "code"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diag"))
	p.AppendChild(op)
	return p
}

func envelope(id int64) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "id"))
	return p
}

func str(p *ber.Packet) string {
	if s, ok := p.Value.(string); ok {
		return s
	}
	return p.Data.String()
}

// bind — simple bind: пустой пароль — «неаутентифицированный» bind,
// который каталог принимает (RFC 4513, 5.1.2): клиент обязан его не слать.
func (d *Directory) bind(op *ber.Packet) int {
	if len(op.Children) < 3 {
		return resultProtocol
	}
	dn, pw := str(op.Children[1]), op.Children[2].Data.String()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.binds = append(d.binds, dn)
	if pw == "" {
		return resultSuccess
	}
	for _, e := range d.entries {
		if strings.EqualFold(e.dn, dn) && e.password != "" && e.password == pw {
			return resultSuccess
		}
	}
	return resultInvalidCreds
}

func (d *Directory) search(id int64, op *ber.Packet) []*ber.Packet {
	if len(op.Children) < 8 {
		return []*ber.Packet{result(id, 5, resultProtocol)}
	}
	base := str(op.Children[0])
	scope, _ := op.Children[1].Value.(int64)
	limit, _ := op.Children[3].Value.(int64)
	filter := op.Children[6]
	var want []string
	for _, a := range op.Children[7].Children {
		want = append(want, strings.ToLower(str(a)))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record(filter)
	baseFound := false
	var matched []*entry
	for _, e := range d.entries {
		if strings.EqualFold(e.dn, base) {
			baseFound = true
		}
		inScope := strings.EqualFold(e.dn, base)
		if scope != 0 {
			inScope = inScope || strings.HasSuffix(strings.ToLower(e.dn), ","+strings.ToLower(base))
		}
		if inScope && d.match(e, filter) {
			matched = append(matched, e)
		}
	}
	if !baseFound {
		return []*ber.Packet{result(id, 5, resultNoSuchObject)}
	}
	var out []*ber.Packet
	code := resultSuccess
	for i, e := range matched {
		if limit > 0 && int64(i) >= limit {
			code = resultSizeLimit
			break
		}
		out = append(out, entryPacket(id, e, want))
	}
	if d.filler > 0 {
		pad := &entry{dn: base, attrs: map[string][][]byte{"pad": {make([]byte, d.filler)}}, names: map[string]string{"pad": "pad"}}
		out = append(out, entryPacket(id, pad, []string{"pad"}))
	}
	return append(out, result(id, 5, code))
}

// record сохраняет пары «атрибут=значение» равенств фильтра.
func (d *Directory) record(f *ber.Packet) {
	switch f.Tag {
	case 0, 1, 2:
		for _, c := range f.Children {
			d.record(c)
		}
	case 3, 9:
		var parts []string
		for _, c := range f.Children {
			parts = append(parts, str(c))
		}
		d.filters = append(d.filters, strings.Join(parts, "="))
	}
}

func entryPacket(id int64, e *entry, want []string) *ber.Packet {
	p := envelope(id)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "entry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, "dn"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attrs")
	for _, k := range want {
		vs, ok := e.attrs[k]
		if !ok {
			continue
		}
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attr")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.names[k], "type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range vs {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v), "val"))
		}
		a.AppendChild(set)
		attrs.AppendChild(a)
	}
	op.AppendChild(attrs)
	p.AppendChild(op)
	return p
}

// match — запись удовлетворяет фильтру (подмножество RFC 4511, 4.5.1.7).
func (d *Directory) match(e *entry, f *ber.Packet) bool {
	switch f.Tag {
	case 0: // and
		for _, c := range f.Children {
			if !d.match(e, c) {
				return false
			}
		}
		return true
	case 1: // or
		for _, c := range f.Children {
			if d.match(e, c) {
				return true
			}
		}
		return false
	case 2: // not
		return len(f.Children) == 1 && !d.match(e, f.Children[0])
	case 3: // equalityMatch
		if len(f.Children) != 2 {
			return false
		}
		return e.has(str(f.Children[0]), str(f.Children[1]))
	case 7: // present
		a := strings.ToLower(f.Data.String())
		_, ok := e.attrs[a]
		return ok || a == "objectclass"
	case 9: // extensibleMatch: только вложенные группы AD
		var rule, typ, val string
		for _, c := range f.Children {
			switch c.Tag {
			case 1:
				rule = c.Data.String()
			case 2:
				typ = c.Data.String()
			case 3:
				val = c.Data.String()
			}
		}
		if rule != nestedRuleAD || !strings.EqualFold(typ, "member") {
			return false
		}
		return d.nested(e, val, 0)
	}
	return false
}

// nested — группа e содержит dn напрямую или через вложенные группы.
func (d *Directory) nested(e *entry, dn string, depth int) bool {
	if depth > 16 {
		return false
	}
	for _, m := range e.attrs["member"] {
		if strings.EqualFold(string(m), dn) {
			return true
		}
		for _, g := range d.entries {
			if strings.EqualFold(g.dn, string(m)) && d.nested(g, dn, depth+1) {
				return true
			}
		}
	}
	return false
}

func (e *entry) has(attr, v string) bool {
	for _, x := range e.attrs[strings.ToLower(attr)] {
		if strings.EqualFold(string(x), v) {
			return true
		}
	}
	return false
}
