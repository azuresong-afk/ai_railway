package auth

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

type issued struct{ key, prefix, hash string }

func issue(t *testing.T) issued {
	t.Helper()
	r, h := prims(t)
	key, prefix, hash, err := NewAppKey(r, h)
	if err != nil {
		t.Fatal(err)
	}
	return issued{key, prefix, hash}
}

var (
	now    = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	client = netip.MustParseAddr("10.1.2.3")
)

func TestDM38_AuthenticateReasons(t *testing.T) {
	_, h := prims(t)
	ok, revoked, expired, cidr, other := issue(t), issue(t), issue(t), issue(t), issue(t)
	a, err := NewAuthenticator(h, []KeyRecord{
		{AppID: "app", Env: "test", Prefix: ok.prefix, SHA256: ok.hash, Expires: now.Add(time.Second)},
		{AppID: "app", Prefix: revoked.prefix, SHA256: revoked.hash, Revoked: true},
		{AppID: "app", Prefix: expired.prefix, SHA256: expired.hash, Expires: now},
		{AppID: "app", Prefix: cidr.prefix, SHA256: cidr.hash, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	id, f := a.Authenticate(ok.key, client, now)
	if f != nil || id.AppID != "app" || id.Env != "test" || id.KeyPrefix != ok.prefix {
		t.Fatalf("действующий ключ: %+v %+v", id, f)
	}
	// Секрет известного префикса подменён: причина invalid, а не revoked и т. п.
	forged := revoked.prefix + ok.key[len(ok.prefix):]
	cases := []struct {
		name, key, reason, prefix, app string
	}{
		{"неизвестный префикс", other.key, ReasonInvalid, other.prefix, ""},
		{"чужой секрет", forged, ReasonInvalid, revoked.prefix, "app"},
		{"отозван", revoked.key, ReasonRevoked, revoked.prefix, "app"},
		{"истёк ровно сейчас", expired.key, ReasonExpired, expired.prefix, "app"},
		{"вне подсети", cidr.key, ReasonAddress, cidr.prefix, "app"},
		{"не ключ", "sk-123", ReasonMalformed, "", ""},
		{"пусто", "", ReasonMalformed, "", ""},
		{"длинный", ok.key + strings.Repeat("a", MaxKeyLen), ReasonMalformed, "", ""},
	}
	for _, c := range cases {
		id, f := a.Authenticate(c.key, client, now)
		if id != nil || f == nil || f.Reason != c.reason || f.KeyPrefix != c.prefix || f.AppID != c.app {
			t.Errorf("%s: %+v %+v", c.name, id, f)
		}
	}
	// Граница: подсеть, в которую адрес входит, в том числе в записи IPv4-in-IPv6.
	for _, addr := range []string{"192.168.255.255", "::ffff:192.168.0.1"} {
		if _, f := a.Authenticate(cidr.key, netip.MustParseAddr(addr), now); f != nil {
			t.Errorf("%s: %+v", addr, f)
		}
	}
	// Нулевой адрес не входит ни в одну подсеть.
	if _, f := a.Authenticate(cidr.key, netip.Addr{}, now); f == nil || f.Reason != ReasonAddress {
		t.Errorf("нулевой адрес: %+v", f)
	}
}

func TestNewAuthenticatorRejectsBadRecords(t *testing.T) {
	_, h := prims(t)
	k := issue(t)
	good := KeyRecord{AppID: "a", Prefix: k.prefix, SHA256: k.hash}
	for name, recs := range map[string][]KeyRecord{
		"дубль":       {good, good},
		"без app":     {{Prefix: k.prefix, SHA256: k.hash}},
		"префикс":     {{AppID: "a", Prefix: "aisec_X", SHA256: k.hash}},
		"хеш":         {{AppID: "a", Prefix: k.prefix, SHA256: "abc"}},
		"хеш верхний": {{AppID: "a", Prefix: k.prefix, SHA256: strings.ToUpper(k.hash)}},
		"пустой хеш":  {{AppID: "a", Prefix: k.prefix}},
		"пустой ключ": {{}},
	} {
		if _, err := NewAuthenticator(h, recs); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestBearerToken(t *testing.T) {
	k := strings.Repeat("k", MaxKeyLen)
	for _, c := range []struct {
		in   []string
		want string
		ok   bool
	}{
		{[]string{"Bearer abc"}, "abc", true},
		{[]string{"bearer abc"}, "abc", true},
		{[]string{"BEARER " + k}, k, true},
		{[]string{"Bearer " + k + "k"}, "", false},
		{[]string{"Bearer "}, "", false},
		{[]string{"Bearer"}, "", false},
		{[]string{"Basic abc"}, "", false},
		{[]string{"Bearer a", "Bearer b"}, "", false},
		{nil, "", false},
		{[]string{"Bearerabc"}, "", false},
	} {
		got, err := BearerToken(c.in)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%q: %q %v", c.in, got, err)
		}
	}
}

// Разбор заголовка Authorization и ключа — цель фаззинга (ТЗ, 8.5): ни при
// каком вводе не паника, а успех возможен только с выпущенным ключом.
func FuzzAuthenticate(f *testing.F) {
	r, h := prims(f)
	key, prefix, hash, err := NewAppKey(r, h)
	if err != nil {
		f.Fatal(err)
	}
	a, err := NewAuthenticator(h, []KeyRecord{{AppID: "a", Prefix: prefix, SHA256: hash}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add("Bearer " + key)
	f.Add("Bearer " + prefix + "_" + strings.Repeat("A", 43))
	f.Add("bearer aisec_")
	f.Add("Basic Zm9vOmJhcg==")
	f.Fuzz(func(t *testing.T, header string) {
		tok, err := BearerToken([]string{header})
		if err != nil {
			return
		}
		id, fail := a.Authenticate(tok, client, now)
		if (id == nil) == (fail == nil) {
			t.Fatalf("ровно одно из Identity и Failure: %+v %+v", id, fail)
		}
		if id != nil && tok != key {
			t.Fatalf("принят не выпущенный ключ %q", tok)
		}
	})
}
