package ldap_test

import (
	"fmt"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"

	"github.com/azuresong-afk/ai_railway/internal/auth/ldap"
)

// FuzzUserFilter — логин из запроса входа подставляется в шаблон фильтра
// (ADR-0025, 2.3): у допустимого шаблона фильтр с любым логином
// разбирается, а логин не меняет структуры фильтра.
func FuzzUserFilter(f *testing.F) {
	f.Add("(&(objectClass=person)(uid={login}))", "ivanov")
	f.Add("(|(uid={login})(mail={login}))", "*)(uid=*")
	f.Add("(sAMAccountName={login})", "a\\2a\x00(")
	f.Add("(uid={login})", "иванов")
	f.Fuzz(func(t *testing.T, tmpl, login string) {
		cfg := ldap.Config{URL: "ldaps://dc1.example.test", BindDN: "cn=svc,dc=example,dc=test",
			UserBaseDN: "dc=example,dc=test", UserFilter: tmpl, IDAttribute: "entryUUID",
			DisplayAttribute: "cn", GroupMode: ldap.GroupsMemberOf}
		// Пустой логин отклоняется до поиска (Client.Authenticate).
		if login == "" || ldap.ValidateConfig(cfg) != nil {
			return
		}
		got, err := goldap.CompileFilter(ldap.UserFilter(tmpl, login))
		if err != nil {
			t.Fatalf("фильтр с логином %q не разобран: %v", login, err)
		}
		want, err := goldap.CompileFilter(ldap.UserFilter(tmpl, "x"))
		if err != nil {
			t.Fatal(err)
		}
		if shape(got) != shape(want) {
			t.Fatalf("логин %q изменил структуру фильтра", login)
		}
	})
}

// shape — дерево фильтра без значений: теги и число потомков. Значение
// равенства — универсальная строка, её содержимое не учитывается.
func shape(p *ber.Packet) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d.%d(", p.ClassType, p.Tag)
	if p.ClassType == ber.ClassContext && p.TagType == ber.TypeConstructed {
		for _, c := range p.Children {
			b.WriteString(shape(c))
		}
	}
	b.WriteString(")")
	return b.String()
}

// FuzzGroupFilter — DN пользователя из ответа каталога подставляется в
// фильтр поиска групп экранированным.
func FuzzGroupFilter(f *testing.F) {
	f.Add("uid=ivanov,cn=users,dc=example,dc=test")
	f.Add("cn=a\\,b)(x=*,dc=test")
	f.Fuzz(func(t *testing.T, dn string) {
		for _, mode := range []string{ldap.GroupsMember, ldap.GroupsADNested} {
			got, err := goldap.CompileFilter(ldap.GroupFilter(mode, dn))
			if err != nil {
				t.Fatalf("%s: %v", mode, err)
			}
			want, err := goldap.CompileFilter(ldap.GroupFilter(mode, "x"))
			if err != nil {
				t.Fatal(err)
			}
			if shape(got) != shape(want) {
				t.Fatalf("%s: DN %q изменил структуру фильтра", mode, dn)
			}
		}
	})
}

// FuzzEntryID — идентификатор записи из ответа каталога.
func FuzzEntryID(f *testing.F) {
	f.Add("entryUUID", []byte("6f1c2a7e-0d2b-4c55-9a43-1b2f3c4d5e6f"))
	f.Add("objectGUID", []byte("0123456789abcdef"))
	f.Add("ipaUniqueID", []byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, attr string, v []byte) {
		id, err := ldap.EntryID(attr, [][]byte{v})
		if err != nil {
			return
		}
		if id == "" || len(id) > 255 || strings.ContainsFunc(id, func(r rune) bool { return r <= 0x20 || r > 0x7e }) {
			t.Fatalf("идентификатор %q", id)
		}
	})
}

// FuzzSameDN — сравнение DN групп каталога с таблицей ролей.
func FuzzSameDN(f *testing.F) {
	f.Add("cn=Admins,dc=example,dc=test", "CN=admins, DC=Example,DC=test")
	f.Add("cn=a\\2cb,dc=test", "cn=a\\,b,dc=test")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, a, b string) {
		if ldap.SameDN(a, b) != ldap.SameDN(b, a) {
			t.Fatal("сравнение несимметрично")
		}
		if ldap.SameDN(a, b) && !ldap.ValidDN(a) {
			t.Fatalf("совпал неразобранный DN %q", a)
		}
	})
}
