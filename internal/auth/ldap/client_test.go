package ldap_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth/ldap"
	"github.com/azuresong-afk/ai_railway/internal/auth/ldap/ldaptest"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

// Синтетический каталог: пароли и идентификаторы не принадлежат реальным
// людям и системам.
const (
	svcDN     = "uid=aisec-svc,cn=sysaccounts,dc=example,dc=test"
	svcPass   = "synthetic-service-credential-1"
	usersDN   = "cn=users,dc=example,dc=test"
	groupsDN  = "cn=groups,dc=example,dc=test"
	ivanDN    = "uid=ivanov,cn=users,dc=example,dc=test"
	ivanPass  = "synthetic-user-credential-7"
	ivanUUID  = "6f1c2a7e-0d2b-4c55-9a43-1b2f3c4d5e6f"
	adminsDN  = "cn=aisec-admins,cn=groups,dc=example,dc=test"
	auditDN   = "cn=aisec-auditors,cn=groups,dc=example,dc=test"
	nestedDN  = "cn=all-staff,cn=groups,dc=example,dc=test"
	userQuery = "(&(objectClass=person)(uid={login}))"
)

type env struct {
	dir *ldaptest.Directory
	c   *ldap.Client
	cfg ldap.Config
}

func newEnv(t *testing.T, ldaps bool, opts ...ldap.Option) *env {
	t.Helper()
	dir, err := ldaptest.New(ldaps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dir.Close)
	dir.Add("dc=example,dc=test", nil, "")
	dir.Add(usersDN, nil, "")
	dir.Add(groupsDN, nil, "")
	dir.Add(svcDN, map[string][]string{"objectClass": {"account"}}, svcPass)
	dir.Add(ivanDN, map[string][]string{"objectClass": {"person"}, "uid": {"ivanov"}, "entryUUID": {ivanUUID},
		"displayName": {"Иванов Иван"}, "memberOf": {adminsDN}}, ivanPass)
	dir.Add(adminsDN, map[string][]string{"objectClass": {"groupOfNames"}, "member": {ivanDN}}, "")
	dir.Add(auditDN, map[string][]string{"objectClass": {"groupOfUniqueNames"}, "uniqueMember": {ivanDN}}, "")
	dir.Add(nestedDN, map[string][]string{"objectClass": {"group"}, "member": {adminsDN}}, "")
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ldap.New(p, opts...)
	if err != nil {
		t.Fatal(err)
	}
	// Каталог теста — на 127.0.0.1: loopback разрешается явно.
	c.AllowNetworks([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	return &env{dir: dir, c: c, cfg: ldap.Config{URL: dir.URL, RootsPEM: dir.RootPEM, BindDN: svcDN, BindPassword: svcPass,
		UserBaseDN: usersDN, UserFilter: userQuery, IDAttribute: "entryUUID", DisplayAttribute: "displayName",
		GroupMode: ldap.GroupsMemberOf}}
}

func code(t *testing.T, err error, want string) {
	t.Helper()
	if got := ldap.ErrorCode(err); got != want {
		t.Fatalf("код %q, ожидался %q (%v)", got, want, err)
	}
}

func TestAuthenticateLDAPSMemberOf(t *testing.T) {
	e := newEnv(t, true)
	id, err := e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != ivanUUID || id.DN != ivanDN || id.DisplayName != "Иванов Иван" || !slices.Equal(id.Groups, []string{adminsDN}) {
		t.Fatalf("пользователь: %+v", id)
	}
	// Сервисная учётная запись и пользователь — отдельными bind.
	if b := e.dir.Binds(); !slices.Equal(b, []string{svcDN, ivanDN}) {
		t.Fatalf("bind: %v", b)
	}
}

func TestAuthenticateStartTLSGroupSearch(t *testing.T) {
	e := newEnv(t, false)
	e.cfg.GroupMode, e.cfg.GroupBaseDN = ldap.GroupsMember, groupsDN
	id, err := e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(id.Groups)
	if !slices.Equal(id.Groups, []string{adminsDN, auditDN}) {
		t.Fatalf("группы: %v", id.Groups)
	}
}

func TestAuthenticateADNestedGroups(t *testing.T) {
	e := newEnv(t, true)
	e.cfg.GroupMode, e.cfg.GroupBaseDN = ldap.GroupsADNested, groupsDN
	id, err := e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(id.Groups)
	if !slices.Equal(id.Groups, []string{adminsDN, nestedDN}) {
		t.Fatalf("вложенные группы: %v", id.Groups)
	}
}

func TestAuthenticateWrongPassword(t *testing.T) {
	e := newEnv(t, true)
	_, err := e.c.Authenticate(context.Background(), e.cfg, "ivanov", "synthetic-wrong-credential")
	code(t, err, ldap.CodeCredentials)
}

// Пустой пароль не уходит в каталог: bind с ним «неаутентифицированный»
// и прошёл бы (RFC 4513, 5.1.2).
func TestAuthenticateEmptyPasswordNoBind(t *testing.T) {
	e := newEnv(t, true)
	_, err := e.c.Authenticate(context.Background(), e.cfg, "ivanov", "")
	code(t, err, ldap.CodeCredentials)
	if b := e.dir.Binds(); len(b) != 0 {
		t.Fatalf("bind при пустом пароле: %v", b)
	}
}

func TestAuthenticateUnknownAndAmbiguous(t *testing.T) {
	e := newEnv(t, true)
	_, err := e.c.Authenticate(context.Background(), e.cfg, "petrov", ivanPass)
	code(t, err, ldap.CodeNotFound)
	e.dir.Add("uid=ivanov2,cn=users,dc=example,dc=test", map[string][]string{"objectClass": {"person"}, "uid": {"ivanov"},
		"entryUUID": {"0b7d4c1e-2f3a-4b5c-8d9e-0f1a2b3c4d5e"}}, ivanPass)
	_, err = e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	code(t, err, ldap.CodeAmbiguous)
	// Пароль при неоднозначности не проверяется.
	if b := e.dir.Binds(); slices.Contains(b, ivanDN) {
		t.Fatalf("bind пользователя при неоднозначности: %v", b)
	}
}

// Логин подставляется в фильтр экранированным (RFC 4515): «*» и скобки
// не расширяют поиск.
func TestAuthenticateFilterInjection(t *testing.T) {
	e := newEnv(t, true)
	_, err := e.c.Authenticate(context.Background(), e.cfg, "*)(uid=*", ivanPass)
	code(t, err, ldap.CodeNotFound)
	_, err = e.c.Authenticate(context.Background(), e.cfg, "*", ivanPass)
	code(t, err, ldap.CodeNotFound)
	f := e.dir.Filters()
	if !slices.Contains(f, "uid=*)(uid=*") || !slices.Contains(f, "uid=*") {
		t.Fatalf("фильтры: %v", f)
	}
}

// 4В14 (ревью 4.r1): шаблон, где {login} стоит вне значения условия,
// отклоняется — логин «:» превратил бы равенство в расширяемое сравнение.
func TestValidateConfigLoginOutsideValue(t *testing.T) {
	base := ldap.Config{URL: "ldaps://dc1.example.test", BindDN: svcDN, UserBaseDN: usersDN, UserFilter: userQuery,
		IDAttribute: "entryUUID", DisplayAttribute: "displayName", GroupMode: ldap.GroupsMemberOf}
	for _, tmpl := range []string{"(*{login}=)", "(*{login}=x)", "(uid*{login}=v)", "(&(objectClass=person)(cn*{login}=*))",
		"(:{login})", "({login}=x)"} {
		c := base
		c.UserFilter = tmpl
		var ce *ldap.ConfigError
		err := ldap.ValidateConfig(c)
		if !errors.As(err, &ce) || ce.Field != "user_filter" || !errors.Is(err, ldap.ErrLoginPlacement) {
			t.Errorf("%s: %v", tmpl, err)
		}
	}
	for _, tmpl := range []string{"(uid={login})", "(|(uid={login})(mail={login}))", "(cn=*{login}*)", "(cn={login}*)",
		"(&(objectClass=person)(!(uid={login})))", "(uid:caseExactMatch:={login})", "(mail~={login})", "(uidNumber>={login})"} {
		c := base
		c.UserFilter = tmpl
		if err := ldap.ValidateConfig(c); err != nil {
			t.Errorf("%s: %v", tmpl, err)
		}
	}
}

// 4В14: уже сохранённый шаблон с {login} вне значения — вход отказывает с
// кодом config, к каталогу не обращается, логин не подставляется.
func TestAuthenticateSavedBadFilter(t *testing.T) {
	e := newEnv(t, true)
	cfg := e.cfg
	cfg.UserFilter = "(*{login}=)"
	_, err := e.c.Authenticate(context.Background(), cfg, ":", ivanPass)
	code(t, err, ldap.CodeConfig)
	if !errors.Is(err, ldap.ErrLoginPlacement) {
		t.Fatalf("ошибка: %v", err)
	}
	if f, b := e.dir.Filters(), e.dir.Binds(); len(f) != 0 || len(b) != 0 {
		t.Fatalf("обращение к каталогу: фильтры %v, bind %v", f, b)
	}
}

func TestAuthenticateServiceBindFails(t *testing.T) {
	e := newEnv(t, true)
	e.cfg.BindPassword = "synthetic-wrong-service"
	_, err := e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	code(t, err, ldap.CodeServiceBind)
	e.cfg.BindPassword = ""
	_, err = e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	code(t, err, ldap.CodeConfig)
}

func TestAuthenticateTLSRejected(t *testing.T) {
	for _, ldaps := range []bool{true, false} {
		e := newEnv(t, ldaps)
		other, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{"127.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}
		e.cfg.RootsPEM = other.Root
		_, err = e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
		code(t, err, ldap.CodeTLS)
		if b := e.dir.Binds(); len(b) != 0 {
			t.Fatalf("bind без доверенного TLS: %v", b)
		}
	}
}

// Корень доверенный, но сертификат выдан на другое имя: TLS не
// устанавливается, bind не выполняется (ADR-0025, 2.1).
func TestAuthenticateHostnameMismatch(t *testing.T) {
	for _, ldaps := range []bool{true, false} {
		e := newEnv(t, ldaps)
		dir, err := ldaptest.NewForHosts(ldaps, []string{"ldap.example.test"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(dir.Close)
		dir.Add(svcDN, nil, svcPass)
		e.cfg.URL, e.cfg.RootsPEM = dir.URL, dir.RootPEM
		_, err = e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
		code(t, err, ldap.CodeTLS)
		if b := dir.Binds(); len(b) != 0 {
			t.Fatalf("bind при чужом имени в сертификате: %v", b)
		}
	}
}

func TestAuthenticateStartTLSRefused(t *testing.T) {
	e := newEnv(t, false)
	e.dir.RefuseStartTLS()
	_, err := e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	code(t, err, ldap.CodeTLS)
	if b := e.dir.Binds(); len(b) != 0 {
		t.Fatalf("bind без StartTLS: %v", b)
	}
}

func TestAuthenticateBlockedAddress(t *testing.T) {
	e := newEnv(t, true)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ldap.New(p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	code(t, err, ldap.CodeBlocked)
	for _, u := range []string{"ldaps://169.254.169.254", "ldaps://[::1]:636", "ldaps://100.100.100.200", "ldaps://0.0.0.0"} {
		cfg := e.cfg
		cfg.URL = u
		_, err = c.Authenticate(context.Background(), cfg, "ivanov", ivanPass)
		code(t, err, ldap.CodeBlocked)
	}
}

func TestAuthenticateTimeout(t *testing.T) {
	e := newEnv(t, true, ldap.WithTimeout(300*time.Millisecond))
	e.dir.SetDelay(time.Second)
	start := time.Now()
	_, err := e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	code(t, err, ldap.CodeTimeout)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("срок не соблюдён: %v", d)
	}
}

func TestAuthenticateResponseLimit(t *testing.T) {
	e := newEnv(t, true)
	e.dir.PadSearch(ldap.MaxRead + 1)
	_, err := e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	code(t, err, ldap.CodeTooLarge)
}

func TestAuthenticateObjectGUID(t *testing.T) {
	e := newEnv(t, true)
	guid := []byte{0x01, 0xff, 0x00, 0x7f, 0x80, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0}
	e.dir.SetRaw(ivanDN, "objectGUID", guid)
	e.cfg.IDAttribute = "objectGUID"
	id, err := e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != "01ff007f80102030405060708090a0b0" {
		t.Fatalf("objectGUID: %s", id.ID)
	}
	e.dir.SetRaw(ivanDN, "objectGUID", guid[:15])
	_, err = e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	code(t, err, ldap.CodeIdentity)
	e.cfg.IDAttribute = "ipaUniqueID"
	_, err = e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
	code(t, err, ldap.CodeIdentity)
}

func TestAuthenticateConcurrent(t *testing.T) {
	e := newEnv(t, false)
	errs := make(chan error, 2*ldap.MaxConcurrent)
	for range 2 * ldap.MaxConcurrent {
		go func() {
			_, err := e.c.Authenticate(context.Background(), e.cfg, "ivanov", ivanPass)
			errs <- err
		}()
	}
	for range 2 * ldap.MaxConcurrent {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestCheck(t *testing.T) {
	e := newEnv(t, false)
	if err := e.c.Check(context.Background(), e.cfg); err != nil {
		t.Fatal(err)
	}
	cfg := e.cfg
	cfg.UserBaseDN = "cn=missing,dc=example,dc=test"
	code(t, e.c.Check(context.Background(), cfg), ldap.CodeResponse)
	cfg = e.cfg
	cfg.GroupMode, cfg.GroupBaseDN = ldap.GroupsMember, "cn=nogroups,dc=example,dc=test"
	code(t, e.c.Check(context.Background(), cfg), ldap.CodeResponse)
	cfg = e.cfg
	cfg.UserFilter = "(uid=x)"
	code(t, e.c.Check(context.Background(), cfg), ldap.CodeConfig)
}

func TestValidateConfig(t *testing.T) {
	base := ldap.Config{URL: "ldaps://dc1.example.test", BindDN: svcDN, UserBaseDN: usersDN, UserFilter: userQuery,
		IDAttribute: "entryUUID", DisplayAttribute: "displayName", GroupMode: ldap.GroupsMemberOf}
	if err := ldap.ValidateConfig(base); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		field string
		mut   func(*ldap.Config)
	}{
		{"url", func(c *ldap.Config) { c.URL = "http://dc1.example.test" }},
		{"url", func(c *ldap.Config) { c.URL = "ldaps://user:pw@dc1.example.test" }},
		{"url", func(c *ldap.Config) { c.URL = "ldaps://dc1.example.test/dc=example,dc=test" }},
		{"url", func(c *ldap.Config) { c.URL = "ldaps://dc1.example.test:0" }},
		{"url", func(c *ldap.Config) { c.URL = "ldaps://dc1.example.test:70000" }},
		{"url", func(c *ldap.Config) { c.URL = "ldaps://" }},
		{"url", func(c *ldap.Config) { c.URL = "ldaps://dc1.example.test?x" }},
		{"bind_dn", func(c *ldap.Config) { c.BindDN = "" }},
		{"bind_dn", func(c *ldap.Config) { c.BindDN = "not a dn" }},
		{"user_base_dn", func(c *ldap.Config) { c.UserBaseDN = "cn=,=x" }},
		{"user_filter", func(c *ldap.Config) { c.UserFilter = "(uid=ivanov)" }},
		{"user_filter", func(c *ldap.Config) { c.UserFilter = "(&(uid={login})" }},
		{"user_filter", func(c *ldap.Config) { c.UserFilter = "uid={login}" }},
		{"user_filter", func(c *ldap.Config) { c.UserFilter = "({login}=x)" }},
		{"user_filter", func(c *ldap.Config) { c.UserFilter = "(:{login})" }},
		{"user_filter", func(c *ldap.Config) { c.UserFilter = "(uid={login})" + strings.Repeat(" ", 600) }},
		{"id_attribute", func(c *ldap.Config) { c.IDAttribute = "uid" }},
		{"display_attribute", func(c *ldap.Config) { c.DisplayAttribute = "display name" }},
		{"display_attribute", func(c *ldap.Config) { c.DisplayAttribute = "1cn" }},
		{"group_mode", func(c *ldap.Config) { c.GroupMode = "all" }},
		{"group_base_dn", func(c *ldap.Config) { c.GroupMode = ldap.GroupsMember }},
		{"group_base_dn", func(c *ldap.Config) { c.GroupMode, c.GroupBaseDN = ldap.GroupsADNested, "x" }},
	}
	for _, tc := range cases {
		c := base
		tc.mut(&c)
		var ce *ldap.ConfigError
		if err := ldap.ValidateConfig(c); !errors.As(err, &ce) || ce.Field != tc.field {
			t.Errorf("%+v: %v, ожидалось поле %s", c, err, tc.field)
		}
	}
	ok := base
	ok.URL = "ldap://10.0.0.5:3389"
	if err := ldap.ValidateConfig(ok); err != nil {
		t.Fatal(err)
	}
}

func TestSameDN(t *testing.T) {
	if !ldap.SameDN("CN=AISec-Admins, CN=Groups,DC=Example,DC=Test", adminsDN) {
		t.Fatal("регистр и пробелы")
	}
	if ldap.SameDN(adminsDN, auditDN) || ldap.SameDN("", "") || ldap.SameDN("bad", "bad") {
		t.Fatal("разные или неверные DN")
	}
}

func TestEntryID(t *testing.T) {
	bad := [][][]byte{nil, {[]byte("a"), []byte("b")}, {{}}, {[]byte("with space")}, {[]byte("ctl\x01")},
		{[]byte(strings.Repeat("a", 256))}}
	for _, v := range bad {
		if _, err := ldap.EntryID("entryUUID", v); ldap.ErrorCode(err) != ldap.CodeIdentity {
			t.Fatalf("%q: %v", v, err)
		}
	}
}

func TestGostProfile(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileGOST)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ldap.New(p); !errors.Is(err, aisecCrypto.ErrNotImplemented) {
		t.Fatalf("gost: %v", err)
	}
}
