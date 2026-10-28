package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/license"
)

// licTestNow — «сейчас» сервиса лицензий: тестовый рабочий ключ лицензий
// заверен с 01.10.2026 (testdata/license).
var licTestNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

// licEnv — окружение приложений с сервисом лицензий на своих часах.
type licEnv struct {
	*appsEnv
	lic   *license.Service
	store *license.Memory
	clock *testClock
}

func newLicenseEnv(t *testing.T, extra ...Route) *licEnv {
	t.Helper()
	le := &licEnv{store: license.NewMemory(), clock: &testClock{t: licTestNow}}
	le.appsEnv = newAppsEnv(t, func(e *appsEnv, o *Options) {
		p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
		if err != nil {
			t.Fatal(err)
		}
		le.lic, err = license.New(license.Options{Store: le.store, Provider: p, Clock: le.clock.now, Logger: quiet(),
			Usage: func(ctx context.Context) (license.Usage, error) {
				list, err := e.apps.Applications(ctx, audit.DefaultOrgID, "", nil, 1000)
				return license.Usage{Applications: len(list)}, err
			}})
		if err != nil {
			t.Fatal(err)
		}
		o.License = le.lic
		o.Extra = append(o.Extra, extra...)
	})
	return le
}

func (le *licEnv) setNow(t time.Time) {
	le.clock.mu.Lock()
	defer le.clock.mu.Unlock()
	le.clock.t = t
}

// testLicense — коммерческая лицензия № n на год с 28.10.2026: одно
// приложение, модуль теневого ИИ без модуля агентов.
func testLicense(n uint64) *license.License {
	return &license.License{Number: n, Licensee: license.Licensee{Organization: "ООО «Тестовый заказчик»", INN: "0012345673"},
		IssuedAt: licTestNow.Truncate(24 * time.Hour), ValidFrom: licTestNow.Truncate(24 * time.Hour),
		ValidUntil: time.Date(2027, 10, 28, 0, 0, 0, 0, time.UTC), Type: license.TypeCommercial,
		Limits: license.Limits{Gateways: 1, Applications: 1}, Modules: []string{license.ModuleShadowAI}}
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/license/" + name) //nolint:gosec // G304: фикстура теста из репозитория
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signLicense подписывает лицензию тестовым рабочим ключом лицензий.
func signLicense(t *testing.T, l *license.License) string {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	_, seed, err := aisecCrypto.DecodeKeyPEM(readTestdata(t, "subkey-test.signkey"), aisecCrypto.KeyKindVendorSubkey)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := license.Encode(l)
	if err != nil {
		t.Fatal(err)
	}
	file, err := aisecCrypto.SignLicense(s, readTestdata(t, "subkey-test.endorsement"), payload)
	if err != nil {
		t.Fatal(err)
	}
	return string(file)
}

func putLicenseBody(t *testing.T, file, password string) string {
	t.Helper()
	return mustJSON(t, map[string]string{"license": file, "password": password})
}

// ЗИ.2, УПД.2 (ADR-0026, п. 6): сведения о лицензии читают администраторы и
// аудитор, загружает только system_admin (и security_admin) в сессии с
// паролем; отказы пишутся в аудит.
func TestLicenseAccess(t *testing.T) {
	le := newLicenseEnv(t)
	sys := le.mustLogin(t, "sysadm")
	admin := le.mustLogin(t, "admin")
	auditor := le.mustLogin(t, "auditor")
	analyst := le.mustLogin(t, "analyst")
	owner := le.mustLogin(t, "owner")
	file := signLicense(t, testLicense(1))

	_, before := lastDenied(t, le.mem)
	for _, s := range []session{analyst, owner} {
		mustProblem(t, le.call(s, "GET", "/api/v1/license", "", false), 403, CodeForbidden)
	}
	for _, s := range []session{analyst, owner, auditor} {
		mustProblem(t, le.call(s, "PUT", "/api/v1/license", putLicenseBody(t, file, tPhrase), true), 403, CodeForbidden)
	}
	if _, after := lastDenied(t, le.mem); after != before+5 {
		t.Fatalf("записей access.denied: %d → %d", before, after)
	}
	for _, s := range []session{sys, admin, auditor} {
		w := le.call(s, "GET", "/api/v1/license", "", false)
		if v := decode[license.Info](t, w.Body.Bytes()); w.Code != 200 || v.State != license.PhaseNone || v.Restricted {
			t.Fatalf("без лицензии: %d %s", w.Code, w.Body)
		}
	}

	// Токен API лицензию не загружает: права license.manage ему не выдать.
	if auth.TokenGrantable(auth.PermLicenseManage) || !auth.TokenGrantable(auth.PermLicenseRead) {
		t.Fatal("license.manage выдаётся токену")
	}
	bearer := session{bearer: le.issueToken(t, sys, auth.PermLicenseRead).Token}
	mustProblem(t, le.call(bearer, "PUT", "/api/v1/license", putLicenseBody(t, file, tPhrase), false), 403, CodeForbidden)
	if w := le.call(bearer, "GET", "/api/v1/license", "", false); w.Code != 200 {
		t.Fatalf("чтение токеном: %d %s", w.Code, w.Body)
	}
	// Без пароля и с неверным — отказ до проверки файла.
	mustProblem(t, le.call(sys, "PUT", "/api/v1/license", putLicenseBody(t, file, "неверный"), true), 403, CodeReauthFailed)
	if w := le.call(sys, "PUT", "/api/v1/license", putLicenseBody(t, file, ""), true); w.Code == 200 {
		t.Fatal("загрузка без пароля")
	}
	mustProblem(t, le.call(sys, "PUT", "/api/v1/license", `{"license":"","password":"x"}`, true), 400, CodeInvalidRequest)
	if n := len(le.store.Records); n != 0 {
		t.Fatalf("записи о загрузке без повторной проверки: %d", n)
	}

	w := le.call(sys, "PUT", "/api/v1/license", putLicenseBody(t, file, tPhrase), true)
	if v := decode[license.Info](t, w.Body.Bytes()); w.Code != 200 || v.State != license.PhaseActive || v.Number != 1 {
		t.Fatalf("загрузка: %d %s", w.Code, w.Body)
	}
	mustProblem(t, le.call(sys, "PUT", "/api/v1/license", putLicenseBody(t, file, tPhrase), true), 409, CodeConflict)
	mustProblem(t, le.call(sys, "PUT", "/api/v1/license", putLicenseBody(t, "не лицензия", tPhrase), true), 422, CodeUnprocessable)
	tampered := strings.Replace(file, `"signature":"`, `"signature":"A`, 1)
	mustProblem(t, le.call(admin, "PUT", "/api/v1/license", putLicenseBody(t, tampered, tPhrase), true), 422, CodeUnprocessable)
	var loaded, rejected int
	for _, r := range le.store.Records {
		switch r.Action {
		case "license.loaded":
			loaded++
		case "license.rejected":
			rejected++
		}
	}
	if loaded != 1 || rejected != 3 {
		t.Fatalf("аудит: загружено %d, отклонено %d", loaded, rejected)
	}
	if strings.Contains(le.log.String(), file[:40]) {
		t.Fatal("файл лицензии в техническом журнале")
	}
}

// ADR-0026, п. 5: после льготного периода изменения конфигурации закрыты,
// чтение и маршруты из списка исключений работают; новая лицензия снимает
// запрет. Выключенный модуль — license_module, предел приложений —
// license_limit.
func TestLicenseRestrictionsViaAPI(t *testing.T) {
	le := newLicenseEnv(t)
	sys := le.mustLogin(t, "sysadm")
	analyst := le.mustLogin(t, "analyst")

	// Без лицензии (пилот по договору) ограничений нет.
	prov := le.provider(t, sys, "llm-a")
	le.application(t, sys, "app-a", prov.ID, tOwnerID)
	if w := le.call(sys, "PUT", "/api/v1/license", putLicenseBody(t, signLicense(t, testLicense(1)), tPhrase), true); w.Code != 200 {
		t.Fatalf("загрузка: %d %s", w.Code, w.Body)
	}

	// Предел приложений: одно уже есть.
	body := fmt.Sprintf(`{"slug":"app-b","name":"Приложение","owner_id":%q,"env":"test","provider_id":%q,"models":["gpt-4o-mini"]}`,
		tOwnerID, prov.ID)
	mustProblem(t, le.call(sys, "POST", "/api/v1/applications", body, true), 403, license.CodeLimit)
	// Модуль агентов не входит в лицензию: изменения закрыты, чтение работает.
	mustProblem(t, le.call(sys, "POST", "/api/v1/agents", `{"name":"a"}`, true), 403, license.CodeModule)
	if w := le.call(sys, "GET", "/api/v1/agents", "", false); w.Code != 200 {
		t.Fatalf("список агентов: %d %s", w.Code, w.Body)
	}

	// Льготный период: изменения работают.
	le.setNow(time.Date(2027, 11, 10, 0, 0, 0, 0, time.UTC))
	le.provider(t, sys, "llm-b")
	if v := decode[license.Info](t, le.call(sys, "GET", "/api/v1/license", "", false).Body.Bytes()); v.State != license.PhaseGrace {
		t.Fatalf("льготный период: %+v", v)
	}

	// После льготного периода: отказ изменению, чтение и исключения работают.
	le.setNow(time.Date(2027, 12, 1, 0, 0, 0, 0, time.UTC))
	mustProblem(t, le.call(sys, "POST", "/api/v1/providers", `{"slug":"llm-c"}`, true), 403, license.CodeRestricted)
	mustProblem(t, le.call(sys, "DELETE", "/api/v1/providers/"+prov.ID, "", true), 403, license.CodeRestricted)
	if w := le.call(analyst, "GET", "/api/v1/providers", "", false); w.Code != 200 {
		t.Fatalf("чтение: %d %s", w.Code, w.Body)
	}
	// Права проверяются раньше лицензии: аналитик получает обычный отказ.
	mustProblem(t, le.call(analyst, "POST", "/api/v1/providers", `{"slug":"llm-c"}`, true), 403, CodeForbidden)
	// Исключение: своя учётная запись.
	if w := le.call(sys, "PUT", "/api/v1/me/email", `{"email":"sysadm@example.ru","password":"`+tPhrase+`"}`, true); w.Code != 200 {
		t.Fatalf("свой e-mail: %d %s", w.Code, w.Body)
	}

	// Новая лицензия (исключение из запрета) снимает его.
	next := testLicense(2)
	next.IssuedAt, next.ValidFrom, next.ValidUntil = time.Date(2027, 12, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2027, 12, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 12, 1, 0, 0, 0, 0, time.UTC)
	next.Limits.Applications = 0
	if w := le.call(sys, "PUT", "/api/v1/license", putLicenseBody(t, signLicense(t, next), tPhrase), true); w.Code != 200 {
		t.Fatalf("новая лицензия: %d %s", w.Code, w.Body)
	}
	le.application(t, sys, "app-b", prov.ID, tOwnerID)
}

// 4В17 ревью 4.r2: после льготного периода можно отключить вход через
// внешний IdP и каталог и снять исключение из политики — это снижение
// доступа и возврат контроля, а не изменение конфигурации в пользу
// заказчика.
func TestLicenseRestrictedAllowsDisablingExternalLogin(t *testing.T) {
	le := newLicenseEnv(t)
	sys := le.mustLogin(t, "sysadm")
	if w := le.call(sys, "PUT", "/api/v1/license", putLicenseBody(t, signLicense(t, testLicense(1)), tPhrase), true); w.Code != 200 {
		t.Fatalf("загрузка: %d %s", w.Code, w.Body)
	}
	sec := le.mustLogin(t, "admin")
	le.setNow(time.Date(2027, 12, 1, 0, 0, 0, 0, time.UTC))
	mustProblem(t, le.call(sec, "PUT", "/api/v1/auth/idp", `{}`, true), 403, license.CodeRestricted)
	for _, path := range []string{"/api/v1/auth/idp", "/api/v1/auth/ldap",
		"/api/v1/policies/01900000-0000-7000-8000-0000000000ff/exceptions/01900000-0000-7000-8000-0000000000fe"} {
		w := le.call(sec, "DELETE", path, `{"password":"`+tPhrase+`"}`, true)
		if w.Code == http.StatusForbidden {
			t.Errorf("DELETE %s после льготного периода: %d %s", path, w.Code, w.Body)
		}
	}
}

// ADR-0026, п. 5: новый изменяющий маршрут без строки в списке исключений
// проходит проверку лицензии, то есть закрыт после льготного периода.
func TestLicenseGateNewMutatingRoute(t *testing.T) {
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	le := newLicenseEnv(t,
		Route{Method: http.MethodPost, Path: "/api/v1/zz-new-route", Permission: auth.PermProvidersManage, Handler: ok},
		Route{Method: http.MethodGet, Path: "/api/v1/zz-new-route", Permission: auth.PermProvidersManage, Handler: ok})
	sys := le.mustLogin(t, "sysadm")
	if w := le.call(sys, "PUT", "/api/v1/license", putLicenseBody(t, signLicense(t, testLicense(1)), tPhrase), true); w.Code != 200 {
		t.Fatalf("загрузка: %d %s", w.Code, w.Body)
	}
	if w := le.call(sys, "POST", "/api/v1/zz-new-route", "", true); w.Code != http.StatusNoContent {
		t.Fatalf("до истечения: %d %s", w.Code, w.Body)
	}
	le.setNow(time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC))
	mustProblem(t, le.call(sys, "POST", "/api/v1/zz-new-route", "", true), 403, license.CodeRestricted)
	if w := le.call(sys, "GET", "/api/v1/zz-new-route", "", false); w.Code != http.StatusNoContent {
		t.Fatalf("чтение: %d %s", w.Code, w.Body)
	}
}

// Список исключений ссылается только на существующие изменяющие маршруты
// консоли; модули — на существующие префиксы. Устаревшая строка — ошибка:
// иначе маршрут с тем же путём в будущем получил бы исключение без ревью.
func TestLicenseExemptList(t *testing.T) {
	_, rt, err := New(Options{Hasher: testHasher(t), Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]Route{}
	for _, r := range rt.Routes() {
		registered[routeKey(r)] = r
	}
	for key := range licenseExempt {
		r, ok := registered[key]
		if !ok {
			t.Errorf("исключение %q: маршрут не зарегистрирован", key)
			continue
		}
		if r.Public || !mutating(r.Method) {
			t.Errorf("исключение %q: маршрут открытый или не изменяющий", key)
		}
	}
	for key := range licenseModuleExempt {
		if _, ok := licenseExempt[key]; !ok {
			if _, ok := registered[key]; !ok {
				t.Errorf("исключение модуля %q: маршрут не зарегистрирован", key)
			}
		}
	}
	for _, m := range licenseModules {
		found := false
		for key := range registered {
			if strings.Contains(key, " "+m.prefix+"/") || strings.HasSuffix(key, " "+m.prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("префикс модуля %s: маршрутов нет", m.prefix)
		}
	}
	// Все прочие изменяющие маршруты консоли под проверкой.
	gated := 0
	for key, r := range registered {
		g, _ := licenseRule(r)
		_, exempt := licenseExempt[key]
		switch {
		case r.Public || !strings.HasPrefix(r.Path, "/api/") || !mutating(r.Method):
			if g {
				t.Errorf("%s: проверка лицензии на открытом или читающем маршруте", key)
			}
		case !exempt && !g:
			t.Errorf("%s: изменяющий маршрут без проверки лицензии", key)
		case !exempt:
			gated++
		}
	}
	if gated < 50 {
		t.Fatalf("под проверкой всего %d маршрутов", gated)
	}
}

// ADR-0026, п. 5: сверх предела шлюзов регистрация — 403 license_limit,
// токен не погашен и годится после снятия предела.
func TestGatewayRegisterLicenseLimit(t *testing.T) {
	svc, _ := newGatewayEnv(t)
	h, _, err := New(Options{Logger: quiet(), Hasher: testHasher(t), Gateways: svc,
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}}})
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := svc.IssueToken(context.Background(), gwregistry.TokenInput{Name: "gw-2", Actor: audit.Actor{Type: audit.ActorCLI, ID: "uid:0"}})
	if err != nil {
		t.Fatal(err)
	}
	_, csr, err := aisecCrypto.NewClientCSR("gw")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"token":"` + tok + `","csr":` + jsonString(string(csr)) + `}`
	register := func() *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/gateways/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	limit := true
	svc.SetAdmission(func(context.Context) error {
		if limit {
			return &license.Denied{Code: license.CodeLimit, Message: "Предел шлюзов лицензии."}
		}
		return nil
	})
	mustProblem(t, register(), 403, license.CodeLimit)
	limit = false
	if w := register(); w.Code != http.StatusCreated {
		t.Fatalf("после снятия предела: %d %s", w.Code, w.Body)
	}
}

// ADR-0026, п. 5: маршрут из списка исключений запрета изменений проверяет
// модуль и после льготного периода, и у недействительной лицензии.
func TestLicenseExemptRouteKeepsModuleCheck(t *testing.T) {
	le := newLicenseEnv(t)
	sys := le.mustLogin(t, "sysadm")
	l := testLicense(1)
	l.Modules = []string{license.ModuleAgents}
	if w := le.call(sys, "PUT", "/api/v1/license", putLicenseBody(t, signLicense(t, l), tPhrase), true); w.Code != 200 {
		t.Fatalf("загрузка: %d %s", w.Code, w.Body)
	}
	imp := func() *httptest.ResponseRecorder {
		return le.callFile(sys, "POST", "/api/v1/shadow-ai/imports?format=squid", "text/plain", []byte("x"))
	}
	mustProblem(t, imp(), 403, license.CodeModule)
	le.setNow(time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC))
	mustProblem(t, imp(), 403, license.CodeModule)
	if !strings.Contains(le.log.String(), "изменение отклонено лицензией") {
		t.Fatal("отказ по лицензии не в техническом журнале")
	}
	// Недействительная лицензия: модулей нет.
	le.store.Replace(audit.DefaultOrgID, []byte(`{"format":"aisec-license-v1"}`))
	if err := le.lic.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	mustProblem(t, le.call(sys, "POST", "/api/v1/providers", `{"slug":"llm-c"}`, true), 403, license.CodeRestricted)
	mustProblem(t, imp(), 403, license.CodeModule)
}
