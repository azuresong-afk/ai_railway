package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/quotalease"
)

// memQuotaStore — режим квот и аренда в памяти: выдаёт want целиком.
type memQuotaStore struct {
	mode     string
	online   int
	setUp    bool
	recs     []audit.Entry
	leases   []quotalease.LeaseInput
	leaseErr error
	observed map[string]bool
}

func newMemQuotaStore() *memQuotaStore {
	return &memQuotaStore{mode: quotalease.ModeLocal, setUp: true, observed: map[string]bool{}}
}

func (m *memQuotaStore) Settings(context.Context, string, time.Time) (quotalease.Settings, error) {
	return quotalease.Settings{Mode: m.mode, GatewaysOnline: m.online}, nil
}

func (m *memQuotaStore) SetMode(_ context.Context, _, mode string, _ time.Time, fn func(quotalease.Settings) (audit.Entry, error)) error {
	if !m.setUp {
		return quotalease.ErrNotSetUp
	}
	if m.mode == mode {
		return nil
	}
	rec, err := fn(quotalease.Settings{Mode: m.mode, GatewaysOnline: m.online})
	if err != nil {
		return err
	}
	m.mode, m.recs = mode, append(m.recs, rec)
	return nil
}

func (m *memQuotaStore) Lease(_ context.Context, in quotalease.LeaseInput) (quotalease.Response, error) {
	if m.leaseErr != nil {
		return quotalease.Response{}, m.leaseErr
	}
	if m.mode != quotalease.ModeLeased {
		return quotalease.Response{}, quotalease.ErrModeLocal
	}
	m.leases = append(m.leases, in)
	resp := quotalease.Response{ServerTime: in.Now, Gateways: m.online}
	for _, a := range in.Request.Apps {
		ar := quotalease.AppResponse{App: a.App}
		for _, q := range a.Quotas {
			id, err := in.NewID()
			if err != nil {
				return quotalease.Response{}, err
			}
			ar.Quotas = append(ar.Quotas, quotalease.Grant{Quota: q.Quota, RequestID: q.RequestID, Lease: id, Granted: q.Want,
				TTLMS: quotalease.MinuteTTL.Milliseconds(), Limit: q.Want})
		}
		resp.Apps = append(resp.Apps, ar)
	}
	return resp, nil
}

func (m *memQuotaStore) Observe(_ context.Context, _, gatewayID string, autonomous bool, _ time.Time) error {
	m.observed[gatewayID] = autonomous
	return nil
}

func (m *memQuotaStore) Health(context.Context, string, time.Time) (quotalease.Health, error) {
	return quotalease.Health{Mode: m.mode, Online: m.online}, nil
}

func (m *memQuotaStore) Purge(context.Context, string, time.Time) (int64, error) { return 0, nil }

func (m *memQuotaStore) Record(_ context.Context, e audit.Entry) error {
	m.recs = append(m.recs, e)
	return nil
}

// testIDs — генератор ID на случайном источнике профиля standard.
func testIDs(t testing.TB) *ids.Generator {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	return ids.NewGenerator(r)
}

func newQuotaService(t testing.TB, st quotalease.Store, ids *ids.Generator) *quotalease.Service {
	t.Helper()
	svc, err := quotalease.New(quotalease.Options{Store: st, IDs: ids, OrgID: audit.DefaultOrgID, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// Задача 4.29 (ADR-0021, п. 2): режим квот читают с budgets.read, меняет
// quota_mode.manage (администраторы системы и безопасности). Переход на
// local при нескольких шлюзах на связи — ослабление (DM-40): с текущим
// паролем, в аудите weakening и причина.
func TestQuotaSettingsViaAPI(t *testing.T) {
	e := newAlertsEnv(t)
	st := newMemQuotaStore()
	h, _, err := New(Options{Hasher: testHasher(t), Logger: slog.New(slog.NewTextHandler(e.log, nil)),
		Auth: testAuth(t, e.mem, auth.WithClock(e.clock.now)), Quotas: newQuotaService(t, st, e.ids),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 100000, Window: time.Minute}}}})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	admin, sys := e.mustLogin(t, "admin"), e.mustLogin(t, "sysadm")
	analyst, auditor, owner := e.mustLogin(t, "analyst"), e.mustLogin(t, "auditor"), e.mustLogin(t, "owner")
	const path = "/api/v1/quota-settings"

	mustProblem(t, e.call(owner, "GET", path, "", false), 403, CodeForbidden)
	for _, s := range []session{analyst, auditor, owner} {
		mustProblem(t, e.call(s, "PUT", path, `{"mode":"leased"}`, true), 403, CodeForbidden)
	}
	if st.mode != quotalease.ModeLocal || len(st.recs) != 0 {
		t.Fatalf("режим изменён без права: %+v", st)
	}
	w := e.call(auditor, "GET", path, "", false)
	if got := decode[quotalease.Settings](t, w.Body.Bytes()); w.Code != 200 || got.Mode != quotalease.ModeLocal {
		t.Fatalf("режим по умолчанию: %d %s", w.Code, w.Body)
	}
	for _, b := range []string{`{"mode":"cluster"}`, `{"mode":""}`, `{"mode":"leased","x":1}`} {
		mustProblem(t, e.call(sys, "PUT", path, b, true), 400, CodeInvalidRequest)
	}
	// Включение аренды — без повторной проверки.
	st.online = 2
	if w := e.call(sys, "PUT", path, `{"mode":"leased"}`, true); w.Code != 200 || st.mode != quotalease.ModeLeased {
		t.Fatalf("включение аренды: %d %s", w.Code, w.Body)
	}
	// Возврат на local при двух шлюзах: без пароля — 400 с полем password,
	// неверный — 403, верный — 200 и weakening.
	w = e.call(admin, "PUT", path, `{"mode":"local"}`, true)
	mustProblem(t, w, 400, CodeInvalidRequest)
	if p := decode[Problem](t, w.Body.Bytes()); len(p.Errors) != 1 || p.Errors[0].Field != "password" {
		t.Fatalf("поле ошибки: %s", w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", path, `{"mode":"local","password":"не тот пароль"}`, true), 403, CodeReauthFailed)
	if st.mode != quotalease.ModeLeased {
		t.Fatal("режим ослаблен без проверки")
	}
	if w := e.call(admin, "PUT", path, `{"mode":"local","password":"`+tPhrase+`"}`, true); w.Code != 200 {
		t.Fatalf("переход на local: %d %s", w.Code, w.Body)
	}
	if len(st.recs) != 2 {
		t.Fatalf("аудит: %+v", st.recs)
	}
	on, off := st.recs[0].Details.(map[string]any), st.recs[1].Details.(map[string]any)
	if st.recs[1].Action != "install.quota_mode_changed" || off["weakening"] != true || on["weakening"] != false ||
		strings.Join(off["weakening_reasons"].([]string), ",") != "quota_local_multi_gateway" || st.recs[1].Actor.ID != tAdminID {
		t.Fatalf("аудит: %+v", st.recs)
	}
	// Один шлюз на связи — переход на local не ослабление.
	st.online = 1
	if w := e.call(sys, "PUT", path, `{"mode":"leased"}`, true); w.Code != 200 {
		t.Fatal(w.Body)
	}
	if w := e.call(sys, "PUT", path, `{"mode":"local"}`, true); w.Code != 200 || st.recs[3].Details.(map[string]any)["weakening"] != false {
		t.Fatalf("один шлюз: %d %s", w.Code, w.Body)
	}
	// До первичной настройки — 409.
	st.setUp = false
	mustProblem(t, e.call(sys, "PUT", path, `{"mode":"leased"}`, true), 409, CodeConflict)
}

func TestQuotaSettingsUnavailable(t *testing.T) {
	e := newAlertsEnv(t)
	h, _, err := New(Options{Hasher: testHasher(t), Logger: quiet(), Auth: testAuth(t, e.mem, auth.WithClock(e.clock.now)),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 100000, Window: time.Minute}}}})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	mustProblem(t, e.call(e.mustLogin(t, "auditor"), "GET", "/api/v1/quota-settings", "", false), 503, CodeUnavailable)
}

// internalQuotas — внутренний порт шлюза gw с арендой квот svc.
func internalQuotas(t testing.TB, svc *quotalease.Service, gw string) http.Handler {
	t.Helper()
	reg, _ := newGatewayEnv(t)
	h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: reg, Authorizer: asGateway(gw),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}}, Extra: QuotaInternalRoutes(svc, quiet())})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

const tLeaseBody = `{"apps":[{"app":"crm","quotas":[{"quota":"requests_per_minute","request_id":"0192a000-0000-7000-8000-0000000000a1","want":5}]}]}`

// POST /internal/v1/quota-leases: аренда по ID шлюза из сертификата,
// режим local — 409, неверный запрос — 400, нарушение в отчёте — 400 и
// quota.lease_violation, ограничитель — 429 по ID шлюза, не по адресу.
func TestQuotaLeasesInternal(t *testing.T) {
	e := newAlertsEnv(t)
	st := newMemQuotaStore()
	svc := newQuotaService(t, st, e.ids)
	const gw = "01900000-0000-7000-8000-00000000c0a1"
	h := internalQuotas(t, svc, gw)
	post := func(h http.Handler, body string) int {
		return do(h, "POST", "/internal/v1/quota-leases", body, "Content-Type", "application/json").Code
	}
	if c := post(h, tLeaseBody); c != http.StatusConflict {
		t.Fatalf("режим local: %d", c)
	}
	st.mode = quotalease.ModeLeased
	w := do(h, "POST", "/internal/v1/quota-leases", tLeaseBody, "Content-Type", "application/json")
	resp := decode[quotalease.Response](t, w.Body.Bytes())
	if w.Code != 200 || len(resp.Apps) != 1 || resp.Apps[0].Quotas[0].Granted != 5 || st.leases[0].GatewayID != gw {
		t.Fatalf("аренда: %d %s", w.Code, w.Body)
	}
	if c := do(h, "POST", "/internal/v1/quota-leases", tLeaseBody).Code; c != http.StatusUnsupportedMediaType {
		t.Fatalf("без Content-Type: %d", c)
	}
	for _, b := range []string{`{}`, `{"apps":[]}`, `{"apps":[{"app":"CRM","quotas":[]}]}`, tLeaseBody + `{}`,
		strings.Replace(tLeaseBody, `"want":5`, `"want":-1`, 1), strings.Replace(tLeaseBody, `"want":5`, `"want":5,"x":1`, 1)} {
		if c := post(h, b); c != http.StatusBadRequest {
			t.Errorf("%s: %d", b, c)
		}
	}
	if c := post(h, `{"apps":[`+strings.Repeat(" ", quotalease.MaxBody)+`]}`); c != http.StatusRequestEntityTooLarge {
		t.Fatalf("тело больше 64 КиБ: %d", c)
	}
	// Нарушение — 400 и запись аудита от имени шлюза.
	st.leaseErr = &quotalease.Violation{App: "crm", Quota: quotalease.QuotaRPM, Lease: "x", Reason: quotalease.ReasonOverused}
	if c := post(h, tLeaseBody); c != http.StatusBadRequest {
		t.Fatalf("нарушение: %d", c)
	}
	if n := len(st.recs); n != 1 || st.recs[0].Action != "quota.lease_violation" || st.recs[0].Actor.ID != gw ||
		st.recs[0].Result != audit.ResultFailure {
		t.Fatalf("аудит нарушения: %+v", st.recs)
	}
	st.leaseErr = nil
	// Ограничитель: 10 запросов в секунду на шлюз; другой шлюз не затронут.
	limited := 0
	for range quotalease.RatePerSecond + 5 {
		w := do(h, "POST", "/internal/v1/quota-leases", tLeaseBody, "Content-Type", "application/json")
		if w.Code == http.StatusTooManyRequests {
			limited++
			if w.Header().Get("Retry-After") != "1" {
				t.Fatalf("Retry-After: %q", w.Header().Get("Retry-After"))
			}
		}
	}
	if limited == 0 {
		t.Fatal("ограничитель не сработал")
	}
	if c := post(internalQuotas(t, svc, "01900000-0000-7000-8000-00000000c0a2"), tLeaseBody); c != http.StatusOK {
		t.Fatalf("другой шлюз: %d", c)
	}
}

// Шлюз не может арендовать без права gateway.internal (403) — субъект не
// шлюз.
func TestQuotaLeasesForbidden(t *testing.T) {
	e := newAlertsEnv(t)
	st := newMemQuotaStore()
	st.mode = quotalease.ModeLeased
	reg, _ := newGatewayEnv(t)
	h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: reg, Authorizer: allowPerm{},
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}}, Extra: QuotaInternalRoutes(newQuotaService(t, st, e.ids), quiet())})
	if err != nil {
		t.Fatal(err)
	}
	if c := do(h, "POST", "/internal/v1/quota-leases", tLeaseBody, "Content-Type", "application/json").Code; c != http.StatusForbidden {
		t.Fatalf("без права: %d", c)
	}
	if len(st.leases) != 0 {
		t.Fatal("аренда выдана без права")
	}
}

// Heartbeat (задача 4.29): сервер с арендой отвечает quota_leases и
// записывает признак автономной доли шлюза; без сервиса квот — нет.
func TestHeartbeatQuotaAutonomous(t *testing.T) {
	reg, gw := newGatewayEnv(t)
	st := newMemQuotaStore()
	h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: reg, Authorizer: asGateway(gw.ID),
		Quotas: newQuotaService(t, st, testIDs(t))})
	if err != nil {
		t.Fatal(err)
	}
	w := do(h, http.MethodPost, "/internal/v1/heartbeat", `{"version":"1","quota_autonomous":true}`, "Content-Type", "application/json")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"quota_leases":true`) || !st.observed[gw.ID] {
		t.Fatalf("heartbeat: %d %s %v", w.Code, w.Body, st.observed)
	}
	w = do(h, http.MethodPost, "/internal/v1/heartbeat", `{"version":"1","quota_autonomous":false}`, "Content-Type", "application/json")
	if w.Code != http.StatusOK || st.observed[gw.ID] {
		t.Fatalf("снятие признака: %d %v", w.Code, st.observed)
	}
	h2, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: reg, Authorizer: asGateway(gw.ID)})
	if err != nil {
		t.Fatal(err)
	}
	if w := do(h2, http.MethodPost, "/internal/v1/heartbeat", `{"version":"1"}`, "Content-Type", "application/json"); strings.Contains(w.Body.String(), "quota_leases") {
		t.Fatalf("без аренды: %s", w.Body)
	}
}
