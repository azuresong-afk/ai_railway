package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

// Пакеты конфигурации на внутреннем порту (задача 2.13). Подпись, проверка
// и сборка — в internal/policy/bundle; здесь — контракт маршрутов и отказы.

type bundleEnv struct {
	fx  *bundletest.Fixture
	svc *build.Service
	rec *recAudit
}

// newBundleEnv — приложение crm с политикой corp, которой нужен словарь
// codename; withLists = false — словаря нет, пакет не собирается.
func newBundleEnv(t testing.TB, withLists bool) *bundleEnv {
	t.Helper()
	ctx := context.Background()
	fx := bundletest.New(t)
	e := &bundleEnv{fx: fx, rec: &recAudit{}}
	reg, err := detect.NewRegistry(builtin.All()...)
	if err != nil {
		t.Fatal(err)
	}
	pols, err := versions.New(versions.Options{Store: versions.NewMemory(), Provider: fx.Provider, Catalog: reg})
	if err != nil {
		t.Fatal(err)
	}
	r, err := fx.Provider.Random()
	if err != nil {
		t.Fatal(err)
	}
	dk, err := aisecCrypto.RandomBytes(r, aisecCrypto.AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	box, err := keyring.NewStaticKey(fx.Provider, "01900000-0000-7000-8000-0000000000d1", dk)
	if err != nil {
		t.Fatal(err)
	}
	as, err := apps.New(apps.Options{Store: apps.NewMemory(), Provider: fx.Provider, Box: box, Policies: pols,
		OwnerCheck: func(context.Context, string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	by := apps.By{Actor: audit.Actor{Type: audit.ActorUser, ID: tOwnerID, Name: "owner"}, Policy: true,
		Confirm: func(context.Context) error { return nil }}
	ca, err := aisecCrypto.NewCA("AISec test provider CA", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	prov, err := as.CreateProvider(ctx, by, apps.ProviderInput{Slug: "llm", Name: "LLM", Type: "openai",
		BaseURL: "https://llm.example/v1", CAPEM: string(ca.CertPEM())})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := as.SetCredential(ctx, by, prov.ID, []byte(tSecret)); err != nil {
		t.Fatal(err)
	}
	spec, _ := policy.Template(policy.TemplateBase)
	spec.ID, spec.Name = "corp", "Корпоративная"
	spec.Rules = append(spec.Rules, policy.RuleSpec{ID: "codename", Detector: "lists", Categories: []string{"lists.codename"},
		Action: policy.Block, Severity: policy.High})
	if _, err := pols.Create(ctx, versions.By{Actor: by.Actor}, spec, versions.SourceAPI, "", versions.ConsoleDefaults); err != nil {
		t.Fatal(err)
	}
	in := apps.AppInput{Slug: "crm", Name: "CRM", Env: "prod", OwnerID: tOwnerID, ProviderID: prov.ID, Models: []string{"gpt-4o"}}
	prot := apps.ProtectionInput{Policy: "corp", PolicyMode: "enforce"}
	if withLists {
		prot.Lists = &[]apps.List{{ID: "projects", Category: "codename", Words: []string{"проект зенит"}}}
	}
	app, err := as.CreateApplication(ctx, by, in, &prot)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := as.IssueKey(ctx, by, app.ID, "", apps.KeyInput{Name: "k1"}); err != nil {
		t.Fatal(err)
	}
	if e.svc, err = build.New(build.Options{Apps: as, Policies: pols, Store: build.NewMemory(), Audit: e.rec,
		Sealer: fx.Sealer, Provider: fx.Provider, Logger: quiet()}); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *bundleEnv) handler(t testing.TB, authz Authorizer) http.Handler {
	t.Helper()
	svc, _ := newGatewayEnv(t)
	h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: svc, Authorizer: authz,
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}}, Extra: BundleRoutes(e.svc, quiet())})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (e *bundleEnv) actions() []string {
	e.rec.mu.Lock()
	defer e.rec.mu.Unlock()
	var out []string
	for _, x := range e.rec.entries {
		out = append(out, x.Action)
	}
	return out
}

func TestBundleGet(t *testing.T) {
	e := newBundleEnv(t, true)
	h := e.handler(t, asGateway(bundletest.GatewayID))
	key := base64.RawURLEncoding.EncodeToString(e.fx.Recipient.PublicKey())
	const path = "/internal/v1/policies/bundle"
	for name, hdr := range map[string][]string{
		"без ключа":        nil,
		"короткий ключ":    {BundleKeyHeader, "AAAA"},
		"с дополнением":    {BundleKeyHeader, key + "="},
		"два заголовка":    {BundleKeyHeader, key, BundleKeyHeader, key},
		"не base64url":     {BundleKeyHeader, strings.Repeat("!", 43)},
		"стандартный b64+": {BundleKeyHeader, strings.Repeat("+", 43)},
	} {
		if w := do(h, http.MethodGet, path, "", hdr...); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	w := do(h, http.MethodGet, path, "", BundleKeyHeader, key)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("пакет: %d %v", w.Code, w.Header())
	}
	if strings.Contains(w.Body.String(), tSecret) {
		t.Fatal("учётные данные в ответе открытым текстом")
	}
	b, err := e.fx.Opener(t).Open(w.Body.Bytes(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.ETag() != w.Header().Get("ETag") || b.Secrets["llm"] != tSecret {
		t.Fatalf("ETag %q / %q, секрет расшифрован: %v", b.ETag(), w.Header().Get("ETag"), b.Secrets["llm"] == tSecret)
	}
	w = do(h, http.MethodGet, path, "", BundleKeyHeader, key, "If-None-Match", b.ETag())
	if w.Code != http.StatusNotModified || w.Body.Len() != 0 || w.Header().Get("ETag") != b.ETag() {
		t.Fatalf("If-None-Match: %d %q", w.Code, w.Body)
	}
	// В аудите: сборка (в хранилище) и одна выдача; 304 не пишется.
	if got := e.actions(); len(got) != 1 || got[0] != "bundle.deliver" {
		t.Fatalf("аудит: %v", got)
	}
}

// В16 ревью 2.r3b: приложение без нужного словаря исключается из пакета, а
// пакет выдаётся: в нём ID и ключи приложения, шлюз ответит на них 503.
func TestBundleExcludesInvalidApp(t *testing.T) {
	e := newBundleEnv(t, false)
	h := e.handler(t, asGateway(bundletest.GatewayID))
	w := do(h, http.MethodGet, "/internal/v1/policies/bundle", "", BundleKeyHeader,
		base64.RawURLEncoding.EncodeToString(e.fx.Recipient.PublicKey()))
	if w.Code != http.StatusOK {
		t.Fatalf("пакет: %d %s", w.Code, w.Body)
	}
	b, err := e.fx.Opener(t).Open(w.Body.Bytes(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Content.Applications) != 0 || len(b.Content.Unavailable) != 1 || b.Content.Unavailable[0].ID != "crm" ||
		len(b.Content.Unavailable[0].Keys) != 1 {
		t.Fatalf("содержимое: %+v", b.Content)
	}
}

// Пакет и отчёт — только шлюзу с проверенным сертификатом (ИАФ.10).
func TestBundleRequiresGatewayCert(t *testing.T) {
	e := newBundleEnv(t, true)
	h := e.handler(t, nil)
	key := base64.RawURLEncoding.EncodeToString(e.fx.Recipient.PublicKey())
	if w := do(h, http.MethodGet, "/internal/v1/policies/bundle", "", BundleKeyHeader, key); w.Code != http.StatusUnauthorized {
		t.Fatalf("пакет без сертификата: %d", w.Code)
	}
	if w := do(h, http.MethodPost, "/internal/v1/policies/bundle/status", `{"result":"applied","version":1}`,
		"Content-Type", "application/json"); w.Code != http.StatusUnauthorized {
		t.Fatalf("отчёт без сертификата: %d", w.Code)
	}
	if len(e.actions()) != 0 {
		t.Fatalf("аудит без сертификата: %v", e.actions())
	}
}

func TestBundleStatus(t *testing.T) {
	e := newBundleEnv(t, true)
	h := e.handler(t, asGateway(bundletest.GatewayID))
	const path = "/internal/v1/policies/bundle/status"
	for _, body := range []string{`{}`, `{"result":"applied"}`, `{"result":"rejected","version":1,"reason":"x"}`,
		`{"result":"applied","version":1,"reason":"signature"}`, `{"result":"applied","version":1,"extra":1}`} {
		if w := do(h, http.MethodPost, path, body, "Content-Type", "application/json"); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
	if w := do(h, http.MethodPost, path, `{"result":"rejected","version":7,"reason":"signature"}`, "Content-Type", "application/json"); w.Code != http.StatusNoContent {
		t.Fatalf("отчёт об отказе: %d %s", w.Code, w.Body)
	}
	if w := do(h, http.MethodPost, path, `{"result":"applied","version":7}`, "Content-Type", "application/json"); w.Code != http.StatusNoContent {
		t.Fatalf("отчёт о применении: %d %s", w.Code, w.Body)
	}
	if got := e.actions(); strings.Join(got, ",") != "bundle.rejected,bundle.applied" {
		t.Fatalf("аудит: %v", got)
	}
	if e.rec.entries[0].Actor.ID != bundletest.GatewayID || e.rec.entries[0].Result != audit.ResultFailure {
		t.Fatalf("запись об отказе: %+v", e.rec.entries[0])
	}
}

// FuzzBundleStatusRequest: любое тело отчёта — 204 или ошибка клиента в
// формате Problem Details, без паники и 500.
func FuzzBundleStatusRequest(f *testing.F) {
	e := newBundleEnv(f, true)
	h := e.handler(f, asGateway(bundletest.GatewayID))
	for _, s := range []string{`{"result":"applied","version":1}`, `{"result":"rejected","version":0,"reason":"rollback"}`,
		`{}`, `[]`, `{"version":"1"}`, "\x00", `{"result":"applied","version":1}{}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/internal/v1/policies/bundle/status", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		switch w.Code {
		case http.StatusNoContent:
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatalf("ошибка не в формате Problem Details: %q", w.Header().Get("Content-Type"))
			}
		default:
			t.Fatalf("код %d: %s", w.Code, w.Body)
		}
	})
}
