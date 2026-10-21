package build_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

const (
	owner      = "01900000-0000-7000-8000-00000000a0a1"
	credential = "sk-synthetic-provider-credential-01"
)

type recorder struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (r *recorder) Record(_ context.Context, e audit.Entry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, e)
	return nil
}

func (r *recorder) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.entries {
		out = append(out, e.Action+":"+string(e.Result))
	}
	return out
}

type env struct {
	fx       *bundletest.Fixture
	now      time.Time
	apps     *apps.Service
	policies *versions.Service
	store    *build.Memory
	audit    *recorder
	svc      *build.Service
	provider apps.Provider
	app      apps.Application
	key      apps.Key
	appsBy   apps.By
	polBy    versions.By
}

func (e *env) clock() time.Time { return e.now }

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	fx := bundletest.New(t)
	e := &env{fx: fx, now: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), store: build.NewMemory(), audit: &recorder{},
		appsBy: apps.By{Actor: audit.Actor{Type: audit.ActorUser, ID: owner, Name: "admin"}},
		polBy:  versions.By{Actor: audit.Actor{Type: audit.ActorUser, ID: owner, Name: "admin"}}}
	reg, err := detect.NewRegistry(builtin.All()...)
	if err != nil {
		t.Fatal(err)
	}
	if e.policies, err = versions.New(versions.Options{Store: versions.NewMemory(), Provider: fx.Provider, Catalog: reg, Clock: e.clock}); err != nil {
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
	if e.apps, err = apps.New(apps.Options{Store: apps.NewMemory(), Provider: fx.Provider, Box: box, Clock: e.clock,
		Policies: e.policies, OwnerCheck: func(context.Context, string) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	ca, err := aisecCrypto.NewCA("AISec test provider CA", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if e.provider, err = e.apps.CreateProvider(ctx, e.appsBy, apps.ProviderInput{Slug: "llm", Name: "LLM", Type: "openai",
		BaseURL: "https://llm.example/v1", CAPEM: string(ca.CertPEM())}); err != nil {
		t.Fatal(err)
	}
	if _, err = e.apps.SetCredential(ctx, e.appsBy, e.provider.ID, []byte(credential)); err != nil {
		t.Fatal(err)
	}
	spec, _ := policy.Template(policy.TemplateBase)
	spec.ID, spec.Name = "corp", "Корпоративная"
	spec.Rules = append(spec.Rules, policy.RuleSpec{ID: "codename", Detector: "lists", Categories: []string{"lists.codename"},
		Action: policy.Block, Severity: policy.High})
	if _, err = e.policies.Create(ctx, e.polBy, spec, versions.SourceAPI, "", versions.ConsoleDefaults); err != nil {
		t.Fatal(err)
	}
	if e.app, err = e.apps.CreateApplication(ctx, e.appsBy, apps.AppInput{Slug: "crm", Name: "CRM", Env: "prod", OwnerID: owner,
		ProviderID: e.provider.ID, Models: []string{"gpt-4o"},
		Lists: []apps.List{{ID: "projects", Category: "codename", Words: []string{"проект зенит"}}}},
		&apps.ProtectionInput{Policy: "corp", PolicyMode: "enforce"}); err != nil {
		t.Fatal(err)
	}
	if e.key, _, err = e.apps.IssueKey(ctx, e.appsBy, e.app.ID, "", apps.KeyInput{Name: "k1"}); err != nil {
		t.Fatal(err)
	}
	if e.svc, err = build.New(build.Options{Apps: e.apps, Policies: e.policies, Store: e.store, Audit: e.audit,
		Sealer: fx.Sealer, Provider: fx.Provider, Clock: e.clock}); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestBuildVersionsOnlyOnChange(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	r1, err := e.svc.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Version != e.now.UnixMilli() {
		t.Fatalf("версия %d, ожидалось время сборки в мс", r1.Version)
	}
	if bytes.Contains(r1.Content, []byte(credential)) {
		t.Fatal("учётные данные в содержимом пакета")
	}
	c, err := bundle.ParseContent(r1.Content)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Applications) != 1 || c.Applications[0].ID != "crm" || len(c.Applications[0].Keys) != 1 ||
		c.Applications[0].Keys[0].Prefix != e.key.Prefix || len(c.Policies) != 1 || c.Policies[0].ID != "corp" ||
		c.Providers[0].CredentialSetAt == nil || c.Applications[0].Lists[0].Category != "codename" {
		t.Fatalf("содержимое: %+v", c)
	}
	if got := e.store.Records(); len(got) != 1 || got[0].Action != "bundle.build" || got[0].Result != audit.ResultSuccess {
		t.Fatalf("аудит сборки: %+v", got)
	}

	// Те же данные — та же версия, без записи.
	r2, err := e.svc.Current(ctx)
	if err != nil || r2.Version != r1.Version || e.store.Versions(audit.DefaultOrgID) != 1 {
		t.Fatalf("повтор: %d, %v", r2.Version, err)
	}

	// Отзыв ключа — новая версия без ключа; часы не сдвинулись — версия +1.
	if _, err := e.apps.RevokeKey(ctx, e.appsBy, e.key.ID, ""); err != nil {
		t.Fatal(err)
	}
	r3, err := e.svc.Current(ctx)
	if err != nil || r3.Version != r1.Version+1 {
		t.Fatalf("после отзыва: %d, %v", r3.Version, err)
	}
	if c, _ := bundle.ParseContent(r3.Content); len(c.Applications[0].Keys) != 0 {
		t.Fatal("отозванный ключ в пакете")
	}

	// Новые учётные данные провайдера — новая версия.
	e.now = e.now.Add(time.Minute)
	if _, err := e.apps.SetCredential(ctx, e.appsBy, e.provider.ID, []byte(credential+"-2")); err != nil {
		t.Fatal(err)
	}
	r4, err := e.svc.Current(ctx)
	if err != nil || r4.Version != e.now.UnixMilli() {
		t.Fatalf("после смены учётных данных: %d, %v", r4.Version, err)
	}
}

func TestDeliverEncryptsForGateway(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	d, err := e.svc.Deliver(ctx, build.Gateway{ID: bundletest.GatewayID}, e.fx.Recipient.PublicKey(), "")
	if err != nil {
		t.Fatal(err)
	}
	if d.NotModified || d.ETag != bundle.ETag(d.Version) || bytes.Contains(d.Body, []byte(credential)) {
		t.Fatalf("выдача: %+v", d.ETag)
	}
	b, err := e.fx.Opener(t).Open(d.Body, 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Secrets["llm"] != credential {
		t.Fatal("учётные данные не расшифрованы шлюзом")
	}
	if got := e.audit.actions(); !slices.Equal(got, []string{"bundle.deliver:success"}) {
		t.Fatalf("аудит выдачи: %v", got)
	}

	// If-None-Match с этой версией — 304 без записи в аудит.
	d2, err := e.svc.Deliver(ctx, build.Gateway{ID: bundletest.GatewayID}, e.fx.Recipient.PublicKey(), `W/"1", `+d.ETag)
	if err != nil || !d2.NotModified || d2.Body != nil {
		t.Fatalf("If-None-Match: %+v, %v", d2, err)
	}
	if len(e.audit.actions()) != 1 {
		t.Fatal("ответ 304 записан в аудит")
	}

	// Пакет другого шлюза этот шлюз не примет.
	d3, err := e.svc.Deliver(ctx, build.Gateway{ID: "другой"}, e.fx.Recipient.PublicKey(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.fx.Opener(t).Open(d3.Body, 0); bundle.Reason(err) != bundle.ReasonGatewayMismatch {
		t.Fatalf("пакет чужого шлюза: %v", err)
	}

	if _, err := e.svc.Deliver(ctx, build.Gateway{ID: bundletest.GatewayID}, []byte("short"), ""); !errors.Is(err, build.ErrNoRecipientKey) {
		t.Fatalf("без ключа шлюза: %v", err)
	}
}

// TestBuildInvalidKeepsLastGood — политика ссылается на словарь, которого
// нет у приложения: шлюз отверг бы такой пакет, поэтому сервер его не
// собирает и выдаёт последнюю корректную версию; неудача в аудите один раз.
func TestBuildInvalidKeepsLastGood(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	good, err := e.svc.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.apps.UpdateApplication(ctx, e.appsBy, e.app.ID, apps.AppInput{Name: "CRM", Env: "prod", OwnerID: owner,
		ProviderID: e.provider.ID, Models: []string{"gpt-4o"}}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		got, err := e.svc.Current(ctx)
		if err != nil || got.Version != good.Version {
			t.Fatalf("после ошибки: %d, %v", got.Version, err)
		}
	}
	var failures int
	for _, a := range e.audit.actions() {
		if a == "bundle.build:failure" {
			failures++
		}
	}
	if failures != 1 {
		t.Fatalf("неудачных сборок в аудите: %d (%v)", failures, e.audit.actions())
	}
	if !strings.Contains(e.audit.entries[0].Details.(map[string]any)["reason"].(string), "crm") {
		t.Fatalf("в причине нет приложения: %v", e.audit.entries[0].Details)
	}
}

func TestBuildInvalidWithoutVersion(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	if _, err := e.apps.UpdateApplication(ctx, e.appsBy, e.app.ID, apps.AppInput{Name: "CRM", Env: "prod", OwnerID: owner,
		ProviderID: e.provider.ID, Models: []string{"gpt-4o"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Current(ctx); !errors.Is(err, build.ErrNoBundle) {
		t.Fatalf("нет корректной версии: %v", err)
	}
	if _, err := e.svc.Deliver(ctx, build.Gateway{ID: bundletest.GatewayID}, e.fx.Recipient.PublicKey(), ""); !errors.Is(err, build.ErrNoBundle) {
		t.Fatalf("выдача: %v", err)
	}
}

func TestRecordReport(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	gw := build.Gateway{ID: bundletest.GatewayID}
	for _, bad := range []build.Report{
		{Result: "ok", Version: 1},
		{Result: build.ResultApplied, Version: 0},
		{Result: build.ResultApplied, Version: 1, Reason: bundle.ReasonSignature},
		{Result: build.ResultRejected, Version: 1, Reason: "другое"},
	} {
		if err := e.svc.RecordReport(ctx, gw, bad); !errors.Is(err, build.ErrInvalidReport) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	rej := build.Report{Result: build.ResultRejected, Version: 5, Reason: bundle.ReasonSignature}
	for range 3 {
		if err := e.svc.RecordReport(ctx, gw, rej); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.svc.RecordReport(ctx, gw, build.Report{Result: build.ResultApplied, Version: 4}); err != nil {
		t.Fatal(err)
	}
	if got := e.audit.actions(); !slices.Equal(got, []string{"bundle.rejected:failure", "bundle.applied:success"}) {
		t.Fatalf("аудит отчётов: %v", got)
	}
	if d := e.audit.entries[0].Details.(map[string]any); d["reason"] != bundle.ReasonSignature || d["threat"] != "DM-42" {
		t.Fatalf("подробности: %v", d)
	}
	// Через минуту тот же отчёт пишется снова.
	e.now = e.now.Add(time.Minute)
	if err := e.svc.RecordReport(ctx, gw, rej); err != nil {
		t.Fatal(err)
	}
	if len(e.audit.actions()) != 3 {
		t.Fatalf("повтор через минуту: %v", e.audit.actions())
	}
}
