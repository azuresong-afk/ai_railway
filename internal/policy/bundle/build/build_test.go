package build_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
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
	credential = "sk-synthetic-provider-credential-01" //nolint:gosec // G101: синтетические учётные данные провайдера для теста, нигде не выданы
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
		appsBy: apps.By{Actor: audit.Actor{Type: audit.ActorUser, ID: owner, Name: "admin"}, Policy: true,
			Confirm: func(context.Context) error { return nil }},
		polBy: versions.By{Actor: audit.Actor{Type: audit.ActorUser, ID: owner, Name: "admin"},
			Confirm: func(context.Context) error { return nil }}}
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
		ProviderID: e.provider.ID, Models: []string{"gpt-4o"}},
		&apps.ProtectionInput{Policy: "corp", PolicyMode: "enforce",
			Lists: &[]apps.List{{ID: "projects", Category: "codename", Words: []string{"проект зенит"}}}}); err != nil {
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
	if c, _ := bundle.ParseContent(r3.Content); len(c.Applications[0].Keys) != 0 { //nolint:gosec // G104: содержимое уже разобрано выше без ошибки, важен список ключей
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
	d, err := e.svc.Deliver(ctx, build.Gateway{ID: bundletest.GatewayID}, e.fx.Recipient.PublicKey(), "", -1)
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
	d2, err := e.svc.Deliver(ctx, build.Gateway{ID: bundletest.GatewayID}, e.fx.Recipient.PublicKey(), `W/"1", `+d.ETag, -1)
	if err != nil || !d2.NotModified || d2.Body != nil {
		t.Fatalf("If-None-Match: %+v, %v", d2, err)
	}
	if len(e.audit.actions()) != 1 {
		t.Fatal("ответ 304 записан в аудит")
	}

	// Пакет другого шлюза этот шлюз не примет.
	d3, err := e.svc.Deliver(ctx, build.Gateway{ID: "другой"}, e.fx.Recipient.PublicKey(), "", -1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.fx.Opener(t).Open(d3.Body, 0); bundle.Reason(err) != bundle.ReasonGatewayMismatch {
		t.Fatalf("пакет чужого шлюза: %v", err)
	}

	if _, err := e.svc.Deliver(ctx, build.Gateway{ID: bundletest.GatewayID}, []byte("short"), "", -1); !errors.Is(err, build.ErrNoRecipientKey) {
		t.Fatalf("без ключа шлюза: %v", err)
	}
}

// 3Н2 ревью 3.r1: шлюз знает заявление о доверии новее сервера (БД
// восстановлена из дампа до ротации) — запись bundle.trust_rollback не
// чаще раза в минуту на шлюз; пакет выдаётся как обычно.
func TestDeliverTrustRollback(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	for range 2 {
		if _, err := e.svc.Deliver(ctx, build.Gateway{ID: bundletest.GatewayID}, e.fx.Recipient.PublicKey(), "", 5); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"bundle.trust_rollback:failure", "bundle.deliver:success", "bundle.deliver:success"}
	if got := e.audit.actions(); !slices.Equal(got, want) {
		t.Fatalf("аудит: %v, ожидалось %v", got, want)
	}
	// Номер не больше серверного — без записи.
	e.now = e.now.Add(2 * time.Minute)
	if _, err := e.svc.Deliver(ctx, build.Gateway{ID: bundletest.GatewayID}, e.fx.Recipient.PublicKey(), "", 0); err != nil {
		t.Fatal(err)
	}
	if got := e.audit.actions(); len(got) != 4 || got[3] != "bundle.deliver:success" {
		t.Fatalf("аудит: %v", got)
	}
}

// TestBuildExcludesInvalidApp — В16 ревью 2.r3b: политика ссылается на
// словарь, которого нет у приложения. Шлюз не применил бы такое
// приложение, поэтому оно исключается: в пакете остаются его ID и
// действующие ключи (шлюз отвечает 503), остальные приложения и отзыв
// ключей доставляются.
func TestBuildExcludesInvalidApp(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	good, err := e.svc.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.apps.CreateApplication(ctx, e.appsBy, apps.AppInput{Slug: "bot", Name: "Бот", Env: "test", OwnerID: owner,
		ProviderID: e.provider.ID, Models: []string{"gpt-4o"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.apps.SetProtection(ctx, e.appsBy, e.app.ID, apps.ProtectionInput{Lists: &[]apps.List{}}); err != nil {
		t.Fatal(err)
	}
	k2, _, err := e.apps.IssueKey(ctx, e.appsBy, e.app.ID, "", apps.KeyInput{Name: "k2"})
	if err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Minute)
	r, err := e.svc.Current(ctx)
	if err != nil || r.Version == good.Version {
		t.Fatalf("сборка с неверным приложением: %d, %v", r.Version, err)
	}
	c, err := bundle.ParseContent(r.Content)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Applications) != 1 || c.Applications[0].ID != other.Slug || len(c.Unavailable) != 1 ||
		c.Unavailable[0].ID != "crm" || len(c.Unavailable[0].Keys) != 2 || len(c.Policies) != 0 {
		t.Fatalf("содержимое: %+v", c)
	}
	recs := e.store.Records()
	d := recs[len(recs)-1].Details.(map[string]any)
	ex, _ := d["excluded"].([]build.Excluded)
	if d["excluded_count"] != 1 || len(ex) != 1 || ex[0].Application != "crm" || !strings.Contains(ex[0].Reason, "lists.codename") {
		t.Fatalf("исключение в аудите: %v", d)
	}
	h, err := e.svc.Health(ctx)
	if err != nil || h.Failed || len(h.Excluded) != 1 || h.Version != r.Version {
		t.Fatalf("состояние сборки: %+v %v", h, err)
	}
	// Отзыв ключа исключённого приложения доходит до шлюзов.
	if _, err := e.apps.RevokeKey(ctx, e.appsBy, k2.ID, ""); err != nil {
		t.Fatal(err)
	}
	r2, err := e.svc.Current(ctx)
	if err != nil || r2.Version == r.Version {
		t.Fatalf("после отзыва: %d %v", r2.Version, err)
	}
	if c, _ := bundle.ParseContent(r2.Content); len(c.Unavailable[0].Keys) != 1 || c.Unavailable[0].Keys[0].Prefix != e.key.Prefix { //nolint:gosec // G104: содержимое уже проверено сборкой, важен список ключей
		t.Fatalf("отозванный ключ исключённого приложения в пакете: %+v", c.Unavailable)
	}
	// Архив — приложение пропадает из пакета вместе с ключами.
	if _, err := e.apps.ArchiveApplication(ctx, e.appsBy, e.app.ID); err != nil {
		t.Fatal(err)
	}
	r3, err := e.svc.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := bundle.ParseContent(r3.Content); len(c.Unavailable) != 0 || len(c.Applications) != 1 { //nolint:gosec // G104: содержимое уже проверено сборкой
		t.Fatalf("архивное приложение в пакете: %+v", c)
	}
	if h, _ := e.svc.Health(ctx); len(h.Excluded) != 0 { //nolint:gosec // G104: ошибка проверена выше тем же вызовом Current
		t.Fatalf("исключение осталось после архивации: %+v", h)
	}
}

// TestBuildTooLargeKeepsLastGood — сбой уровня пакета (размер больше
// половины MaxSize): шлюзам выдаётся последняя корректная версия, неудача
// в аудите один раз; без корректной версии — ErrNoBundle.
func TestBuildTooLargeKeepsLastGood(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	good, err := e.svc.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	words := make([]string, 0, 19000)
	for i := range 19000 {
		words = append(words, fmt.Sprintf("%06d %s", i, strings.Repeat("я", 45)))
	}
	big := &[]apps.List{{ID: "big", Category: "big", Words: words[:10000]}, {ID: "big2", Category: "big2", Words: words[10000:]}}
	for i := range 3 {
		if _, err := e.apps.CreateApplication(ctx, e.appsBy, apps.AppInput{Slug: fmt.Sprintf("big-%d", i), Name: "Большое",
			Env: "test", OwnerID: owner, ProviderID: e.provider.ID, Models: []string{"gpt-4o"}}, &apps.ProtectionInput{Lists: big}); err != nil {
			t.Fatal(err)
		}
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
	if h, err := e.svc.Health(ctx); err != nil || !h.Failed || !strings.Contains(h.Reason, "больше") || h.Version != good.Version {
		t.Fatalf("состояние сборки: %+v %v", h, err)
	}

	// Без корректной версии — ErrNoBundle и отказ выдачи.
	fresh, err := build.New(build.Options{Apps: e.apps, Policies: e.policies, Store: build.NewMemory(), Audit: e.audit,
		Sealer: e.fx.Sealer, Provider: e.fx.Provider, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Current(ctx); !errors.Is(err, build.ErrNoBundle) {
		t.Fatalf("нет корректной версии: %v", err)
	}
	if _, err := fresh.Deliver(ctx, build.Gateway{ID: bundletest.GatewayID}, e.fx.Recipient.PublicKey(), "", -1); !errors.Is(err, build.ErrNoBundle) {
		t.Fatalf("выдача: %v", err)
	}
}

// В16 ревью 2.r3b: проверка при сохранении — изменение, исключающее
// приложение из пакета, отклоняется до записи.
func TestCheckOnSave(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	cur, err := e.apps.Application(ctx, e.app.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.CheckApplication(ctx, &cur, cur); err != nil {
		t.Fatalf("текущее приложение: %v", err)
	}
	noLists := cur
	noLists.Lists = nil
	if err := e.svc.CheckApplication(ctx, &cur, noLists); !errors.Is(err, apps.ErrBreaksBundle) || !strings.Contains(err.Error(), "lists.codename") {
		t.Fatalf("приложение без словаря: %v", err)
	}
	spec, _ := policy.Template(policy.TemplateBase)
	spec.ID = "corp"
	if err := e.svc.CheckPolicy(ctx, spec); err != nil {
		t.Fatalf("политика без словаря: %v", err)
	}
	spec.Rules = append(spec.Rules, policy.RuleSpec{ID: "secret", Detector: "lists", Categories: []string{"lists.secret"},
		Action: policy.Block, Severity: policy.High})
	if err := e.svc.CheckPolicy(ctx, spec); !errors.Is(err, versions.ErrBreaksBundle) || !strings.Contains(err.Error(), "crm") {
		t.Fatalf("политика со словарём, которого нет у приложения: %v", err)
	}
	// Приложение, которое не проходит и с текущей версией, новую версию
	// не блокирует (самопроверка H4, С3): текущая версия уже со словарём,
	// которого у crm нет, следующая ужесточает другое правило.
	if _, err := e.policies.Update(ctx, e.polBy, "corp", 1, spec, versions.SourceAPI, "", versions.ConsoleDefaults); err != nil {
		t.Fatal(err)
	}
	stricter := *spec
	stricter.Rules = append(slices.Clone(spec.Rules), policy.RuleSpec{ID: "secret2", Detector: "lists", Categories: []string{"lists.codename"},
		Action: policy.Block, Severity: policy.High})
	if err := e.svc.CheckPolicy(ctx, &stricter); err != nil {
		t.Fatalf("приложение сломано и текущей версией: %v", err)
	}
	spec.ID = "unused"
	if err := e.svc.CheckPolicy(ctx, spec); err != nil {
		t.Fatalf("политика без приложений: %v", err)
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

// TestBuildOnlyOnRevisionChange — Н26, задача 3.34: N опросов без
// изменений — одна выборка данных; данные выбираются заново только при
// смене счётчика изменений конфигурации или после срока ближайшего ключа.
func TestBuildOnlyOnRevisionChange(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	var rev int64 = 7
	svc, err := build.New(build.Options{Apps: e.apps, Policies: e.policies, Store: e.store, Audit: e.audit,
		Sealer: e.fx.Sealer, Provider: e.fx.Provider, Clock: e.clock,
		Revision: func(context.Context) (int64, error) { return rev, nil }})
	if err != nil {
		t.Fatal(err)
	}
	gw := build.Gateway{ID: bundletest.GatewayID}
	first, err := svc.Deliver(ctx, gw, e.fx.Recipient.PublicKey(), "", -1)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		d, err := svc.Deliver(ctx, gw, e.fx.Recipient.PublicKey(), first.ETag, -1)
		if err != nil || !d.NotModified {
			t.Fatalf("304: %+v, %v", d, err)
		}
	}
	if n := svc.Builds(); n != 1 {
		t.Fatalf("21 опрос без изменений: выборок %d, ожидалась одна", n)
	}

	// Изменение без смены счётчика (так в БД не бывает: счётчик растёт в
	// той же транзакции) не видно — значит, сборку запускает именно счётчик.
	if _, err := e.apps.RevokeKey(ctx, e.appsBy, e.key.ID, ""); err != nil {
		t.Fatal(err)
	}
	if r, err := svc.Current(ctx); err != nil || r.Version != first.Version || svc.Builds() != 1 {
		t.Fatalf("без смены счётчика: версия %d, выборок %d, %v", r.Version, svc.Builds(), err)
	}
	rev++
	r, err := svc.Current(ctx)
	if err != nil || r.Version == first.Version || svc.Builds() != 2 {
		t.Fatalf("после смены счётчика: версия %d, выборок %d, %v", r.Version, svc.Builds(), err)
	}
	if _, err := svc.Current(ctx); err != nil || svc.Builds() != 2 {
		t.Fatalf("повтор: выборок %d, %v", svc.Builds(), err)
	}

	// Ключ истекает без изменения в БД: после его срока — новая выборка.
	k, _, err := e.apps.IssueKey(ctx, e.appsBy, e.app.ID, "", apps.KeyInput{Name: "k2", ExpiresInDays: 1})
	if err != nil {
		t.Fatal(err)
	}
	rev++
	if r, err = svc.Current(ctx); err != nil || svc.Builds() != 3 {
		t.Fatalf("новый ключ: выборок %d, %v", svc.Builds(), err)
	}
	if c, _ := bundle.ParseContent(r.Content); len(c.Applications[0].Keys) != 1 { //nolint:gosec // G104: содержимое сохранено сборкой, важен список ключей
		t.Fatal("нового ключа нет в пакете")
	}
	e.now = k.ExpiresAt.Add(-time.Second)
	if _, err := svc.Current(ctx); err != nil || svc.Builds() != 3 {
		t.Fatalf("до срока ключа: выборок %d, %v", svc.Builds(), err)
	}
	e.now = k.ExpiresAt
	if r, err = svc.Current(ctx); err != nil || svc.Builds() != 4 {
		t.Fatalf("срок ключа: выборок %d, %v", svc.Builds(), err)
	}
	if c, _ := bundle.ParseContent(r.Content); len(c.Applications[0].Keys) != 0 { //nolint:gosec // G104: содержимое сохранено сборкой, важен список ключей
		t.Fatal("истёкший ключ остался в пакете")
	}
}

// TestDeliverReusesSealed — задача 3.34: та же версия тому же шлюзу с тем
// же ключом получателя не подписывается заново; другая версия или другой
// ключ — подписывается.
func TestDeliverReusesSealed(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	gw := build.Gateway{ID: bundletest.GatewayID}
	d1, err := e.svc.Deliver(ctx, gw, e.fx.Recipient.PublicKey(), "", -1)
	if err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Minute)
	d2, err := e.svc.Deliver(ctx, gw, e.fx.Recipient.PublicKey(), "", -1)
	if err != nil || !bytes.Equal(d1.Body, d2.Body) {
		t.Fatalf("повторная выдача той же версии подписана заново: %v", err)
	}
	if _, err := e.fx.Opener(t).Open(d2.Body, 0); err != nil {
		t.Fatal(err)
	}
	cached := 0
	for _, en := range e.audit.entries {
		if d, _ := en.Details.(map[string]any); en.Action == "bundle.deliver" && d["cached"] == true {
			cached++
		}
	}
	if cached != 1 || len(e.audit.actions()) != 2 {
		t.Fatalf("выдача из памяти не записана в аудит: %v", e.audit.actions())
	}
	other := bytes.Clone(e.fx.Recipient.PublicKey())
	other[0] ^= 1
	d3, err := e.svc.Deliver(ctx, gw, other, "", -1)
	if err != nil || bytes.Equal(d3.Body, d1.Body) {
		t.Fatalf("другой ключ получателя — тот же пакет: %v", err)
	}
	if _, err := e.apps.RevokeKey(ctx, e.appsBy, e.key.ID, ""); err != nil {
		t.Fatal(err)
	}
	d4, err := e.svc.Deliver(ctx, gw, e.fx.Recipient.PublicKey(), "", -1)
	if err != nil || d4.Version == d1.Version || bytes.Equal(d4.Body, d1.Body) {
		t.Fatalf("новая версия — прежний пакет: %v", err)
	}
}

// Раздел budgets (задача 3.18): нет цен и бюджетов — раздела нет; цены
// провайдеров пакета и жёсткие бюджеты — по slug, бюджет в 1e-7 ₽; мягкий
// бюджет в пакет не входит, но включает учёт расхода.
func TestBuildBudgetsSection(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	content := func() *bundle.Content {
		t.Helper()
		r, err := e.svc.Current(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c, err := bundle.ParseContent(r.Content)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := content(); c.Budgets != nil {
		t.Fatalf("раздел без цен и бюджетов: %+v", c.Budgets)
	}
	e.apps.SetTimezone(func(context.Context) (string, error) { return "Europe/Moscow", nil })
	if _, err := e.apps.SetBudget(ctx, e.appsBy, e.app.ID, apps.BudgetInput{Mode: apps.BudgetSoft, Limit: "100"}); err != nil {
		t.Fatal(err)
	}
	if c := content(); c.Budgets == nil || c.Budgets.Timezone != "Europe/Moscow" || len(c.Budgets.Hard) != 0 || len(c.Budgets.Prices) != 0 {
		t.Fatalf("мягкий бюджет: %+v", c.Budgets)
	}
	if _, err := e.apps.CreatePrice(ctx, e.appsBy, apps.PriceInput{ProviderID: e.provider.ID, Model: "gpt-4o", Input: "0.25", Output: "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.apps.SetBudget(ctx, e.appsBy, e.app.ID, apps.BudgetInput{Mode: apps.BudgetHard, Limit: "15000.50"}); err != nil {
		t.Fatal(err)
	}
	c := content()
	want := bundle.Budgets{Timezone: "Europe/Moscow",
		Prices: []bundle.ModelPrice{{Provider: "llm", Model: "gpt-4o", Input: 2_500, Output: 10_000}},
		Hard:   []bundle.HardBudget{{App: "crm", Limit: 1_500_050 * bundle.CostUnitsPerKopeck}}}
	if c.Budgets == nil || c.Budgets.Timezone != want.Timezone || !slices.Equal(c.Budgets.Prices, want.Prices) || !slices.Equal(c.Budgets.Hard, want.Hard) {
		t.Fatalf("раздел: %+v", c.Budgets)
	}
}

// Сертификат заказчика (задача 3.27): раздел gateway_tls и ключ в секретах
// шлюза; срок сертификата — срок пересборки, истёкший в пакет не входит;
// сертификат заменён после сборки версии — новая запечатка этой версии
// отказывает.
func TestBuildGatewayTLSSection(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.now = time.Now().UTC().Truncate(time.Second)
	var rev int64 = 1
	svc, err := build.New(build.Options{Apps: e.apps, Policies: e.policies, Store: e.store, Audit: e.audit,
		Sealer: e.fx.Sealer, Provider: e.fx.Provider, Clock: e.clock,
		Revision: func(context.Context) (int64, error) { return rev, nil }})
	if err != nil {
		t.Fatal(err)
	}
	const host = "aisec-gw.example.ru"
	short, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{host}, NotAfter: e.now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := e.apps.SetGatewayTLS(ctx, e.appsBy, apps.GatewayTLSInput{Host: host, ChainPEM: short.Full(), KeyPEM: short.Key})
	if err != nil {
		t.Fatal(err)
	}
	rev++
	gw := build.Gateway{ID: bundletest.GatewayID}
	d, err := svc.Deliver(ctx, gw, e.fx.Recipient.PublicKey(), "", -1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(d.Body, []byte("PRIVATE KEY")) {
		t.Fatal("ключ сертификата в пакете открытым текстом")
	}
	b, err := e.fx.Opener(t).Open(d.Body, 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Content.GatewayTLS == nil || b.Content.GatewayTLS.Fingerprint != cert.Cert.Fingerprint || !strings.Contains(string(b.TLSKey), "PRIVATE KEY") {
		t.Fatalf("раздел gateway_tls: %+v", b.Content.GatewayTLS)
	}
	if _, _, err := aisecCrypto.ParseServerCert([]byte(b.Content.GatewayTLS.ChainPEM), b.TLSKey, host, e.now); err != nil {
		t.Fatalf("шлюз не примет раздел: %v", err)
	}
	builds := svc.Builds()

	// Срок сертификата — срок пересборки: до него сборок нет, после —
	// пакет без раздела (шлюзы возвращаются к своему сертификату).
	e.now = cert.Cert.NotAfter.Add(-time.Second)
	if _, err := svc.Current(ctx); err != nil || svc.Builds() != builds {
		t.Fatalf("до срока: выборок %d, %v", svc.Builds(), err)
	}
	e.now = cert.Cert.NotAfter
	r, err := svc.Current(ctx)
	if err != nil || svc.Builds() != builds+1 {
		t.Fatalf("срок сертификата: выборок %d, %v", svc.Builds(), err)
	}
	if c, err := bundle.ParseContent(r.Content); err != nil || c.GatewayTLS != nil {
		t.Fatalf("истёкший сертификат остался в пакете: %v", err)
	}

	// Новый сертификат: версия собрана; затем сертификат заменён без смены
	// счётчика — выдача собранной версии отказывает (ключ не от неё).
	e.now = time.Now().UTC().Truncate(time.Second)
	next, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{host}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.apps.SetGatewayTLS(ctx, e.appsBy, apps.GatewayTLSInput{Host: host, ChainPEM: next.Full(), KeyPEM: next.Key}); err != nil {
		t.Fatal(err)
	}
	rev++
	if _, err := svc.Deliver(ctx, gw, e.fx.Recipient.PublicKey(), "", -1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.apps.SetGatewayTLS(ctx, e.appsBy, apps.GatewayTLSInput{Host: host, ChainPEM: short.Full(), KeyPEM: short.Key}); err != nil {
		t.Fatal(err)
	}
	// Уже запечатанный для этого шлюза пакет выдаётся повторно (3.34), а
	// новая запечатка — другому шлюзу — отказывает.
	if _, err := svc.Deliver(ctx, build.Gateway{ID: "другой"}, e.fx.Recipient.PublicKey(), "", -1); err == nil || !strings.Contains(err.Error(), "заменён после сборки") {
		t.Fatalf("выдача версии с заменённым сертификатом: %v", err)
	}
}
