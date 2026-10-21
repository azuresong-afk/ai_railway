package apps_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
)

// Синтетические учётные записи владельцев.
const (
	ownerA = "01900000-0000-7000-8000-00000000a0a1"
	ownerB = "01900000-0000-7000-8000-00000000a0b1"
	nobody = "01900000-0000-7000-8000-00000000a0ff"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type env struct {
	svc   *apps.Service
	mem   *apps.Memory
	clock *clock
	box   *keyring.Box
	h     aisecCrypto.Hasher
	caPEM string
	by    apps.By
}

func newEnv(t *testing.T, withBox bool) *env {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	key, err := aisecCrypto.RandomBytes(r, aisecCrypto.AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{mem: apps.NewMemory(), clock: &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)},
		by: apps.By{Actor: audit.Actor{Type: audit.ActorUser, ID: ownerA, Name: "admin"}}}
	if withBox {
		if e.box, err = keyring.NewStaticKey(p, "01900000-0000-7000-8000-0000000000d1", key); err != nil {
			t.Fatal(err)
		}
	}
	if e.h, err = p.Hasher(); err != nil {
		t.Fatal(err)
	}
	ca, err := aisecCrypto.NewCA("AISec test provider CA", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.caPEM = string(ca.CertPEM())
	owners := map[string]bool{ownerA: true, ownerB: true}
	e.svc, err = apps.New(apps.Options{Store: e.mem, Provider: p, Box: e.box, Clock: e.clock.now,
		OwnerCheck: func(_ context.Context, id string) error {
			if !owners[id] {
				return errors.New("нет такой учётной записи")
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) providerInput(slug string) apps.ProviderInput {
	return apps.ProviderInput{Slug: slug, Name: "Провайдер " + slug, Type: "openai", BaseURL: "https://llm.example/v1", CAPEM: e.caPEM}
}

func (e *env) provider(t *testing.T, slug string) apps.Provider {
	t.Helper()
	p, err := e.svc.CreateProvider(context.Background(), e.by, e.providerInput(slug))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func appInput(slug, providerID, owner string) apps.AppInput {
	return apps.AppInput{Slug: slug, Name: "Приложение " + slug, OwnerID: owner, Env: "test", ProviderID: providerID,
		Models: []string{"gpt-4o-mini"}, Aliases: map[string]string{"default": "gpt-4o-mini"}}
}

func (e *env) app(t *testing.T, slug, providerID, owner string) apps.Application {
	t.Helper()
	a, err := e.svc.CreateApplication(context.Background(), e.by, appInput(slug, providerID, owner), nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (e *env) last(t *testing.T, action string) audit.Entry {
	t.Helper()
	recs := e.mem.Records()
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i].Action == action {
			return recs[i]
		}
	}
	t.Fatalf("нет записи %s в аудите", action)
	return audit.Entry{}
}

func (e *env) count(action string) int {
	n := 0
	for _, r := range e.mem.Records() {
		if r.Action == action {
			n++
		}
	}
	return n
}

func inputErr(t *testing.T, err error, want string) {
	t.Helper()
	var ie *apps.InputError
	if !errors.As(err, &ie) {
		t.Fatalf("ожидалась ошибка ввода (%s), получено %v", want, err)
	}
	if !strings.Contains(ie.Error(), want) {
		t.Fatalf("в ошибке нет %q: %v", want, ie)
	}
}

// Каждая запись аудита — из перечня (РСБ.2) и без секретов в подробностях.
func checkRecords(t *testing.T, e *env, secrets ...string) {
	t.Helper()
	for _, r := range e.mem.Records() {
		if _, ok := audit.Lookup(r.Action); !ok {
			t.Errorf("событие %s вне перечня аудита", r.Action)
		}
		if _, err := audit.CanonicalDetails(r.Details); err != nil {
			t.Errorf("%s: подробности не проходят проверку журнала: %v", r.Action, err)
		}
		s := fmt.Sprintf("%+v", r)
		for _, sec := range secrets {
			if strings.Contains(s, sec) {
				t.Errorf("%s: секрет в записи аудита", r.Action)
			}
		}
	}
}

func TestProviderLifecycle(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	p := e.provider(t, "openai-main")
	if !p.External || p.Credential != nil || p.BaseURL != "https://llm.example/v1" {
		t.Fatalf("новый провайдер: %+v", p)
	}
	if _, err := e.svc.CreateProvider(ctx, e.by, e.providerInput("openai-main")); !errors.Is(err, apps.ErrSlugTaken) {
		t.Fatalf("повтор slug: %v", err)
	}
	for name, mod := range map[string]func(*apps.ProviderInput){
		"slug":     func(in *apps.ProviderInput) { in.Slug = "Bad_Slug" },
		"base_url": func(in *apps.ProviderInput) { in.BaseURL = "http://llm.example/v1" },
		"ca_pem": func(in *apps.ProviderInput) {
			in.CAPEM = "-----BEGIN CERTIFICATE-----\nmusor\n-----END CERTIFICATE-----\n"
		},
		"type":                     func(in *apps.ProviderInput) { in.Type = "claude" },
		"для GigaChat нужен scope": func(in *apps.ProviderInput) { in.Type = "gigachat" },
		"folder_id":                func(in *apps.ProviderInput) { in.FolderID = "abc" },
		"connect_timeout":          func(in *apps.ProviderInput) { in.ConnectTimeout = 601 },
		"name":                     func(in *apps.ProviderInput) { in.Name = "строка\nс переводом" },
	} {
		in := e.providerInput("p-" + fmt.Sprint(len(name)))
		mod(&in)
		_, err := e.svc.CreateProvider(ctx, e.by, in)
		inputErr(t, err, name)
	}
	// Граница: таймаут 600 с и GigaChat со scope.
	in := e.providerInput("giga")
	in.Type, in.Scope, in.ConnectTimeout = "gigachat", "GIGACHAT_API_CORP", 600
	if _, err := e.svc.CreateProvider(ctx, e.by, in); err != nil {
		t.Fatal(err)
	}
	upd := e.providerInput("")
	upd.Name = "Основной"
	p2, err := e.svc.UpdateProvider(ctx, e.by, p.ID, upd)
	if err != nil || p2.Name != "Основной" || p2.Slug != "openai-main" || !p2.External {
		t.Fatalf("изменение: %+v %v", p2, err)
	}
	if r := e.last(t, "provider.update"); r.Object.ID != p.ID {
		t.Fatalf("аудит изменения: %+v", r)
	}
	a := e.app(t, "crm", p.ID, ownerA)
	if _, err := e.svc.DeleteProvider(ctx, e.by, p.ID); !errors.Is(err, apps.ErrProviderInUse) {
		t.Fatalf("удаление используемого: %v", err)
	}
	// Архивное приложение тоже держит провайдера: ссылки сохраняются.
	if _, err := e.svc.ArchiveApplication(ctx, e.by, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DeleteProvider(ctx, e.by, p.ID); !errors.Is(err, apps.ErrProviderInUse) {
		t.Fatalf("удаление провайдера архивного приложения: %v", err)
	}
	other := e.provider(t, "spare")
	if _, err := e.svc.DeleteProvider(ctx, e.by, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Provider(ctx, other.ID); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("после удаления: %v", err)
	}
	if e.count("provider.create") != 3 || e.count("provider.delete") != 1 {
		t.Fatalf("аудит: %v", e.mem.Records())
	}
	checkRecords(t, e)
}

// ЗИ.1: учётные данные шифруются ключом данных с AAD строки и не
// возвращаются; шифротекст другой строки не расшифровывается.
func TestProviderCredential(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	p1, p2 := e.provider(t, "one"), e.provider(t, "two")
	const secret = "sk-synthetic-0123456789abcdef"
	got, err := e.svc.SetCredential(ctx, e.by, p1.ID, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if got.Credential == nil || strings.Contains(string(got.Credential.Data), secret) || got.Credential.KeyID != e.box.KeyID() {
		t.Fatalf("учётные данные не зашифрованы: %+v", got.Credential)
	}
	plain, err := e.svc.OpenCredential(ctx, p1.ID)
	if err != nil || string(plain) != secret {
		t.Fatalf("расшифровка: %q %v", plain, err)
	}
	if r := e.last(t, "provider.credentials_set"); r.Object.ID != p1.ID {
		t.Fatalf("аудит: %+v", r)
	}
	// Перестановка шифротекста в другую строку — отказ (AAD, Р4).
	if _, err := e.mem.UpdateProvider(ctx, audit.DefaultOrgID, p2.ID, func(p *apps.Provider) (audit.Entry, error) {
		p.Credential = got.Credential
		return audit.Entry{Action: "provider.update"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.OpenCredential(ctx, p2.ID); err == nil {
		t.Fatal("чужой шифротекст расшифрован")
	}
	// Замена — признак replaced; пустое и слишком большое — отказ.
	if _, err := e.svc.SetCredential(ctx, e.by, p1.ID, []byte("sk-synthetic-new")); err != nil {
		t.Fatal(err)
	}
	if d := e.last(t, "provider.credentials_set").Details.(map[string]any); d["replaced"] != true {
		t.Fatalf("подробности замены: %v", d)
	}
	for _, bad := range [][]byte{nil, []byte("   "), []byte(strings.Repeat("a", apps.MaxCredential+1)),
		[]byte("sk-1\r\nX-Injected: 1"), []byte("sk-\x00"), []byte("ключ")} {
		_, err := e.svc.SetCredential(ctx, e.by, p1.ID, bad)
		inputErr(t, err, "credential")
	}
	if _, err := e.svc.SetCredential(ctx, e.by, p1.ID, []byte(strings.Repeat("a", apps.MaxCredential))); err != nil {
		t.Fatalf("граница 16 КиБ: %v", err)
	}
	if _, err := e.svc.SetCredential(ctx, e.by, nobody, []byte("x")); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("нет провайдера: %v", err)
	}
	if _, err := e.svc.OpenCredential(ctx, e.provider(t, "three").ID); !errors.Is(err, apps.ErrNoCredential) {
		t.Fatalf("без учётных данных: %v", err)
	}
	checkRecords(t, e, secret, "sk-synthetic-new")

	// Без ключа данных учётные данные не принимаются.
	nb := newEnv(t, false)
	p := nb.provider(t, "one")
	if _, err := nb.svc.SetCredential(ctx, nb.by, p.ID, []byte(secret)); !errors.Is(err, apps.ErrNoDataKey) {
		t.Fatalf("без ключа данных: %v", err)
	}
}

// ТЗ 5.4, DM-40: снятие признака «внешний» — ослабление, с причиной и в аудит.
func TestProviderExternal(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := e.provider(t, "vllm")
	_, err := e.svc.SetExternal(ctx, e.by, p.ID, false, "  ")
	inputErr(t, err, "reason")
	got, err := e.svc.SetExternal(ctx, e.by, p.ID, false, "vLLM в контуре заказчика")
	if err != nil || got.External {
		t.Fatalf("снятие: %+v %v", got, err)
	}
	d := e.last(t, "provider.external_changed").Details.(map[string]any)
	if d["weakening"] != true || d["after"] != false || d["reason"] != "vLLM в контуре заказчика" {
		t.Fatalf("подробности: %v", d)
	}
	// Без изменения записи нет.
	if _, err := e.svc.SetExternal(ctx, e.by, p.ID, false, "повтор"); err != nil {
		t.Fatal(err)
	}
	if n := e.count("provider.external_changed"); n != 1 {
		t.Fatalf("записей %d", n)
	}
	if _, err := e.svc.SetExternal(ctx, e.by, p.ID, true, "обратно"); err != nil {
		t.Fatal(err)
	}
	if d := e.last(t, "provider.external_changed").Details.(map[string]any); d["weakening"] != false {
		t.Fatalf("установка признака — не ослабление: %v", d)
	}
	// Изменение провайдера признак не трогает.
	if _, err := e.svc.SetExternal(ctx, e.by, p.ID, false, "снова"); err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.UpdateProvider(ctx, e.by, p.ID, e.providerInput("")); err != nil || got.External {
		t.Fatalf("PUT провайдера вернул признак «внешний»: %v", err)
	}
}

func TestApplicationProtectionDefaults(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := e.provider(t, "main")
	a := e.app(t, "crm", p.ID, ownerA)
	if a.Policy != "base" || a.PolicyMode != "monitor" || a.Storage != "masked" || a.FailMode != "fail_closed" || a.UserFrom != "none" {
		t.Fatalf("умолчания: %+v", a.Protection)
	}
	// Режим — из выбранной политики (вопрос 1.19): «ПДн — строго» — enforce.
	strict, err := e.svc.CreateApplication(ctx, e.by, appInput("hr", p.ID, ownerA), &apps.ProtectionInput{Policy: "pii-strict"})
	if err != nil || strict.PolicyMode != "enforce" {
		t.Fatalf("pii-strict: %+v %v", strict.Protection, err)
	}
	explicit, err := e.svc.CreateApplication(ctx, e.by, appInput("bi", p.ID, ownerA),
		&apps.ProtectionInput{Policy: "pii-strict", PolicyMode: "monitor", Storage: "none"})
	if err != nil || explicit.PolicyMode != "monitor" || explicit.Storage != "none" {
		t.Fatalf("явный режим: %+v %v", explicit.Protection, err)
	}
	if d := e.last(t, "application.create").Details.(map[string]any); d["weakening"] != true {
		t.Fatalf("storage none при создании — ослабление: %v", d)
	}
	for want, prot := range map[string]apps.ProtectionInput{
		"policy":      {Policy: "no-such-policy"},
		"policy_mode": {PolicyMode: "audit"},
		"storage":     {Storage: "all"},
	} {
		_, err := e.svc.CreateApplication(ctx, e.by, appInput("x-"+want[:3], p.ID, ownerA), &prot)
		inputErr(t, err, want)
	}
	if _, err := e.svc.CreateApplication(ctx, e.by, appInput("crm", p.ID, ownerA), nil); !errors.Is(err, apps.ErrSlugTaken) {
		t.Fatalf("повтор slug: %v", err)
	}
	if _, err := e.svc.CreateApplication(ctx, e.by, appInput("orphan", nobody, ownerA), nil); !errors.Is(err, apps.ErrProviderNotFound) {
		t.Fatalf("нет провайдера: %v", err)
	}
	_, err = e.svc.CreateApplication(ctx, e.by, appInput("nouser", p.ID, nobody), nil)
	inputErr(t, err, "owner_id")
	// Проверки — те же, что у файла шлюза.
	for want, mod := range map[string]func(*apps.AppInput){
		"DM-33":               func(in *apps.AppInput) { in.Models = nil },
		"псевдоним":           func(in *apps.AppInput) { in.Aliases = map[string]string{"x": "not-allowed"} },
		"env":                 func(in *apps.AppInput) { in.Env = "stage" },
		"quotas.max_tokens":   func(in *apps.AppInput) { in.Quotas.MaxTokens = -1 },
		"exfil_allow_domains": func(in *apps.AppInput) { in.ExfilAllowDomains = []string{"http://bad"} },
		"name":                func(in *apps.AppInput) { in.Name = strings.Repeat("я", 201) },
		"provider_id":         func(in *apps.AppInput) { in.ProviderID = "not-a-uuid" },
	} {
		in := appInput("v-"+fmt.Sprint(len(want)), p.ID, ownerA)
		mod(&in)
		_, err := e.svc.CreateApplication(ctx, e.by, in, nil)
		inputErr(t, err, want)
	}
	// Граница длины названия.
	in := appInput("long", p.ID, ownerA)
	in.Name = strings.Repeat("я", 200)
	if _, err := e.svc.CreateApplication(ctx, e.by, in, nil); err != nil {
		t.Fatal(err)
	}
	checkRecords(t, e)
}

// DM-40: перевод в monitor и режим хранения none/full — ослабление.
func TestSetProtection(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := e.provider(t, "main")
	a, err := e.svc.CreateApplication(ctx, e.by, appInput("crm", p.ID, ownerA), &apps.ProtectionInput{Policy: "pii-strict"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.SetProtection(ctx, e.by, a.ID, apps.ProtectionInput{PolicyMode: "monitor"})
	if err != nil || got.Policy != "pii-strict" || got.PolicyMode != "monitor" || got.Storage != "masked" {
		t.Fatalf("перевод в monitor: %+v %v", got.Protection, err)
	}
	if d := e.last(t, "application.protection_changed").Details.(map[string]any); d["weakening"] != true {
		t.Fatalf("ослабление не отмечено: %v", d)
	}
	if _, err := e.svc.SetProtection(ctx, e.by, a.ID, apps.ProtectionInput{PolicyMode: "monitor"}); err != nil {
		t.Fatal(err)
	}
	if n := e.count("application.protection_changed"); n != 1 {
		t.Fatalf("без изменения тоже записано: %d", n)
	}
	// Смена политики без режима — режим новой политики.
	got, err = e.svc.SetProtection(ctx, e.by, a.ID, apps.ProtectionInput{Policy: "external-no-pii"})
	if err != nil || got.PolicyMode != "enforce" {
		t.Fatalf("смена политики: %+v %v", got.Protection, err)
	}
	if d := e.last(t, "application.protection_changed").Details.(map[string]any); d["weakening"] != false {
		t.Fatalf("усиление отмечено как ослабление: %v", d)
	}
	for _, s := range []string{"full", "none"} {
		if _, err := e.svc.SetProtection(ctx, e.by, a.ID, apps.ProtectionInput{Storage: s}); err != nil {
			t.Fatal(err)
		}
		if d := e.last(t, "application.protection_changed").Details.(map[string]any); d["weakening"] != true {
			t.Fatalf("storage %s: %v", s, d)
		}
	}
	// Изменение приложения поля защиты не трогает.
	upd := appInput("", p.ID, ownerB)
	got, err = e.svc.UpdateApplication(ctx, e.by, a.ID, upd)
	if err != nil || got.Storage != "none" || got.Slug != "crm" || got.OwnerID != ownerB {
		t.Fatalf("изменение: %+v %v", got, err)
	}
	checkRecords(t, e)
}

// ИАФ.8: ключ показывается один раз, хранится хеш; срок, подсети, лимит.
func TestKeyIssue(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	a := e.app(t, "crm", e.provider(t, "main").ID, ownerA)
	k, raw, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "prod", AllowedCIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}})
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := auth.ParseAppKey(raw)
	if err != nil || prefix != k.Prefix {
		t.Fatalf("ключ %q: префикс %q, %v", raw, k.Prefix, err)
	}
	if !auth.KeyMatches(e.h, raw, hex.EncodeToString(k.Hash)) || auth.KeyMatches(e.h, raw+"x", hex.EncodeToString(k.Hash)) {
		t.Fatal("хеш ключа не совпадает")
	}
	if !k.ExpiresAt.Equal(e.clock.t.Add(365*24*time.Hour)) || k.Status(e.clock.t) != apps.KeyActive || len(k.AllowedCIDRs) != 2 {
		t.Fatalf("ключ: %+v", k)
	}
	if d := e.last(t, "app_key.issue").Details.(map[string]any); d["prefix"] != k.Prefix {
		t.Fatalf("аудит выпуска: %v", d)
	}
	for want, in := range map[string]apps.KeyInput{
		"allowed_cidrs":   {Name: "x", AllowedCIDRs: []string{"10.1.2.3/8"}},
		"IPv4":            {Name: "x", AllowedCIDRs: []string{"::ffff:10.0.0.0/104"}},
		"expires_in_days": {Name: "x", ExpiresInDays: apps.MaxKeyDays + 1},
		"name":            {Name: ""},
	} {
		_, _, err := e.svc.IssueKey(ctx, e.by, a.ID, "", in)
		inputErr(t, err, want)
	}
	many := make([]string, apps.MaxCIDRs+1)
	for i := range many {
		many[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	_, _, err = e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "x", AllowedCIDRs: many})
	inputErr(t, err, "allowed_cidrs")
	// Границы: 730 суток и 64 подсети.
	if k, _, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "max", ExpiresInDays: apps.MaxKeyDays, AllowedCIDRs: many[:apps.MaxCIDRs]}); err != nil ||
		!k.ExpiresAt.Equal(e.clock.t.Add(apps.MaxKeyDays*24*time.Hour)) {
		t.Fatalf("граница: %+v %v", k, err)
	}
	// Лимит действующих ключей.
	for i := 2; i < apps.MaxActiveKeys; i++ {
		if _, _, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: fmt.Sprint("k", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "over"}); !errors.Is(err, apps.ErrTooManyKeys) {
		t.Fatalf("лимит: %v", err)
	}
	if _, _, err := e.svc.IssueKey(ctx, e.by, nobody, "", apps.KeyInput{Name: "x"}); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("нет приложения: %v", err)
	}
	checkRecords(t, e, raw)
}

// ИАФ.8: ротация с перекрытием, срок только сокращается; отзыв немедленный и необратимый.
func TestKeyRotateRevoke(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	a := e.app(t, "crm", e.provider(t, "main").ID, ownerA)
	old, _, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "prod", AllowedCIDRs: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	nk, raw, prev, err := e.svc.RotateKey(ctx, e.by, old.ID, "", apps.RotateInput{})
	if err != nil {
		t.Fatal(err)
	}
	if nk.RotatedFrom != old.ID || nk.Name != "prod" || len(nk.AllowedCIDRs) != 1 || nk.Prefix == old.Prefix || raw == "" {
		t.Fatalf("новый ключ: %+v", nk)
	}
	if !prev.ExpiresAt.Equal(e.clock.t.Add(apps.DefaultOverlap)) || prev.Status(e.clock.t) != apps.KeyActive {
		t.Fatalf("перекрытие: %+v", prev)
	}
	if d := e.last(t, "app_key.rotate").Details.(map[string]any); d["rotated_from"] != old.ID || d["previous_prefix"] != old.Prefix {
		t.Fatalf("аудит ротации: %v", d)
	}
	// Перекрытие длиннее остатка срока срок не продлевает.
	short, _, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "short", ExpiresInDays: 1})
	if err != nil {
		t.Fatal(err)
	}
	long := 30 * 24 * time.Hour
	if _, _, prev, err := e.svc.RotateKey(ctx, e.by, short.ID, "", apps.RotateInput{Overlap: &long}); err != nil || !prev.ExpiresAt.Equal(short.ExpiresAt) {
		t.Fatalf("срок продлён: %+v %v", prev, err)
	}
	// Перекрытие 0 — прежний ключ перестаёт действовать сразу.
	zero := time.Duration(0)
	_, _, prev, err = e.svc.RotateKey(ctx, e.by, nk.ID, "", apps.RotateInput{Overlap: &zero})
	if err != nil || prev.Status(e.clock.t) != apps.KeyExpired {
		t.Fatalf("перекрытие 0: %+v %v", prev, err)
	}
	if _, _, _, err := e.svc.RotateKey(ctx, e.by, nk.ID, "", apps.RotateInput{}); !errors.Is(err, apps.ErrKeyInactive) {
		t.Fatalf("ротация истёкшего: %v", err)
	}
	over := apps.MaxOverlap + time.Hour
	_, _, _, err = e.svc.RotateKey(ctx, e.by, old.ID, "", apps.RotateInput{Overlap: &over})
	inputErr(t, err, "overlap_hours")
	// Отзыв.
	r, err := e.svc.RevokeKey(ctx, e.by, old.ID, "")
	if err != nil || r.Status(e.clock.t) != apps.KeyRevoked {
		t.Fatalf("отзыв: %+v %v", r, err)
	}
	if _, err := e.svc.RevokeKey(ctx, e.by, old.ID, ""); !errors.Is(err, apps.ErrKeyInactive) {
		t.Fatalf("повторный отзыв: %v", err)
	}
	if _, _, _, err := e.svc.RotateKey(ctx, e.by, old.ID, "", apps.RotateInput{}); !errors.Is(err, apps.ErrKeyInactive) {
		t.Fatalf("ротация отозванного: %v", err)
	}
	keys, err := e.svc.Keys(ctx, a.ID, "")
	if err != nil || len(keys) != 5 || keys[0].CreatedAt.Before(keys[len(keys)-1].CreatedAt) {
		t.Fatalf("ключи: %d %v", len(keys), err)
	}
	checkRecords(t, e, raw)
}

// УПД.8: владелец видит и меняет ключи только своих приложений; чужое — как отсутствующее.
func TestOwnerScope(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := e.provider(t, "main")
	mine, theirs := e.app(t, "mine", p.ID, ownerA), e.app(t, "theirs", p.ID, ownerB)
	list, err := e.svc.Applications(ctx, ownerA, nil, 10)
	if err != nil || len(list) != 1 || list[0].ID != mine.ID {
		t.Fatalf("свои: %+v %v", list, err)
	}
	all, err := e.svc.Applications(ctx, "", nil, 10)
	if err != nil || len(all) != 2 {
		t.Fatalf("все: %d %v", len(all), err)
	}
	if _, err := e.svc.Application(ctx, theirs.ID, ownerA); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("чужое приложение: %v", err)
	}
	if _, err := e.svc.Keys(ctx, theirs.ID, ownerA); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("чужие ключи: %v", err)
	}
	if _, _, err := e.svc.IssueKey(ctx, e.by, theirs.ID, ownerA, apps.KeyInput{Name: "x"}); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("ключ чужому: %v", err)
	}
	k, _, err := e.svc.IssueKey(ctx, e.by, theirs.ID, "", apps.KeyInput{Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RevokeKey(ctx, e.by, k.ID, ownerA); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("отзыв чужого: %v", err)
	}
	if _, _, _, err := e.svc.RotateKey(ctx, e.by, k.ID, ownerA, apps.RotateInput{}); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("ротация чужого: %v", err)
	}
	if _, _, err := e.svc.IssueKey(ctx, e.by, mine.ID, ownerA, apps.KeyInput{Name: "own"}); err != nil {
		t.Fatalf("свой ключ: %v", err)
	}
	// Страницы по курсору.
	page, err := e.svc.Applications(ctx, "", nil, 1)
	if err != nil || len(page) != 1 {
		t.Fatal(err)
	}
	next, err := e.svc.Applications(ctx, "", &apps.Cursor{CreatedAt: page[0].CreatedAt, ID: page[0].ID}, 10)
	if err != nil || len(next) != 1 || next[0].ID == page[0].ID {
		t.Fatalf("вторая страница: %+v %v", next, err)
	}
}

func TestArchive(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	a := e.app(t, "crm", e.provider(t, "main").ID, ownerA)
	k1, _, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RevokeKey(ctx, e.by, k1.ID, ""); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.ArchiveApplication(ctx, e.by, a.ID)
	if err != nil || !got.Archived() {
		t.Fatalf("архив: %+v %v", got, err)
	}
	if d := e.last(t, "application.archive").Details.(map[string]any); d["revoked_keys"] != 1 {
		t.Fatalf("отозвано ключей: %v", d)
	}
	keys, err := e.svc.Keys(ctx, a.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Status(e.clock.t) != apps.KeyRevoked {
			t.Fatalf("ключ архивного приложения действует: %+v", k)
		}
	}
	if _, err := e.svc.ArchiveApplication(ctx, e.by, a.ID); !errors.Is(err, apps.ErrArchived) {
		t.Fatalf("повторный архив: %v", err)
	}
	if _, err := e.svc.UpdateApplication(ctx, e.by, a.ID, appInput("", a.ProviderID, ownerA)); !errors.Is(err, apps.ErrArchived) {
		t.Fatalf("изменение архивного: %v", err)
	}
	if _, _, err := e.svc.IssueKey(ctx, e.by, a.ID, "", apps.KeyInput{Name: "c"}); !errors.Is(err, apps.ErrArchived) {
		t.Fatalf("ключ архивному: %v", err)
	}
	if _, err := e.svc.SetProtection(ctx, e.by, a.ID, apps.ProtectionInput{Storage: "none"}); !errors.Is(err, apps.ErrArchived) {
		t.Fatalf("поля защиты архивного: %v", err)
	}
	checkRecords(t, e)
}
