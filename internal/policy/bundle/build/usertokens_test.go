package build_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
)

// Разделы user_tokens и user_token_keys (задача 4.21 этапа 4).

const tokIssuer = "https://idp.example.test/realms/aisec"

// fakeIdP — источник ключей IdP для сборки.
type fakeIdP struct {
	issuer string
	keys   *aisecCrypto.JWKS
	err    error
	calls  int
}

func (f *fakeIdP) get(context.Context) (string, *aisecCrypto.JWKS, error) {
	f.calls++
	return f.issuer, f.keys, f.err
}

func idpKeys(t *testing.T, e *env, alg, kid string) *aisecCrypto.JWKS {
	t.Helper()
	s, err := cryptotest.NewJWTSigner(alg, kid, 0)
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.fx.Provider.JWT()
	if err != nil {
		t.Fatal(err)
	}
	k, err := v.ParseJWKS(cryptotest.JWKS(s))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func content(t *testing.T, svc *build.Service) *bundle.Content {
	t.Helper()
	rec, err := svc.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, err := bundle.ParseContent(rec.Content)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBuildUserTokens(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	idp := &fakeIdP{issuer: tokIssuer, keys: idpKeys(t, e, "ES256", "k1")}
	svc, err := build.New(build.Options{Apps: e.apps, Policies: e.policies, Store: e.store, Audit: e.audit,
		Sealer: e.fx.Sealer, Provider: e.fx.Provider, Clock: e.clock, IdPKeys: idp.get})
	if err != nil {
		t.Fatal(err)
	}
	// Без настроек — без разделов и без обращения к IdP.
	if c := content(t, svc); len(c.UserTokens) != 0 || len(c.UserTokenKeys) != 0 || idp.calls != 0 {
		t.Fatalf("без настроек: %+v %+v, обращений %d", c.UserTokens, c.UserTokenKeys, idp.calls)
	}
	leeway := 30
	if _, err := e.apps.SetUserAccess(ctx, e.appsBy, e.app.ID, apps.UserAccessInput{Mode: apps.UserTokenRequired, Issuer: tokIssuer,
		Audience: "aisec-gateway", Leeway: &leeway, ModelGroups: map[string][]string{"gpt-4o": {"analysts"}}}); err != nil {
		t.Fatal(err)
	}
	c := content(t, svc)
	if len(c.UserTokens) != 1 || c.UserTokens[0].App != "crm" || c.UserTokens[0].Leeway != 30 ||
		c.UserTokens[0].ModelGroups["gpt-4o"][0] != "analysts" || len(c.UserTokenKeys) != 1 || c.UserTokenKeys[0].Issuer != tokIssuer {
		t.Fatalf("разделы: %+v %+v", c.UserTokens, c.UserTokenKeys)
	}
	v, err := e.fx.Provider.JWT()
	if err != nil {
		t.Fatal(err)
	}
	if k, err := v.ParseJWKS(c.UserTokenKeys[0].JWKS); err != nil || !k.Has("k1") {
		t.Fatalf("ключи в пакете: %v", err)
	}
	// IdP недоступен — в пакете ключи прежней версии.
	idp.err = errors.New("IdP: network")
	if c := content(t, svc); len(c.UserTokenKeys) != 1 || c.UserTokenKeys[0].Issuer != tokIssuer {
		t.Fatalf("при недоступном IdP: %+v", c.UserTokenKeys)
	}
	// IdP недоступен дольше MaxStaleUserTokenKeys — ключей в пакете нет.
	e.now = e.now.Add(build.MaxStaleUserTokenKeys + time.Minute)
	if c := content(t, svc); len(c.UserTokens) != 1 || len(c.UserTokenKeys) != 0 {
		t.Fatalf("после срока прежних ключей: %+v", c.UserTokenKeys)
	}
	// IdP сменил ключ — новая версия с новым ключом.
	idp.err, idp.keys = nil, idpKeys(t, e, "RS256", "k2")
	c = content(t, svc)
	if k, err := v.ParseJWKS(c.UserTokenKeys[0].JWKS); err != nil || !k.Has("k2") || k.Has("k1") {
		t.Fatalf("после смены ключа: %v", err)
	}
	// Издатель IdP другой — ключей нет: шлюзы отклоняют JWT.
	idp.issuer = "https://other.example.test"
	if c := content(t, svc); len(c.UserTokens) != 1 || len(c.UserTokenKeys) != 0 {
		t.Fatalf("чужой издатель: %+v", c.UserTokenKeys)
	}
	// Модели больше нет у приложения — её группы в пакет не идут.
	if _, err := e.apps.UpdateApplication(ctx, e.appsBy, e.app.ID, apps.AppInput{Slug: "crm", Name: "CRM", Env: "prod", OwnerID: owner,
		ProviderID: e.provider.ID, Models: []string{"gpt-4o-mini"}}); err != nil {
		t.Fatal(err)
	}
	if c := content(t, svc); len(c.UserTokens) != 1 || c.UserTokens[0].ModelGroups != nil {
		t.Fatalf("группы удалённой модели: %+v", c.UserTokens)
	}
	// Режим off — раздела нет.
	if _, err := e.apps.SetUserAccess(ctx, e.appsBy, e.app.ID, apps.UserAccessInput{Mode: apps.UserTokenOff}); err != nil {
		t.Fatal(err)
	}
	if c := content(t, svc); len(c.UserTokens) != 0 || len(c.UserTokenKeys) != 0 {
		t.Fatalf("режим off: %+v", c.UserTokens)
	}
}

// 4Н14 ревью 4.r2: срок прежних ключей IdP (24 ч) отсчитывается от
// последнего получения, сохранённого на сервере, а не от запуска: после
// перезапуска сервера с недоступным IdP ключ, полученный давно, в пакет
// не возвращается.
func TestUserTokenKeysStaleSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	idp := &fakeIdP{issuer: tokIssuer, keys: idpKeys(t, e, "ES256", "k1")}
	start := func() *build.Service {
		svc, err := build.New(build.Options{Apps: e.apps, Policies: e.policies, Store: e.store, Audit: e.audit,
			Sealer: e.fx.Sealer, Provider: e.fx.Provider, Clock: e.clock, IdPKeys: idp.get})
		if err != nil {
			t.Fatal(err)
		}
		return svc
	}
	svc := start()
	if _, err := e.apps.SetUserAccess(ctx, e.appsBy, e.app.ID, apps.UserAccessInput{Mode: apps.UserTokenRequired, Issuer: tokIssuer,
		Audience: "aisec-gateway"}); err != nil {
		t.Fatal(err)
	}
	if c := content(t, svc); len(c.UserTokenKeys) != 1 {
		t.Fatalf("ключи: %+v", c.UserTokenKeys)
	}
	got := e.now
	if at, err := e.store.UserTokenKeysAt(ctx, audit.DefaultOrgID); err != nil || !at.Equal(got) {
		t.Fatalf("момент получения не сохранён: %v %v", at, err)
	}
	// IdP недоступен; сервер перезапускается каждые 20 ч.
	idp.err = errors.New("IdP: network")
	e.now = got.Add(20 * time.Hour)
	if c := content(t, start()); len(c.UserTokenKeys) != 1 {
		t.Fatalf("в пределах срока после перезапуска: %+v", c.UserTokenKeys)
	}
	e.now = got.Add(build.MaxStaleUserTokenKeys + time.Minute)
	if c := content(t, start()); len(c.UserTokens) != 1 || len(c.UserTokenKeys) != 0 {
		t.Fatalf("после срока и перезапуска ключи остались: %+v", c.UserTokenKeys)
	}
}
