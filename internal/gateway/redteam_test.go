package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// Ключ запуска тестирования устойчивости (задача 5.32, ADR-0031, раздел 2):
// признак test из пакета доходит до личности запроса, и событие запроса с
// таким ключом помечено test; с обычным ключом — нет.
func TestTestKeyMarksEvent(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	testKey, pt, ht, err := auth.NewAppKey(rnd, h)
	if err != nil {
		t.Fatal(err)
	}
	plainKey, pp, hp, err := auth.NewAppKey(rnd, h)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).UTC()
	c := bundle.Content{Applications: []bundle.Application{{ID: "app", Env: "prod", Keys: []bundle.Key{
		{Prefix: pt, SHA256: ht, ExpiresAt: exp, Test: true}, {Prefix: pp, SHA256: hp, ExpiresAt: exp}}}}}
	recs, err := c.KeyRecords()
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.NewAuthenticator(h, recs)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := policy.Template(policy.TemplateBase)
	spec.ID = "base"
	u, err := url.Parse("https://127.0.0.1:1/v1")
	if err != nil {
		t.Fatal(err)
	}
	prov, err := providers.NewOpenAI(providers.OpenAIConfig{BaseConfig: providers.BaseConfig{ID: "up", Transport: &http.Transport{}, Logger: quiet()}, BaseURL: u})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRouter([]config.Application{{ID: "app", Env: "prod", Provider: "up", Models: []string{"m"}, Policy: "base"}},
		map[string]providers.Provider{"up": prov}, []policy.Spec{*spec})
	if err != nil {
		t.Fatal(err)
	}
	ch := &ChatHandler{cfg: ChatConfig{IDs: ids.NewGenerator(rnd)}, logger: quiet()}
	app := rt.apps["app"]
	for _, tc := range []struct {
		key  string
		test bool
	}{{testKey, true}, {plainKey, false}} {
		id, fail := a.Authenticate(tc.key, netip.MustParseAddr("127.0.0.1"), time.Now())
		if fail != nil {
			t.Fatal(fail)
		}
		if id.Test != tc.test {
			t.Fatalf("личность ключа: %+v", id)
		}
		r := httptest.NewRequestWithContext(context.WithValue(context.Background(), identityKey{}, id), http.MethodPost,
			"/v1/chat/completions", nil)
		w := httptest.NewRecorder()
		rec, ok := ch.newEventRecord(w, r, app, "gateway_request", "m", false, "", time.Now())
		if !ok || rec.ev.Test != tc.test || w.Header().Get(HeaderEventID) != rec.ev.ID {
			t.Fatalf("событие: %+v", rec.ev)
		}
	}
}
