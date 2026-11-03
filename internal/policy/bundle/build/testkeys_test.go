package build_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
)

// Ключи запусков тестирования устойчивости (задача 5.32, ADR-0031,
// раздел 2): в пакет — у своего приложения с признаком test рядом с
// обычными ключами; ключ чужого (неизвестного) приложения не выводится;
// ошибка источника — пакет не собирается.
func TestBuildTestKeys(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	exp := e.now.Add(31 * time.Minute).UTC()
	tk := bundle.Key{Prefix: "aisec_tst00001", SHA256: strings.Repeat("a", 64), ExpiresAt: exp}
	var fail error
	svc, err := build.New(build.Options{Apps: e.apps, Policies: e.policies, Store: build.NewMemory(), Audit: e.audit,
		Sealer: e.fx.Sealer, Provider: e.fx.Provider, Clock: e.clock,
		TestKeys: func(context.Context, time.Time) (map[string][]bundle.Key, error) {
			return map[string][]bundle.Key{e.app.ID: {tk}, "01900000-0000-7000-8000-00000000ffff": {tk}}, fail
		}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := bundle.ParseContent(r.Content)
	if err != nil {
		t.Fatal(err)
	}
	apps := c.Applications
	if len(apps) != 1 {
		t.Fatalf("приложения: %+v", apps)
	}
	var tests, plain int
	for _, k := range apps[0].Keys {
		switch {
		case k.Prefix == tk.Prefix && k.Test && k.ExpiresAt.Equal(exp):
			tests++
		case !k.Test:
			plain++
		default:
			t.Fatalf("ключ: %+v", k)
		}
	}
	if tests != 1 || plain != 1 {
		t.Fatalf("ключи приложения: %+v", apps[0].Keys)
	}
	recs, err := c.KeyRecords()
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		if rec.Test != (rec.Prefix == tk.Prefix) {
			t.Fatalf("запись ключа: %+v", rec)
		}
	}
	fail = errors.New("БД недоступна")
	broken, err := build.New(build.Options{Apps: e.apps, Policies: e.policies, Store: build.NewMemory(), Audit: e.audit,
		Sealer: e.fx.Sealer, Provider: e.fx.Provider, Clock: e.clock,
		TestKeys: func(context.Context, time.Time) (map[string][]bundle.Key, error) { return nil, fail }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.Current(ctx); err == nil {
		t.Fatal("ошибка ключей запусков не остановила сборку")
	}
}
