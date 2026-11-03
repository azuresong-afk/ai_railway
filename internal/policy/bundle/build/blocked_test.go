package build_test

import (
	"context"
	"errors"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
)

// Запрещённые модели в пакете (задача 5.22 этапа 5): в раздел входят
// только модели провайдеров пакета с допустимым именем, без повторов, по
// порядку; приложение теряет запрещённую модель; ошибка реестра — пакет
// не собирается.
func TestBuildBlockedModels(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	prov := e.provider.Slug
	var list []bundle.BlockedModel
	var fail error
	svc, err := build.New(build.Options{Apps: e.apps, Policies: e.policies, Store: build.NewMemory(), Audit: e.audit,
		Sealer: e.fx.Sealer, Provider: e.fx.Provider, Clock: e.clock,
		BlockedModels: func(context.Context) ([]bundle.BlockedModel, error) { return list, fail }})
	if err != nil {
		t.Fatal(err)
	}
	list = []bundle.BlockedModel{{Provider: prov, Model: "gpt-4o"}, {Provider: "ghost", Model: "x"},
		{Provider: prov, Model: "bad name"}, {Provider: prov, Model: "gpt-4o"}, {Provider: prov, Model: "a-model"}}
	r, err := svc.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := bundle.ParseContent(r.Content)
	if err != nil {
		t.Fatal(err)
	}
	want := []bundle.BlockedModel{{Provider: prov, Model: "a-model"}, {Provider: prov, Model: "gpt-4o"}}
	if len(c.BlockedModels) != 2 || c.BlockedModels[0] != want[0] || c.BlockedModels[1] != want[1] {
		t.Fatalf("раздел: %+v", c.BlockedModels)
	}
	if apps := c.GatewayApplications(); len(apps) != 1 || len(apps[0].Models) != 0 {
		t.Fatalf("приложение с запрещённой моделью: %+v", apps)
	}
	fail = errors.New("реестр недоступен")
	broken, err := build.New(build.Options{Apps: e.apps, Policies: e.policies, Store: build.NewMemory(), Audit: e.audit,
		Sealer: e.fx.Sealer, Provider: e.fx.Provider, Clock: e.clock,
		BlockedModels: func(context.Context) ([]bundle.BlockedModel, error) { return list, fail }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.Current(ctx); err == nil {
		t.Fatal("ошибка реестра не остановила сборку")
	}
}
