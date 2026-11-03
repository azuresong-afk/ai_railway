package bundle_test

import (
	"slices"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Раздел blocked_models пакета (задача 5.22 этапа 5, ADR-0029, дополнение
// 1): запрещённая сканером модель исключается из моделей и псевдонимов
// приложений своего провайдера — шлюз отвечает model_not_allowed.

func TestBlockedModelsSection(t *testing.T) {
	c := budgetsContent(t, nil)
	c.Applications[0].Models = []string{"gpt-4o", "gpt-4o-mini"}
	c.Applications[0].Aliases = map[string]string{"fast": "gpt-4o-mini", "main": "gpt-4o"}
	if err := c.Validate(); err != nil {
		t.Fatalf("без раздела: %v", err)
	}
	c.BlockedModels = []bundle.BlockedModel{{Provider: "llm", Model: "gpt-4o"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("верный раздел: %v", err)
	}
	apps := c.GatewayApplications()
	if !slices.Equal(apps[0].Models, []string{"gpt-4o-mini"}) || len(apps[0].Aliases) != 1 || apps[0].Aliases["fast"] != "gpt-4o-mini" {
		t.Fatalf("приложение: модели %v, псевдонимы %v", apps[0].Models, apps[0].Aliases)
	}
	// Исходное содержимое не меняется.
	if len(c.Applications[0].Models) != 2 || len(c.Applications[0].Aliases) != 2 {
		t.Fatal("GatewayApplications изменил содержимое пакета")
	}
	// Запрет модели другого провайдера приложение не затрагивает.
	c.BlockedModels = []bundle.BlockedModel{{Provider: "llm", Model: "o1"}}
	if apps := c.GatewayApplications(); len(apps[0].Models) != 2 || len(apps[0].Aliases) != 2 {
		t.Fatalf("чужая модель: %+v", apps[0])
	}
	for name, bs := range map[string][]bundle.BlockedModel{
		"нет провайдера": {{Provider: "other", Model: "gpt-4o"}},
		"пустая модель":  {{Provider: "llm", Model: ""}},
		"имя с пробелом": {{Provider: "llm", Model: "gpt 4o"}},
		"повтор":         {{Provider: "llm", Model: "gpt-4o"}, {Provider: "llm", Model: "gpt-4o"}},
		"сверх предела":  make([]bundle.BlockedModel, bundle.MaxBlockedModels+1),
	} {
		c.BlockedModels = bs
		if err := c.Validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}
