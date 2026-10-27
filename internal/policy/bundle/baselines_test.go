package bundle_test

import (
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Раздел prompt_baselines пакета (задача 4.14 этапа 4).

func baselinesContent(t *testing.T, bs []bundle.PromptBaseline) *bundle.Content {
	t.Helper()
	c := budgetsContent(t, nil)
	c.PromptBaselines = bs
	return c
}

func TestPromptBaselinesSectionValidate(t *testing.T) {
	good := func() []bundle.PromptBaseline {
		return []bundle.PromptBaseline{{App: "crm", Hash: strings.Repeat("a", 64), Mode: bundle.PromptModeBlock}}
	}
	if err := baselinesContent(t, good()).Validate(); err != nil {
		t.Fatalf("верный раздел: %v", err)
	}
	// Пакет без эталонов — без раздела в JSON (пакет прежней версии).
	raw, err := baselinesContent(t, nil).Marshal()
	if err != nil || strings.Contains(string(raw), "prompt_baselines") {
		t.Fatalf("раздел в пакете без эталонов: %s %v", raw, err)
	}
	for name, mod := range map[string]func(bs []bundle.PromptBaseline) []bundle.PromptBaseline{
		"чужое приложение": func(bs []bundle.PromptBaseline) []bundle.PromptBaseline { bs[0].App = "other"; return bs },
		"повтор":           func(bs []bundle.PromptBaseline) []bundle.PromptBaseline { return append(bs, bs[0]) },
		"короткий хеш":     func(bs []bundle.PromptBaseline) []bundle.PromptBaseline { bs[0].Hash = bs[0].Hash[:63]; return bs },
		"хеш не hex": func(bs []bundle.PromptBaseline) []bundle.PromptBaseline {
			bs[0].Hash = strings.Repeat("g", 64)
			return bs
		},
		"режим off":    func(bs []bundle.PromptBaseline) []bundle.PromptBaseline { bs[0].Mode = "off"; return bs },
		"пустой режим": func(bs []bundle.PromptBaseline) []bundle.PromptBaseline { bs[0].Mode = ""; return bs },
		"слишком много": func([]bundle.PromptBaseline) []bundle.PromptBaseline {
			return make([]bundle.PromptBaseline, bundle.MaxApplications+1)
		},
	} {
		if err := baselinesContent(t, mod(good())).Validate(); err == nil {
			t.Errorf("%s: раздел принят", name)
		}
	}
}
