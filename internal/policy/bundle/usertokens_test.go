package bundle_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
)

// Разделы user_token_keys и user_tokens пакета (задача 4.21 этапа 4).

const tokIssuer = "https://idp.example.test/realms/aisec"

func userTokensContent(t *testing.T) *bundle.Content {
	t.Helper()
	c := bundletest.New(t).Content(t)
	c.Applications[0].Aliases = map[string]string{"smart": "gpt-4o"}
	c.UserTokenKeys = []bundle.IssuerKeys{{Issuer: tokIssuer, JWKS: json.RawMessage(`{"keys":[]}`)}}
	c.UserTokens = []bundle.UserToken{{App: "crm", Mode: bundle.UserTokenRequired, Issuer: tokIssuer, Audience: "aisec-gateway",
		GroupsClaim: "groups", Leeway: 60, ModelGroups: map[string][]string{"gpt-4o": {"analysts"}, "smart": {"Аналитики"}}}}
	return c
}

func TestUserTokensSectionValidate(t *testing.T) {
	if err := userTokensContent(t).Validate(); err != nil {
		t.Fatalf("верный раздел: %v", err)
	}
	// Без проверки JWT — без разделов в JSON (пакет прежней версии).
	raw, err := bundletest.New(t).Content(t).Marshal()
	if err != nil || strings.Contains(string(raw), "user_token") {
		t.Fatalf("раздел в пакете без JWT: %s %v", raw, err)
	}
	for name, mod := range map[string]func(c *bundle.Content){
		"чужое приложение":    func(c *bundle.Content) { c.UserTokens[0].App = "other" },
		"повтор приложения":   func(c *bundle.Content) { c.UserTokens = append(c.UserTokens, c.UserTokens[0]) },
		"режим off":           func(c *bundle.Content) { c.UserTokens[0].Mode = "off" },
		"издатель http":       func(c *bundle.Content) { c.UserTokens[0].Issuer = "http://idp.example.test" },
		"издатель с запросом": func(c *bundle.Content) { c.UserTokens[0].Issuer = tokIssuer + "?a=1" },
		"пустая аудитория":    func(c *bundle.Content) { c.UserTokens[0].Audience = "" },
		"аудитория с пробелом": func(c *bundle.Content) {
			c.UserTokens[0].Audience = "a b"
		},
		"утверждение с пробелом": func(c *bundle.Content) { c.UserTokens[0].GroupsClaim = "my groups" },
		"допуск больше предела":  func(c *bundle.Content) { c.UserTokens[0].Leeway = bundle.MaxUserTokenLeeway + 1 },
		"отрицательный допуск":   func(c *bundle.Content) { c.UserTokens[0].Leeway = -1 },
		"чужая модель":           func(c *bundle.Content) { c.UserTokens[0].ModelGroups["gpt-5"] = []string{"a"} },
		"модель без групп":       func(c *bundle.Content) { c.UserTokens[0].ModelGroups["gpt-4o"] = nil },
		"группа с управляющим":   func(c *bundle.Content) { c.UserTokens[0].ModelGroups["gpt-4o"] = []string{"a\nb"} },
		"длинная группа": func(c *bundle.Content) {
			c.UserTokens[0].ModelGroups["gpt-4o"] = []string{strings.Repeat("г", bundle.MaxGroupLen)}
		},
		"повтор издателя": func(c *bundle.Content) { c.UserTokenKeys = append(c.UserTokenKeys, c.UserTokenKeys[0]) },
		"JWKS не объект":  func(c *bundle.Content) { c.UserTokenKeys[0].JWKS = json.RawMessage(`[1]`) },
		"JWKS больше предела": func(c *bundle.Content) {
			c.UserTokenKeys[0].JWKS = json.RawMessage(`{"k":"` + strings.Repeat("a", bundle.MaxJWKSBytes) + `"}`)
		},
		"слишком много издателей": func(c *bundle.Content) {
			for i := range bundle.MaxUserTokenIssuers {
				c.UserTokenKeys = append(c.UserTokenKeys, bundle.IssuerKeys{Issuer: tokIssuer + "/" + strings.Repeat("x", i+1),
					JWKS: json.RawMessage(`{}`)})
			}
		},
	} {
		c := userTokensContent(t)
		mod(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: раздел принят", name)
		}
	}
}
