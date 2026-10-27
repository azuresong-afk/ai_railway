package apps_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/apps"
)

// Пользователь приложения по JWT и доступ к моделям по группам (задача
// 4.21 этапа 4): проверка ввода, ослабление с повторной проверкой (DM-40).

const issuer = "https://idp.example.test/realms/aisec"

func userInput(mode string, mg map[string][]string) apps.UserAccessInput {
	return apps.UserAccessInput{Mode: mode, Issuer: issuer, Audience: "aisec-gateway", ModelGroups: mg}
}

func reasons(t *testing.T, e *env) []any {
	t.Helper()
	d := details(t, e.last(t, "application.user_access_set"))
	r, _ := d["weakening_reasons"].([]any)
	if (len(r) > 0) != (d["weakening"] == true) {
		t.Fatalf("weakening и причины расходятся: %v", d)
	}
	return r
}

func TestUserAccessLifecycle(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	a := e.app(t, "sales", e.provider(t, "llm").ID, ownerA)
	u, err := e.svc.UserAccess(ctx, a.ID)
	if err != nil || u.Configured || u.Mode != apps.UserTokenOff || u.GroupsClaim != "groups" || u.Leeway != 60 {
		t.Fatalf("по умолчанию: %+v %v", u, err)
	}
	noConfirm := e.by
	noConfirm.Confirm = nil
	// Включение и ужесточение — без повторной проверки.
	u, err = e.svc.SetUserAccess(ctx, noConfirm, a.ID, userInput(apps.UserTokenRequired,
		map[string][]string{"gpt-4o-mini": {" b ", "a", "a"}, "default": {"a"}}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(u.ModelGroups["gpt-4o-mini"], []string{"a", "b"}) || !u.Configured {
		t.Fatalf("группы: %+v", u.ModelGroups)
	}
	if r := reasons(t, e); len(r) != 0 {
		t.Fatalf("ужесточение — ослабление: %v", r)
	}
	n := len(e.mem.Records())
	if _, err := e.svc.SetUserAccess(ctx, noConfirm, a.ID, userInput(apps.UserTokenRequired,
		map[string][]string{"gpt-4o-mini": {"b", "a"}, "default": {"a"}})); err != nil || len(e.mem.Records()) != n {
		t.Fatalf("повтор без изменений: %v, записей %d → %d", err, n, len(e.mem.Records()))
	}
	// Ослабления: каждое без повторной проверки — отказ, с ней — причина.
	leeway := 120
	for _, c := range []struct {
		in     apps.UserAccessInput
		reason string
	}{
		{userInput(apps.UserTokenRequired, map[string][]string{"gpt-4o-mini": {"a", "b", "c"}, "default": {"a"}}), "model_groups"},
		{userInput(apps.UserTokenRequired, map[string][]string{"gpt-4o-mini": {"a"}}), "model_groups"},
		{apps.UserAccessInput{Mode: apps.UserTokenRequired, Issuer: issuer, Audience: "aisec-gateway", Leeway: &leeway,
			ModelGroups: map[string][]string{"gpt-4o-mini": {"a"}}}, "user_token_leeway"},
		{apps.UserAccessInput{Mode: apps.UserTokenRequired, Issuer: issuer + "2", Audience: "aisec-gateway", Leeway: &leeway,
			ModelGroups: map[string][]string{"gpt-4o-mini": {"a"}}}, "user_token_trust"},
		{apps.UserAccessInput{Mode: apps.UserTokenRequired, Issuer: issuer + "2", Audience: "aisec-gateway", Leeway: &leeway,
			GroupsClaim: "roles", ModelGroups: map[string][]string{"gpt-4o-mini": {"a"}}}, "user_token_groups_claim"},
		{apps.UserAccessInput{Mode: apps.UserTokenOptional, Issuer: issuer + "2", Audience: "aisec-gateway", Leeway: &leeway,
			GroupsClaim: "roles", ModelGroups: map[string][]string{"gpt-4o-mini": {"a"}}}, "user_token_mode"},
		{apps.UserAccessInput{Mode: apps.UserTokenOff}, "user_token_mode"},
	} {
		if _, err := e.svc.SetUserAccess(ctx, noConfirm, a.ID, c.in); !errors.Is(err, apps.ErrConfirmRequired) {
			t.Fatalf("%s без повторной проверки: %v", c.reason, err)
		}
		if _, err := e.svc.SetUserAccess(ctx, e.by, a.ID, c.in); err != nil {
			t.Fatalf("%s: %v", c.reason, err)
		}
		if r := reasons(t, e); !slices.Contains(r, any(c.reason)) {
			t.Fatalf("%s: причины %v", c.reason, r)
		}
	}
	// Группы псевдонима, которого у приложения больше нет, не действуют:
	// их пропажа при следующем сохранении — не ослабление.
	if _, err := e.svc.SetUserAccess(ctx, e.by, a.ID, apps.UserAccessInput{Mode: apps.UserTokenRequired, Issuer: issuer,
		Audience: "aisec-gateway", ModelGroups: map[string][]string{"gpt-4o-mini": {"a"}, "default": {"a"}}}); err != nil {
		t.Fatal(err)
	}
	in := appInput("sales", a.ProviderID, ownerA)
	in.Aliases = nil
	if _, err := e.svc.UpdateApplication(ctx, e.by, a.ID, in); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetUserAccess(ctx, noConfirm, a.ID, apps.UserAccessInput{Mode: apps.UserTokenRequired, Issuer: issuer,
		Audience: "aisec-gateway", ModelGroups: map[string][]string{"gpt-4o-mini": {"a"}}}); err != nil {
		t.Fatalf("без удалённого псевдонима: %v", err)
	}
	if r := reasons(t, e); len(r) != 0 {
		t.Fatalf("удалённый псевдоним — ослабление: %v", r)
	}
	if _, err := e.svc.UserAccess(ctx, "01900000-0000-7000-8000-0000000000ff"); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("чужое приложение: %v", err)
	}
}

// Граничные значения и неверный ввод.
func TestUserAccessValidation(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	a := e.app(t, "sales", e.provider(t, "llm").ID, ownerA)
	big := func(n int) map[string][]string {
		g := make([]string, n)
		for i := range g {
			g[i] = strings.Repeat("g", i%200+1) + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
		}
		return map[string][]string{"gpt-4o-mini": g}
	}
	over, zero := 301, 0
	for name, in := range map[string]apps.UserAccessInput{
		"неизвестный режим":      {Mode: "strict"},
		"без издателя":           {Mode: apps.UserTokenRequired, Audience: "x"},
		"издатель http":          {Mode: apps.UserTokenRequired, Issuer: "http://idp.example.test", Audience: "x"},
		"без аудитории":          {Mode: apps.UserTokenOptional, Issuer: issuer},
		"аудитория с пробелом":   {Mode: apps.UserTokenOptional, Issuer: issuer, Audience: "a b"},
		"утверждение кириллицей": {Mode: apps.UserTokenOptional, Issuer: issuer, Audience: "x", GroupsClaim: "группы"},
		"допуск больше 300":      {Mode: apps.UserTokenOptional, Issuer: issuer, Audience: "x", Leeway: &over},
		"группы без JWT":         {Mode: apps.UserTokenOff, ModelGroups: map[string][]string{"gpt-4o-mini": {"a"}}},
		"чужая модель":           userInput(apps.UserTokenRequired, map[string][]string{"gpt-5": {"a"}}),
		"пустая группа":          userInput(apps.UserTokenRequired, map[string][]string{"gpt-4o-mini": {" "}}),
		"управляющий символ":     userInput(apps.UserTokenRequired, map[string][]string{"gpt-4o-mini": {"a\tb"}}),
		"больше 64 групп":        userInput(apps.UserTokenRequired, big(65)),
	} {
		_, err := e.svc.SetUserAccess(ctx, e.by, a.ID, in)
		var ie *apps.InputError
		if !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Ровно на границе — принимается.
	in := userInput(apps.UserTokenRequired, big(64))
	in.Leeway = &zero
	if _, err := e.svc.SetUserAccess(ctx, e.by, a.ID, in); err != nil {
		t.Fatalf("на границе: %v", err)
	}
}
