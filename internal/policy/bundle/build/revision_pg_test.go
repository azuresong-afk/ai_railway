package build_test

import (
	"context"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

// TestPGConfigRevisionRebuild — задача 3.34 (Н26) на живой БД: счётчик
// изменений растёт в транзакции изменения приложения, ключа, провайдера,
// политики и настроек установки (триггеры миграции 0030); опросы без
// изменений — одна выборка данных, изменение любого объекта — ровно одна
// новая.
func TestPGConfigRevisionRebuild(t *testing.T) {
	ctx := pgCtx(t)
	_, owner, app := migrated(t)
	fx := bundletest.New(t)
	org := audit.DefaultOrgID
	if _, err := owner.Exec(ctx, `INSERT INTO users (id, org_id, login, display_name, role, status, password_hash,
		password_changed_at, must_change_password, created_at, created_by)
		VALUES ($1, $2, 'owner', 'Владелец', 'app_owner', 'active', 'x', now(), false, now(), 'test')`, owner1, org); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO install_settings (org_id, timezone, retention_mode, updated_at)
		VALUES ($1, 'Europe/Moscow', 'masked', now())`, org); err != nil {
		t.Fatal(err)
	}
	l, err := audit.New(app, fx.Provider)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := detect.NewRegistry(builtin.All()...)
	if err != nil {
		t.Fatal(err)
	}
	pst, err := versions.NewPGStore(app, l)
	if err != nil {
		t.Fatal(err)
	}
	pols, err := versions.New(versions.Options{Store: pst, Provider: fx.Provider, Catalog: reg})
	if err != nil {
		t.Fatal(err)
	}
	ast, err := apps.NewPGStore(app, l)
	if err != nil {
		t.Fatal(err)
	}
	as, err := apps.New(apps.Options{Store: ast, Provider: fx.Provider, Policies: pols,
		OwnerCheck: func(context.Context, string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	st, err := build.NewPGStore(app, l)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := build.New(build.Options{Apps: as, Policies: pols, Store: st, Audit: l, Sealer: fx.Sealer, Provider: fx.Provider,
		Revision: func(ctx context.Context) (int64, error) { return st.Revision(ctx, org) }})
	if err != nil {
		t.Fatal(err)
	}
	by := apps.By{Actor: audit.Actor{Type: audit.ActorUser, ID: owner1, Name: "admin"}, Policy: true,
		Confirm: func(context.Context) error { return nil }}
	pby := versions.By{Actor: by.Actor, Confirm: by.Confirm}
	ca, err := aisecCrypto.NewCA("AISec test provider CA", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	prov, err := as.CreateProvider(ctx, by, apps.ProviderInput{Slug: "llm", Name: "LLM", Type: "openai",
		BaseURL: "https://llm.example/v1", CAPEM: string(ca.CertPEM())})
	if err != nil {
		t.Fatal(err)
	}
	a, err := as.CreateApplication(ctx, by, apps.AppInput{Slug: "crm", Name: "CRM", Env: "prod", OwnerID: owner1,
		ProviderID: prov.ID, Models: []string{"gpt-4o"}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rev := func() int64 {
		t.Helper()
		n, err := st.Revision(ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	poll := func(what string, want int64) {
		t.Helper()
		for range 5 {
			if _, err := svc.Current(ctx); err != nil {
				t.Fatalf("%s: %v", what, err)
			}
		}
		if got := svc.Builds(); got != want {
			t.Fatalf("%s: выборок %d, ожидалось %d", what, got, want)
		}
	}
	poll("первые опросы", 1)

	builds := int64(1)
	changes := []struct {
		name string
		fn   func() error
	}{
		{"приложение", func() error {
			_, err := as.UpdateApplication(ctx, by, a.ID, apps.AppInput{Name: "CRM 2", Env: "prod", OwnerID: owner1,
				ProviderID: prov.ID, Models: []string{"gpt-4o"}})
			return err
		}},
		{"ключ", func() error { _, _, err := as.IssueKey(ctx, by, a.ID, "", apps.KeyInput{Name: "k1"}); return err }},
		{"провайдер", func() error {
			_, err := as.UpdateProvider(ctx, by, prov.ID, apps.ProviderInput{Name: "LLM 2", Type: "openai",
				BaseURL: "https://llm.example/v1", CAPEM: string(ca.CertPEM()), ConnectTimeout: 5})
			return err
		}},
		{"политика", func() error {
			spec, _ := policy.Template(policy.TemplateBase)
			spec.ID, spec.Name = "corp", "Корпоративная"
			_, err := pols.Create(ctx, pby, spec, versions.SourceAPI, "", versions.ConsoleDefaults)
			return err
		}},
		{"словарь", func() error {
			_, err := as.SetProtection(ctx, by, a.ID, apps.ProtectionInput{
				Lists: &[]apps.List{{ID: "projects", Category: "codename", Words: []string{"проект зенит"}}}})
			return err
		}},
		{"настройки установки", func() error {
			_, err := owner.Exec(ctx, `UPDATE install_settings SET timezone = 'UTC' WHERE org_id = $1`, org)
			return err
		}},
	}
	for _, c := range changes {
		before := rev()
		if err := c.fn(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if after := rev(); after <= before {
			t.Fatalf("%s: счётчик %d → %d", c.name, before, after)
		}
		builds++
		poll(c.name, builds)
	}

	// Изменение без различий счётчик не трогает.
	before := rev()
	if _, err := owner.Exec(ctx, `UPDATE applications SET name = name WHERE org_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	if rev() != before {
		t.Fatal("UPDATE без различий увеличил счётчик")
	}
	poll("без различий", builds)
}

const owner1 = "01900000-0000-7000-8000-00000000a0b1"
