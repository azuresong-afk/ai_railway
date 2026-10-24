package apps_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

// Цены, бюджеты и счётчики расхода на живой БД (задача 3.18).
func TestPGBudgetsAndUsage(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	p, a := e.fixture(t)
	revision := func() int64 {
		t.Helper()
		var r int64
		if err := e.owner.QueryRow(ctx, "SELECT coalesce(max(revision), 0) FROM config_revisions").Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	rev0 := revision()
	pr, err := e.svc.CreatePrice(ctx, e.by, apps.PriceInput{ProviderID: p.ID, Model: "gpt-4o-mini", Input: "0.15", Output: "0.6"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreatePrice(ctx, e.by, apps.PriceInput{ProviderID: p.ID, Model: "gpt-4o-mini", Input: "1", Output: "1"}); !errors.Is(err, apps.ErrPriceExists) {
		t.Fatalf("повтор цены: %v", err)
	}
	// Не-UUID провайдера — ошибка поля, а не ошибка СУБД (500).
	if _, err := e.svc.CreatePrice(ctx, e.by, apps.PriceInput{ProviderID: "not-a-uuid", Model: "m", Input: "1", Output: "1"}); err == nil ||
		!strings.Contains(err.Error(), "provider_id") {
		t.Fatalf("не-UUID провайдера: %v", err)
	}
	if _, err := e.svc.UpdatePrice(ctx, e.by, pr.ID, apps.PriceInput{Input: "0.2", Output: "0.8"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetBudget(ctx, e.by, a.ID, apps.BudgetInput{Mode: apps.BudgetHard, Limit: "10"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetBudget(ctx, e.by, a.ID, apps.BudgetInput{Mode: apps.BudgetHard, Limit: "20"}); err != nil {
		t.Fatal(err)
	}
	// Изменения цен и бюджетов меняют ревизию: пакет пересобирается (3.34).
	if r := revision(); r < rev0+4 {
		t.Fatalf("ревизия: %d → %d", rev0, r)
	}
	sec, err := e.svc.BudgetSection(ctx)
	if err != nil || len(sec.Prices) != 1 || sec.Prices[0].Input != 2_000 || len(sec.Hard) != 1 || sec.Hard[0].Limit != 2_000 {
		t.Fatalf("раздел пакета: %+v %v", sec, err)
	}

	month := "2026-10"
	e.clock.t = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	gw1, gw2 := "01900000-0000-7000-8000-00000000f001", "01900000-0000-7000-8000-00000000f002"
	s1 := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	s2 := s1.Add(48 * time.Hour)
	rep := func(cost, req int64, months ...string) gwregistry.BudgetReport {
		var r gwregistry.BudgetReport
		for _, m := range months {
			r.Months = append(r.Months, gwregistry.BudgetMonth{Month: m, Apps: []gwregistry.BudgetUsage{
				{App: "helpdesk", Cost: cost, PricedTokens: req * 10, Requests: req, UnpricedTokens: 7, UnpricedRequests: 1},
				{App: "gone", Cost: 5, Requests: 1}}})
		}
		return r
	}
	if _, err := e.svc.SyncBudget(ctx, gw1, s1, rep(700_000_000, 3, "2026-09", month)); err != nil {
		t.Fatal(err)
	}
	// Запоздалый меньший отчёт того же процесса ничего не уменьшает.
	if _, err := e.svc.SyncBudget(ctx, gw1, s1, rep(100, 1, month)); err != nil {
		t.Fatal(err)
	}
	// Новый процесс gw1 и второй шлюз видят расход остальных.
	st, err := e.svc.SyncBudget(ctx, gw1, s2, rep(300_000_000, 1, month))
	if err != nil || st.Month != month || st.Others["helpdesk"] != 700_000_000 {
		t.Fatalf("новый процесс: %+v %v", st, err)
	}
	if _, ok := st.Others["gone"]; ok {
		t.Fatal("в ответе приложение без жёсткого бюджета")
	}
	st, err = e.svc.SyncBudget(ctx, gw2, s1, gwregistry.BudgetReport{Months: []gwregistry.BudgetMonth{{Month: month}}})
	if err != nil || st.Others["helpdesk"] != 1_000_000_000 {
		t.Fatalf("второй шлюз: %+v %v", st, err)
	}
	bs, err := e.svc.BudgetStatus(ctx, a.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	// 1e9 единиц = 100 ₽ при бюджете 20 ₽.
	if bs.Month != month || bs.Cost != 1_000_000_000 || bs.Requests != 4 || bs.PricedTokens != 40 || bs.UnpricedRequests != 2 ||
		bs.UnpricedTokens != 14 || bs.Percent != 500 || !bs.Exhausted {
		t.Fatalf("состояние: %+v", bs)
	}
	if bs, err := e.svc.BudgetStatus(ctx, a.ID, "2026-09"); err != nil || bs.Cost != 700_000_000 {
		t.Fatalf("сентябрь: %+v %v", bs, err)
	}
	list, _, err := e.svc.BudgetStatuses(ctx, "")
	if err != nil || len(list) != 1 || list[0].App.ID != a.ID {
		t.Fatalf("список: %+v %v", list, err)
	}
	if _, err := e.svc.DeleteBudget(ctx, e.by, a.ID); err != nil {
		t.Fatal(err)
	}
	// Без бюджета приложение с расходом остаётся в списке.
	if list, _, err := e.svc.BudgetStatuses(ctx, ""); err != nil || len(list) != 1 || list[0].Budget != nil {
		t.Fatalf("список без бюджета: %+v %v", list, err)
	}
	if _, err := e.svc.DeletePrice(ctx, e.by, pr.ID); err != nil {
		t.Fatal(err)
	}
	acts := e.actions(t)
	for _, act := range []string{"model_price.create", "model_price.update", "model_price.delete", "budget.set", "budget.delete"} {
		if acts[act] == 0 {
			t.Errorf("нет записи %s в аудите", act)
		}
	}
	if acts["budget.set"] != 2 {
		t.Errorf("budget.set: %d", acts["budget.set"])
	}
}
