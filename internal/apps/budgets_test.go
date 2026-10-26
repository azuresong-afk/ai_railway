package apps_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

// Цены моделей и бюджеты приложений (задача 3.18).

func TestParseMoney(t *testing.T) {
	for _, tc := range []struct {
		in     string
		digits int
		limit  int64
		want   int64
		ok     bool
	}{
		{"0", 4, 100, 0, true},
		{"1", 4, 100_000, 10_000, true},
		{"0.15", 4, 100_000, 1_500, true},
		{"0.0001", 4, 100_000, 1, true},
		{"1000000", 4, apps.MaxPriceUnits, apps.MaxPriceUnits, true},
		{"1000000.0001", 4, apps.MaxPriceUnits, 0, false},
		{"15000.50", 2, apps.MaxBudgetKopecks, 1_500_050, true},
		{"007.5", 2, 10_000, 750, true},
		{"0.12345", 4, 100_000, 0, false},
		{"", 2, 100, 0, false},
		{".5", 2, 100, 0, false},
		{"1.", 2, 100, 0, false},
		{"-1", 2, 100, 0, false},
		{"+1", 2, 100, 0, false},
		{"1,5", 2, 1000, 0, false},
		{"1e3", 2, 1_000_000, 0, false},
		{" 1", 2, 1000, 0, false},
		{"1.2.3", 4, 100_000, 0, false},
		{"١", 2, 1000, 0, false},
		// Переполнение: целая часть × масштаб не помещается в int64.
		{"92233720368547758", 4, math.MaxInt64, 0, false},
		{"9223372036854775807", 0, math.MaxInt64, math.MaxInt64, true},
		{"9223372036854775808", 0, math.MaxInt64, 0, false},
		{strings.Repeat("1", 33), 0, math.MaxInt64, 0, false},
	} {
		got, err := apps.ParseMoney(tc.in, tc.digits, tc.limit)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ParseMoney(%q, %d): %d %v, ожидается %d ok=%v", tc.in, tc.digits, got, err, tc.want, tc.ok)
		}
	}
}

func TestFormatMoneyAndPercent(t *testing.T) {
	for v, want := range map[int64]string{0: "0.00", 5: "0.05", 150: "1.50", 1_500_050: "15000.50", -3: "0.00"} {
		if got := apps.FormatMoney(v, 2); got != want {
			t.Errorf("FormatMoney(%d): %q", v, got)
		}
	}
	if got := apps.FormatMoney(1, 4); got != "0.0001" {
		t.Errorf("цена: %q", got)
	}
	// Расход округляется вверх до копейки: не занижается.
	for cost, want := range map[int64]string{0: "0.00", 1: "0.01", 100_000: "0.01", 100_001: "0.02", 1_000_000_000: "100.00"} {
		if got := apps.FormatCost(cost); got != want {
			t.Errorf("FormatCost(%d): %q, ожидается %q", cost, got, want)
		}
	}
	// Бюджет 100 ₽ = 10 000 копеек = 1e9 единиц расхода.
	for cost, want := range map[int64]int64{0: 0, 799_999_999: 79, 800_000_000: 80, 1_000_000_000: 100, 2_500_000_000: 250, math.MaxInt64: math.MaxInt64 / 10_000_000} {
		if got := apps.Percent(cost, 10_000); got != want {
			t.Errorf("Percent(%d): %d, ожидается %d", cost, got, want)
		}
	}
	if apps.Percent(100, 0) != 0 || apps.Percent(100, math.MaxInt64) != 0 {
		t.Error("без бюджета или с переполнением — 0")
	}
}

// FuzzParseMoney: любая строка — сумма в пределах или ошибка; принятая
// сумма выводится и разбирается обратно в то же значение.
func FuzzParseMoney(f *testing.F) {
	for _, s := range []string{"0", "0.15", "15000.50", "1000000", "1.", ".1", "-1", "1e5", "9223372036854775807", "1,5", "０"} {
		f.Add(s, 4)
	}
	f.Fuzz(func(t *testing.T, s string, digits int) {
		digits = ((digits % 10) + 10) % 10
		v, err := apps.ParseMoney(s, digits, apps.MaxBudgetKopecks)
		if err != nil {
			return
		}
		if v < 0 || v > apps.MaxBudgetKopecks {
			t.Fatalf("%q: %d вне пределов", s, v)
		}
		back, err := apps.ParseMoney(apps.FormatMoney(v, digits), digits, apps.MaxBudgetKopecks)
		if err != nil || back != v {
			t.Fatalf("%q → %d → %q → %d %v", s, v, apps.FormatMoney(v, digits), back, err)
		}
	})
}

func TestPrices(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := e.provider(t, "llm")
	pr, err := e.svc.CreatePrice(ctx, e.by, apps.PriceInput{ProviderID: p.ID, Model: "gpt-4o-mini", Input: "0.15", Output: "0.6"})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Input != 1_500 || pr.Output != 6_000 {
		t.Fatalf("цена: %+v", pr)
	}
	if r := e.last(t, "model_price.create"); r.Details.(map[string]any)["input"] != "0.1500" {
		t.Fatalf("аудит: %+v", r.Details)
	}
	if _, err := e.svc.CreatePrice(ctx, e.by, apps.PriceInput{ProviderID: p.ID, Model: "gpt-4o-mini", Input: "1", Output: "1"}); !errors.Is(err, apps.ErrPriceExists) {
		t.Fatalf("повтор: %v", err)
	}
	if _, err := e.svc.CreatePrice(ctx, e.by, apps.PriceInput{ProviderID: nobody, Model: "m", Input: "1", Output: "1"}); !errors.Is(err, apps.ErrProviderNotFound) {
		t.Fatalf("нет провайдера: %v", err)
	}
	_, err = e.svc.CreatePrice(ctx, e.by, apps.PriceInput{ProviderID: p.ID, Model: "bad\nname", Input: "-1", Output: "0.00001"})
	inputErr(t, err, "model")
	if _, err := e.svc.UpdatePrice(ctx, e.by, pr.ID, apps.PriceInput{Input: "0.2", Output: "0.8"}); err != nil {
		t.Fatal(err)
	}
	r := e.last(t, "model_price.update").Details.(map[string]any)
	if r["before"].(map[string]any)["input"] != "0.1500" || r["after"].(map[string]any)["input"] != "0.2000" || r["relaxed"] != false {
		t.Fatalf("аудит изменения: %+v", r)
	}
	// Снижение цены уменьшает учитываемый расход — relaxed.
	if _, err := e.svc.UpdatePrice(ctx, e.by, pr.ID, apps.PriceInput{Input: "0.2", Output: "0.7999"}); err != nil {
		t.Fatal(err)
	}
	if r := e.last(t, "model_price.update").Details.(map[string]any); r["relaxed"] != true {
		t.Fatalf("снижение цены: %+v", r)
	}
	_, err = e.svc.CreatePrice(ctx, e.by, apps.PriceInput{ProviderID: "not-a-uuid", Model: "m", Input: "1", Output: "1"})
	inputErr(t, err, "provider_id")
	if _, err := e.svc.UpdatePrice(ctx, e.by, nobody, apps.PriceInput{Input: "1", Output: "1"}); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("нет цены: %v", err)
	}
	// Удаление провайдера удаляет его цены.
	if _, err := e.svc.CreatePrice(ctx, e.by, apps.PriceInput{ProviderID: p.ID, Model: "other", Input: "1", Output: "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DeletePrice(ctx, e.by, pr.ID); err != nil || e.count("model_price.delete") != 1 {
		t.Fatalf("удаление: %v", err)
	}
	if r := e.last(t, "model_price.delete").Details.(map[string]any); r["relaxed"] != true {
		t.Fatalf("аудит удаления цены: %+v", r)
	}
	if _, err := e.svc.DeleteProvider(ctx, e.by, p.ID); err != nil {
		t.Fatal(err)
	}
	if ps, err := e.svc.Prices(ctx); err != nil || len(ps) != 0 {
		t.Fatalf("цены удалённого провайдера: %v %v", ps, err)
	}
}

func TestBudgets(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	p := e.provider(t, "llm")
	a := e.app(t, "crm", p.ID, ownerA)
	e.svc.SetTimezone(func(context.Context) (string, error) { return "Europe/Moscow", nil })
	if _, err := e.svc.BudgetStatus(ctx, a.ID, ""); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.SetBudget(ctx, e.by, a.ID, apps.BudgetInput{Mode: "strict", Limit: "0"})
	inputErr(t, err, "mode")
	if _, err := e.svc.SetBudget(ctx, e.by, a.ID, apps.BudgetInput{Mode: apps.BudgetHard, Limit: "100"}); err != nil {
		t.Fatal(err)
	}
	if d := e.last(t, "budget.set").Details.(map[string]any); d["relaxed"] != false || d["before"] != nil {
		t.Fatalf("первый бюджет: %+v", d)
	}
	// Понижение жёсткого — не послабление; повышение, перевод в soft и
	// снятие — послабление (relaxed), но без повторной проверки.
	for _, tc := range []struct {
		in      apps.BudgetInput
		relaxed bool
	}{
		{apps.BudgetInput{Mode: apps.BudgetHard, Limit: "50"}, false},
		{apps.BudgetInput{Mode: apps.BudgetHard, Limit: "50.01"}, true},
		{apps.BudgetInput{Mode: apps.BudgetSoft, Limit: "50.01"}, true},
		{apps.BudgetInput{Mode: apps.BudgetHard, Limit: "10"}, false},
	} {
		if _, err := e.svc.SetBudget(ctx, e.by, a.ID, tc.in); err != nil {
			t.Fatal(err)
		}
		if d := e.last(t, "budget.set").Details.(map[string]any); d["relaxed"] != tc.relaxed {
			t.Fatalf("%+v: relaxed %v", tc.in, d["relaxed"])
		}
	}
	sec, err := e.svc.BudgetSection(ctx)
	if err != nil || sec.Timezone != "Europe/Moscow" || len(sec.Hard) != 1 || sec.Hard[0].Limit != 1_000 || !sec.AnyBudget {
		t.Fatalf("раздел пакета: %+v %v", sec, err)
	}
	// Расход за октябрь по Москве: два процесса одного шлюза и второй шлюз.
	e.clock.t = time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)
	started := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	rep := func(cost int64) gwregistry.BudgetReport {
		return gwregistry.BudgetReport{Months: []gwregistry.BudgetMonth{{Month: "2026-10",
			Apps: []gwregistry.BudgetUsage{{App: "crm", Cost: cost, PricedTokens: 10, Requests: 1, UnpricedRequests: 1, UnpricedTokens: 3}}}}}
	}
	if _, err := e.svc.SyncBudget(ctx, "gw1", started, rep(400_000_000)); err != nil {
		t.Fatal(err)
	}
	// Повтор и запоздалый меньший отчёт расход не меняют (наибольшее).
	if _, err := e.svc.SyncBudget(ctx, "gw1", started, rep(300_000_000)); err != nil {
		t.Fatal(err)
	}
	st, err := e.svc.SyncBudget(ctx, "gw2", started, rep(600_000_000))
	if err != nil || st.Month != "2026-10" || st.Others["crm"] != 400_000_000 {
		t.Fatalf("чужой расход для gw2: %+v %v", st, err)
	}
	if st, err := e.svc.SyncBudget(ctx, "gw1", started.Add(time.Hour), rep(1)); err != nil || st.Others["crm"] != 1_000_000_000 {
		t.Fatalf("новый процесс gw1 видит прежний расход: %+v %v", st, err)
	}
	bs, err := e.svc.BudgetStatus(ctx, a.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if bs.Month != "2026-10" || bs.Cost != 1_000_000_001 || bs.Requests != 3 || bs.UnpricedRequests != 3 || bs.Percent != 1000 || !bs.Exhausted {
		t.Fatalf("состояние: %+v", bs)
	}
	// Через час по UTC в Москве ноябрь: расхода нет.
	e.clock.t = time.Date(2026, 10, 31, 21, 0, 0, 0, time.UTC)
	if bs, err := e.svc.BudgetStatus(ctx, a.ID, ""); err != nil || bs.Month != "2026-11" || bs.Cost != 0 || bs.Exhausted {
		t.Fatalf("ноябрь: %+v %v", bs, err)
	}
	list, month, err := e.svc.BudgetStatuses(ctx, "2026-10")
	if err != nil || month != "2026-10" || len(list) != 1 || list[0].App.Slug != "crm" {
		t.Fatalf("список: %+v %v", list, err)
	}
	if _, _, err := e.svc.BudgetStatuses(ctx, "2026-13"); err == nil {
		t.Fatal("неверный месяц принят")
	}
	if _, err := e.svc.DeleteBudget(ctx, e.by, a.ID); err != nil {
		t.Fatal(err)
	}
	if d := e.last(t, "budget.delete").Details.(map[string]any); d["relaxed"] != true {
		t.Fatalf("снятие жёсткого: %+v", d)
	}
	if _, err := e.svc.DeleteBudget(ctx, e.by, a.ID); !errors.Is(err, apps.ErrNoBudget) {
		t.Fatalf("повторное снятие: %v", err)
	}
	if _, err := e.svc.SetBudget(ctx, e.by, nobody, apps.BudgetInput{Mode: apps.BudgetSoft, Limit: "1"}); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("нет приложения: %v", err)
	}
}

// 3В23 ревью 3.r3: месяц отчёта шлюза сверяется с месяцем сервера в поясе
// установки с допуском в сутки; расходящийся отчёт не сохраняется.
func TestSyncBudgetMonthSkew(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.svc.SetTimezone(func(context.Context) (string, error) { return "Europe/Moscow", nil })
	e.clock.t = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	started := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	rep := func(months ...string) gwregistry.BudgetReport {
		var r gwregistry.BudgetReport
		for _, m := range months {
			r.Months = append(r.Months, gwregistry.BudgetMonth{Month: m, Apps: []gwregistry.BudgetUsage{{App: "crm", Cost: 5, Requests: 1}}})
		}
		return r
	}
	for _, months := range [][]string{{"2026-10", "2026-11"}, {"2026-09"}, {"2027-10"}} {
		if _, err := e.svc.SyncBudget(ctx, "gw1", started, rep(months...)); err == nil || !strings.Contains(err.Error(), "часы шлюза") {
			t.Fatalf("%v: %v", months, err)
		}
	}
	if st, err := e.svc.SyncBudget(ctx, "gw1", started, rep("2026-09", "2026-10")); err != nil || st.Month != "2026-10" {
		t.Fatalf("свой месяц: %+v %v", st, err)
	}
	// 31 октября 23:30 по Москве: ноябрь шлюза — в пределах суток.
	e.clock.t = time.Date(2026, 10, 31, 20, 30, 0, 0, time.UTC)
	if st, err := e.svc.SyncBudget(ctx, "gw2", started, rep("2026-11")); err != nil || st.Month != "2026-11" {
		t.Fatalf("ноябрь в пределах допуска: %+v %v", st, err)
	}
}
