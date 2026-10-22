package bundle_test

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
)

// Раздел budgets пакета (задача 3.18).

func budgetsContent(t *testing.T, b *bundle.Budgets) *bundle.Content {
	t.Helper()
	c := bundletest.New(t).Content(t)
	c.Budgets = b
	return c
}

func goodBudgets() *bundle.Budgets {
	return &bundle.Budgets{Timezone: "Europe/Moscow",
		Prices: []bundle.ModelPrice{{Provider: "llm", Model: "gpt-4o", Input: 1_500, Output: 6_000}},
		Hard:   []bundle.HardBudget{{App: "crm", Limit: 1_000_000_000}}}
}

func TestBudgetsSectionValidate(t *testing.T) {
	if err := budgetsContent(t, goodBudgets()).Validate(); err != nil {
		t.Fatalf("верный раздел: %v", err)
	}
	if err := budgetsContent(t, nil).Validate(); err != nil {
		t.Fatalf("без раздела: %v", err)
	}
	// Пакет прежней версии разбирается: раздела нет в JSON.
	raw, err := budgetsContent(t, nil).Marshal()
	if err != nil || strings.Contains(string(raw), "budgets") {
		t.Fatalf("раздел в пакете без бюджетов: %s %v", raw, err)
	}
	for name, mod := range map[string]func(b *bundle.Budgets){
		"пустой пояс":            func(b *bundle.Budgets) { b.Timezone = "" },
		"Local":                  func(b *bundle.Budgets) { b.Timezone = "Local" },
		"неизвестный пояс":       func(b *bundle.Budgets) { b.Timezone = "Mars/Olympus" },
		"чужой провайдер":        func(b *bundle.Budgets) { b.Prices[0].Provider = "other" },
		"пустая модель":          func(b *bundle.Budgets) { b.Prices[0].Model = "" },
		"управляющий символ":     func(b *bundle.Budgets) { b.Prices[0].Model = "a\tb" },
		"длинная модель":         func(b *bundle.Budgets) { b.Prices[0].Model = strings.Repeat("m", 129) },
		"повтор цены":            func(b *bundle.Budgets) { b.Prices = append(b.Prices, b.Prices[0]) },
		"отрицательная цена":     func(b *bundle.Budgets) { b.Prices[0].Input = -1 },
		"цена сверх предела":     func(b *bundle.Budgets) { b.Prices[0].Output = bundle.MaxPrice + 1 },
		"чужое приложение":       func(b *bundle.Budgets) { b.Hard[0].App = "other" },
		"повтор бюджета":         func(b *bundle.Budgets) { b.Hard = append(b.Hard, b.Hard[0]) },
		"нулевой бюджет":         func(b *bundle.Budgets) { b.Hard[0].Limit = 0 },
		"бюджет сверх предела":   func(b *bundle.Budgets) { b.Hard[0].Limit = bundle.MaxBudget + 1 },
		"слишком много цен":      func(b *bundle.Budgets) { b.Prices = make([]bundle.ModelPrice, bundle.MaxPrices+1) },
		"слишком много бюджетов": func(b *bundle.Budgets) { b.Hard = make([]bundle.HardBudget, bundle.MaxApplications+1) },
	} {
		b := goodBudgets()
		mod(b)
		if err := budgetsContent(t, b).Validate(); err == nil {
			t.Errorf("%s: раздел принят", name)
		}
	}
}

func TestBudgetMoney(t *testing.T) {
	p := bundle.ModelPrice{Input: 1_500, Output: 6_000}
	// 1 000 токенов входа по 0,15 ₽ и 500 выхода по 0,60 ₽ — 0,45 ₽.
	if got := bundle.Cost(p, 1_000, 500); got != 45*bundle.CostUnitsPerRuble/100 {
		t.Fatalf("расход: %d", got)
	}
	if bundle.Cost(p, -5, -5) != 0 {
		t.Fatal("отрицательные токены")
	}
	big := bundle.ModelPrice{Input: bundle.MaxPrice, Output: bundle.MaxPrice}
	if bundle.Cost(big, math.MaxInt64, 1) != math.MaxInt64 || bundle.AddCost(math.MaxInt64, 1) != math.MaxInt64 {
		t.Fatal("переполнение не насыщается")
	}
	if bundle.KopecksToCost(1) != bundle.CostUnitsPerKopeck || bundle.KopecksToCost(math.MaxInt64) != math.MaxInt64 {
		t.Fatal("копейки")
	}
}

func TestBudgetMonths(t *testing.T) {
	msk, err := bundle.LoadLocation("Europe/Moscow")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 12, 31, 20, 59, 59, 0, time.UTC) // 23:59:59 по Москве
	if bundle.Month(at, msk) != "2026-12" || bundle.Month(at.Add(time.Second), msk) != "2027-01" || bundle.Month(at, time.UTC) != "2026-12" {
		t.Fatal("месяц в часовом поясе")
	}
	if next := bundle.NextMonth(at, msk); !next.Equal(at.Add(time.Second)) {
		t.Fatalf("начало следующего месяца: %v", next)
	}
	for s, ok := range map[string]bool{"2026-10": true, "2026-13": false, "2026-1": false, "26-10-": false, "2026/10": false, "": false} {
		if bundle.ValidMonth(s) != ok {
			t.Errorf("ValidMonth(%q)", s)
		}
	}
}
