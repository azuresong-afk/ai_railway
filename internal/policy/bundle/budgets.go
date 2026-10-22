package bundle

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/config"
)

// Раздел budgets пакета: цены моделей и жёсткие бюджеты приложений (ТЗ 5.8,
// 4.2; решение Р7 этапа 3, задача 3.18). Деньги — целые числа:
//   - цена — десятитысячные доли рубля (0,0001 ₽) за 1 000 токенов;
//   - расход и бюджет в пакете — десятимиллионные доли рубля (1e-7 ₽):
//     токены × цена дают расход ровно, без округления.
//
// Мягкие бюджеты в пакет не входят: шлюз их не применяет, оповещения
// считает сервер (задача 3.12). Шлюз считает расход всех приложений по
// ценам раздела и отклоняет запросы приложения с жёстким бюджетом, когда
// расход месяца в часовом поясе установки достиг бюджета.

// Пределы раздела budgets.
const (
	// MaxPrices — цен в пакете.
	MaxPrices = 10000
	// MaxModelName — длина имени модели в цене.
	MaxModelName = 128
	// MaxPrice — цена за 1 000 токенов: 1 000 000 ₽ в единицах 0,0001 ₽.
	MaxPrice = 10_000_000_000
	// MaxBudget — месячный бюджет: 1 000 000 000 ₽ в единицах 1e-7 ₽.
	MaxBudget = 10_000_000_000_000_000
	// MaxTimezone — длина имени часового пояса.
	MaxTimezone = 64
)

// Масштабы денежных единиц.
const (
	// PriceUnitsPerRuble — единиц цены в рубле (цена за 1 000 токенов).
	PriceUnitsPerRuble = 10_000
	// CostUnitsPerRuble — единиц расхода в рубле.
	CostUnitsPerRuble = 10_000_000
	// CostUnitsPerKopeck — единиц расхода в копейке.
	CostUnitsPerKopeck = CostUnitsPerRuble / 100
)

// Budgets — раздел budgets пакета.
type Budgets struct {
	// Timezone — часовой пояс установки (install_settings): по нему шлюз
	// определяет месяц расхода.
	Timezone string       `json:"timezone"`
	Prices   []ModelPrice `json:"prices"`
	Hard     []HardBudget `json:"hard"`
}

// ModelPrice — цена модели провайдера за 1 000 токенов, единицы 0,0001 ₽.
type ModelPrice struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Input    int64  `json:"input"`
	Output   int64  `json:"output"`
}

// HardBudget — жёсткий месячный бюджет приложения, единицы 1e-7 ₽.
type HardBudget struct {
	App   string `json:"app"`
	Limit int64  `json:"limit"`
}

// validate проверяет раздел: providers и apps — ID провайдеров и
// действующих приложений пакета.
func (b *Budgets) validate(providers, apps map[string]bool) []error {
	if b == nil {
		return nil
	}
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if _, err := LoadLocation(b.Timezone); err != nil {
		add("budgets.timezone: %v", err)
	}
	if len(b.Prices) > MaxPrices || len(b.Hard) > MaxApplications {
		add("budgets: больше %d цен или %d бюджетов", MaxPrices, MaxApplications)
		return errs
	}
	seen := map[string]bool{}
	for i, p := range b.Prices {
		at := fmt.Sprintf("budgets.prices[%d]", i)
		if !providers[p.Provider] {
			add("%s: провайдер %q не описан в пакете", at, short(p.Provider))
		}
		if !ValidModelName(p.Model) {
			add("%s: model — от 1 до %d печатных символов", at, MaxModelName)
		}
		key := p.Provider + "\x00" + p.Model
		if seen[key] {
			add("%s: повторная цена модели", at)
		}
		seen[key] = true
		if p.Input < 0 || p.Input > MaxPrice || p.Output < 0 || p.Output > MaxPrice {
			add("%s: цена — от 0 до %d", at, int64(MaxPrice))
		}
	}
	hard := map[string]bool{}
	for i, h := range b.Hard {
		at := fmt.Sprintf("budgets.hard[%d]", i)
		if !apps[h.App] || hard[h.App] {
			add("%s: приложение %q не описано в пакете или повторено", at, short(h.App))
		}
		hard[h.App] = true
		if h.Limit < 1 || h.Limit > MaxBudget {
			add("%s: limit — от 1 до %d", at, int64(MaxBudget))
		}
	}
	return errs
}

// ValidModelName — имя модели в цене: 1–128 печатных символов без
// управляющих.
func ValidModelName(s string) bool {
	if s == "" || len(s) > MaxModelName || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// LoadLocation — часовой пояс установки по имени IANA (как в
// install_settings): «Local» и пустое имя не принимаются.
func LoadLocation(name string) (*time.Location, error) {
	if name == "" || len(name) > MaxTimezone || name == "Local" {
		return nil, errors.New("неверное имя часового пояса")
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, errors.New("неизвестный часовой пояс")
	}
	return loc, nil
}

// Month — месяц момента t в часовом поясе loc: «ГГГГ-ММ».
func Month(t time.Time, loc *time.Location) string { return t.In(loc).Format("2006-01") }

// NextMonth — начало следующего месяца после t в часовом поясе loc.
func NextMonth(t time.Time, loc *time.Location) time.Time {
	l := t.In(loc)
	return time.Date(l.Year(), l.Month()+1, 1, 0, 0, 0, 0, loc)
}

// ValidMonth — строка месяца «ГГГГ-ММ».
func ValidMonth(s string) bool {
	if len(s) != 7 || s[4] != '-' {
		return false
	}
	_, err := time.Parse("2006-01", s)
	return err == nil
}

// Cost — расход запроса в единицах 1e-7 ₽: входные токены × цену входа и
// выходные × цену выхода; при переполнении — math.MaxInt64 (сумма не может
// стать отрицательной или маленькой). Отрицательные токены — ноль.
func Cost(p ModelPrice, input, output int64) int64 {
	return AddCost(mulCost(input, p.Input), mulCost(output, p.Output))
}

func mulCost(tokens, price int64) int64 {
	if tokens <= 0 || price <= 0 {
		return 0
	}
	hi, lo := bits.Mul64(uint64(tokens), uint64(price))
	if hi != 0 || lo > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(lo)
}

// AddCost складывает неотрицательные суммы с насыщением на math.MaxInt64.
func AddCost(a, b int64) int64 {
	a, b = max(a, 0), max(b, 0)
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// KopecksToCost переводит копейки в единицы расхода с насыщением.
func KopecksToCost(k int64) int64 { return mulCost(k, CostUnitsPerKopeck) }

// budgetsApps — ID провайдеров и действующих приложений содержимого.
func (c *Content) budgetIDs() (providers, apps map[string]bool) {
	providers, apps = map[string]bool{}, map[string]bool{}
	for _, p := range c.Providers {
		providers[p.ID] = true
	}
	for _, a := range c.Applications {
		if config.ValidID(a.ID) {
			apps[a.ID] = true
		}
	}
	return providers, apps
}
