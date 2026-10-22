package apps

import (
	"errors"
	"math"
	"math/bits"
	"strconv"
	"strings"
)

// Денежные суммы в API — десятичные строки в рублях («1250.50»), внутри —
// целые числа без плавающей точки (задача 3.18): цена — в 0,0001 ₽ за
// 1 000 токенов, бюджет — в копейках, расход — в 1e-7 ₽ (bundle.Cost).

// Пределы и точность сумм.
const (
	// PriceDigits — знаков после запятой в цене за 1 000 токенов.
	PriceDigits = 4
	// BudgetDigits — знаков после запятой в бюджете (копейки).
	BudgetDigits = 2
	// MaxPriceUnits — цена до 1 000 000 ₽ за 1 000 токенов.
	MaxPriceUnits = 10_000_000_000
	// MaxBudgetKopecks — бюджет до 1 000 000 000 ₽ в месяц.
	MaxBudgetKopecks = 100_000_000_000
	// maxMoneyString — длина строки суммы.
	maxMoneyString = 32
)

var errMoney = errors.New("неверная сумма")

// ParseMoney разбирает десятичную строку рублей «целая[.дробная]» с не
// более чем digits знаками после точки и возвращает сумму в единицах
// 10^-digits рубля, не больше limit. Знак, пробелы, экспонента, запятая и
// пустая целая часть не принимаются.
func ParseMoney(s string, digits int, limit int64) (int64, error) {
	if s == "" || len(s) > maxMoneyString || digits < 0 || digits > 9 {
		return 0, errMoney
	}
	whole, frac, dot := strings.Cut(s, ".")
	if whole == "" || dot && (frac == "" || len(frac) > digits) {
		return 0, errMoney
	}
	for _, part := range []string{whole, frac} {
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return 0, errMoney
			}
		}
	}
	w, err := strconv.ParseUint(whole, 10, 64)
	if err != nil {
		return 0, errMoney
	}
	scale := uint64(1)
	for range digits {
		scale *= 10
	}
	hi, lo := bits.Mul64(w, scale)
	if hi != 0 || lo > math.MaxInt64 {
		return 0, errMoney
	}
	v := int64(lo)
	if frac != "" {
		f, err := strconv.ParseInt(frac+strings.Repeat("0", digits-len(frac)), 10, 64)
		if err != nil || v > math.MaxInt64-f {
			return 0, errMoney
		}
		v += f
	}
	if v > limit {
		return 0, errMoney
	}
	return v, nil
}

// FormatMoney — сумма v в единицах 10^-digits рубля десятичной строкой
// с digits знаками после точки; отрицательные суммы не выводятся (0).
func FormatMoney(v int64, digits int) string {
	v = max(v, 0)
	s := strconv.FormatInt(v, 10)
	if digits <= 0 {
		return s
	}
	if len(s) <= digits {
		s = strings.Repeat("0", digits-len(s)+1) + s
	}
	return s[:len(s)-digits] + "." + s[len(s)-digits:]
}

// FormatCost — расход в 1e-7 ₽ рублями с копейками, округление вверх до
// копейки: расход не занижается.
func FormatCost(cost int64) string {
	const perKopeck = 100_000
	cost = max(cost, 0)
	k := cost / perKopeck
	if cost%perKopeck != 0 {
		k++
	}
	return FormatMoney(k, BudgetDigits)
}

// Percent — доля расхода cost (1e-7 ₽) от бюджета limitKopecks в целых
// процентах, округление вниз; ровно бюджет — 100. Без бюджета — 0.
func Percent(cost, limitKopecks int64) int64 {
	if limitKopecks <= 0 || cost <= 0 {
		return 0
	}
	// cost × 100 / (limit × 100 000) = cost / (limit × 1000) без переполнения.
	hi, lo := bits.Mul64(uint64(limitKopecks), 1000)
	if hi != 0 {
		return 0
	}
	p := uint64(cost) / lo
	if p > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(p)
}
