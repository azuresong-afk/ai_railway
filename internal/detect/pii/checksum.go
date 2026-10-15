package pii

// Контрольные суммы российских идентификаторов. На вход — строки только из
// цифр ASCII нужной длины (проверяет вызывающий).

func digit(b byte) int { return int(b - '0') }

// SNILSChecksum — контрольное число СНИЛС по первым девяти цифрам: сумма
// цифр с весами 9…1; меньше 100 — сама сумма; 100 и 101 — 00; больше —
// остаток от деления на 101 (100 — тоже 00).
func SNILSChecksum(nine string) int {
	s := 0
	for i := 0; i < 9; i++ {
		s += digit(nine[i]) * (9 - i)
	}
	switch {
	case s < 100:
		return s
	case s <= 101:
		return 0
	}
	s %= 101
	if s == 100 {
		return 0
	}
	return s
}

// ValidSNILS — 11 цифр с верным контрольным числом. Номера не больше
// 001-001-998 контрольным числом не проверяются и не считаются СНИЛС.
func ValidSNILS(d string) bool {
	if len(d) != 11 || d[:9] <= "001001998" {
		return false
	}
	return SNILSChecksum(d[:9]) == digit(d[9])*10+digit(d[10])
}

func weighted(d string, w []int) int {
	s := 0
	for i, k := range w {
		s += digit(d[i]) * k
	}
	return s % 11 % 10
}

var (
	inn10w   = []int{2, 4, 10, 3, 5, 9, 4, 6, 8}
	inn12w11 = []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	inn12w12 = []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
)

// ValidINN10 — ИНН юридического лица (10 цифр).
func ValidINN10(d string) bool {
	return len(d) == 10 && weighted(d, inn10w) == digit(d[9])
}

// ValidINN12 — ИНН физического лица (12 цифр, две контрольные цифры).
func ValidINN12(d string) bool {
	return len(d) == 12 && weighted(d, inn12w11) == digit(d[10]) && weighted(d, inn12w12) == digit(d[11])
}

// mod — остаток от деления числа из цифр d на m без переполнения.
func mod(d string, m int) int {
	r := 0
	for i := 0; i < len(d); i++ {
		r = (r*10 + digit(d[i])) % m
	}
	return r
}

// ValidOGRN — ОГРН юридического лица: 13 цифр, первая 1 или 5, последняя —
// остаток от деления первых 12 на 11 (последняя цифра остатка).
func ValidOGRN(d string) bool {
	return len(d) == 13 && (d[0] == '1' || d[0] == '5') && mod(d[:12], 11)%10 == digit(d[12])
}

// ValidOGRNIP — ОГРНИП: 15 цифр, первая 3, последняя — остаток от деления
// первых 14 на 13 (последняя цифра остатка).
func ValidOGRNIP(d string) bool {
	return len(d) == 15 && d[0] == '3' && mod(d[:14], 13)%10 == digit(d[14])
}

// ValidLuhn — номер карты: 13–19 цифр, алгоритм Луна, первая цифра 2–6
// (платёжные системы: Мир, Visa, Mastercard, Maestro, UnionPay, American Express).
func ValidLuhn(d string) bool {
	if len(d) < 13 || len(d) > 19 || d[0] < '2' || d[0] > '6' {
		return false
	}
	s := 0
	for i := 0; i < len(d); i++ {
		n := digit(d[len(d)-1-i])
		if i%2 == 1 {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		s += n
	}
	return s%10 == 0
}

// ValidAccountKey — ключ (9-я цифра) счёта в кредитной организации: три
// последние цифры БИК и 20 цифр счёта с весами 7, 1, 3, …; сумма младших
// разрядов произведений делится на 10.
func ValidAccountKey(bik, acc string) bool {
	return len(bik) == 9 && accountKey(bik[6:], acc)
}

// accountKey — проверка ключа по трём цифрам перед счётом (для корр. счетов
// это «0» и разряды 5–6 БИК).
func accountKey(prefix, acc string) bool {
	if len(prefix) != 3 || len(acc) != 20 {
		return false
	}
	d := prefix + acc
	w := [3]int{7, 1, 3}
	s := 0
	for i := 0; i < len(d); i++ {
		s += digit(d[i]) * w[i%3] % 10
	}
	return s%10 == 0
}
