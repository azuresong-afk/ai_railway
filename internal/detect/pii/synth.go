package pii

import (
	"fmt"
	"strconv"
)

// Генератор синтетических ПДн для корпусов и тестов (CLAUDE.md: ПДн в тестах
// только синтетические — валидные контрольные суммы, но не принадлежат
// реальным людям). Значения строятся детерминированно из номера n, чтобы
// корпус воспроизводился; это не источник случайности для безопасности.
//
// Почему значения не могут принадлежать реальным лицам:
//   - ИНН, ОГРН, ОГРНИП — код региона 00 (в России его нет: коды 01–99);
//   - карты — тестовые BIN 400000 (Visa) и 555555 (Mastercard), которые
//     платёжные системы и эквайеры используют для тестов;
//   - СНИЛС — номера 9xx-xxx-xxx: выдано около 200 млн номеров, нумерация
//     сквозная и до этого диапазона не доходит (допущение, docs/detectors.md);
//   - паспорт — серия на 00 (такого кода региона по ОКАТО нет), БИК — регион
//     00, e-mail — домен .test, телефон — код 300 (не выделен).

// mix — перемешивание номера (splitmix64), только для разнообразия цифр.
func mix(n uint64) uint64 {
	n += 0x9e3779b97f4a7c15
	n = (n ^ (n >> 30)) * 0xbf58476d1ce4e5b9
	n = (n ^ (n >> 27)) * 0x94d049bb133111eb
	return n ^ (n >> 31)
}

// digits — k цифр из номера n.
func digits(n uint64, k int) string {
	return fmt.Sprintf("%0*d", k, mix(n)%pow10(k))
}

func pow10(k int) uint64 {
	p := uint64(1)
	for range k {
		p *= 10
	}
	return p
}

// SynthSNILS — синтетический СНИЛС, 11 цифр: 9xx xxx xxx + контрольное число.
func SynthSNILS(n uint64) string {
	nine := "9" + digits(n, 8)
	return nine + fmt.Sprintf("%02d", SNILSChecksum(nine))
}

// SynthINN10 — синтетический ИНН ЮЛ с кодом региона 00.
func SynthINN10(n uint64) string {
	d := "00" + digits(n, 7)
	return d + strconv.Itoa(weighted(d+"0", inn10w))
}

// SynthINN12 — синтетический ИНН ФЛ с кодом региона 00.
func SynthINN12(n uint64) string {
	d := "00" + digits(n, 8)
	d += strconv.Itoa(weighted(d+"0", inn12w11))
	return d + strconv.Itoa(weighted(d+"0", inn12w12))
}

// SynthOGRN — синтетический ОГРН: признак 1, год, регион 00.
func SynthOGRN(n uint64) string {
	d := "1" + digits(n, 2) + "00" + digits(n+1, 7)
	return d + strconv.Itoa(mod(d, 11)%10)
}

// SynthOGRNIP — синтетический ОГРНИП: признак 3, год, регион 00.
func SynthOGRNIP(n uint64) string {
	d := "3" + digits(n, 2) + "00" + digits(n+1, 9)
	return d + strconv.Itoa(mod(d, 13)%10)
}

// SynthCard — синтетический номер карты (16 цифр) на тестовом BIN.
func SynthCard(n uint64) string {
	bin := "400000"
	if n%2 == 1 {
		bin = "555555"
	}
	d := bin + digits(n, 9)
	for c := 0; c <= 9; c++ {
		if s := d + strconv.Itoa(c); ValidLuhn(s) {
			return s
		}
	}
	return "" // недостижимо: одна из десяти цифр всегда даёт верную сумму
}

// SynthPassport — серия и номер паспорта «00 xx xxxxxx»: первые две цифры
// серии — код региона по ОКАТО, кода 00 нет.
func SynthPassport(n uint64) string {
	return "00 " + digits(n, 2) + " " + digits(n+1, 6)
}

// SynthPhone — телефон «+7 300 xxx-xx-xx»: код 300 в российском плане
// нумерации не выделен (допущение, docs/detectors.md).
func SynthPhone(n uint64) string {
	d := digits(n, 7)
	return "+7 300 " + d[:3] + "-" + d[3:5] + "-" + d[5:]
}

// SynthEmail — адрес в домене .test (RFC 2606: зарезервирован для тестов).
func SynthEmail(n uint64) string {
	return "client" + digits(n, 4) + "@pochta.test"
}

// SynthBIK — БИК «04 00 00 xxx»: регион 00 не существует, номер банка
// 050–999 (как у кредитных организаций).
func SynthBIK(n uint64) string {
	return fmt.Sprintf("040000%03d", 50+n%950)
}

// SynthAccount — счёт физлица в рублях (40817 810) с ключом по SynthBIK(n).
func SynthAccount(n uint64) string {
	tail := "0000" + digits(n, 7)
	for k := 0; k <= 9; k++ {
		if s := "40817810" + strconv.Itoa(k) + tail; ValidAccountKey(SynthBIK(n), s) {
			return s
		}
	}
	return "" // недостижимо: вес ключа 3 взаимно прост с 10
}
