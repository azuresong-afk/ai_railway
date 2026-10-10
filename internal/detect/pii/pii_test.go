package pii

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

func find(t testing.TB, text string, dir detect.Direction) []detect.Finding {
	t.Helper()
	fs, err := New().Detect(context.Background(), detect.Text{Text: text, Direction: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if err := detect.ValidateFinding(f, New(), len(text)); err != nil {
			t.Fatalf("%q: %v", text, err)
		}
	}
	return fs
}

func TestChecksums(t *testing.T) {
	// Общеизвестные значения из открытых справочников (не ПДн физических лиц):
	// ИНН и ОГРН ПАО Сбербанк; СНИЛС 112-233-445 95 — пример из описания алгоритма.
	for name, ok := range map[string]bool{
		"inn10 Сбербанка":     ValidINN10("7707083893"),
		"ogrn Сбербанка":      ValidOGRN("1027700132195"),
		"snils пример":        ValidSNILS("11223344595"),
		"luhn тестовой карты": ValidLuhn("4111111111111111"),
		"synth inn12":         ValidINN12(SynthINN12(7)),
		"synth ogrnip":        ValidOGRNIP(SynthOGRNIP(7)),
	} {
		if !ok {
			t.Errorf("%s: контрольная сумма не сошлась", name)
		}
	}
	for name, bad := range map[string]bool{
		"inn10 цифра":        ValidINN10("7707083894"),
		"inn12 вторая цифра": ValidINN12(bump(SynthINN12(7))),
		"snils сумма":        ValidSNILS("11223344596"),
		"snils малый номер":  ValidSNILS("00100199800"),
		"ogrn первая цифра":  ValidOGRN("2027700132195"),
		"luhn":               ValidLuhn("4111111111111112"),
		"luhn первая цифра":  ValidLuhn("1111111111111117"),
		"длина":              ValidINN12("12345"),
	} {
		if bad {
			t.Errorf("%s: принято неверное значение", name)
		}
	}
	// СНИЛС: суммы 100 и 101 дают 00, больше 101 — остаток от деления на 101.
	if SNILSChecksum("000000000") != 0 || SNILSChecksum("100000000") != 9 {
		t.Fatal("контрольное число СНИЛС")
	}
}

// Все синтетические значения проходят проверку и не похожи на реальные:
// регион 00, тестовые BIN, СНИЛС 9xx.
func TestSynth(t *testing.T) {
	for n := uint64(0); n < 2000; n++ {
		s, i10, i12, o, oip, c := SynthSNILS(n), SynthINN10(n), SynthINN12(n), SynthOGRN(n), SynthOGRNIP(n), SynthCard(n)
		switch {
		case !ValidSNILS(s) || s[0] != '9':
			t.Fatalf("СНИЛС %s", s)
		case !ValidINN10(i10) || i10[:2] != "00", !ValidINN12(i12) || i12[:2] != "00":
			t.Fatalf("ИНН %s %s", i10, i12)
		case !ValidOGRN(o) || o[3:5] != "00", !ValidOGRNIP(oip) || oip[3:5] != "00":
			t.Fatalf("ОГРН %s %s", o, oip)
		case !ValidLuhn(c) || (c[:6] != "400000" && c[:6] != "555555"):
			t.Fatalf("карта %s", c)
		}
	}
}

// bump меняет последнюю цифру на следующую по модулю 10.
func bump(s string) string {
	return s[:len(s)-1] + string('0'+(s[len(s)-1]-'0'+1)%10)
}

func cats(fs []detect.Finding, min float64) string {
	var out []string
	for _, f := range fs {
		if f.Score >= min {
			out = append(out, f.Category)
		}
	}
	return strings.Join(out, ",")
}

// TestDM31_PIIInRequest: идентификаторы в запросе к модели (DM-31).
func TestDM31_PIIInRequest(t *testing.T) {
	snils, inn12, inn10, ogrn, ogrnip, card := SynthSNILS(1), SynthINN12(1), SynthINN10(1), SynthOGRN(1), SynthOGRNIP(1), SynthCard(1)
	snilsFmt := snils[:3] + "-" + snils[3:6] + "-" + snils[6:9] + " " + snils[9:]
	cardFmt := card[:4] + " " + card[4:8] + " " + card[8:12] + " " + card[12:]
	cases := []struct{ text, want string }{
		{"Мой СНИЛС " + snilsFmt + ", проверьте", CatSNILS},
		{"snils: " + snils, CatSNILS},
		{snilsFmt, CatSNILS},
		{"ИНН " + inn12, CatINN},
		{inn12, CatINN},
		{"ИНН организации " + inn10, CatINN},
		{"ИНН:" + inn10, CatINN},
		{"ОГРН " + ogrn, CatOGRN},
		{"ОГРНИП " + ogrnip, CatOGRNIP},
		{"карта " + cardFmt, CatCard},
		{cardFmt, CatCard},
		{"оплатил картой " + card, CatCard},
		{"card " + card[:4] + "-" + card[4:8] + "-" + card[8:12] + "-" + card[12:], CatCard},
		// Лишняя группа цифр рядом не мешает.
		{"карта " + cardFmt + " 15 шт", CatCard},
		{"ИНН " + inn12 + " и СНИЛС " + snilsFmt, CatINN + "," + CatSNILS},
	}
	for _, c := range cases {
		fs := find(t, c.text, detect.Input)
		if got := cats(fs, 0.5); got != c.want {
			t.Errorf("%q: %q, ожидалось %q", c.text, got, c.want)
		}
		for _, f := range fs {
			if f.Threat != "DM-31" || f.Detector != ID || f.Version != Version {
				t.Errorf("%q: %+v", c.text, f)
			}
			// Позиции указывают на само значение — по ним будет маскирование.
			if v := c.text[f.Start:f.End]; strings.Trim(v, "0123456789 -") != "" {
				t.Errorf("%q: позиции [%d,%d) — %q", c.text, f.Start, f.End, v)
			}
		}
	}
}

// TestDM09_PIIInResponse: те же значения в ответе модели — строка DM-09.
func TestDM09_PIIInResponse(t *testing.T) {
	fs := find(t, "Ваш ИНН: "+SynthINN12(3), detect.Output)
	if len(fs) != 1 || fs[0].Threat != "DM-09" || fs[0].Category != CatINN {
		t.Fatalf("%+v", fs)
	}
}

// Ложные срабатывания дороже пропусков (ТЗ, 1.6): числа без верной суммы,
// даты, суммы, номера заказов не считаются ПДн (часть 2 — part2_test.go).
func TestNoFalsePositives(t *testing.T) {
	snils := SynthSNILS(2)
	wrongSnils := snils[:9] + "00"
	if ValidSNILS(wrongSnils) {
		wrongSnils = snils[:9] + "01"
	}
	for _, text := range []string{
		"Дата 12.03.2024, сумма 1 500 000 руб.",
		"Заказ № 4000 0012 3456 7891 отменён", // не проходит алгоритм Луна
		"СНИЛС " + wrongSnils[:3] + "-" + wrongSnils[3:6] + "-" + wrongSnils[6:9] + " " + wrongSnils[9:],
		"ИНН 7707083894",
		"GUID 550e8400-e29b-41d4-a716-446655440000",
		"IP 192.168.100.200 и порт 8443",
		"Сумма 12345678901234567890 копеек", // 20 цифр — не значение
		"шифр 1234-5678",
		"IMEI 356938035643809",     // 15 цифр, сумма Луна сходится, префикс 35
		"created_at=1791396000123", // метка времени в мс: 13 цифр на 1
		"",
	} {
		if got := cats(find(t, text, detect.Input), 0.5); got != "" {
			t.Errorf("%q: ложное срабатывание %q", text, got)
		}
	}
	// ИНН ЮЛ без контекста: находка есть, но ниже порога 0,5.
	fs := find(t, "номер "+SynthINN10(5), detect.Input)
	if len(fs) != 1 || fs[0].Score >= 0.5 {
		t.Fatalf("ИНН ЮЛ без контекста: %+v", fs)
	}
}

func TestKnownCardPrefix(t *testing.T) {
	for d, want := range map[string]bool{
		"4000000000000002":    true,  // Visa 16
		"2200000000000004":    true,  // Мир 16
		"5555555555554444":    true,  // Mastercard
		"378282246310005":     true,  // American Express 15
		"356938035643809":     false, // IMEI (35, 15 цифр)
		"5555555555555555557": false, // Mastercard не бывает 19 цифр
		"6011000000000004":    false, // Discover — не в списке
	} {
		if got := knownCardPrefix(d); got != want {
			t.Errorf("%s: %v", d, got)
		}
	}
}

func TestContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Detect(ctx, detect.Text{Text: "ИНН " + SynthINN12(1), Direction: detect.Input}); err == nil {
		t.Fatal("отменённый контекст не учтён")
	}
}

// Детектор — цель фаззинга (ТЗ, 5.2, 8.5): без паники, находки корректны,
// значение по позициям проходит свою проверку.
func FuzzDetect(f *testing.F) {
	f.Add("ИНН " + SynthINN12(1) + " карта " + SynthCard(2))
	f.Add("123-456-789 01 9")
	f.Add(strings.Repeat("1 ", 40))
	f.Add("паспорт " + SynthPassport(1) + ", тел. " + SynthPhone(1) + ", " + SynthEmail(1))
	f.Add("дата рождения 12 марта 1985, р/с " + SynthAccount(1) + " БИК " + SynthBIK(1))
	f.Fuzz(func(t *testing.T, text string) {
		for _, fd := range find(t, text, detect.Input) {
			if v := text[fd.Start:fd.End]; !validValue(fd.Category, v) {
				t.Fatalf("находка %s %q не проходит проверку", fd.Category, v)
			}
		}
	})
}

// validValue — значение находки соответствует категории.
func validValue(cat, v string) bool {
	d := onlyDigits(v)
	switch cat {
	case CatSNILS:
		return ValidSNILS(d)
	case CatOGRN:
		return ValidOGRN(d)
	case CatOGRNIP:
		return ValidOGRNIP(d)
	case CatCard:
		return ValidLuhn(d)
	case CatINN:
		return ValidINN10(d) || ValidINN12(d)
	case CatPassport:
		return len(d) == 10
	case CatPhone:
		return len(d) == 10 || len(d) == 11
	case CatEmail:
		return strings.Count(v, "@") == 1 && utf8.ValidString(v)
	case CatBirthdate:
		return len(d) >= 5 && len(d) <= 8
	case CatAccount:
		return len(d) == 20 && d == v && accountPrefix[d[:3]]
	}
	return false
}

// Бенчмарк: промпт 8 КБ с несколькими значениями (цель ТЗ 5.1 — p95 ≤ 30 мс
// на все правила).
func BenchmarkDetect8KB(b *testing.B) {
	var sb strings.Builder
	for sb.Len() < 8<<10 {
		sb.WriteString("Клиент просит проверить договор, номер заказа 12345, дата 12.03.2024. ")
		sb.WriteString("ИНН " + SynthINN12(9) + ", карта " + SynthCard(9) + ". ")
	}
	text := detect.Text{Text: sb.String(), Direction: detect.Input}
	d := New()
	b.SetBytes(int64(len(text.Text)))
	for b.Loop() {
		if _, err := d.Detect(context.Background(), text); err != nil {
			b.Fatal(err)
		}
	}
}
