package pii

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

func TestAccountKey(t *testing.T) {
	// Корр. счёт ПАО Сбербанк (открытые данные организации): ключ считается
	// по «0» и разрядам 5–6 БИК 044525225.
	if !accountKey("025", "30101810400000000225") {
		t.Fatal("ключ корр. счёта не сошёлся")
	}
	if accountKey("025", bump("30101810400000000225")) || ValidAccountKey("04452522", SynthAccount(1)) || accountKey("025", "123") {
		t.Fatal("принят неверный счёт")
	}
}

func TestSynthPart2(t *testing.T) {
	for n := uint64(0); n < 2000; n++ {
		p, ph, em, bik, acc := SynthPassport(n), SynthPhone(n), SynthEmail(n), SynthBIK(n), SynthAccount(n)
		switch {
		case len(onlyDigits(p)) != 10 || p[:2] != "00":
			t.Fatalf("паспорт %s", p)
		case !strings.HasPrefix(ph, "+7 300 ") || len(onlyDigits(ph)) != 11:
			t.Fatalf("телефон %s", ph)
		case !strings.HasSuffix(em, "@pochta.test"):
			t.Fatalf("e-mail %s", em)
		case bik[:6] != "040000" || bik[6:] < "050" || !ValidAccountKey(bik, acc) || acc[:8] != "40817810":
			t.Fatalf("счёт %s %s", bik, acc)
		}
	}
}

// TestDM31_PIIInRequestPart2: паспорт, телефон, e-mail, дата рождения, счёт
// в запросе к модели (DM-31). want — категория и значение, которое будет
// замаскировано.
func TestDM31_PIIInRequestPart2(t *testing.T) {
	pass, phone, mail, bik, acc := SynthPassport(1), SynthPhone(1), SynthEmail(1), SynthBIK(1), SynthAccount(1)
	pd := onlyDigits(pass)
	phd := onlyDigits(phone)
	cases := []struct{ text, cat, value string }{
		{"Паспорт " + pass + ", выдан ОВД", CatPassport, pass},
		{"паспорт: " + pd, CatPassport, pd},
		{"Серия " + pd[:4] + " " + pd[4:], CatPassport, pd[:4] + " " + pd[4:]},
		{"паспорт " + pd[:4] + " № " + pd[4:], CatPassport, pd[:4] + " № " + pd[4:]},
		{pd[:2] + " " + pd[2:4] + " № " + pd[4:], CatPassport, pd[:2] + " " + pd[2:4] + " № " + pd[4:]},
		{pass + " выдан 01.02.2003", CatPassport, pass},
		{"Мой телефон " + phone, CatPhone, phone},
		{"Звоните: 8" + phd[1:], CatPhone, "8" + phd[1:]},
		{"+" + phd, CatPhone, "+" + phd},
		{"8 (" + phd[1:4] + ") " + phd[4:7] + "-" + phd[7:9] + "-" + phd[9:], CatPhone, "8 (" + phd[1:4] + ") " + phd[4:7] + "-" + phd[7:9] + "-" + phd[9:]},
		{"8-" + phd[1:4] + "-" + phd[4:7] + "-" + phd[7:9] + "-" + phd[9:], CatPhone, "8-" + phd[1:4] + "-" + phd[4:7] + "-" + phd[7:9] + "-" + phd[9:]},
		{"(" + phd[1:4] + ") " + phd[4:7] + "-" + phd[7:9] + "-" + phd[9:], CatPhone, "(" + phd[1:4] + ") " + phd[4:7] + "-" + phd[7:9] + "-" + phd[9:]},
		{"WhatsApp " + phd, CatPhone, phd},
		{"Пишите на " + mail + ".", CatEmail, mail},
		{"e-mail: Иван.Петров@почта.test", CatEmail, "Иван.Петров@почта.test"},
		{"ящик@пдн-синтетика-0000.рф", CatEmail, "ящик@пдн-синтетика-0000.рф"},
		{"Дата рождения: 12.03.1985", CatBirthdate, "12.03.1985"},
		{"родился 1 марта 1985 года", CatBirthdate, "1 марта 1985"},
		{"Иванов И. И., 29/02/1984 г.р.", CatBirthdate, "29/02/1984"},
		{"DOB 1985-03-12", CatBirthdate, "1985-03-12"},
		{"date of birth: 12.03.1985", CatBirthdate, "12.03.1985"},
		{"р/с " + acc + " в банке, БИК " + bik, CatAccount, acc},
		{"Счёт " + acc, CatAccount, acc},
		{acc, CatAccount, acc}, // 40817 и код валюты 810 на своих местах
	}
	for _, c := range cases {
		fs := find(t, c.text, detect.Input)
		var got []string
		for _, f := range fs {
			if f.Score >= 0.5 {
				got = append(got, f.Category+"="+c.text[f.Start:f.End])
			}
			if f.Threat != "DM-31" || f.Detector != ID || f.Version != Version {
				t.Errorf("%q: %+v", c.text, f)
			}
		}
		if want := c.cat + "=" + c.value; strings.Join(got, ",") != want {
			t.Errorf("%q: %q, ожидалось %q", c.text, got, want)
		}
	}
}

// TestDM09_PIIInResponsePart2: телефон и e-mail в ответе модели — DM-09.
func TestDM09_PIIInResponsePart2(t *testing.T) {
	fs := find(t, "Контакт клиента: "+SynthPhone(4)+", "+SynthEmail(4), detect.Output)
	if cats(fs, 0.5) != CatPhone+","+CatEmail {
		t.Fatalf("%+v", fs)
	}
	for _, f := range fs {
		if f.Threat != "DM-09" {
			t.Fatalf("%+v", f)
		}
	}
}

// Ложные срабатывания части 2: даты без слова «рождения», номера
// организаций, общие ящики, договоры с «№», корр. счёт банка.
func TestNoFalsePositivesPart2(t *testing.T) {
	acc := SynthAccount(3)
	for _, text := range []string{
		"Встреча 12.03.2024 в 15:30",
		"Отчёт за 2024-03-12",
		"Дата рождения: 31.02.1985",     // нет такой даты
		"Дата рождения: 12.03.1885",     // раньше 1900
		"Дата рождения: 12.03/1985",     // разные разделители
		"год рождения 1985",             // только год — не дата
		"Горячая линия 8 800 555-35-35", // номер организации
		"Телефон 8 800 555-35-35",
		"Пишите на support@pochta.test",
		"git@pochta.test:org/repo.git",
		"Договор 0024 № 100500 от 01.02.2024",
		"БИК 044525225, корр. счёт 30101810400000000225",
		"Номер 1" + acc,            // 21 цифра
		"Код 00000000000000000000", // 20 цифр не на 40x
		"версия 1.2.3, сборка 7 916 1234",
		"ID 7300123456", // 10 цифр на 7 — не телефон
		"Справка: user@@pochta.test",
		// Ключевые слова — по границе слова; «г.р.» — только целиком.
		"Приказ от 12.03.2024 г. регламентирует порядок",
		"Отчётный год. Расчёт от 01.11.2023", // «д. р» внутри «год. Р»
		"Рождество 07.01.2025, офис закрыт",
		"Adobe Reader 2024-03-12", // «dob» внутри «adobe»
		"День рождения компании 12.03.2015",
		"Дата рождения не указана, договор от 01.02.2020",
		// Имена файлов с «@».
		"logo@2x.png и icon@3x.webp",
	} {
		if got := cats(find(t, text, detect.Input), 0.5); got != "" {
			t.Errorf("%q: ложное срабатывание %q", text, got)
		}
	}
}

// Дата рождения проверяется календарём и границами: 29 февраля — только в
// високосный год, «112.03.1985» — не дата.
func TestBirthdateEdges(t *testing.T) {
	for text, want := range map[string]bool{
		"дата рождения 29.02.1984":  true,
		"дата рождения 29.02.1985":  false,
		"дата рождения 112.03.1985": false,
		"дата рождения 12.03.19851": false,
		"рождения 31 декабря 1999":  true,
		"рождения 31 ДЕКАБРЯ 1999":  true,
		"рождения 32 декабря 1999":  false,
	} {
		if got := cats(find(t, text, detect.Input), 0.5) == CatBirthdate; got != want {
			t.Errorf("%q: %v", text, got)
		}
	}
}

// Находки на тексте из Word и веба: неразрывные пробелы и дефисы, буквы в
// форме NFD — позиции охватывают значение целиком (по ним маскирование).
func TestTypographyAndNFD(t *testing.T) {
	phone, card, snils := SynthPhone(5), SynthCard(5), SynthSNILS(5)
	nbspPhone := strings.NewReplacer(" ", "\u00a0", "-", "\u2011").Replace(phone)
	nbspCard := card[:4] + "\u00a0" + card[4:8] + "\u00a0" + card[8:12] + "\u00a0" + card[12:]
	nbspSnils := snils[:3] + "\u2011" + snils[3:6] + "\u2011" + snils[6:9] + "\u202f" + snils[9:]
	nfd := "андре\u0438\u0306.петров@pochta.test" // «й» = «и» + U+0306
	for _, c := range []struct{ text, cat, value string }{
		{"тел. " + nbspPhone, CatPhone, nbspPhone},
		{"карта " + nbspCard, CatCard, nbspCard},
		{"СНИЛС " + nbspSnils, CatSNILS, nbspSnils},
		{"почта " + nfd, CatEmail, nfd},
	} {
		fs := find(t, c.text, detect.Input)
		if len(fs) != 1 || fs[0].Category != c.cat || c.text[fs[0].Start:fs[0].End] != c.value || fs[0].Score < 0.5 {
			t.Errorf("%q: %+v", c.text, fs)
		}
	}
}

// Оценка телефона: «7» и мобильный код 9xx — выше порога, «7» и другие
// коды — ниже, номера 8-80x — организации.
func TestPhoneScore(t *testing.T) {
	for _, c := range []struct {
		first     byte
		area      string
		separated bool
		kw        bool
		want      float64
	}{
		{'7', "900", false, false, 0.7},
		{'7', "300", false, false, 0.45},
		{'8', "300", false, false, 0.7},
		{'8', "300", true, false, 0.8},
		{'+', "300", true, false, 0.85},
		{'8', "800", true, false, 0.2},
		{'8', "800", true, true, 0.3},
		{'7', "300", false, true, 0.95},
	} {
		if _, got := phoneScore(c.first, c.area, c.separated, c.kw); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

// Год рождения сверяется с часами детектора: дата позже текущего года —
// не дата рождения.
func TestBirthYearClock(t *testing.T) {
	d := Detector{now: func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) }}
	for text, want := range map[string]int{"дата рождения 12.03.1999": 1, "дата рождения 12.03.2001": 0} {
		fs, err := d.Detect(context.Background(), detect.Text{Text: text, Direction: detect.Input})
		if err != nil || len(fs) != want {
			t.Errorf("%q: %+v, %v", text, fs, err)
		}
	}
}
