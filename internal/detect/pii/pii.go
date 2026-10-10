// Пакет pii — детектор pii.ru: российские персональные данные и
// идентификаторы с проверкой контрольных сумм (ТЗ, 5.2; DM-31 — в запросе
// к модели, DM-09 — в ответе).
//
// Часть 1 (задача 1.11): СНИЛС, ИНН ФЛ и ЮЛ, ОГРН, ОГРНИП, номер карты.
// Часть 2 (задача 1.12, part2.go): паспорт РФ, телефон, e-mail, дата
// рождения в контексте, расчётный счёт с проверкой ключа по БИК.
// Кандидат — последовательность цифр с разделителями «пробел» и «дефис».
// Значение засчитывается только с верной контрольной суммой и подходящей
// раскладкой (СНИЛС — ddd-ddd-ddd dd, карта — группы по четыре, остальное —
// сплошные цифры); оценка выше, если рядом ключевое слово («ИНН», «карта»).
package pii

import (
	"context"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// ID и версия детектора.
const (
	ID      = "pii.ru"
	Version = "1.1.0"
)

// Категории находок.
const (
	CatSNILS  = "pii.snils"
	CatINN    = "pii.inn"
	CatOGRN   = "pii.ogrn"
	CatOGRNIP = "pii.ogrnip"
	CatCard   = "pii.card"
	// Часть 2.
	CatPassport  = "pii.passport"
	CatPhone     = "pii.phone"
	CatEmail     = "pii.email"
	CatBirthdate = "pii.birthdate"
	CatAccount   = "pii.account"
)

// Detector — детектор pii.ru. Без состояния, безопасен для одновременного
// вызова.
type Detector struct{}

// New создаёт детектор.
func New() Detector { return Detector{} }

// ID — идентификатор детектора.
func (Detector) ID() string { return ID }

// Version — версия детектора.
func (Detector) Version() string { return Version }

// Directions — запрос и ответ.
func (Detector) Directions() []detect.Direction {
	return []detect.Direction{detect.Input, detect.Output}
}

// candidateRe — от 10 до 19 цифр, между цифрами — не больше одного пробела
// или дефиса. RE2: время линейно от длины текста.
var candidateRe = regexp.MustCompile(`\d(?:[ \-]?\d){9,18}`)

// keywords — слова контекста по категориям (в нижнем регистре).
var keywords = map[string][]string{
	CatSNILS:  {"снилс", "страхов", "пенсион", "snils"},
	CatINN:    {"инн", "inn", "налогоплательщ", "taxpayer"},
	CatOGRN:   {"огрн", "ogrn", "регистрационн"},
	CatOGRNIP: {"огрнип", "ogrnip"},
	CatCard:   {"карт", "card", "visa", "mastercard", "maestro", "мир ", "cvv", "оплат", "pan"},
	// Часть 2.
	CatPassport: {"паспорт", "серия", "passport"},
	CatPhone:    {"тел", "phone", "моб", "звон", "whatsapp", "telegram", "сотов", "номер для связи"},
	CatAccount:  {"р/с", "р/сч", "расч", "счёт", "счет", "лицев", "account", "acct"},
}

// contextWindow — сколько байт перед значением просматривается в поисках
// ключевого слова.
const contextWindow = 48

// Detect находит идентификаторы в тексте.
func (d Detector) Detect(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	threat := "DM-31"
	if t.Direction == detect.Output {
		threat = "DM-09"
	}
	var out []detect.Finding
	for _, m := range candidateRe.FindAllStringIndex(t.Text, -1) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Значение не должно продолжать более длинное число.
		if m[0] > 0 && isDigit(t.Text[m[0]-1]) || m[1] < len(t.Text) && isDigit(t.Text[m[1]]) {
			continue
		}
		// «+7 …» — телефон, а не идентификатор (телефоны — part2.go).
		if m[0] > 0 && t.Text[m[0]-1] == '+' {
			continue
		}
		for _, v := range scan(t.Text, m[0], m[1]) {
			v.f.Detector, v.f.Version, v.f.Threat = ID, Version, threat
			v.f.Score = score(v.rule, t.Text[v.f.Start], hasKeyword(t.Text, v.f.Start, v.f.Category))
			out = append(out, v.f)
		}
	}
	more, err := detectPart2(ctx, t.Text, threat)
	if err != nil {
		return nil, err
	}
	return dedupe(append(out, more...)), nil
}

// dedupe оставляет на одном и том же фрагменте одну находку — с наибольшей
// оценкой («89161234567»: телефон, а не СНИЛС с низкой оценкой).
func dedupe(fs []detect.Finding) []detect.Finding {
	best := map[[2]int]int{}
	var out []detect.Finding
	for _, f := range fs {
		k := [2]int{f.Start, f.End}
		if i, ok := best[k]; ok {
			if f.Score > out[i].Score {
				out[i] = f
			}
			continue
		}
		best[k] = len(out)
		out = append(out, f)
	}
	return out
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// group — группа цифр кандидата и разделитель перед ней.
type group struct {
	start, end int  // байтовые позиции в тексте
	sep        byte // разделитель перед группой; 0 — первая группа
}

type match struct {
	f    detect.Finding
	rule string
}

// scan ищет в кандидате [start, end) значения: перебирает подпоследовательности
// групп от самой длинной, чтобы лишняя группа рядом («карта 4000 … 0002 15 шт»)
// не мешала распознать значение.
func scan(text string, start, end int) []match {
	var groups []group
	gs := start
	var sep byte
	for i := start; i <= end; i++ {
		if i == end || !isDigit(text[i]) {
			groups = append(groups, group{gs, i, sep})
			if i < end {
				sep, gs = text[i], i+1
			}
		}
	}
	var out []match
	for i := 0; i < len(groups); {
		found := false
		for j := len(groups); j > i; j-- {
			if m, ok := classify(text, groups[i:j]); ok {
				out = append(out, m)
				i, found = j, true
				break
			}
		}
		if !found {
			i++
		}
	}
	return out
}

// classify определяет вид значения по раскладке групп и контрольной сумме.
func classify(text string, gs []group) (match, bool) {
	var b strings.Builder
	sizes := make([]int, len(gs))
	for k, g := range gs {
		b.WriteString(text[g.start:g.end])
		sizes[k] = g.end - g.start
	}
	digits := b.String()
	start, end := gs[0].start, gs[len(gs)-1].end
	mk := func(cat, rule string) (match, bool) {
		return match{f: detect.Finding{Category: cat, Start: start, End: end, Rule: rule}, rule: rule}, true
	}
	if len(gs) == 1 {
		switch len(digits) {
		case 10:
			// 10 цифр подряд рядом со словом «паспорт» — серия и номер паспорта.
			if hasKeyword(text, start, CatPassport) {
				return mk(CatPassport, "passport.bare")
			}
			if ValidINN10(digits) {
				return mk(CatINN, "inn10")
			}
		case 11:
			if ValidSNILS(digits) {
				return mk(CatSNILS, "snils.bare")
			}
		case 12:
			if ValidINN12(digits) {
				return mk(CatINN, "inn12")
			}
		case 13:
			if ValidOGRN(digits) {
				return mk(CatOGRN, "ogrn")
			}
		case 15:
			if ValidOGRNIP(digits) {
				return mk(CatOGRNIP, "ogrnip")
			}
		}
		// Без группировки — только с префиксом известной платёжной системы:
		// иначе алгоритму Луна отвечает и IMEI телефона (15 цифр).
		if ValidLuhn(digits) && knownCardPrefix(digits) {
			return mk(CatCard, "card.bare")
		}
		return match{}, false
	}
	sameSep := true
	for _, g := range gs[2:] {
		if g.sep != gs[1].sep {
			sameSep = false
		}
	}
	// СНИЛС: 123-456-789 01, 123-456-789-01 или 123 456 789 01.
	snilsLayout := equal(sizes, 3, 3, 3, 2) && gs[1].sep == gs[2].sep && (gs[3].sep == gs[1].sep || gs[3].sep == ' ')
	// Карта: 4-4-4-4, 4-4-4-4-3 (19 цифр), 4-6-5 (American Express), 4-6-4.
	cardLayout := sameSep && (equal(sizes, 4, 4, 4, 4) || equal(sizes, 4, 4, 4, 4, 3) || equal(sizes, 4, 6, 5) || equal(sizes, 4, 6, 4))
	switch {
	case snilsLayout && ValidSNILS(digits):
		return mk(CatSNILS, "snils.formatted")
	case cardLayout && ValidLuhn(digits):
		return mk(CatCard, "card.grouped")
	case equal(sizes, 2, 2, 6) && gs[1].sep == ' ' && gs[2].sep == ' ':
		// Паспорт: серия «45 06» и номер — контрольной суммы нет, раскладка
		// характерная.
		return mk(CatPassport, "passport.226")
	case equal(sizes, 4, 6) && gs[1].sep == ' ':
		return mk(CatPassport, "passport.46")
	}
	return match{}, false
}

func equal(got []int, want ...int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// score — уверенность по виду значения, раскладке и контексту. Без
// ключевого слова оценка ниже порога по умолчанию 0,5 там, где случайное
// число проходит проверку слишком часто: одна контрольная цифра (ИНН ЮЛ,
// ОГРН — метка времени в миллисекундах, ОГРНИП — IMEI) или 11 цифр на 7/8
// (телефон без форматирования).
func score(rule string, first byte, kw bool) float64 {
	if kw {
		return 0.97
	}
	switch rule {
	case "snils.formatted", "card.grouped":
		return 0.9
	case "inn12":
		return 0.75
	case "card.bare":
		return 0.65
	case "snils.bare":
		if first == '7' || first == '8' {
			return 0.4
		}
		return 0.65
	case "ogrnip":
		return 0.45
	case "ogrn":
		return 0.4
	case "inn10":
		return 0.3
	case "passport.226":
		return 0.6
	case "passport.46":
		// «4506 123456» — так пишут и другие номера; без слова «паспорт» — ниже порога.
		return 0.35
	}
	return 0.5
}

// knownCardPrefix — префикс и длина номера известной платёжной системы:
// Visa (4; 13, 16, 19), Mastercard (51–55, 2221–2720; 16), Мир (2200–2204;
// 16–19), American Express (34, 37; 15), UnionPay (62; 16–19), JCB
// (3528–3589; 16), Maestro (50, 56–58, 63, 67; 12–19).
func knownCardPrefix(d string) bool {
	n := len(d)
	p2 := int(d[0]-'0')*10 + int(d[1]-'0')
	p4 := p2*100 + int(d[2]-'0')*10 + int(d[3]-'0')
	switch {
	case d[0] == '4':
		return n == 13 || n == 16 || n == 19
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720:
		return n == 16
	case p4 >= 2200 && p4 <= 2204, p2 == 62:
		return n >= 16
	case p2 == 34 || p2 == 37:
		return n == 15
	case p4 >= 3528 && p4 <= 3589:
		return n == 16
	case p2 == 50, p2 >= 56 && p2 <= 58, p2 == 63, p2 == 67:
		return true
	}
	return false
}

// hasKeyword ищет ключевое слово категории в окне перед значением.
func hasKeyword(text string, start int, cat string) bool {
	from := start - contextWindow
	if from < 0 {
		from = 0
	}
	for from < start && !utf8.RuneStart(text[from]) {
		from++
	}
	window := strings.ToLower(text[from:start])
	for _, k := range keywords[cat] {
		if strings.Contains(window, k) {
			return true
		}
	}
	return false
}
