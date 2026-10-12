// Пакет pii — детектор pii.ru: российские персональные данные и
// идентификаторы с проверкой контрольных сумм (ТЗ, 5.2; DM-31 — в запросе
// к модели, DM-09 — в ответе).
//
// Часть 1 (задача 1.11): СНИЛС, ИНН ФЛ и ЮЛ, ОГРН, ОГРНИП, номер карты.
// Часть 2 (задача 1.12, part2.go): паспорт РФ, телефон, e-mail, дата
// рождения в контексте, расчётный счёт с проверкой ключа по БИК.
// Кандидат — последовательность цифр с разделителями «пробел» и «дефис»
// (в том числе неразрывными). Значение засчитывается только с верной
// контрольной суммой и подходящей раскладкой (СНИЛС — ddd-ddd-ddd dd, карта —
// группы по четыре, остальное — сплошные цифры); оценка выше, если рядом
// ключевое слово («ИНН», «карта»).
package pii

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// ID и версия детектора.
const (
	ID      = "pii.ru"
	Version = "1.2.0"
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

// Detector — детектор pii.ru. Без изменяемого состояния, безопасен для
// одновременного вызова.
type Detector struct {
	// now — часы для проверки года рождения; nil — time.Now.
	now func() time.Time
}

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

func (d Detector) year() int {
	if d.now != nil {
		return d.now().Year()
	}
	return time.Now().Year()
}

// keywords — слова контекста по категориям: «слово*» — начало слова, «слово»
// — слово целиком (kws). Короткие слова — только целиком: «инн» не должно
// находиться в «длинное», «тел» — в «пользователь».
var keywords = map[string][]keyword{
	CatSNILS:  kws("снилс", "страхов*", "пенсион*", "snils"),
	CatINN:    kws("инн", "inn", "налогоплательщ*", "taxpayer*"),
	CatOGRN:   kws("огрн", "ogrn", "регистрационн*"),
	CatOGRNIP: kws("огрнип", "ogrnip"),
	CatCard:   kws("карт*", "card*", "visa", "mastercard", "maestro", "мир", "cvv", "оплат*", "pan"),
	// Часть 2.
	CatPassport: kws("паспорт*", "passport*"),
	CatPhone:    kws("тел", "tel", "телефон*", "phone*", "моб*", "звон*", "позвон*", "перезвон*", "сотов*", "whatsapp", "telegram", "call*", "номер для связи"),
	CatAccount:  kws("р/с", "р/сч", "расчётн*", "расчетн*", "счёт*", "счет*", "лицев*", "account*", "acct"),
}

// passportSeries — «серия» повышает оценку раскладок паспорта, но одна, без
// 10 цифр подряд, паспортом не считается («вторая серия набрала …»).
var passportSeries = kws("серия", "серии", "серию", "series")

// contextWindow — сколько байт перед значением просматривается в поисках
// ключевого слова.
const contextWindow = 48

func hasKeyword(text string, start int, cat string) bool {
	return lastKeyword(text, start-contextWindow, start, keywords[cat]) >= 0
}

// Detect находит идентификаторы в тексте.
func (d Detector) Detect(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	threat := "DM-31"
	if t.Direction == detect.Output {
		threat = "DM-09"
	}
	text := t.Text
	var out []detect.Finding
	emit := func(m match) {
		m.f.Detector, m.f.Version, m.f.Threat = ID, Version, threat
		kw := hasKeyword(text, m.f.Start, m.f.Category)
		if m.f.Category == CatPassport && !kw {
			kw = lastKeyword(text, m.f.Start-contextWindow, m.f.Start, passportSeries) >= 0
		}
		m.f.Score = score(m.rule, text[m.f.Start], kw)
		out = append(out, m.f)
	}
	// Кандидат — цифры, между которыми не больше одного разделителя; длина
	// не ограничена: длинная последовательность («СНИЛС ИНН» через пробел)
	// разбирается по группам, а не отбрасывается.
	for i, n := 0, 0; i < len(text); n++ {
		if n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if !isDigit(text[i]) {
			i++
			continue
		}
		s, e := i, 0
		var err error
		if e, err = candidateEnd(ctx, text, i); err != nil {
			return nil, err
		}
		i = e
		// Меньше 10 байт — меньше 10 цифр; «+7 …» — телефон (part2.go);
		// дробь и идентификатор с латиницей — не значение.
		if e-s < 10 || s > 0 && text[s-1] == '+' || !standalone(text, s, e) {
			continue
		}
		if err := scan(ctx, text, s, e, emit); err != nil {
			return nil, err
		}
	}
	more, err := detectPart2(ctx, text, threat, d.year())
	if err != nil {
		return nil, err
	}
	return dedupe(append(out, more...)), nil
}

// dedupe оставляет на одном и том же фрагменте одну находку — с наибольшей
// оценкой («83001234567»: телефон, а не СНИЛС с низкой оценкой).
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

// group — группа цифр кандидата и разделитель перед ней.
type group struct {
	start, end int  // байтовые позиции в тексте
	sep        byte // разделитель перед группой (' ' или '-'); 0 — первая группа
}

type match struct {
	f    detect.Finding
	rule string
}

// maxGroups — наибольшее число групп в раскладке (карта 4-4-4-4-3).
const maxGroups = 5

// scan ищет значения в кандидате [start, end). Идёт по группам цифр окном до
// maxGroups и в каждой позиции пробует самую длинную подходящую раскладку,
// поэтому лишняя группа рядом не мешает («карта 4000 … 1241 15 шт»), а
// несколько значений подряд находятся все. Память — O(1), время — линейно
// от длины кандидата; ctx проверяется каждые 1024 шага.
func scan(ctx context.Context, text string, start, end int, emit func(match)) error {
	var win [maxGroups]group
	n, pos := 0, start
	var sep byte
	read := func() bool {
		if pos >= end {
			return false
		}
		gs := pos
		for pos < end && isDigit(text[pos]) {
			pos++
		}
		win[n] = group{gs, pos, sep}
		n++
		if pos < end {
			r, size := utf8.DecodeRuneInString(text[pos:])
			sep = sepRune(r)
			pos += size
		}
		return true
	}
	shift := func(k int) {
		copy(win[:], win[k:n])
		n -= k
	}
	for step := 0; ; step++ {
		if step%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		for n < maxGroups && read() {
		}
		if n == 0 {
			return nil
		}
		k := 1
		for j := n; j >= 1; j-- {
			whole := win[0].start == start && win[j-1].end == end
			if m, ok := classify(text, win[:j], whole); ok {
				emit(m)
				k = j
				break
			}
		}
		shift(k)
	}
}

// classify определяет вид значения по раскладке групп и контрольной сумме.
// whole — группы составляют весь кандидат: раскладки без контрольной суммы
// (паспорт) засчитываются только так («2024 03 15 100000» — не паспорт).
func classify(text string, gs []group, whole bool) (match, bool) {
	start, end := gs[0].start, gs[len(gs)-1].end
	mk := func(cat, rule string) (match, bool) {
		return match{f: detect.Finding{Category: cat, Start: start, End: end, Rule: rule}, rule: rule}, true
	}
	if len(gs) == 1 {
		d := text[start:end]
		switch len(d) {
		case 10:
			// 10 цифр подряд рядом со словом «паспорт» — серия и номер; но если
			// ближе стоит «ИНН» и сумма ИНН сходится — это ИНН.
			p := lastKeyword(text, start-contextWindow, start, keywords[CatPassport])
			innNearer := ValidINN10(d) && lastKeyword(text, start-contextWindow, start, keywords[CatINN]) > p
			if p >= 0 && !innNearer {
				return mk(CatPassport, "passport.bare")
			}
			if ValidINN10(d) {
				return mk(CatINN, "inn10")
			}
		case 11:
			if ValidSNILS(d) {
				return mk(CatSNILS, "snils.bare")
			}
		case 12:
			if ValidINN12(d) {
				return mk(CatINN, "inn12")
			}
		case 13:
			if ValidOGRN(d) {
				return mk(CatOGRN, "ogrn")
			}
		case 15:
			if ValidOGRNIP(d) {
				return mk(CatOGRNIP, "ogrnip")
			}
		}
		// Без группировки — только с префиксом известной платёжной системы:
		// иначе алгоритму Луна отвечает и IMEI телефона (15 цифр).
		if ValidLuhn(d) && knownCardPrefix(d) {
			if len(d) == 16 && commonCard(d) {
				return mk(CatCard, "card.bare")
			}
			// 13 цифр Visa (штрихкод EAN-13), Maestro, Amex — без слова
			// «карта» ниже порога.
			return mk(CatCard, "card.bare.other")
		}
		return match{}, false
	}
	var sizes [maxGroups]int
	total := 0
	for k, g := range gs {
		sizes[k] = g.end - g.start
		total += sizes[k]
	}
	if total < 10 || total > 19 {
		return match{}, false
	}
	sz := sizes[:len(gs)]
	sameSep := true
	for _, g := range gs[2:] {
		if g.sep != gs[1].sep {
			sameSep = false
		}
	}
	// СНИЛС: 123-456-789 01, 123-456-789-01 или 123 456 789 01.
	snilsLayout := equal(sz, 3, 3, 3, 2) && gs[1].sep == gs[2].sep && (gs[3].sep == gs[1].sep || gs[3].sep == ' ')
	// Карта: 4-4-4-4, 4-4-4-4-3 (19 цифр), 4-6-5 (American Express), 4-6-4.
	cardLayout := sameSep && (equal(sz, 4, 4, 4, 4) || equal(sz, 4, 4, 4, 4, 3) || equal(sz, 4, 6, 5) || equal(sz, 4, 6, 4))
	switch {
	case snilsLayout || cardLayout:
		var b strings.Builder
		b.Grow(total)
		for _, g := range gs {
			b.WriteString(text[g.start:g.end])
		}
		d := b.String()
		if snilsLayout && ValidSNILS(d) {
			return mk(CatSNILS, "snils.formatted")
		}
		if cardLayout && ValidLuhn(d) {
			return mk(CatCard, "card.grouped")
		}
	case whole && equal(sz, 2, 2, 6) && gs[1].sep == ' ' && gs[2].sep == ' ':
		// Паспорт: серия «00 12» и номер — контрольной суммы нет, раскладка
		// характерная.
		return mk(CatPassport, "passport.226")
	case whole && equal(sz, 4, 6) && gs[1].sep == ' ':
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
	case "ogrn", "card.bare.other":
		return 0.4
	case "inn10":
		return 0.3
	case "passport.226":
		return 0.6
	case "passport.46":
		// «0012 345678» — так пишут и другие номера; без слова «паспорт» — ниже порога.
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
		return n >= 16 && n <= 19
	case p2 == 34 || p2 == 37:
		return n == 15
	case p4 >= 3528 && p4 <= 3589:
		return n == 16
	case p2 == 50, p2 >= 56 && p2 <= 58, p2 == 63, p2 == 67:
		return n >= 12 && n <= 19
	}
	return false
}

// commonCard — 16 цифр Visa, Mastercard или Мир: только такие номера без
// слова «карта» засчитываются выше порога.
func commonCard(d string) bool {
	p2 := int(d[0]-'0')*10 + int(d[1]-'0')
	p4 := p2*100 + int(d[2]-'0')*10 + int(d[3]-'0')
	return d[0] == '4' || p2 >= 51 && p2 <= 55 || p4 >= 2221 && p4 <= 2720 || p4 >= 2200 && p4 <= 2204
}
