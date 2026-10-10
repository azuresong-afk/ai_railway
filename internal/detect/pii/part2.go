package pii

// Часть 2 детектора pii.ru (задача 1.12): телефон, e-mail, дата рождения в
// контексте, расчётный счёт с проверкой ключа по БИК, паспорт с «№».
// Все выражения — RE2: время линейно от длины текста.

import (
	"context"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

var (
	// phoneRe — российский номер: +7, 8 или 7, код в скобках или без,
	// разделители «пробел» и «дефис»; либо местный формат «(916) 123-45-67».
	phoneRe = regexp.MustCompile(`(?:\+7|8|7)[ \-]?(?:\(\d{3}\)|\d{3})[ \-]?\d{3}[ \-]?\d{2}[ \-]?\d{2}|\(\d{3}\) ?\d{3}-\d{2}-\d{2}`)
	// domainRe — домен после «@»: до восьми меток и домен верхнего уровня
	// латиницей или .рф, .рус. Применяется только с позиции после «@», а не
	// ко всему тексту: Unicode-классы с повторами для NFA дороги.
	domainRe = regexp.MustCompile(`^(?:[\p{L}\p{N}\-]{1,63}\.){1,8}(?i:[a-z]{2,24}|рф|рус)`)
	// dateRe — 12.03.1985, 12/03/1985, 1985-03-12, 12 марта 1985.
	dateRe = regexp.MustCompile(`(\d{1,2})([./])(\d{1,2})([./])(\d{4})|(\d{4})-(\d{2})-(\d{2})|(\d{1,2}) (?i:(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)) (\d{4})`)
	// passportNoRe — «45 06 № 123456», «4506 номер 123456».
	passportNoRe = regexp.MustCompile(`\d{2} ?\d{2} ?(?:№|N|No\.?|номер) ?\d{6}`)
)

// Ключевые слова, которые есть только в части 2.
var (
	birthBefore = []string{"рожд", "д.р", "д. р", "родил", "born", "birth", "dob"}
	birthAfter  = []string{"г.р", "г. р", "года рождения"}
	// roleMailbox — общие ящики организаций: не ПДн конкретного человека.
	roleMailbox = map[string]bool{
		"info": true, "support": true, "noreply": true, "no-reply": true, "admin": true,
		"postmaster": true, "webmaster": true, "sales": true, "help": true, "office": true,
		"git": true, "press": true, "abuse": true, "root": true, "mail": true,
	}
	months = map[string]time.Month{
		"января": 1, "февраля": 2, "марта": 3, "апреля": 4, "мая": 5, "июня": 6,
		"июля": 7, "августа": 8, "сентября": 9, "октября": 10, "ноября": 11, "декабря": 12,
	}
	// accountPrefix — балансовые счета клиентов: 405–408 — расчётные и
	// текущие (40817 — физлица, 40802 — ИП), 423 и 426 — вклады физлиц.
	accountPrefix = map[string]bool{"405": true, "406": true, "407": true, "408": true, "423": true, "426": true}
	// accountCurrency — код валюты в разрядах 6–8 счёта.
	accountCurrency = map[string]bool{"810": true, "643": true, "840": true, "978": true, "156": true}
)

// birthWindow — сколько байт перед датой просматривается в поисках слова
// «рождения»: около 20 символов кириллицы. Шире нельзя: «Дата рождения не
// указана, договор от 01.02.2020» — дата договора, а не рождения.
const birthWindow = 40

// bounded — значение [s, e) не продолжает более длинное число.
func bounded(text string, s, e int) bool {
	return (s == 0 || !isDigit(text[s-1])) && (e == len(text) || !isDigit(text[e]))
}

// addFunc — добавить находку категории cat по правилу rule на [s, e).
type addFunc = func(cat, rule string, s, e int, score float64)

func detectPart2(ctx context.Context, text, threat string) ([]detect.Finding, error) {
	var out []detect.Finding
	add := func(cat, rule string, s, e int, score float64) {
		out = append(out, detect.Finding{Detector: ID, Version: Version, Category: cat, Threat: threat, Score: score, Start: s, End: e, Rule: rule})
	}
	for _, step := range []func(string, addFunc){phones, emails, birthdates, accounts, passportsNo} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		step(text, add)
	}
	return out, nil
}

// phones — телефоны. Без ключевого слова оценка зависит от записи: «+7» —
// почти наверняка телефон, «7» без плюса — часто просто число.
func phones(text string, add addFunc) {
	for _, m := range phoneRe.FindAllStringIndex(text, -1) {
		s, e := m[0], m[1]
		if !bounded(text, s, e) {
			continue
		}
		v := text[s:e]
		d := onlyDigits(v)
		area := d[len(d)-10 : len(d)-7]
		// Коды 3xx, 4xx, 8xx — географические, 9xx — мобильные, 7xx —
		// Казахстан; 0xx, 1xx, 2xx, 5xx, 6xx не выделены.
		if !strings.ContainsRune("34789", rune(area[0])) {
			continue
		}
		kw := hasKeyword(text, s, CatPhone)
		var score float64
		rule := "phone"
		switch {
		case strings.HasPrefix(area, "80"):
			// 8 800 … и другие непротарифицированные номера — организации.
			rule, score = "phone.service", 0.2
			if kw {
				score = 0.3
			}
		case kw:
			score = 0.95
		case v[0] == '+':
			score = 0.85
		case v[0] == '(':
			score = 0.7
		case v[0] == '7':
			score = 0.45
		case len(v) > len(d):
			score = 0.8 // «8 916 …» с разделителями
		default:
			score = 0.7 // «89161234567»
		}
		add(CatPhone, rule, s, e, score)
	}
}

// emails — адреса электронной почты; общие ящики организаций — ниже порога.
func emails(text string, add addFunc) {
	floor := 0 // конец предыдущего адреса: адреса не пересекаются
	for i := 0; i < len(text); i++ {
		at := strings.IndexByte(text[i:], '@')
		if at < 0 {
			return
		}
		at += i
		i = at
		s := localStart(text, at, floor)
		if s == at {
			continue
		}
		m := domainRe.FindStringIndex(text[at+1:])
		if m == nil {
			continue
		}
		e := at + 1 + m[1]
		// Домен верхнего уровня не обрезан: «user@mail.ruя» — не адрес.
		if r, _ := utf8.DecodeRuneInString(text[e:]); e < len(text) && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			continue
		}
		if roleMailbox[strings.ToLower(text[s:at])] {
			add(CatEmail, "email.role", s, e, 0.4)
		} else {
			add(CatEmail, "email", s, e, 0.9)
		}
		floor, i = e, e-1
	}
}

// localStart — начало локальной части адреса перед «@» в позиции at: до 64
// символов из букв, цифр и «._%+-», не левее floor.
func localStart(text string, at, floor int) int {
	s := at
	for n := 0; n < 64 && s > floor; n++ {
		r, size := utf8.DecodeLastRuneInString(text[floor:s])
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && !strings.ContainsRune("._%+-", r) {
			break
		}
		s -= size
	}
	return s
}

// birthdates — дата засчитывается только рядом со словом «рождения»: без
// контекста даты встречаются повсюду и ПДн не являются.
func birthdates(text string, add addFunc) {
	if !hasBirthWord(text) {
		return
	}
	now := time.Now().Year()
	// Сначала границы дат без подгрупп (быстрее), затем разбор найденного.
	for _, m := range dateRe.FindAllStringIndex(text, -1) {
		s, e := m[0], m[1]
		if !bounded(text, s, e) {
			continue
		}
		sub := dateRe.FindStringSubmatch(text[s:e])
		g := func(i int) string { return sub[i] }
		var day, year int
		var month time.Month
		switch {
		case g(1) != "":
			if g(2) != g(4) {
				continue // «12.03/1985»
			}
			day, month, year = atoi(g(1)), time.Month(atoi(g(3))), atoi(g(5))
		case g(6) != "":
			year, month, day = atoi(g(6)), time.Month(atoi(g(7))), atoi(g(8))
		default:
			day, month, year = atoi(g(9)), months[strings.ToLower(g(10))], atoi(g(11))
		}
		if year < 1900 || year > now || !validDate(year, month, day) {
			continue
		}
		if !birthContext(text, s, e) {
			continue
		}
		add(CatBirthdate, "birthdate", s, e, 0.9)
	}
}

// hasBirthWord — в тексте есть хотя бы одно слово контекста даты рождения:
// без него даты не разбираются вовсе.
func hasBirthWord(text string) bool {
	lower := strings.ToLower(text)
	for _, ks := range [][]string{birthBefore, birthAfter} {
		for _, k := range ks {
			if strings.Contains(lower, k) {
				return true
			}
		}
	}
	return false
}

// birthContext — «дата рождения», «д.р.», «born» перед датой или «г.р.» после.
func birthContext(text string, s, e int) bool {
	from := max(s-birthWindow, 0)
	for from < s && !utf8.RuneStart(text[from]) {
		from++
	}
	before := strings.ToLower(text[from:s])
	for _, k := range birthBefore {
		if strings.Contains(before, k) {
			return true
		}
	}
	to := min(e+32, len(text))
	for to > e && to < len(text) && !utf8.RuneStart(text[to]) {
		to--
	}
	after := strings.TrimLeft(strings.ToLower(text[e:to]), " ")
	for _, k := range birthAfter {
		if strings.HasPrefix(after, k) {
			return true
		}
	}
	return false
}

func validDate(y int, m time.Month, d int) bool {
	if m < 1 || m > 12 || d < 1 {
		return false
	}
	t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return t.Day() == d && t.Month() == m
}

// atoi — короткая строка цифр ASCII (проверено выражением) в число.
func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + digit(s[i])
	}
	return n
}

func onlyDigits(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// accounts — расчётные счета клиентов. Ключ (9-я цифра) проверяется по
// любому БИК из того же текста: если сошёлся — это счёт почти наверняка.
func accounts(text string, add addFunc) {
	// Счёт — ровно 20 цифр подряд, БИК — ровно 9 на «04»; ищутся по
	// максимальным последовательностям цифр без регулярных выражений.
	var biks, accs [][2]int
	for i := 0; i < len(text); {
		if !isDigit(text[i]) {
			i++
			continue
		}
		j := i
		for j < len(text) && isDigit(text[j]) {
			j++
		}
		switch {
		case j-i == 9 && text[i:i+2] == "04":
			biks = append(biks, [2]int{i, j})
		case j-i == 20 && accountPrefix[text[i:i+3]]:
			accs = append(accs, [2]int{i, j})
		}
		i = j
	}
	for _, a := range accs {
		s, e := a[0], a[1]
		acc := text[s:e]
		keyOK := false
		for _, b := range biks {
			if ValidAccountKey(text[b[0]:b[1]], acc) {
				keyOK = true
				break
			}
		}
		switch {
		case keyOK:
			add(CatAccount, "account.bik", s, e, 0.95)
		case hasKeyword(text, s, CatAccount):
			add(CatAccount, "account", s, e, 0.6)
		case accountCurrency[acc[5:8]]:
			// Балансовый счёт клиента и код валюты на своих местах.
			add(CatAccount, "account", s, e, 0.55)
		default:
			add(CatAccount, "account", s, e, 0.35)
		}
	}
}

// passportsNo — «45 06 № 123456». Слитная серия «4506 № 123456» так же
// пишется у договоров и заказов — без слова «паспорт» ниже порога.
func passportsNo(text string, add addFunc) {
	if !strings.Contains(text, "№") && !strings.Contains(text, "номер") && !strings.Contains(text, "N") {
		return
	}
	for _, m := range passportNoRe.FindAllStringIndex(text, -1) {
		s, e := m[0], m[1]
		if !bounded(text, s, e) {
			continue
		}
		switch {
		case hasKeyword(text, s, CatPassport):
			add(CatPassport, "passport.no", s, e, 0.97)
		case text[s+2] == ' ':
			add(CatPassport, "passport.no", s, e, 0.85)
		default:
			add(CatPassport, "passport.no", s, e, 0.4)
		}
	}
}
