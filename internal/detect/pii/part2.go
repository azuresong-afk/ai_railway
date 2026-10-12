package pii

// Часть 2 детектора pii.ru (задача 1.12): телефон, e-mail, дата рождения в
// контексте, расчётный счёт с проверкой ключа по БИК, паспорт с «№».
// Все выражения — RE2: время линейно от длины текста; срок (ctx)
// проверяется внутри каждого шага.

import (
	"context"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// sep — необязательный разделитель внутри номера.
const sep = `[` + sepClass + `]?`

var (
	// phoneRe — российский номер: +7, 8 или 7, код в скобках или без; либо
	// местный формат «(916) 123-45-67».
	phoneRe = regexp.MustCompile(`^(?:\+7|8|7)` + sep + `(?:\(\d{3}\)|\d{3})` + sep + `\d{3}` + sep + `\d{2}` + sep + `\d{2}|^\(\d{3}\)` + sep + `\d{3}[\-\x{2010}\x{2011}]\d{2}[\-\x{2010}\x{2011}]\d{2}`)
	// domainRe — домен после «@»: до восьми меток и домен верхнего уровня
	// латиницей или .рф, .рус. Применяется только с позиции после «@», а не
	// ко всему тексту: Unicode-классы с повторами для NFA дороги. \p{M} —
	// буквы в форме NFD («й» = «и» + U+0306).
	domainRe = regexp.MustCompile(`^(?:[\p{L}\p{M}\p{N}\-]{1,63}\.){1,8}(?i:[a-z]{2,24}|рф|рус)`)
	// dateRe — 12.03.1985, 12/03/1985, 1985-03-12, 12 марта 1985.
	dateRe = regexp.MustCompile(`^(?:(\d{1,2})([./])(\d{1,2})([./])(\d{4})|(\d{4})-(\d{2})-(\d{2})|(\d{1,2})[ \x{00A0}](?i:(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря))[ \x{00A0}](\d{4}))`)
	// passportNoRe — «00 12 № 345678», «0012 номер 345678».
	passportNoRe = regexp.MustCompile(`^\d{2}` + sep + `\d{2}` + sep + `(?:№|N|No\.?|номер)` + sep + `\d{6}`)
)

// Ключевые слова, которые есть только в части 2.
var (
	// birthBefore — перед датой: «дата рождения», «родился», «д.р.», «DOB».
	// «Рождество» и «Adobe» не подходят: слова ищутся по границе слова.
	birthBefore = kws("рожден*", "рождён*", "рожд.", "родил*", "born", "birth*", "dob", "д.р", "д. р")
	// birthAfter — после даты: «1985 г.р.»; «г. регламентирует» — нет.
	birthAfter = kws("г.р", "г. р", "года рождения")
	// birthOrg — «день рождения компании»: дата основания, не ПДн.
	birthOrg = kws("компани*", "организаци*", "фирм*", "предприяти*", "проект*", "магазин*", "сайт*", "бренд*", "company", "brand*")
	// roleMailbox — общие ящики организаций: не ПДн конкретного человека.
	roleMailbox = map[string]bool{
		"info": true, "support": true, "noreply": true, "no-reply": true, "admin": true,
		"postmaster": true, "webmaster": true, "sales": true, "help": true, "office": true,
		"git": true, "press": true, "abuse": true, "root": true, "mail": true,
	}
	// fileExt — «logo@2x.png»: имя файла, а не адрес. Домены верхнего уровня,
	// которые совпадают с расширениями и встречаются в адресах русскоязычных
	// пользователей (.md — Молдова), сюда не входят.
	fileExt = map[string]bool{
		"png": true, "jpg": true, "jpeg": true, "gif": true, "webp": true, "svg": true, "bmp": true, "ico": true,
		"js": true, "ts": true, "json": true, "css": true, "html": true, "htm": true, "txt": true, "pdf": true,
		"zip": true, "gz": true, "tar": true, "mov": true, "mp4": true, "mp3": true, "wav": true, "py": true,
		"go": true, "rs": true, "yaml": true, "yml": true, "xml": true, "csv": true, "exe": true, "dll": true,
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

// addFunc — добавить находку категории cat по правилу rule на [s, e).
type addFunc = func(cat, rule string, s, e int, score float64)

func detectPart2(ctx context.Context, text, threat string, year int) ([]detect.Finding, error) {
	var out []detect.Finding
	add := func(cat, rule string, s, e int, score float64) {
		out = append(out, detect.Finding{Detector: ID, Version: Version, Category: cat, Threat: threat, Score: score, Start: s, End: e, Rule: rule})
	}
	steps := []func(context.Context, string, addFunc) error{
		phones, emails, accounts, passportsNo,
		func(ctx context.Context, text string, add addFunc) error { return birthdates(ctx, text, year, add) },
	}
	for _, step := range steps {
		if err := step(ctx, text, add); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// phones — телефоны. Без ключевого слова оценка зависит от записи.
func phones(ctx context.Context, text string, add addFunc) error {
	return anchoredMatches(ctx, phoneRe, text, phoneStart, func(s, e int) {
		if !standalone(text, s, e) {
			return
		}
		v := text[s:e]
		d := onlyDigits(v)
		area := d[len(d)-10 : len(d)-7]
		// Коды 3xx, 4xx, 8xx — географические, 9xx — мобильные, 7xx —
		// Казахстан; 0xx, 1xx, 2xx, 5xx, 6xx не выделены.
		if !strings.ContainsRune("34789", rune(area[0])) {
			return
		}
		rule, sc := phoneScore(v[0], area, len(v) > len(d), hasKeyword(text, s, CatPhone))
		add(CatPhone, rule, s, e, sc)
	})
}

// phoneStart — в позиции i может начаться телефон: «+», «(», «7» или «8»
// не внутри числа.
func phoneStart(text string, i int) bool {
	switch text[i] {
	case '+', '(', '7', '8':
		return i == 0 || !isDigit(text[i-1])
	}
	return false
}

// phoneScore — оценка телефона по первому символу записи, коду зоны,
// наличию разделителей и ключевому слову.
func phoneScore(first byte, area string, separated, kw bool) (string, float64) {
	switch {
	case strings.HasPrefix(area, "80"):
		// 8 800 … и другие непротарифицированные номера — организации.
		if kw {
			return "phone.service", 0.3
		}
		return "phone.service", 0.2
	case kw:
		return "phone", 0.95
	case first == '+':
		return "phone", 0.85
	case first == '(':
		return "phone", 0.7
	case first == '7' && area[0] == '9':
		// 7 и мобильный код 9xx — так номера хранят в базах и CRM.
		return "phone", 0.7
	case first == '7':
		// 7 и другие коды без плюса — часто просто число.
		return "phone", 0.45
	case separated:
		return "phone", 0.8 // «8 916 …» с разделителями
	}
	return "phone", 0.7 // «89161234567»
}

// emails — адреса электронной почты; общие ящики организаций и имена файлов
// («logo@2x.png») — ниже порога.
func emails(ctx context.Context, text string, add addFunc) error {
	floor := 0 // конец предыдущего адреса: адреса не пересекаются
	for i, n := 0, 0; i < len(text); i, n = i+1, n+1 {
		if n%64 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		at := strings.IndexByte(text[i:], '@')
		if at < 0 {
			return nil
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
		if r, _ := utf8.DecodeRuneInString(text[e:]); e < len(text) && (isLetter(r) || unicode.IsDigit(r)) {
			continue
		}
		tld := strings.ToLower(text[strings.LastIndexByte(text[:e], '.')+1 : e])
		switch {
		case fileExt[tld]:
			add(CatEmail, "email.file", s, e, 0.3)
		case roleMailbox[strings.ToLower(text[s:at])]:
			add(CatEmail, "email.role", s, e, 0.4)
		default:
			add(CatEmail, "email", s, e, 0.9)
		}
		floor, i = e, e-1
	}
	return nil
}

// localStart — начало локальной части адреса перед «@» в позиции at: до 64
// символов из букв (в том числе в форме NFD), цифр и «._%+-», не левее floor.
func localStart(text string, at, floor int) int {
	s := at
	for n := 0; n < 64 && s > floor; n++ {
		r, size := utf8.DecodeLastRuneInString(text[floor:s])
		if !isLetter(r) && !unicode.IsNumber(r) && !strings.ContainsRune("._%+-", r) {
			break
		}
		s -= size
	}
	return s
}

// birthdates — дата засчитывается только рядом со словом «рождения»: без
// контекста даты встречаются повсюду и ПДн не являются.
func birthdates(ctx context.Context, text string, year int, add addFunc) error {
	if ok, err := containsFold(ctx, text, birthRoots); !ok || err != nil {
		return err
	}
	return anchoredMatches(ctx, dateRe, text, numberStart, func(s, e int) {
		if !bounded(text, s, e) {
			return
		}
		sub := dateRe.FindStringSubmatch(text[s:e])
		var day, y int
		var month time.Month
		switch {
		case sub[1] != "":
			if sub[2] != sub[4] {
				return // «12.03/1985»
			}
			day, month, y = atoi(sub[1]), time.Month(atoi(sub[3])), atoi(sub[5])
		case sub[6] != "":
			y, month, day = atoi(sub[6]), time.Month(atoi(sub[7])), atoi(sub[8])
		default:
			day, month, y = atoi(sub[9]), months[strings.ToLower(sub[10])], atoi(sub[11])
		}
		if y < 1900 || y > year || !validDate(y, month, day) || !birthContext(text, s, e) {
			return
		}
		add(CatBirthdate, "birthdate", s, e, 0.9)
	})
}

// birthRoots — грубый отбор: без этих сочетаний в тексте даты не разбираются.
var birthRoots = []string{"рожд", "родил", "born", "birth", "dob", "д.р", "д. р", "г.р", "г. р"}

// birthContext — «дата рождения», «д.р.», «born» перед датой (и между ними
// нет слов «компании», «проекта») или «г.р.» сразу после даты.
func birthContext(text string, s, e int) bool {
	if k := lastKeyword(text, s-birthWindow, s, birthBefore); k >= 0 && lastKeyword(text, k, s, birthOrg) < 0 {
		return true
	}
	p := e
	for p < len(text) {
		r, size := utf8.DecodeRuneInString(text[p:])
		if sepRune(r) != ' ' {
			break
		}
		p += size
	}
	return p < len(text) && keywordAt(text, p, birthAfter) >= 0
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
func accounts(ctx context.Context, text string, add addFunc) error {
	// Счёт — ровно 20 цифр подряд, БИК — ровно 9 на «04»; ищутся по
	// максимальным последовательностям цифр без регулярных выражений.
	var biks, accs [][2]int
	for i, n := 0, 0; i < len(text); n++ {
		if n%(64<<10) == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if !isDigit(text[i]) {
			i++
			continue
		}
		j := i
		for j < len(text) && isDigit(text[j]) {
			j++
		}
		switch {
		case !standalone(text, i, j):
		case j-i == 9 && text[i:i+2] == "04":
			biks = append(biks, [2]int{i, j})
		case j-i == 20 && accountPrefix[text[i:i+3]]:
			accs = append(accs, [2]int{i, j})
		}
		i = j
	}
	for k, a := range accs {
		if k%64 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
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
	return nil
}

// passportsNo — «00 12 № 345678». Слитная серия «0012 № 345678» так же
// пишется у договоров и заказов — без слова «паспорт» ниже порога.
func passportsNo(ctx context.Context, text string, add addFunc) error {
	if !strings.Contains(text, "№") && !strings.Contains(text, "номер") && !strings.Contains(text, "N") {
		return nil
	}
	return anchoredMatches(ctx, passportNoRe, text, numberStart, func(s, e int) {
		if !standalone(text, s, e) {
			return
		}
		r, _ := utf8.DecodeRuneInString(text[s+2:])
		switch {
		case hasKeyword(text, s, CatPassport) || lastKeyword(text, s-contextWindow, s, passportSeries) >= 0:
			add(CatPassport, "passport.no", s, e, 0.97)
		case sepRune(r) == ' ':
			add(CatPassport, "passport.no", s, e, 0.85)
		default:
			add(CatPassport, "passport.no", s, e, 0.4)
		}
	})
}
