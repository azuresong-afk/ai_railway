package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// Синтетический корпус pii.ner (задача 4.20): фразы запросов и ответов с
// вымышленными людьми, организациями и адресами и разметкой сущностей.
// Фамилии, названия организаций и населённых пунктов составлены из
// словарей ниже; адрес и полное имя вместе никому не принадлежат. Части
// train (обучение, tools/ml) и check (проверочный корпус
// testdata/corpus/pii.ner) строятся из непересекающихся словарей имён,
// фамилий, организаций и городов: проверка не видит имён из обучения.
//
// Сущности: per (человек), org (организация), addr (почтовый адрес), loc
// (город или страна без адреса — не ПДн, находок не даёт; есть в обучении,
// чтобы модель отличала его от адреса). Значения детерминированы номером
// примера.

// Падежи имён: именительный, родительный, дательный, творительный,
// предложный (только у мест).
const (
	nom = iota
	gen
	dat
	ins
	prep
)

// nerVocab — словари одной части корпуса.
type nerVocab struct {
	male, female []string // имена
	patr         []string // основы отчеств: «Иванов» → Иванович, Ивановна
	surOv        []string // фамилии на -ов, -ев, -ин (мужская форма)
	surSky       []string // основы фамилий на -ский: «Заречен» → Зареченский
	surEnko      []string // несклоняемые на -енко
	orgs         []string // названия организаций
	towns        []string // вымышленные города (именительный, для адресов)
	streets      []string // названия улиц (прилагательное женского рода)
	locs         [][3]string
	// Свои шаблоны части сверх общих: проверка видит и незнакомые фразы.
	input, output []string
	salt          uint64 // своя последовательность примеров
}

var nerTrain = nerVocab{
	male:    []string{"Иван", "Олег", "Роман", "Глеб", "Тимур", "Степан", "Арсений", "Никита", "Матвей", "Денис", "Кирилл", "Аркадий", "Борис", "Вадим", "Ефим", "Савелий"},
	female:  []string{"Анна", "Ольга", "Мария", "Наталья", "Ксения", "Дарья", "Елена", "Вера", "Полина", "Алёна", "Зоя", "Яна", "Агата", "Лидия"},
	patr:    []string{"Иванов", "Олегов", "Романов", "Степанов", "Денисов", "Борисов", "Аркадьев", "Матвеев", "Вадимов", "Глебов"},
	surOv:   []string{"Брусников", "Курганов", "Мельников", "Тополев", "Сухарев", "Рыбаков", "Овсянин", "Лапшин", "Калинкин", "Журавлёв", "Соколин", "Кедров", "Пастухов", "Зимин"},
	surSky:  []string{"Заречен", "Белогор", "Ольхов", "Тихорец", "Лугов", "Подгор"},
	surEnko: []string{"Гриценко", "Марченко", "Бондаренко", "Онищенко"},
	orgs:    []string{"Северный ветер", "Луч", "Зелёный сад", "Техностандарт", "Кедровый бор", "Медовик", "Стройресурс", "Ладья", "Вектор Плюс", "Агроснаб", "Полярис", "Ромашка", "Альфа-Логистик", "Сибирский мёд"},
	towns:   []string{"Кедрогорск", "Туманобережск", "Липодольск", "Звездоозёрск", "Ветроград", "Медогорск", "Сосновополье", "Лучезерск"},
	streets: []string{"Липовая", "Садовая", "Солнечная", "Луговая", "Заводская", "Кленовая", "Речная", "Парковая"},
	locs: [][3]string{{"Москва", "Москвы", "Москве"}, {"Казань", "Казани", "Казани"}, {"Новосибирск", "Новосибирска", "Новосибирске"},
		{"Тверь", "Твери", "Твери"}, {"Россия", "России", "России"}, {"Китай", "Китая", "Китае"}, {"Екатеринбург", "Екатеринбурга", "Екатеринбурге"}},
	input: []string{
		"Перешли {PER.dat} счёт от {ORG} и попроси подтвердить получение.",
		"Составь акт сверки между {ORG} и {ORG}.",
		"Уточни у {PER.gen}, можно ли отправить документы на {ADDR}.",
		"короче {PER.nom} опять не сдал отчёт, напиши ему помягче",
		"в {ORGNAME} сменился директор, поздравь {PER.gen} от нас",
	},
	output: []string{"Заявка от {PER.gen} принята, ответ придёт на адрес {ADDR}."},
	salt:   1,
}

var nerCheck = nerVocab{
	male:    []string{"Антон", "Егор", "Захар", "Геннадий", "Илья", "Филипп", "Всеволод", "Тарас", "Святослав", "Юрий", "Фома", "Платон"},
	female:  []string{"Ирина", "Светлана", "Татьяна", "Юлия", "Евгения", "Галина", "Лариса", "Варвара", "Милана", "Людмила", "Инна", "Софья"},
	patr:    []string{"Антонов", "Егоров", "Захаров", "Геннадьев", "Филиппов", "Тарасов", "Юрьев", "Всеволодов"},
	surOv:   []string{"Ястребов", "Голубев", "Шиповников", "Вересаев", "Ковылин", "Черёмухин", "Пряников", "Луковцев", "Барсуков", "Сидоркин"},
	surSky:  []string{"Озерец", "Боров", "Камен", "Снежин"},
	surEnko: []string{"Сидоренко", "Ткаченко", "Литвиненко"},
	orgs:    []string{"Белая гора", "Синий кит", "Металлоформ", "Тёплый дом", "Орбита-Сервис", "Лесные дали", "Профгарант", "Звезда Востока", "Речной порт", "Каскад"},
	towns:   []string{"Ясноборск", "Камышеградск", "Дубравинск", "Ольхогорье", "Светлозерск", "Рябиновск"},
	streets: []string{"Весенняя", "Рябиновая", "Озёрная", "Полевая", "Школьная", "Тенистая"},
	locs: [][3]string{{"Самара", "Самары", "Самаре"}, {"Омск", "Омска", "Омске"}, {"Пермь", "Перми", "Перми"},
		{"Мурманск", "Мурманска", "Мурманске"}, {"Германия", "Германии", "Германии"}, {"Сочи", "Сочи", "Сочи"}},
	input: []string{
		"Подскажи, как обратиться к {PER.dat} в официальном письме.",
		"Сверь реквизиты {ORG}: адрес доставки {ADDR}.",
		"Вчера {PER.nom} из {ORG} обещал прислать смету — напомни ему.",
		"передай {PER.dat}: встреча в 10, переговорка на третьем",
		"{PER.nom} просил скинуть презентацию для {ORGNAME}, сделай короче",
	},
	output: []string{"Посылка для {PER.gen} будет передана в пункт выдачи по адресу {ADDR}."},
	salt:   2,
}

// Шаблоны: {PER.<падеж>}, {ORG}, {ADDR}, {LOC.<падеж>} — падеж nom, gen,
// dat, ins, prep.
var nerInput = []string{
	"Составь письмо для {PER.gen} с напоминанием об оплате.",
	"Напиши поздравление {PER.dat} с днём рождения.",
	"Клиент {PER.nom} просит доставить заказ по адресу {ADDR}.",
	"Подготовь договор аренды между {ORG} и {PER.ins}.",
	"Мой адрес: {ADDR}. Когда приедет курьер?",
	"Сформулируй ответ на жалобу от {PER.gen}, адрес для ответа: {ADDR}.",
	"Кратко опиши, чем занимается {ORG}.",
	"Проверь служебную записку: прошу выплатить премию {PER.dat} за третий квартал.",
	"Найди ошибки в счёте для {ORG}, юридический адрес: {ADDR}.",
	"Запиши встречу с {PER.ins} в {LOC.prep} на пятницу.",
	"Сделай краткое резюме переписки {PER.gen} и {PER.gen}.",
	"Напомни {PER.dat}, что отчёт для {ORG} нужно сдать до 15 числа.",
	"{PER.nom}, руководитель отдела в {ORG}, просит подготовить презентацию.",
	"Отправь уведомление на адрес {ADDR} от имени {ORG}.",
	"Составь характеристику на сотрудника {PER.gen}.",
	"Нужна доверенность: {PER.nom} доверяет {PER.dat} получить посылку.",
	"Как вежливо отказать {PER.dat} в повышении зарплаты?",
	"В {ORG} пришло письмо от {PER.gen} — ответь коротко.",
	"Арендатор {PER.nom} съезжает из квартиры по адресу {ADDR}, составь акт.",
	"Перепиши официальнее: {PER.nom} опоздал на совещание в {ORG}.",
	"Заполни шаблон: получатель — {PER.nom}, адрес — {ADDR}.",
	"Поставщик {ORG} задерживает отгрузку, напиши претензию.",
	// Разговорные: без правовой формы, кавычек, отчества и «ул.».
	"скажи {PER.dat} что созвон переносится",
	"напиши {PER.dat} в чат, пусть пришлёт отчёт",
	"у {PER.gen} завтра день рождения, придумай тост",
	"закажи доставку на {ADDR} к семи вечера",
	"мы с {PER.ins} из компании {ORGNAME} не договорились о цене, как быть?",
}

var nerOutput = []string{
	"Готово: письмо адресовано {PER.dat}, копия направлена в {ORG}.",
	"По вашим данным клиент {PER.nom} зарегистрирован по адресу {ADDR}.",
	"Ответственный за проект — {PER.nom}, представитель {ORG}.",
	"Договор заключён между {ORG} и {PER.ins}.",
	"Курьер доставит заказ по адресу: {ADDR}.",
	"Я подготовил черновик благодарности {PER.dat}.",
	"Встреча с {PER.ins} назначена в офисе {ORG}.",
	"Согласно записи, {PER.nom} работает в {ORG} с прошлого года.",
}

var nerNegInput = []string{
	"Какая погода будет завтра в {LOC.prep}?",
	"Как добраться из {LOC.gen} до центра на поезде?",
	"Напиши функцию сортировки на Go.",
	"Объясни разницу между ООО и АО.",
	"Что такое ИНН и зачем он нужен?",
	"Составь план статьи о налогах для малого бизнеса.",
	"Почему иван-чай считают полезным?",
	"Переведи фразу «доброе утро» на немецкий.",
	"Посоветуй книги о {LOC.prep} для подростков.",
	"Как оформить заявление на отпуск?",
	"Сократи текст до трёх предложений: рынок облачных услуг растёт.",
	"Чем улица отличается от проспекта?",
	"Опиши климат в {LOC.prep}.",
	"Как написать вежливое письмо коллеге?",
	"Подбери синонимы к слову «надёжный».",
	"Сравни Python и Go для веб-сервисов.",
	"Какие документы нужны для открытия ООО?",
	"Что посмотреть в {LOC.prep} за выходные?",
	"Расскажи кратко историю {LOC.gen}.",
	"Сколько дней в високосном году?",
	"Напиши роман в трёх частях о море.",
	"Как сохранить веру в себя после неудачи?",
	"Что значит выражение «последняя надежда»?",
	"Объясни, что такое юридический адрес компании.",
	"Чем акционерное общество отличается от товарищества?",
	"Составь список дел на понедельник.",
	"Какие музеи есть в {LOC.prep}?",
	"Где хранить пароли от рабочих сервисов?",
	"Придумай название для кофейни у реки.",
	"Как правильно указать адрес в анкете: сначала город или улица?",
	"Вера и надежда — главные темы этого романа?",
	"Т. е. всё готово к релизу?",
	"Чем налоги ООО отличаются от налогов ИП?",
	"Сравни тарифы АО и ПАО для небольшой компании.",
}

var nerNegOutput = []string{
	"Вот пример функции сортировки слиянием.",
	"Для регистрации ООО нужны устав и решение учредителя.",
	"В {LOC.prep} завтра ожидается дождь.",
	"Рекомендую начать с плана из трёх разделов.",
	"Отпуск оформляется заявлением на имя руководителя.",
	"Население {LOC.gen} заметно выросло за последние годы.",
	"Юридический адрес указывается в уставе организации.",
	"Роман состоит из трёх частей и эпилога.",
	"{LOC.nom} — крупный транспортный узел.",
	"Вот список дел на понедельник: почта, звонки, отчёт.",
}

// nerRand — детерминированный генератор (splitmix64) по номеру примера;
// не для безопасности.
type nerRand struct{ s uint64 }

func (r *nerRand) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *nerRand) intn(n int) int { return int(r.next() % uint64(n)) } //nolint:gosec // G115: n > 0 и мало

func pick[T any](r *nerRand, xs []T) T { return xs[r.intn(len(xs))] }

// nerEntity — сущность: метка и границы в символах (code points), как
// индексы строк Python.
type nerEntity struct {
	Start, End int
	Label      string
}

// MarshalJSON — [начало, конец, метка].
func (e nerEntity) MarshalJSON() ([]byte, error) { return json.Marshal([]any{e.Start, e.End, e.Label}) }

type nerSample struct {
	Text     string
	Dir      string
	Entities []nerEntity
}

// build подставляет сущности в шаблон и размечает их.
func (v *nerVocab) build(r *nerRand, tmpl, dir string) nerSample {
	var b strings.Builder
	s := nerSample{Dir: dir, Entities: []nerEntity{}}
	for {
		i := strings.IndexByte(tmpl, '{')
		if i < 0 {
			b.WriteString(tmpl)
			break
		}
		j := strings.IndexByte(tmpl[i:], '}') + i
		b.WriteString(tmpl[:i])
		kind, c, _ := strings.Cut(tmpl[i+1:j], ".")
		tmpl = tmpl[j+1:]
		var val, label string
		switch kind {
		case "PER":
			val, label = v.person(r, caseOf(c)), "per"
		case "ORG":
			val, label = v.org(r), "org"
		case "ORGNAME": // название без правовой формы и кавычек
			val, label = pick(r, v.orgs), "org"
		case "ADDR":
			val, label = v.address(r), "addr"
		case "LOC": // формы мест: именительный, родительный, предложный
			forms := pick(r, v.locs)
			val, label = forms[0], "loc"
			switch caseOf(c) {
			case gen:
				val = forms[1]
			case prep:
				val = forms[2]
			}
		}
		// Иногда имя пишут строчными (чат): модель должна это выдержать.
		if label == "per" && r.intn(20) == 0 {
			val = strings.ToLower(val)
		}
		start := utf8.RuneCountInString(b.String())
		b.WriteString(val)
		s.Entities = append(s.Entities, nerEntity{Start: start, End: start + utf8.RuneCountInString(val), Label: label})
	}
	s.Text = b.String()
	return s
}

func caseOf(c string) int {
	switch c {
	case "gen":
		return gen
	case "dat":
		return dat
	case "ins":
		return ins
	case "prep":
		return prep
	}
	return nom
}

// person — имя в падеже c: полное, имя и фамилия, фамилия с инициалами,
// имя и отчество.
func (v *nerVocab) person(r *nerRand, c int) string {
	male := r.intn(2) == 0
	first := pick(r, v.female)
	if male {
		first = pick(r, v.male)
	}
	p := pick(r, v.patr)
	var sur string
	switch k := r.intn(10); {
	case k < 6:
		sur = declSurOv(pick(r, v.surOv), male, c)
	case k < 8:
		sur = declSurSky(pick(r, v.surSky), male, c)
	default:
		sur = pick(r, v.surEnko)
	}
	initials := string([]rune(first)[0]) + ". " + string([]rune(p)[0]) + "."
	switch r.intn(8) {
	case 0, 1:
		return sur + " " + declFirst(first, male, c) + " " + declPatr(p, male, c)
	case 2, 3:
		return declFirst(first, male, c) + " " + sur
	case 4:
		return sur + " " + initials
	case 5:
		return initials + " " + sur
	case 6:
		return declFirst(first, male, c) + " " + declPatr(p, male, c)
	default: // одно имя: «скажи Тарасу»
		return declFirst(first, male, c)
	}
}

// declFirst — имя в падеже: мужские на согласный, -й, -а/-я; женские на
// -а/-я, -ия, -ья.
func declFirst(n string, male bool, c int) string {
	if c == nom {
		return n
	}
	rs := []rune(n)
	last := rs[len(rs)-1]
	stem := string(rs[:len(rs)-1])
	switch {
	case last == 'й':
		return stem + [...]string{"", "я", "ю", "ем"}[c]
	case last == 'я' && strings.HasSuffix(n, "ия"):
		return stem + [...]string{"", "и", "и", "ей"}[c]
	case last == 'я':
		return stem + [...]string{"", "и", "е", "ей"}[c]
	case last == 'а':
		g := "ы"
		if strings.ContainsRune("гкхжшчщ", rs[len(rs)-2]) {
			g = "и"
		}
		return stem + [...]string{"", g, "е", "ой"}[c]
	case male:
		return n + [...]string{"", "а", "у", "ом"}[c]
	}
	return n
}

func declPatr(stem string, male bool, c int) string {
	if male {
		return stem + "ич" + [...]string{"", "а", "у", "ем"}[c]
	}
	return stem + [...]string{"на", "ны", "не", "ной"}[c]
}

// declSurOv — фамилия на -ов, -ев, -ёв, -ин.
func declSurOv(s string, male bool, c int) string {
	if male {
		return s + [...]string{"", "а", "у", "ым"}[c]
	}
	return s + [...]string{"а", "ой", "ой", "ой"}[c]
}

func declSurSky(root string, male bool, c int) string {
	if male {
		return root + [...]string{"ский", "ского", "скому", "ским"}[c]
	}
	return root + [...]string{"ская", "ской", "ской", "ской"}[c]
}

var orgForms = []string{"ООО", "АО", "ПАО", "ЗАО", "АНО"}

// org — организация: правовая форма и название в кавычках, иногда без формы.
func (v *nerVocab) org(r *nerRand) string {
	name := pick(r, v.orgs)
	switch r.intn(5) {
	case 0:
		return "«" + name + "»"
	case 1:
		return pick(r, orgForms) + " \"" + name + "\""
	default:
		return pick(r, orgForms) + " «" + name + "»"
	}
}

// Улицы: прилагательные — с «ул.», «улица», «наб.»; названия в
// родительном — с любым видом.
var (
	streetKinds    = []string{"ул.", "улица", "наб."}
	streetKindsAny = []string{"ул.", "пр-т", "проспект", "пер.", "наб."}
	streetsGen     = []string{"Строителей", "Космонавтов", "Мира", "Победы", "Гагарина"}
)

// address — почтовый адрес: индекс, город, улица, дом, корпус, квартира в
// разных записях.
func (v *nerVocab) address(r *nerRand) string {
	street := pick(r, streetKinds) + " " + pick(r, v.streets)
	if r.intn(4) == 0 {
		street = pick(r, streetKindsAny) + " " + pick(r, streetsGen)
	}
	house := fmt.Sprintf("%d", 1+r.intn(120))
	flat := fmt.Sprintf("%d", 1+r.intn(300))
	town := "г. " + pick(r, v.towns)
	index := fmt.Sprintf("%d%05d", 1+r.intn(6), r.intn(100000))
	switch r.intn(6) {
	case 5: // разговорная запись: «Озёрная 12-45»
		return pick(r, v.streets) + " " + house + "-" + flat
	case 0:
		return index + ", " + town + ", " + street + ", д. " + house + ", кв. " + flat
	case 1:
		return town + ", " + street + ", д. " + house + ", корп. " + fmt.Sprintf("%d", 1+r.intn(5)) + ", кв. " + flat
	case 2:
		return street + ", д. " + house
	case 3:
		return pick(r, v.towns) + ", " + street + ", дом " + house + ", квартира " + flat
	default:
		return town + ", " + street + ", " + house + "-" + flat
	}
}

// nerCategory — категория находки pii.ner по метке сущности (loc — нет).
var nerCategory = map[string]string{"per": "pii.person", "org": "pii.organization", "addr": "pii.address"}

// nerSampleAt — пример номер i части: 50% запросов и 15% ответов с
// сущностями, остальное — без ПДн (иногда с городом или страной).
func nerSampleAt(v *nerVocab, i uint64) nerSample {
	r := &nerRand{s: i*0x2545f4914f6cdd1d + 4200 + v.salt<<40}
	switch k := r.intn(20); {
	case k < 10:
		return v.build(r, pick(r, append(slices.Clip(nerInput), v.input...)), "input")
	case k < 13:
		return v.build(r, pick(r, append(slices.Clip(nerOutput), v.output...)), "output")
	case k < 18:
		return v.build(r, pick(r, nerNegInput), "input")
	default:
		return v.build(r, pick(r, nerNegOutput), "output")
	}
}

// runNER печатает примеры from…from+n-1 части split: format corpus —
// строки корпуса детекторов (expect — категории), spans — текст и
// сущности для обучения (tools/ml/prepare_ner.py).
func runNER(w io.Writer, split, format string, from uint64, n int) error {
	v := &nerTrain
	switch split {
	case "train":
	case "check":
		v = &nerCheck
	default:
		return errors.New("часть корпуса: train или check")
	}
	if format != "corpus" && format != "spans" {
		return errors.New("формат: corpus или spans")
	}
	if n < 1 || n > 10000 {
		return errors.New("n — от 1 до 10 000")
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	// Повторы текста пропускаются: n — число разных примеров, номера
	// примеров идут подряд с пропусками.
	seen := map[string]bool{}
	for i := uint64(0); len(seen) < n; i++ {
		if i >= uint64(n)*20 {
			return fmt.Errorf("не набрать %d разных примеров", n)
		}
		s := nerSampleAt(v, from+i)
		if seen[s.Text] {
			continue
		}
		seen[s.Text] = true
		if format == "spans" {
			if err := enc.Encode(struct {
				ID       string      `json:"id"`
				Dir      string      `json:"direction"`
				Text     string      `json:"text"`
				Entities []nerEntity `json:"entities"`
			}{fmt.Sprintf("ner-%s-%05d", split, from+i), s.Dir, s.Text, s.Entities}); err != nil {
				return err
			}
			continue
		}
		expect := []string{}
		for _, e := range s.Entities {
			if c, ok := nerCategory[e.Label]; ok && !slices.Contains(expect, c) {
				expect = append(expect, c)
			}
		}
		slices.Sort(expect)
		if err := enc.Encode(struct {
			ID     string   `json:"id"`
			Lang   string   `json:"lang"`
			Dir    string   `json:"direction"`
			Source string   `json:"source"`
			Text   string   `json:"text"`
			Expect []string `json:"expect"`
			Note   string   `json:"note"`
		}{fmt.Sprintf("ner-%s-%04d", split, from+i), "ru", s.Dir, sourceOf(s.Dir), s.Text, expect, "синтетика tools/synth-pii -kind ner"}); err != nil {
			return err
		}
	}
	return nil
}

func sourceOf(dir string) string {
	if dir == "output" {
		return "output"
	}
	return "user"
}
