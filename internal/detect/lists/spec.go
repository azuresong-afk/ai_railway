package lists

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect/unihidden"
)

// Пределы правил заказчика (план этапа 1, Р5). Правила приходят из файла
// конфигурации, который пишет администратор, но их число и размер всё равно
// ограничены: словарь и выражения работают на каждом запросе.
const (
	MaxLists        = 64
	MaxWordsPerList = 10000
	MaxWordsTotal   = 20000
	MaxWordBytes    = 128
	MaxWordTokens   = 8
	MaxRegexTotal   = 32
	MaxRegexBytes   = 512
	// MaxRegexInsts — размер скомпилированной программы RE2: ограничивает
	// вложенные повторы вида (a{1000}){1000}, которые безопасны по времени
	// (RE2 линейный), но раздувают память и время каждой проверки.
	MaxRegexInsts = 4000
	// MinStemRunes и MaxStemRunes — длина основы со звёздочкой («взрывчат*»).
	MinStemRunes = 3
	MaxStemRunes = 32
	// DefaultScore — оценка находки, если в списке не указана своя.
	DefaultScore = 0.9
	// DefaultThreat — строка матрицы по умолчанию: запросы на запрещённые темы.
	DefaultThreat = "DM-35"
	// DefaultCategory — вид находки по умолчанию: lists.match.
	DefaultCategory = "match"
)

// Spec — один список заказчика: словарь слов и фраз и/или регулярные
// выражения. Поля с тегами yaml читает internal/config (раздел lists
// приложения).
type Spec struct {
	// ID — имя списка (попадает в правило находки: list.<id>).
	ID string `yaml:"id"`
	// Category — вид находки, lists.<category>: topic, codename, stopword…
	Category string `yaml:"category"`
	// Threat — строка матрицы: DM-18, DM-19, DM-32 или DM-35 (по умолчанию).
	Threat string `yaml:"threat"`
	// Score — оценка находки, 0,1–1 (по умолчанию 0,9).
	Score float64 `yaml:"score"`
	// Direction — input, output или both (по умолчанию).
	Direction string `yaml:"direction"`
	// Words — слова и фразы: без учёта регистра, ё = е, знаки препинания и
	// скрытые символы не мешают; «взрывчат*» — любое слово с такой основой
	// (звёздочка только в конце последнего слова).
	Words []string `yaml:"words"`
	// Regex — выражения RE2 (стандартный regexp) по исходному тексту.
	Regex []string `yaml:"regex"`
	// CaseSensitive — различать регистр в Regex (по умолчанию нет).
	CaseSensitive bool `yaml:"case_sensitive"`
}

var (
	idRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	categoryRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	threats    = map[string]bool{"DM-18": true, "DM-19": true, "DM-32": true, "DM-35": true}
)

type regexRule struct {
	re   *regexp.Regexp
	list int
}

// compiled — разобранный набор списков.
type compiled struct {
	lists []listInfo
	// exact — нормализованная фраза → списки; stem[n] — фраза с основой
	// последнего слова (n слов) → списки; stemLens[n] — длины основ в
	// символах, которые есть в словаре.
	exact    map[string][]uint16
	stem     [MaxWordTokens + 1]map[string][]uint16
	stemLens [MaxWordTokens + 1][]int
	// first[слово] — битовая маска длин фраз из двух и более слов, которые
	// начинаются с этого слова: окна проверяются только после попадания.
	first map[string]uint16
	rx    []regexRule
}

type listInfo struct {
	id, category, threat string
	score                float64
	dirs                 [2]bool // input, output
}

// phrase разбирает слово или фразу словаря: нормализованные слова и признак
// основы.
func phrase(w string) (norm string, stem bool, err error) {
	if len(w) == 0 || len(w) > MaxWordBytes || !utf8.ValidString(w) {
		return "", false, fmt.Errorf("слово %q: длина 1–%d байт, UTF-8", truncate(w), MaxWordBytes)
	}
	if strings.HasSuffix(w, "*") {
		stem = true
		w = w[:len(w)-1]
	}
	if strings.Contains(w, "*") {
		return "", false, fmt.Errorf("слово %q: звёздочка только в конце", truncate(w))
	}
	_, toks, normBytes := tokenize(w)
	if len(toks) == 0 {
		return "", false, fmt.Errorf("слово %q: нет букв и цифр", truncate(w))
	}
	if len(toks) > MaxWordTokens {
		return "", false, fmt.Errorf("слово %q: больше %d слов во фразе", truncate(w), MaxWordTokens)
	}
	norm = string(normBytes)
	if stem {
		n := utf8.RuneCountInString(lastToken(norm))
		if n < MinStemRunes || n > MaxStemRunes {
			return "", false, fmt.Errorf("слово %q: основа — от %d до %d символов", truncate(w), MinStemRunes, MaxStemRunes)
		}
	} else if utf8.RuneCountInString(norm) < 2 {
		return "", false, fmt.Errorf("слово %q: короче двух символов", truncate(w))
	}
	return norm, stem, nil
}

func lastToken(norm string) string {
	if i := strings.LastIndexByte(norm, ' '); i >= 0 {
		return norm[i+1:]
	}
	return norm
}

func truncate(s string) string {
	if len(s) > 32 {
		s = s[:32]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
		s += "…"
	}
	return s
}

// compileRegex компилирует выражение RE2 с проверкой длины, размера
// программы и пустого совпадения.
func compileRegex(expr string, caseSensitive bool) (*regexp.Regexp, error) {
	if len(expr) == 0 || len(expr) > MaxRegexBytes || !utf8.ValidString(expr) {
		return nil, fmt.Errorf("выражение %q: длина 1–%d байт, UTF-8", truncate(expr), MaxRegexBytes)
	}
	full := expr
	if !caseSensitive {
		full = "(?i)" + expr
	}
	re, err := syntax.Parse(full, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("выражение %q: %w", truncate(expr), err)
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		return nil, fmt.Errorf("выражение %q: %w", truncate(expr), err)
	}
	if len(prog.Inst) > MaxRegexInsts {
		return nil, fmt.Errorf("выражение %q: слишком большое (%d инструкций, предел %d)", truncate(expr), len(prog.Inst), MaxRegexInsts)
	}
	c, err := regexp.Compile(full)
	if err != nil {
		return nil, fmt.Errorf("выражение %q: %w", truncate(expr), err)
	}
	// Пустое совпадение размечало бы каждую позицию текста.
	if c.MatchString("") {
		return nil, fmt.Errorf("выражение %q: совпадает с пустой строкой", truncate(expr))
	}
	return c, nil
}

// Validate проверяет списки заказчика и возвращает все ошибки сразу.
func Validate(specs []Spec) error {
	_, err := compile(specs)
	return err
}

func compile(specs []Spec) (*compiled, error) {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if len(specs) > MaxLists {
		return nil, fmt.Errorf("списков больше %d", MaxLists)
	}
	c := &compiled{exact: map[string][]uint16{}, first: map[string]uint16{}}
	for n := range c.stem {
		c.stem[n] = map[string][]uint16{}
	}
	stemLenSet := [MaxWordTokens + 1]map[int]bool{}
	ids := map[string]bool{}
	words, regexes := 0, 0
	for i, s := range specs {
		at := fmt.Sprintf("lists[%d] (%s)", i, s.ID)
		if !idRe.MatchString(s.ID) {
			add("%s: id — строчные латинские буквы, цифры и дефис, до 32 символов", at)
		}
		if ids[s.ID] {
			add("%s: список указан дважды", at)
		}
		ids[s.ID] = true
		info := listInfo{id: s.ID, category: s.Category, threat: s.Threat, score: s.Score}
		if info.category == "" {
			info.category = DefaultCategory
		}
		if !categoryRe.MatchString(info.category) {
			add("%s: category — строчные латинские буквы, цифры и подчёркивание", at)
		}
		if info.threat == "" {
			info.threat = DefaultThreat
		}
		if !threats[info.threat] {
			add("%s: threat — DM-18, DM-19, DM-32 или DM-35", at)
		}
		if info.score == 0 {
			info.score = DefaultScore
		}
		if !(info.score >= 0.1 && info.score <= 1) {
			add("%s: score — от 0,1 до 1", at)
		}
		switch s.Direction {
		case "", "both":
			info.dirs = [2]bool{true, true}
		case "input":
			info.dirs[0] = true
		case "output":
			info.dirs[1] = true
		default:
			add("%s: direction — input, output или both", at)
		}
		if len(s.Words) == 0 && len(s.Regex) == 0 {
			add("%s: нужны words или regex", at)
		}
		if len(s.Words) > MaxWordsPerList {
			add("%s: слов больше %d", at, MaxWordsPerList)
			continue
		}
		li := uint16(len(c.lists)) //nolint:gosec // G115: списков не больше MaxLists (64)
		c.lists = append(c.lists, info)
		for _, w := range s.Words {
			words++
			if words > MaxWordsTotal {
				break
			}
			norm, stem, err := phrase(w)
			if err != nil {
				add("%s: %v", at, err)
				continue
			}
			n := strings.Count(norm, " ") + 1
			m := c.exact
			if stem {
				m = c.stem[n]
				l := utf8.RuneCountInString(lastToken(norm))
				if stemLenSet[n] == nil {
					stemLenSet[n] = map[int]bool{}
				}
				if !stemLenSet[n][l] {
					stemLenSet[n][l] = true
					c.stemLens[n] = append(c.stemLens[n], l)
				}
			}
			if cur := m[norm]; len(cur) == 0 || cur[len(cur)-1] != li {
				m[norm] = append(cur, li)
			}
			if n > 1 {
				head, _, _ := strings.Cut(norm, " ")
				c.first[head] |= 1 << n
			}
		}
		for _, expr := range s.Regex {
			regexes++
			if regexes > MaxRegexTotal {
				break
			}
			re, err := compileRegex(expr, s.CaseSensitive)
			if err != nil {
				add("%s: %v", at, err)
				continue
			}
			c.rx = append(c.rx, regexRule{re: re, list: int(li)})
		}
	}
	if words > MaxWordsTotal {
		add("слов во всех списках больше %d", MaxWordsTotal)
	}
	if regexes > MaxRegexTotal {
		add("выражений во всех списках больше %d", MaxRegexTotal)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("списки: %w", err)
	}
	return c, nil
}

// tokenize нормализует текст для поиска слов: скрытые символы и подмены
// букв устраняются (unihidden.Clean), регистр сводится к нижнему, ё к е,
// словом считается подряд идущие буквы и цифры. Возвращает токены и
// нормализованную строку, где слова разделены одним пробелом.
func tokenize(text string) (offs []int, toks []token, norm []byte) {
	clean, offs := unihidden.Clean(text)
	inTok := false
	for i := 0; i < len(clean); {
		r, size := utf8.DecodeRuneInString(clean[i:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || inTok && unicode.IsMark(r) {
			if !inTok {
				if len(norm) > 0 {
					norm = append(norm, ' ')
				}
				toks = append(toks, token{ns: len(norm), os: offs[i]})
				inTok = true
			}
			r = unicode.ToLower(r)
			if r == 'ё' {
				r = 'е'
			}
			norm = utf8.AppendRune(norm, r)
			i += size
			toks[len(toks)-1].ne = len(norm)
			toks[len(toks)-1].oe = offs[i]
			continue
		}
		inTok = false
		i += size
	}
	return offs, toks, norm
}

type token struct {
	ns, ne int // в нормализованной строке
	os, oe int // в исходном тексте
}
