package inventory

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/injection"
	"github.com/azuresong-afk/ai_railway/internal/detect/unihidden"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Эталоны шаблонов чата (DM-28; задача 5.21 этапа 5, ADR-0029, п. 4 и
// дополнение 1) — служебная база по ADR-0028: вид chat_template_baselines,
// содержимое — JSON. Эталон — семейство и вариант модели, SHA-256
// нормализованного шаблона, источник и лицензия; текст шаблона — только
// если лицензия источника разрешает распространение. Сервер сверяет с ней
// шаблоны чата из отчётов сканера и проверяет их детекторами инъекций.

// Вид и формат базы эталонов.
const (
	TemplatesKind   = "chat_template_baselines"
	TemplatesFormat = "aisec-chat-templates-v1"
)

// Пределы базы эталонов (содержимое — до 2 МиБ, предел конверта).
const (
	MaxTemplateFamilies    = 1000
	MaxFamilyTemplates     = 200
	MaxBaseTemplates       = 5000
	MaxFamilyMatch         = 16
	maxFamilyTitle         = 200
	maxTemplateSource      = 512
	maxTemplateVariant     = 128
	maxTemplateLicense     = 64
	maxTemplateNameInBase  = 128
	minFamilyMatchPatterns = 1
)

// RedistributableLicenses — лицензии источников, при которых текст шаблона
// можно включать в базу: разрешено распространение без особых условий.
// Прочие (лицензии сообщества Llama, Gemma, CC-BY-NC и т. п.) — только хеш.
var RedistributableLicenses = []string{"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC"}

// TemplateBaseline — эталонный шаблон варианта модели.
type TemplateBaseline struct {
	Variant string `json:"variant"`
	// Name — имя именованного шаблона (tool_use и т. п.); пусто — основной.
	Name    string `json:"name,omitempty"`
	SHA256  string `json:"sha256"`
	Source  string `json:"source"`
	License string `json:"license"`
	Text    string `json:"text,omitempty"`
}

// TemplateFamily — семейство моделей. Match — подстроки имени модели в
// нижнем регистре, по которым модель реестра относится к семейству.
type TemplateFamily struct {
	ID        string             `json:"id"`
	Title     string             `json:"title"`
	Match     []string           `json:"match"`
	Templates []TemplateBaseline `json:"templates"`
}

// TemplateBase — содержимое базы эталонов.
type TemplateBase struct {
	Format   string           `json:"format"`
	Version  uint64           `json:"version"`
	Date     string           `json:"date"`
	Families []TemplateFamily `json:"families"`

	day    time.Time
	byHash map[string][]templateRef
	count  int
}

type templateRef struct {
	family  string
	variant string
}

var (
	familyIDRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	familyMatchRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	licenseRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$`)
)

// TemplatesDBKind — вид служебной базы эталонов для internal/servicedb и
// реестра видов выпуска (internal/servicedb/kinds).
func TemplatesDBKind() servicedb.Kind {
	return servicedb.Kind{Name: TemplatesKind, Title: "Эталоны шаблонов чата", Parse: func(b []byte) (servicedb.Content, error) {
		base, err := ParseTemplateBase(b)
		if err != nil {
			return servicedb.Content{}, err
		}
		return servicedb.Content{Value: base, Version: base.Version, Date: base.day, Records: base.count}, nil
	}}
}

// ParseTemplateBase разбирает и проверяет содержимое базы эталонов: строгий
// JSON, пределы, хеш текста совпадает с указанным, текст — только при
// лицензии из RedistributableLicenses.
func ParseTemplateBase(data []byte) (*TemplateBase, error) {
	var b TemplateBase
	if err := decodeStrictLimit(data, &b, aisecCrypto.MaxServiceDBPayload); err != nil {
		return nil, err
	}
	var l errList
	if b.Format != TemplatesFormat {
		l.add("format — %s", TemplatesFormat)
	}
	if b.Version == 0 || b.Version > servicedb.MaxVersion {
		l.add("version — целое от 1")
	}
	day, err := time.Parse(time.DateOnly, b.Date)
	if err != nil {
		l.add("date — ГГГГ-ММ-ДД")
	}
	if len(b.Families) == 0 || len(b.Families) > MaxTemplateFamilies {
		l.add("families — от 1 до %d семейств", MaxTemplateFamilies)
		return nil, l.err()
	}
	h, herr := sha256Hasher()
	if herr != nil {
		return nil, herr
	}
	b.byHash = map[string][]templateRef{}
	ids := map[string]bool{}
	for i, f := range b.Families {
		field := fmt.Sprintf("families[%d]", i)
		if !familyIDRe.MatchString(f.ID) {
			l.add("%s.id — строчные латинские буквы, цифры, «.», «-», «_», до 64 символов", field)
		} else if ids[f.ID] {
			l.add("%s.id — повторяется", field)
		}
		ids[f.ID] = true
		for _, e := range text(field+".title", f.Title, 1, maxFamilyTitle) {
			l.add("%v", e)
		}
		if len(f.Match) < minFamilyMatchPatterns || len(f.Match) > MaxFamilyMatch {
			l.add("%s.match — от %d до %d подстрок имени модели", field, minFamilyMatchPatterns, MaxFamilyMatch)
		}
		for j, m := range f.Match {
			if !familyMatchRe.MatchString(m) {
				l.add("%s.match[%d] — от 2 до 64 символов: строчные латинские буквы, цифры, «.», «-», «_»", field, j)
			}
		}
		if len(f.Templates) == 0 || len(f.Templates) > MaxFamilyTemplates {
			l.add("%s.templates — от 1 до %d эталонов", field, MaxFamilyTemplates)
			continue
		}
		variants := map[string]bool{}
		for j, t := range f.Templates {
			tf := fmt.Sprintf("%s.templates[%d]", field, j)
			b.count++
			if key := t.Variant + "\x00" + t.Name; variants[key] {
				l.add("%s — вариант и имя шаблона повторяются в семействе", tf)
			} else {
				variants[key] = true
			}
			for _, e := range text(tf+".variant", t.Variant, 1, maxTemplateVariant) {
				l.add("%v", e)
			}
			if len(t.Name) > maxTemplateNameInBase || !utf8.ValidString(t.Name) || strings.IndexFunc(t.Name, hidden) >= 0 {
				l.add("%s.name — до %d байт без управляющих символов", tf, maxTemplateNameInBase)
			}
			if !hashRe.MatchString(t.SHA256) {
				l.add("%s.sha256 — 64 шестнадцатеричных символа в нижнем регистре", tf)
			}
			if !httpsSource(t.Source) {
				l.add("%s.source — адрес https до %d байт", tf, maxTemplateSource)
			}
			if !licenseRe.MatchString(t.License) {
				l.add("%s.license — идентификатор лицензии (SPDX или краткое имя), до %d символов", tf, maxTemplateLicense)
			}
			if t.Text != "" {
				switch {
				case !slices.Contains(RedistributableLicenses, t.License):
					l.add("%s.text — текст шаблона допускается только при лицензии %s", tf, strings.Join(RedistributableLicenses, ", "))
				case len(t.Text) > MaxTemplateBytes || !utf8.ValidString(t.Text) || strings.ContainsRune(t.Text, 0):
					l.add("%s.text — до %d КиБ в UTF-8 без нулевых символов", tf, MaxTemplateBytes>>10)
				case hex.EncodeToString(h.Sum([]byte(NormalizeTemplate(t.Text)))) != t.SHA256:
					l.add("%s.sha256 — не совпадает с хешем нормализованного текста", tf)
				}
			}
			b.byHash[t.SHA256] = append(b.byHash[t.SHA256], templateRef{family: f.ID, variant: t.Variant})
		}
	}
	if b.count > MaxBaseTemplates {
		l.add("templates — не больше %d эталонов в базе", MaxBaseTemplates)
	}
	if err := l.err(); err != nil {
		return nil, err
	}
	b.day = day.UTC()
	return &b, nil
}

func httpsSource(s string) bool {
	if s == "" || len(s) > maxTemplateSource || !utf8.ValidString(s) || strings.IndexFunc(s, hidden) >= 0 || strings.ContainsAny(s, " \t") {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// sha256Hasher — SHA-256 в обоих криптопрофилях (ADR-0029, п. 1): хеши
// шаблонов сверяются с эталонами производителя, у которых алгоритм один.
func sha256Hasher() (aisecCrypto.Hasher, error) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return nil, err
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	if h.Name() != HashAlg {
		return nil, errors.New("реестр ИИ: хеш стандартного профиля — не SHA-256")
	}
	return h, nil
}

// NormalizeTemplate — нормализация шаблона перед хешированием: метка
// порядка байтов в начале убирается, переводы строк CRLF и CR — в LF,
// пробелы и табуляции в конце строк и пустые строки в начале и в конце
// убираются. Остальное (в том числе скрытые символы Unicode) сохраняется:
// любое изменение видимого или невидимого текста меняет хеш.
func NormalizeTemplate(s string) string {
	s = strings.TrimPrefix(s, "\ufeff")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimRight(ln, " \t")
	}
	return strings.Trim(strings.Join(lines, "\n"), "\n")
}

// TemplateHash — SHA-256 нормализованного шаблона, шестнадцатеричный.
func TemplateHash(s string) (string, error) {
	h, err := sha256Hasher()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum([]byte(NormalizeTemplate(s)))), nil
}

// familyOf — семейство модели по имени: самая длинная подходящая подстрока
// (llama-3.1 точнее llama-3). Пусто — семейство неизвестно.
func (b *TemplateBase) familyOf(name string) string {
	name = strings.ToLower(name)
	best, bestLen := "", 0
	for _, f := range b.Families {
		for _, m := range f.Match {
			if len(m) > bestLen && strings.Contains(name, m) {
				best, bestLen = f.ID, len(m)
			}
		}
	}
	return best
}

func (b *TemplateBase) hasFamily(id string) bool {
	return slices.ContainsFunc(b.Families, func(f TemplateFamily) bool { return f.ID == id })
}

// Итоги проверки шаблона чата.
const (
	TemplatesNone      = "none"      // шаблонов в отчёте нет
	TemplateBaselineOK = "baseline"  // совпал с эталоном
	TemplateUnknown    = "unknown"   // эталона семейства нет
	TemplateChanged    = "changed"   // отличается от эталонов семейства
	TemplateInjection  = "injection" // детектор нашёл внедрённые инструкции
)

// templateRank — порядок итогов: итог отчёта — наихудший итог шаблона.
var templateRank = map[string]int{TemplatesNone: 0, TemplateBaselineOK: 1, TemplateUnknown: 2, TemplateChanged: 3, TemplateInjection: 4}

// TemplateFinding — находка детектора в шаблоне без текста шаблона.
type TemplateFinding struct {
	Detector string  `json:"detector"`
	Category string  `json:"category"`
	Rule     string  `json:"rule,omitempty"`
	Score    float64 `json:"score"`
}

// TemplateCheck — итог проверки одного шаблона чата.
type TemplateCheck struct {
	File    string `json:"file"`
	Source  string `json:"source"`
	Name    string `json:"name,omitempty"`
	SHA256  string `json:"sha256"`
	Result  string `json:"result"`
	Family  string `json:"family,omitempty"`
	Variant string `json:"variant,omitempty"`
	// BaseVersion — версия базы эталонов, с которой сверялся шаблон; 0 —
	// базы нет.
	BaseVersion uint64            `json:"base_version"`
	Findings    []TemplateFinding `json:"findings,omitempty"`
}

// templateDetectors — детекторы, которыми проверяется шаблон чата: эвристика
// инъекций и скрытые символы Unicode (как описания инструментов MCP,
// задача 4.11).
var templateDetectors = []detect.Detector{injection.New(), unihidden.New()}

// maxTemplateFindings — находок детекторов на шаблон в отчёте.
const maxTemplateFindings = 20

// templateMarkup — находка, которую даёт сама разметка шаблона чата:
// служебные метки ролей (<|im_start|>, <|eot_id|> и т. п.) — категория
// injection.structure и склейка меток (правило concat.token). В запросе
// пользователя это признак инъекции, а в шаблоне чата — его назначение;
// по ним шаблон не отличить от эталона (проверено на шаблонах 19 открытых
// моделей). Остальные находки — переопределение инструкций, смена роли,
// утечка, прочая обфускация и скрытые символы Unicode — учитываются.
func templateMarkup(f detect.Finding) bool {
	return f.Detector == injection.ID && (f.Category == injection.CatStructure || f.Category == injection.CatObfuscation && f.Rule == "concat.token")
}

// checkTemplate сверяет шаблон с эталонами и проверяет детекторами.
// Совпадение с эталоном — доверенный шаблон издателя: находки детекторов
// в нём не делают итог «инъекция» (служебные метки шаблонов похожи на
// разметку ролей), но сохраняются в отчёте.
func checkTemplate(ctx context.Context, base *TemplateBase, version uint64, model string, file string, t ReportTemplate) (TemplateCheck, error) {
	sum, err := TemplateHash(t.Text)
	if err != nil {
		return TemplateCheck{}, err
	}
	c := TemplateCheck{File: file, Source: t.Source, Name: t.Name, SHA256: sum, Result: TemplateUnknown, BaseVersion: version}
	family := ""
	if base != nil {
		family = base.familyOf(model)
		c.Family = family
		if refs := base.byHash[sum]; len(refs) > 0 {
			ref := refs[0]
			for _, r := range refs {
				if r.family == family {
					ref = r
					break
				}
			}
			c.Result, c.Family, c.Variant = TemplateBaselineOK, ref.family, ref.variant
		}
	}
	for _, d := range templateDetectors {
		fs, err := d.Detect(ctx, detect.Text{Text: t.Text, Direction: detect.Input, Source: detect.SourceTool})
		if err != nil {
			return TemplateCheck{}, err
		}
		for _, f := range fs {
			if templateMarkup(f) {
				continue
			}
			if len(c.Findings) < maxTemplateFindings {
				c.Findings = append(c.Findings, TemplateFinding{Detector: f.Detector, Category: f.Category, Rule: f.Rule, Score: f.Score})
			}
		}
	}
	switch {
	case c.Result == TemplateBaselineOK:
	case len(c.Findings) > 0:
		c.Result = TemplateInjection
	case family != "" && base != nil && base.hasFamily(family):
		c.Result = TemplateChanged
	}
	return c, nil
}
