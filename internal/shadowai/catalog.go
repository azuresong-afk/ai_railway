package shadowai

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Каталог доменов публичных ИИ-сервисов (ADR-0027, п. 4) — служебная база,
// подписанная рабочим ключом производителя. Исходник — catalog/catalog.yaml.

const (
	// CatalogFormat — значение поля format каталога.
	CatalogFormat = "aisec-shadow-ai-catalog-v1"
	// CatalogKind — вид служебной базы в подписи (ADR-0027, п. 3).
	CatalogKind = "shadow_ai_catalog"

	maxCatalogSize       = 2 << 20
	maxServices          = 2000
	maxNamesPerService   = 200
	maxNamesTotal        = 20000
	maxServiceIDLen      = 64
	maxServiceNameRunes  = 128
	maxHostLen           = 253
	maxLabelLen          = 63
	catalogDateLayout    = "2006-01-02"
	maxCatalogVersion    = 1<<53 - 1
	maxServiceVendorRune = 128
)

// Категории сервисов.
var categories = map[string]string{
	"chat":     "Чат-ассистент",
	"api":      "API моделей",
	"code":     "Помощник программиста",
	"image":    "Генерация изображений",
	"search":   "Поиск с ИИ",
	"platform": "Платформа моделей",
}

// CategoryTitle — название категории для интерфейса.
func CategoryTitle(c string) string { return categories[c] }

// CatalogService — сервис каталога.
type CatalogService struct {
	ID       string   `yaml:"id" json:"id"`
	Name     string   `yaml:"name" json:"name"`
	Vendor   string   `yaml:"vendor" json:"vendor"`
	Category string   `yaml:"category" json:"category"`
	Domains  []string `yaml:"domains,omitempty" json:"domains"`
	Suffixes []string `yaml:"suffixes,omitempty" json:"suffixes"`
}

// Catalog — разобранный каталог с индексом сопоставления.
type Catalog struct {
	Format   string           `yaml:"format"`
	Version  uint64           `yaml:"version"`
	Date     string           `yaml:"date"`
	Services []CatalogService `yaml:"services"`

	day      time.Time
	byID     map[string]int
	domains  map[string]int
	suffixes map[string]int
}

// Day — дата выпуска каталога (полночь UTC).
func (c *Catalog) Day() time.Time { return c.day }

// ByID — сервис по ID.
func (c *Catalog) ByID(id string) (CatalogService, bool) {
	i, ok := c.byID[id]
	if !ok {
		return CatalogService{}, false
	}
	return c.Services[i], true
}

// ParseCatalog строго разбирает YAML каталога (неизвестные поля, повтор
// имён и ID, неверные имена узлов — отказ) и строит индекс. Вход —
// содержимое подписанной базы или исходник для подписи; разбор покрыт
// fuzz-тестом FuzzParseCatalog.
func ParseCatalog(data []byte) (*Catalog, error) {
	if len(data) == 0 || len(data) > maxCatalogSize {
		return nil, fmt.Errorf("каталог: размер от 1 до %d байт", maxCatalogSize)
	}
	var c Catalog
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("каталог: неверный YAML: %w", yamlErr(err))
	}
	// Второй документ в файле — ошибка: подписанное содержимое однозначно.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("каталог: в файле больше одного документа YAML")
	}
	if err := c.index(); err != nil {
		return nil, fmt.Errorf("каталог: %w", err)
	}
	return &c, nil
}

// yamlErr укорачивает сообщение разборщика: в нём может быть кусок файла.
func yamlErr(err error) error {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return errors.New(s)
}

func (c *Catalog) index() error {
	if c.Format != CatalogFormat {
		return fmt.Errorf("format — %s", CatalogFormat)
	}
	if c.Version == 0 || c.Version > maxCatalogVersion {
		return errors.New("version — целое от 1")
	}
	day, err := time.Parse(catalogDateLayout, c.Date)
	if err != nil || day.Year() < 2020 || day.Year() > 9999 {
		return errors.New("date — дата ГГГГ-ММ-ДД")
	}
	c.day = day
	if len(c.Services) == 0 || len(c.Services) > maxServices {
		return fmt.Errorf("services — от 1 до %d сервисов", maxServices)
	}
	c.byID = make(map[string]int, len(c.Services))
	c.domains = map[string]int{}
	c.suffixes = map[string]int{}
	total := 0
	for i, s := range c.Services {
		switch {
		case !validServiceID(s.ID):
			return fmt.Errorf("сервис %d: id — [a-z0-9-] до %d символов, с буквы или цифры", i+1, maxServiceIDLen)
		case !validText(s.Name, maxServiceNameRunes) || strings.TrimSpace(s.Name) == "":
			return fmt.Errorf("сервис %s: name — до %d символов без управляющих", s.ID, maxServiceNameRunes)
		case !validText(s.Vendor, maxServiceVendorRune):
			return fmt.Errorf("сервис %s: vendor — до %d символов без управляющих", s.ID, maxServiceVendorRune)
		case categories[s.Category] == "":
			return fmt.Errorf("сервис %s: неизвестная категория", s.ID)
		case len(s.Domains)+len(s.Suffixes) == 0 || len(s.Domains)+len(s.Suffixes) > maxNamesPerService:
			return fmt.Errorf("сервис %s: от 1 до %d имён в domains и suffixes", s.ID, maxNamesPerService)
		}
		if _, dup := c.byID[s.ID]; dup {
			return fmt.Errorf("сервис %s: id повторяется", s.ID)
		}
		c.byID[s.ID] = i
		total += len(s.Domains) + len(s.Suffixes)
		if total > maxNamesTotal {
			return fmt.Errorf("больше %d имён узлов", maxNamesTotal)
		}
		for _, list := range []struct {
			names []string
			idx   map[string]int
		}{{s.Domains, c.domains}, {s.Suffixes, c.suffixes}} {
			for _, d := range list.names {
				if !validCatalogHost(d) {
					return fmt.Errorf("сервис %s: имя %q — строчная латиница, цифры, «-» и «.», не меньше двух меток", s.ID, truncate(d, 64))
				}
				if _, dup := c.domains[d]; dup {
					return fmt.Errorf("сервис %s: имя %s уже есть в каталоге", s.ID, d)
				}
				if _, dup := c.suffixes[d]; dup {
					return fmt.Errorf("сервис %s: имя %s уже есть в каталоге", s.ID, d)
				}
				list.idx[d] = i
			}
		}
	}
	return nil
}

func validServiceID(s string) bool {
	if s == "" || len(s) > maxServiceIDLen || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func validText(s string, maxRunes int) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxRunes {
		return false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return false
		}
	}
	return true
}

// validCatalogHost — имя узла каталога в каноническом виде: строчные
// буквы ASCII, цифры и «-» в метках, не меньше двух меток, метка не
// начинается и не кончается «-», последняя метка не только из цифр (не
// адрес IPv4).
func validCatalogHost(h string) bool {
	if len(h) == 0 || len(h) > maxHostLen {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > maxLabelLen || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// NormalizeHost приводит имя узла из журнала к виду каталога: нижний
// регистр ASCII, без порта, завершающей точки и квадратных скобок. Адрес IP,
// имя не из ASCII и имя с пустой меткой дают ok = false: они не
// сопоставляются (DM-37).
func NormalizeHost(h string) (string, bool) {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") {
		return "", false // IPv6 в скобках
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		if strings.Count(h, ":") > 1 {
			return "", false // IPv6 без скобок
		}
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	// «a..» — пустая метка: не имя узла (после снятия одной точки остаётся «a.»).
	if h == "" || len(h) > maxHostLen || strings.HasSuffix(h, ".") {
		return "", false
	}
	// Пустая метка («..», «.a», «a..b») — не имя узла: иначе «..» дало бы «.»,
	// которое при повторной нормализации меняется (FuzzParseSquid).
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return "", false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", false
	}
	b := []byte(h)
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			b[i] = c + 'a' - 'A'
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return "", false
		}
	}
	return string(b), true
}

// Match сопоставляет нормализованное имя узла с каталогом: точное имя из
// domains, затем самый длинный суффикс по меткам из suffixes. Регулярных
// выражений нет: время — линейное по длине имени (DM-37).
func (c *Catalog) Match(host string) (CatalogService, bool) {
	if i, ok := c.domains[host]; ok {
		return c.Services[i], true
	}
	for h := host; ; {
		if i, ok := c.suffixes[h]; ok {
			return c.Services[i], true
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 {
			return CatalogService{}, false
		}
		h = h[dot+1:]
	}
}
