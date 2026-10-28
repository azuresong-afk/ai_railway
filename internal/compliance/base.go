package compliance

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// База требований (ТЗ 2.3, решение Р10): служебная база с источником,
// пунктом, пересказом своими словами, применимостью, признаком «проект»,
// автоматическими проверками и ссылками на доказательства. Встроена в
// сборку (requirements/*.yaml) и обновляется подписанной служебной базой
// вида BaseKind без изменения кода (ADR-0027, п. 3).

const (
	// BaseFormat — значение поля format.
	BaseFormat = "aisec-compliance-base-v1"
	// BaseKind — вид служебной базы в подписи (ADR-0027, п. 3).
	BaseKind = "compliance_requirements"

	maxBaseSize        = 2 << 20
	maxRequirements    = 500
	maxSources         = 50
	maxChecksPerReq    = 8
	maxEvidencePerReq  = 12
	maxParams          = 6
	maxIDLen           = 64
	maxTitleRunes      = 160
	maxSummaryRunes    = 600
	maxClauseRunes     = 120
	maxHintRunes       = 200
	maxParamValueRunes = 64
	maxBaseVersion     = 1<<53 - 1
	baseDateLayout     = "2006-01-02"
)

// Применимость требования (ТЗ 2.1, 2.4).
const (
	AppliesGIS        = "gis"
	AppliesKII        = "kii"
	AppliesISPDn      = "ispdn"
	AppliesCommercial = "commercial"
)

var applicabilityTitles = map[string]string{
	AppliesGIS:        "ГИС",
	AppliesKII:        "КИИ",
	AppliesISPDn:      "ИСПДн",
	AppliesCommercial: "Коммерческий оператор",
}

// Applicabilities — значения применимости в порядке показа.
func Applicabilities() []string {
	return []string{AppliesGIS, AppliesKII, AppliesISPDn, AppliesCommercial}
}

// ApplicabilityTitle — название применимости для интерфейса.
func ApplicabilityTitle(a string) string { return applicabilityTitles[a] }

// Виды доказательств.
const (
	EvidenceScreen = "screen" // экран настроек консоли
	EvidenceAudit  = "audit"  // фильтр журнала аудита
	EvidenceEvents = "events" // фильтр событий
	EvidenceReport = "report" // отчёт
)

// consolePaths — разделы консоли, на которые вправе ссылаться доказательства.
// Ссылки только внутрь консоли: внешних адресов в базе быть не может.
var consolePaths = map[string]bool{
	"/": true, "/events": true, "/alerts": true, "/incidents": true, "/apps": true, "/providers": true,
	"/policies": true, "/usage": true, "/agents": true, "/approvals": true, "/shadow-ai": true,
	"/compliance": true, "/reports": true, "/admin": true, "/system": true,
}

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	sourceRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)
	paramKey  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	queryKey  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`)
	queryText = regexp.MustCompile(`^[A-Za-z0-9 _.:=,()'-]{1,128}$`)
)

// Source — источник требований (документ).
type Source struct {
	ID    string `yaml:"id" json:"id"`
	Title string `yaml:"title" json:"title"`
}

// CheckRef — ссылка на именованную проверку Go с параметрами. Языка
// выражений нет: имя и параметры проверяются по реестру при загрузке базы.
type CheckRef struct {
	Name   string            `yaml:"name" json:"name"`
	Params map[string]string `yaml:"params,omitempty" json:"params,omitempty"`
}

// Evidence — ссылка на доказательство: экран консоли, отчёт, фильтр
// журнала аудита или событий. Содержимого запросов в ссылках нет.
type Evidence struct {
	Kind  string            `yaml:"kind" json:"kind"`
	Title string            `yaml:"title" json:"title"`
	Path  string            `yaml:"path" json:"path"`
	Query map[string]string `yaml:"query,omitempty" json:"query,omitempty"`
	Hint  string            `yaml:"hint,omitempty" json:"hint,omitempty"`
}

// Requirement — требование базы.
type Requirement struct {
	ID string `yaml:"id" json:"id"`
	// Source — ID источника из списка sources базы.
	Source string `yaml:"source" json:"source"`
	// Clause — пункт документа.
	Clause string `yaml:"clause" json:"clause"`
	Title  string `yaml:"title" json:"title"`
	// Summary — пересказ своими словами, не нормативный текст.
	Summary string   `yaml:"summary" json:"summary"`
	Applies []string `yaml:"applies,flow" json:"applies"`
	// Draft — требование из проекта документа: в процент не входит.
	Draft bool `yaml:"draft,omitempty" json:"draft"`
	// Manual — для выполнения нужна ручная отметка (организационные меры);
	// без проверок — единственный способ определить статус.
	Manual   bool       `yaml:"manual,omitempty" json:"manual"`
	Checks   []CheckRef `yaml:"checks,omitempty" json:"checks,omitempty"`
	Evidence []Evidence `yaml:"evidence,omitempty" json:"evidence,omitempty"`
}

// Base — база требований.
type Base struct {
	Format       string        `yaml:"format"`
	Version      uint64        `yaml:"version"`
	Date         string        `yaml:"date"`
	Sources      []Source      `yaml:"sources"`
	Requirements []Requirement `yaml:"requirements"`

	day     time.Time
	byID    map[string]int
	srcByID map[string]int
}

// Day — дата выпуска базы (полночь UTC).
func (b *Base) Day() time.Time { return b.day }

// ByID — требование по ID.
func (b *Base) ByID(id string) (Requirement, bool) {
	i, ok := b.byID[id]
	if !ok {
		return Requirement{}, false
	}
	return b.Requirements[i], true
}

// SourceTitle — название источника по ID.
func (b *Base) SourceTitle(id string) string {
	if i, ok := b.srcByID[id]; ok {
		return b.Sources[i].Title
	}
	return id
}

// ParseBase строго разбирает YAML базы (неизвестные поля, второй документ,
// неизвестная проверка или параметр, повтор ID — отказ). Вход — содержимое
// подписанной базы, встроенный файл или исходник для подписи; разбор
// покрыт fuzz-тестом FuzzParseBase.
func ParseBase(data []byte) (*Base, error) {
	if len(data) == 0 || len(data) > maxBaseSize {
		return nil, fmt.Errorf("база требований: размер от 1 до %d байт", maxBaseSize)
	}
	var b Base
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("база требований: неверный YAML: %w", yamlErr(err))
	}
	// Второй документ в файле — ошибка: подписанное содержимое однозначно.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("база требований: в файле больше одного документа YAML")
	}
	if err := b.validate(); err != nil {
		return nil, fmt.Errorf("база требований: %w", err)
	}
	return &b, nil
}

// yamlErr укорачивает сообщение разборщика: в нём может быть кусок файла.
func yamlErr(err error) error {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return errors.New(s)
}

func validText(s string, maxRunes int, allowEmpty bool) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxRunes {
		return false
	}
	if !allowEmpty && len(bytes.TrimSpace([]byte(s))) == 0 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return false
		}
	}
	return true
}

func (b *Base) validate() error {
	if b.Format != BaseFormat {
		return fmt.Errorf("format — %s", BaseFormat)
	}
	if b.Version == 0 || b.Version > maxBaseVersion {
		return errors.New("version — целое от 1")
	}
	day, err := time.Parse(baseDateLayout, b.Date)
	if err != nil || day.Year() < 2020 || day.Year() > 9999 {
		return errors.New("date — дата ГГГГ-ММ-ДД")
	}
	b.day = day
	if len(b.Sources) == 0 || len(b.Sources) > maxSources {
		return fmt.Errorf("sources — от 1 до %d источников", maxSources)
	}
	b.srcByID = make(map[string]int, len(b.Sources))
	for i, s := range b.Sources {
		if !sourceRe.MatchString(s.ID) || !validText(s.Title, maxTitleRunes, false) {
			return fmt.Errorf("источник %d: id — [a-z0-9-] от 2 до 32 символов, title — текст без управляющих", i+1)
		}
		if _, dup := b.srcByID[s.ID]; dup {
			return fmt.Errorf("источник %s повторяется", s.ID)
		}
		b.srcByID[s.ID] = i
	}
	if len(b.Requirements) == 0 || len(b.Requirements) > maxRequirements {
		return fmt.Errorf("requirements — от 1 до %d требований", maxRequirements)
	}
	b.byID = make(map[string]int, len(b.Requirements))
	for i, r := range b.Requirements {
		if err := validateRequirement(r, b.srcByID); err != nil {
			return fmt.Errorf("требование %d (%s): %w", i+1, truncate(r.ID, 40), err)
		}
		if _, dup := b.byID[r.ID]; dup {
			return fmt.Errorf("требование %s повторяется", r.ID)
		}
		b.byID[r.ID] = i
	}
	return nil
}

func validateRequirement(r Requirement, sources map[string]int) error {
	switch {
	case !idRe.MatchString(r.ID):
		return errors.New("id — [a-z0-9._-] от 2 до 64 символов, с буквы или цифры")
	}
	if _, ok := sources[r.Source]; !ok {
		return errors.New("source — неизвестный источник")
	}
	switch {
	case !validText(r.Clause, maxClauseRunes, false):
		return fmt.Errorf("clause — текст до %d символов без управляющих", maxClauseRunes)
	case !validText(r.Title, maxTitleRunes, false):
		return fmt.Errorf("title — текст до %d символов без управляющих", maxTitleRunes)
	case !validText(r.Summary, maxSummaryRunes, false):
		return fmt.Errorf("summary — пересказ до %d символов без управляющих", maxSummaryRunes)
	case len(r.Applies) == 0 || len(r.Applies) > len(applicabilityTitles):
		return errors.New("applies — от одного значения: gis, kii, ispdn, commercial")
	case len(r.Checks) > maxChecksPerReq:
		return fmt.Errorf("checks — не больше %d проверок", maxChecksPerReq)
	case len(r.Evidence) > maxEvidencePerReq:
		return fmt.Errorf("evidence — не больше %d ссылок", maxEvidencePerReq)
	case len(r.Checks) == 0 && !r.Manual:
		return errors.New("нужна хотя бы одна проверка или manual: true")
	}
	seen := map[string]bool{}
	for _, a := range r.Applies {
		if applicabilityTitles[a] == "" || seen[a] {
			return errors.New("applies — неизвестное или повторное значение")
		}
		seen[a] = true
	}
	names := map[string]bool{}
	for _, c := range r.Checks {
		if err := validateCheckRef(c); err != nil {
			return err
		}
		key := c.Name + "|" + canonicalParams(c.Params)
		if names[key] {
			return fmt.Errorf("проверка %s повторяется с теми же параметрами", c.Name)
		}
		names[key] = true
	}
	for _, e := range r.Evidence {
		if err := validateEvidence(e); err != nil {
			return err
		}
	}
	return nil
}

func canonicalParams(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, k := range keys {
		b.WriteString(k + "=" + p[k] + ";")
	}
	return b.String()
}

func validateCheckRef(c CheckRef) error {
	def, ok := checkRegistry[c.Name]
	if !ok {
		return fmt.Errorf("неизвестная проверка %q", truncate(c.Name, 40))
	}
	if len(c.Params) > maxParams {
		return fmt.Errorf("проверка %s: не больше %d параметров", c.Name, maxParams)
	}
	for k, v := range c.Params {
		if !paramKey.MatchString(k) || !validText(v, maxParamValueRunes, false) {
			return fmt.Errorf("проверка %s: параметр %q задан неверно", c.Name, truncate(k, 32))
		}
		p, known := def.params[k]
		if !known {
			return fmt.Errorf("проверка %s: неизвестный параметр %q", c.Name, truncate(k, 32))
		}
		if !p.valid(v) {
			return fmt.Errorf("проверка %s: значение параметра %s недопустимо", c.Name, k)
		}
	}
	return nil
}

func validateEvidence(e Evidence) error {
	switch e.Kind {
	case EvidenceScreen, EvidenceAudit, EvidenceEvents, EvidenceReport:
	default:
		return errors.New("evidence.kind — screen, audit, events или report")
	}
	if !validText(e.Title, maxTitleRunes, false) || !validText(e.Hint, maxHintRunes, true) {
		return errors.New("evidence: title или hint заданы неверно")
	}
	if !consolePaths[e.Path] {
		return fmt.Errorf("evidence.path %q — не раздел консоли", truncate(e.Path, 40))
	}
	if len(e.Query) > 4 {
		return errors.New("evidence.query — не больше 4 параметров")
	}
	for k, v := range e.Query {
		if !queryKey.MatchString(k) || !queryText.MatchString(v) {
			return fmt.Errorf("evidence.query: параметр %q задан неверно", truncate(k, 16))
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
