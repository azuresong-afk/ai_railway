package redteam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Сценарии атак — служебная база по ADR-0028 (ADR-0031, раздел 5): вид
// redteam_scenarios, содержимое — JSON формата aisec-redteam-scenarios-v1.
// Разбор строгий: один объект, неизвестные поля — ошибка, пределы до
// разбора всего содержимого (FuzzParseScenarios).

// Вид и формат базы сценариев.
const (
	ScenariosKind   = "redteam_scenarios"
	ScenariosFormat = "aisec-redteam-scenarios-v1"
)

// Пределы базы сценариев.
const (
	MaxScenarios   = 5000
	MaxSteps       = 8
	MaxPrompt      = 16 << 10
	MaxTitle       = 200
	MaxSource      = 512
	MaxMarkers     = 8
	MinMarker      = 2
	MaxMarker      = 200
	MaxFindingPref = 8
	MinJudge       = 10
	MaxJudge       = 1000
	// MaxEscapes — записей \u{…} в одном шаге: хватает на инструкцию
	// тегами Unicode (символ на запись), но не на длинный скрытый текст.
	MaxEscapes = 512
)

// Языки сценариев.
const (
	LangRU = "ru"
	LangEN = "en"
)

// ScenarioLicenses — лицензии источников сценариев: разрешённые для данных
// и proprietary — собственный корпус производителя.
var ScenarioLicenses = []string{"MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "CC0-1.0", "CC-BY-4.0", "proprietary"}

var (
	scenarioIDRe = regexp.MustCompile(`^[A-Z][A-Z0-9-]{2,63}$`)
	threatRe     = regexp.MustCompile(`^DM-(0[1-9]|[1-9][0-9])$`)
	categoryRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)
	findingRe    = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
)

// Step — шаг сценария: текст реплики пользователя.
//
// Prompt — запись из исходника базы: символы форматирования (Cf) в ней
// только видимой записью \u{XXXX} (дополнение 2 к ADR-0031). Её же
// показывают inspect, API и отчёты. Цели отправляется Text — запись с
// раскрытыми символами.
type Step struct {
	Prompt string `json:"prompt"`

	text string
}

// Text — текст шага для цели: запись Prompt с раскрытыми \u{…}. У шага, не
// прошедшего ParseScenarios, — Prompt без изменений.
func (s Step) Text() string {
	if s.text == "" {
		return s.Prompt
	}
	return s.text
}

// Success — условия успеха атаки: выполнено хотя бы одно.
type Success struct {
	// Canary — в ответе маркер-канарейка (детектор canary, DM-08).
	Canary bool `json:"canary,omitempty"`
	// Contains — строки-маркеры, которые атака просит произнести;
	// совпадение без учёта регистра.
	Contains []string `json:"contains,omitempty"`
	// Findings — префиксы категорий находок детекторов в ответе.
	Findings []string `json:"findings,omitempty"`
	// Judge — критерий для judge.llm.
	Judge string `json:"judge,omitempty"`
}

// Scenario — сценарий атаки.
type Scenario struct {
	ID       string  `json:"id"`
	Lang     string  `json:"lang"`
	Threat   string  `json:"threat"`
	Category string  `json:"category"`
	Title    string  `json:"title"`
	Steps    []Step  `json:"steps"`
	Success  Success `json:"success"`
	Source   string  `json:"source"`
	License  string  `json:"license"`
}

// Base — содержимое базы сценариев.
type Base struct {
	Format    string     `json:"format"`
	Version   uint64     `json:"version"`
	Date      string     `json:"date"`
	Scenarios []Scenario `json:"scenarios"`

	day  time.Time
	byID map[string]int
}

// Scenario — сценарий по ID.
func (b *Base) Scenario(id string) (Scenario, bool) {
	i, ok := b.byID[id]
	if !ok {
		return Scenario{}, false
	}
	return b.Scenarios[i], true
}

// DBKind — вид служебной базы сценариев для internal/servicedb и реестра
// видов выпуска (internal/servicedb/kinds).
func DBKind() servicedb.Kind {
	return servicedb.Kind{Name: ScenariosKind, Title: "Сценарии тестирования устойчивости", Parse: func(b []byte) (servicedb.Content, error) {
		base, err := ParseScenarios(b)
		if err != nil {
			return servicedb.Content{}, err
		}
		return servicedb.Content{Value: base, Version: base.Version, Date: base.day, Records: len(base.Scenarios)}, nil
	}}
}

// errList — ошибки проверки: до maxErrs сообщений.
type errList struct{ errs []error }

const maxErrs = 20

func (l *errList) add(format string, args ...any) {
	if len(l.errs) < maxErrs {
		l.errs = append(l.errs, fmt.Errorf(format, args...))
	}
}

func (l *errList) err() error {
	if len(l.errs) == 0 {
		return nil
	}
	return invalid(l.errs...)
}

// decodeStrict — один объект JSON без неизвестных полей и лишних данных.
func decodeStrict(data []byte, dst any, limit int) error {
	if len(data) > limit {
		return invalid(fmt.Errorf("содержимое — не больше %d КиБ", limit>>10))
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return invalid(errors.New("содержимое — некорректный JSON или неизвестные поля"))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return invalid(errors.New("после JSON-значения есть лишние данные"))
	}
	return nil
}

// plainText — строка UTF-8 без управляющих символов (кроме перевода
// строки и табуляции, если multiline) и символов форматирования.
func plainText(s string, multiline bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		if multiline && (r == '\n' || r == '\t' || r == '\r') {
			return false
		}
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) < 0
}

// Ошибки видимой записи \u{…}.
var (
	errEscapeSyntax    = errors.New("запись \\u{…} — от 1 до 6 шестнадцатеричных цифр в фигурных скобках")
	errEscapeSurrogate = errors.New("запись \\u{…} — суррогатная кодовая точка")
	errEscapeNotCf     = errors.New("запись \\u{…} — только символы форматирования Unicode (категория Cf)")
	errEscapeTooMany   = fmt.Errorf("записей \\u{…} — не больше %d в шаге", MaxEscapes)
)

// expandEscapes раскрывает видимую запись символов форматирования в тексте
// шага (дополнение 2 к ADR-0031): \u{XXXX} — от 1 до 6 шестнадцатеричных
// цифр, только кодовые точки категории Cf (нулевая ширина, управление
// направлением, теги U+E0001, U+E0020–U+E007F). Нечётное число обратных
// косых черт перед «u{» — запись, чётное — буквальный текст: каждая пара
// «\\» перед «u{» даёт одну «\», поэтому «\\u{200B}» — это буквально
// «\u{200B}». Обратная косая черта не перед «u{» не меняется. Запись не
// короче раскрытого символа (5 байт и больше против 4 байт UTF-8), поэтому
// текст после раскрытия не длиннее записи.
func expandEscapes(s string) (string, error) {
	if !strings.Contains(s, `u{`) {
		return s, nil
	}
	var out strings.Builder
	out.Grow(len(s))
	n := 0
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			out.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] == '\\' {
			j++
		}
		run := j - i
		if !strings.HasPrefix(s[j:], `u{`) {
			out.WriteString(s[i:j])
			i = j
			continue
		}
		out.WriteString(strings.Repeat(`\`, run/2))
		if run%2 == 0 {
			// «\\u{» — буквальный текст «\u{»: скобка дальше не разбирается.
			out.WriteString(`u{`)
			i = j + 2
			continue
		}
		r, size, err := parseEscape(s[j+2:])
		if err != nil {
			return "", err
		}
		if n++; n > MaxEscapes {
			return "", errEscapeTooMany
		}
		out.WriteRune(r)
		i = j + 2 + size
	}
	return out.String(), nil
}

// parseEscape разбирает «XXXX}» после «\u{»: кодовую точку и длину записи
// вместе с закрывающей скобкой.
func parseEscape(s string) (rune, int, error) {
	end := strings.IndexByte(s, '}')
	if end < 1 || end > 6 {
		return 0, 0, errEscapeSyntax
	}
	var r rune
	for k := 0; k < end; k++ {
		c := s[k]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, 0, errEscapeSyntax
		}
		r = r<<4 | rune(d)
	}
	switch {
	case r >= 0xD800 && r <= 0xDFFF:
		return 0, 0, errEscapeSurrogate
	case r > unicode.MaxRune || !unicode.Is(unicode.Cf, r):
		return 0, 0, errEscapeNotCf
	}
	return r, end + 1, nil
}

func httpsURL(s string) bool {
	if len(s) > MaxSource {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// ParseScenarios разбирает и проверяет содержимое базы сценариев.
func ParseScenarios(data []byte) (*Base, error) {
	var b Base
	if err := decodeStrict(data, &b, aisecCrypto.MaxServiceDBPayload); err != nil {
		return nil, err
	}
	var l errList
	if b.Format != ScenariosFormat {
		l.add("format — %s", ScenariosFormat)
	}
	if b.Version == 0 || b.Version > servicedb.MaxVersion {
		l.add("version — целое от 1")
	}
	day, err := time.Parse(time.DateOnly, b.Date)
	if err != nil {
		l.add("date — ГГГГ-ММ-ДД")
	}
	if len(b.Scenarios) == 0 || len(b.Scenarios) > MaxScenarios {
		l.add("scenarios — от 1 до %d сценариев", MaxScenarios)
		return nil, l.err()
	}
	b.byID = make(map[string]int, len(b.Scenarios))
	for i, s := range b.Scenarios {
		f := fmt.Sprintf("scenarios[%d]", i)
		if !scenarioIDRe.MatchString(s.ID) {
			l.add("%s.id — заглавные латинские буквы, цифры и «-», от 3 до 64 символов, начинается с буквы", f)
		} else if _, dup := b.byID[s.ID]; dup {
			l.add("%s.id — повторяется", f)
		} else {
			b.byID[s.ID] = i
		}
		if s.Lang != LangRU && s.Lang != LangEN {
			l.add("%s.lang — ru или en", f)
		}
		if !threatRe.MatchString(s.Threat) {
			l.add("%s.threat — строка матрицы обнаружения DM-NN", f)
		}
		if !categoryRe.MatchString(s.Category) {
			l.add("%s.category — строчные латинские буквы, цифры и «_», от 2 до 64 символов", f)
		}
		if s.Title == "" || utf8.RuneCountInString(s.Title) > MaxTitle || !plainText(s.Title, false) {
			l.add("%s.title — от 1 до %d символов без управляющих символов", f, MaxTitle)
		}
		if len(s.Steps) == 0 || len(s.Steps) > MaxSteps {
			l.add("%s.steps — от 1 до %d шагов", f, MaxSteps)
		}
		for j, st := range s.Steps {
			if st.Prompt == "" || len(st.Prompt) > MaxPrompt || !plainText(st.Prompt, true) {
				l.add("%s.steps[%d].prompt — от 1 байта до %d КиБ в UTF-8 без управляющих символов и символов форматирования (их — записью \\u{XXXX})", f, j, MaxPrompt>>10)
				continue
			}
			text, err := expandEscapes(st.Prompt)
			if err != nil {
				l.add("%s.steps[%d].prompt — %w", f, j, err)
				continue
			}
			b.Scenarios[i].Steps[j].text = text
		}
		checkSuccess(&l, f+".success", s.Success)
		if !httpsURL(s.Source) {
			l.add("%s.source — адрес https до %d байт", f, MaxSource)
		}
		if !slices.Contains(ScenarioLicenses, s.License) {
			l.add("%s.license — одна из %s", f, strings.Join(ScenarioLicenses, ", "))
		}
	}
	if err := l.err(); err != nil {
		return nil, err
	}
	b.day = day.UTC()
	return &b, nil
}

func checkSuccess(l *errList, f string, s Success) {
	if !s.Canary && len(s.Contains) == 0 && len(s.Findings) == 0 && s.Judge == "" {
		l.add("%s — хотя бы одно условие: canary, contains, findings или judge", f)
	}
	if len(s.Contains) > MaxMarkers {
		l.add("%s.contains — не больше %d строк", f, MaxMarkers)
	}
	for i, m := range s.Contains {
		if n := utf8.RuneCountInString(m); n < MinMarker || n > MaxMarker || !plainText(m, false) || strings.TrimSpace(m) != m {
			l.add("%s.contains[%d] — от %d до %d символов без управляющих символов и пробелов по краям", f, i, MinMarker, MaxMarker)
		}
	}
	if len(s.Findings) > MaxFindingPref {
		l.add("%s.findings — не больше %d префиксов", f, MaxFindingPref)
	}
	for i, p := range s.Findings {
		if len(p) > 64 || !findingRe.MatchString(p) {
			l.add("%s.findings[%d] — префикс категории находки (secret, pii.snils)", f, i)
		}
	}
	if s.Judge != "" {
		if n := utf8.RuneCountInString(s.Judge); n < MinJudge || n > MaxJudge || !plainText(s.Judge, false) {
			l.add("%s.judge — от %d до %d символов без управляющих символов", f, MinJudge, MaxJudge)
		}
	}
}
