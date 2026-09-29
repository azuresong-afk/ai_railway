// Команда sast-triage сверяет срабатывания статического анализа (SARIF) с
// разметкой в docs/cert/sast-triage/triage.yaml (ТЗ, 8.4):
//   - каждое срабатывание должно быть размечено как ложное с обоснованием;
//     неразмеченное или истинное срабатывание — ошибка (истинное нужно исправить);
//   - разметка без срабатывания — предупреждение (устарела);
//   - подавления //nolint:gosec в коде выписываются в отдельный отчёт: это
//     тоже решения по срабатываниям, и лаборатория должна их видеть.
//
// Отпечаток срабатывания — правило, файл и текст строки кода без пробелов по
// краям. Номер строки в отпечаток не входит: иначе любая правка выше по файлу
// сбрасывала бы разметку.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Ограничения размеров входных файлов.
const (
	maxSARIF  = 32 << 20
	maxTriage = 4 << 20
	maxSource = 8 << 20
)

// Finding — срабатывание из SARIF.
type Finding struct {
	Rule    string
	File    string
	Line    int
	Message string
	Snippet string
}

// Entry — запись разметки.
type Entry struct {
	Rule          string `yaml:"rule"`
	File          string `yaml:"file"`
	Snippet       string `yaml:"snippet"`
	Verdict       string `yaml:"verdict"`
	Justification string `yaml:"justification"`
	Author        string `yaml:"author"`
	Date          string `yaml:"date"`
}

// Triage — файл разметки.
type Triage struct {
	SchemaVersion int     `yaml:"schema_version"`
	Entries       []Entry `yaml:"entries"`
}

// Вердикты разметки.
const (
	FalsePositive = "false_positive"
	TruePositive  = "true_positive"
)

func main() {
	root := flag.String("root", ".", "корень репозитория")
	sarifPath := flag.String("sarif", "build/sast/gosec.sarif", "отчёт SARIF")
	triagePath := flag.String("triage", "docs/cert/sast-triage/triage.yaml", "файл разметки")
	suppressedOut := flag.String("suppressed", "build/sast/suppressed.md", "куда записать перечень подавлений в коде")
	flag.Parse()

	if err := run(*root, *sarifPath, *triagePath, *suppressedOut); err != nil {
		fmt.Fprintln(os.Stderr, "sast-triage:", err)
		os.Exit(1)
	}
}

func run(root, sarifPath, triagePath, suppressedOut string) (err error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := r.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	fsys := r.FS()

	sarifData, err := readLimited(fsys, sarifPath, maxSARIF)
	if err != nil {
		return err
	}
	findings, err := ParseSARIF(sarifData)
	if err != nil {
		return err
	}
	for i := range findings {
		findings[i].Snippet = sourceLine(fsys, findings[i].File, findings[i].Line)
	}
	triageData, err := readLimited(fsys, triagePath, maxTriage)
	if err != nil {
		return err
	}
	triage, err := ParseTriage(triageData)
	if err != nil {
		return fmt.Errorf("%s: %w", triagePath, err)
	}

	problems, stale := Compare(findings, triage.Entries)
	for _, s := range stale {
		fmt.Fprintln(os.Stderr, "предупреждение:", s)
	}

	suppressed, err := CollectSuppressions(fsys)
	if err != nil {
		return err
	}
	if err := writeSuppressed(suppressedOut, suppressed); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(os.Stdout, "sast-triage: срабатываний %d, размечено ложных %d, подавлений в коде %d (%s)\n",
		len(findings), len(findings)-len(problems), len(suppressed), suppressedOut); err != nil {
		return err
	}
	if len(problems) > 0 {
		return errors.New("не пройдено:\n" + strings.Join(problems, "\n"))
	}
	return nil
}

func readLimited(fsys fs.FS, name string, limit int64) ([]byte, error) {
	info, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s больше %d байт", name, limit)
	}
	return fs.ReadFile(fsys, name)
}

type sarifLog struct {
	Version string `json:"version"`
	Runs    []struct {
		Results []struct {
			RuleID  string `json:"ruleId"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// codeRe выделяет код правила gosec из текста сообщения: «G104: …».
var codeRe = regexp.MustCompile(`^(G\d{3}):`)

// ParseSARIF разбирает отчёт SARIF 2.1.0. Правило — ruleId, для gosec
// уточнённое кодом проверки: «gosec/G104».
func ParseSARIF(data []byte) ([]Finding, error) {
	if len(data) > maxSARIF {
		return nil, fmt.Errorf("SARIF больше %d байт", maxSARIF)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("разбор SARIF: %w", err)
	}
	if log.Version != "2.1.0" {
		return nil, fmt.Errorf("разбор SARIF: ожидается версия 2.1.0, получено %q", log.Version)
	}
	out := []Finding{}
	for _, run := range log.Runs {
		for _, res := range run.Results {
			if res.RuleID == "" || len(res.Locations) == 0 {
				return nil, errors.New("разбор SARIF: срабатывание без правила или места")
			}
			loc := res.Locations[0].PhysicalLocation
			if loc.ArtifactLocation.URI == "" || loc.Region.StartLine < 1 {
				return nil, errors.New("разбор SARIF: срабатывание без файла или строки")
			}
			rule := res.RuleID
			if m := codeRe.FindStringSubmatch(res.Message.Text); m != nil {
				rule += "/" + m[1]
			}
			out = append(out, Finding{
				Rule:    rule,
				File:    strings.TrimPrefix(loc.ArtifactLocation.URI, "file://"),
				Line:    loc.Region.StartLine,
				Message: res.Message.Text,
			})
		}
	}
	return out, nil
}

// ParseTriage разбирает файл разметки со строгой проверкой схемы.
func ParseTriage(data []byte) (*Triage, error) {
	if len(data) > maxTriage {
		return nil, fmt.Errorf("разметка больше %d байт", maxTriage)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var t Triage
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("разбор разметки: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("разбор разметки: ожидается один YAML-документ")
	}
	if t.SchemaVersion != 1 {
		return nil, fmt.Errorf("schema_version: ожидается 1, получено %d", t.SchemaVersion)
	}
	var errs []error
	for i, e := range t.Entries {
		id := fmt.Sprintf("entries[%d]", i)
		for k, v := range map[string]string{"rule": e.Rule, "file": e.File, "snippet": e.Snippet, "justification": e.Justification, "author": e.Author, "date": e.Date} {
			if strings.TrimSpace(v) == "" {
				errs = append(errs, fmt.Errorf("%s: не заполнено поле %s", id, k))
			}
		}
		if e.Verdict != FalsePositive && e.Verdict != TruePositive {
			errs = append(errs, fmt.Errorf("%s: verdict — %s или %s", id, FalsePositive, TruePositive))
		}
		if e.Date != "" {
			if _, err := time.Parse(time.DateOnly, e.Date); err != nil {
				errs = append(errs, fmt.Errorf("%s: date — ГГГГ-ММ-ДД", id))
			}
		}
	}
	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return &t, errors.Join(errs...)
}

func key(rule, file, snippet string) string {
	return rule + "\x00" + file + "\x00" + strings.TrimSpace(snippet)
}

// Compare сверяет срабатывания с разметкой. Возвращает нарушения и
// устаревшие записи разметки.
func Compare(findings []Finding, entries []Entry) (problems, stale []string) {
	byKey := map[string]Entry{}
	used := map[string]bool{}
	for _, e := range entries {
		byKey[key(e.Rule, e.File, e.Snippet)] = e
	}
	for _, f := range findings {
		k := key(f.Rule, f.File, f.Snippet)
		e, ok := byKey[k]
		used[k] = true
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s:%d: %s: не размечено (%s)", f.File, f.Line, f.Rule, f.Message))
		case e.Verdict == TruePositive:
			problems = append(problems, fmt.Sprintf("%s:%d: %s: истинное срабатывание — нужно исправить", f.File, f.Line, f.Rule))
		}
	}
	for _, e := range entries {
		if !used[key(e.Rule, e.File, e.Snippet)] {
			stale = append(stale, fmt.Sprintf("разметка %s %s «%s» не совпала ни с одним срабатыванием — удалите запись", e.Rule, e.File, e.Snippet))
		}
	}
	sort.Strings(problems)
	sort.Strings(stale)
	return problems, stale
}

// sourceLine возвращает строку кода; пустая строка, если файл не прочитан.
func sourceLine(fsys fs.FS, file string, line int) string {
	data, err := readLimited(fsys, file, maxSource)
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxSource)
	for n := 1; sc.Scan(); n++ {
		if n == line {
			return strings.TrimSpace(sc.Text())
		}
	}
	return ""
}

// Suppression — подавление gosec в коде.
type Suppression struct {
	File string
	Line int
	Text string
}

// skipDirs — каталоги вне кода продукта и утилит.
var skipDirs = map[string]bool{".git": true, "vendor": true, "testdata": true, "bin": true, "build": true, "node_modules": true}

// CollectSuppressions находит директивы //nolint, подавляющие gosec, во всех
// .go-файлах. Учитываются только настоящие комментарии-директивы, а не
// упоминания в строках и тексте комментариев.
func CollectSuppressions(fsys fs.FS) ([]Suppression, error) {
	out := []Suppression{}
	fset := token.NewFileSet()
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		data, err := readLimited(fsys, p, maxSource)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, p, data, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("разбор %s: %w", p, err)
		}
		for _, g := range f.Comments {
			for _, c := range g.List {
				if suppressesGosec(c.Text) {
					out = append(out, Suppression{File: p, Line: fset.Position(c.Slash).Line, Text: c.Text})
				}
			}
		}
		return nil
	})
	return out, err
}

// suppressesGosec сообщает, что комментарий — директива nolint для gosec:
// «//nolint:gosec», «//nolint:errcheck,gosec // …» или «//nolint» без списка.
func suppressesGosec(comment string) bool {
	rest, ok := strings.CutPrefix(comment, "//nolint")
	if !ok {
		return false
	}
	if rest == "" || rest[0] == ' ' {
		return true // //nolint без списка подавляет все линтеры
	}
	list, ok := strings.CutPrefix(rest, ":")
	if !ok {
		return false
	}
	if i := strings.IndexByte(list, ' '); i >= 0 {
		list = list[:i]
	}
	for _, l := range strings.Split(list, ",") {
		if l == "gosec" {
			return true
		}
	}
	return false
}

func writeSuppressed(path string, list []Suppression) error {
	var b strings.Builder
	b.WriteString("# Подавления gosec в коде\n\nСформировано `make sast`. Каждое подавление обязано содержать обоснование (nolintlint).\n\n")
	b.WriteString("| Файл | Строка | Директива |\n|---|---|---|\n")
	for _, s := range list {
		fmt.Fprintf(&b, "| `%s` | %d | `%s` |\n", s.File, s.Line, strings.ReplaceAll(s.Text, "|", "\\|"))
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
