package main

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	"github.com/azuresong-afk/ai_railway/tools/internal/repofs"
)

// Result — итог одного теста.
type Result struct {
	Name   string // полное имя, для подтестов — «TestX/подтест»
	Passed bool
}

// maxReport ограничивает размер входных отчётов тестов.
const maxReport = 64 << 20

// testIDRe находит ID строки в имени теста: TestDM07_…, TestX/DM07.
var testIDRe = regexp.MustCompile(`DM(\d{2})`)

// IDsInName возвращает ID строк матрицы из имени теста («DM-07»).
func IDsInName(name string) []string {
	var out []string
	for _, m := range testIDRe.FindAllStringSubmatch(name, -1) {
		out = append(out, "DM-"+m[1])
	}
	return out
}

type testEvent struct {
	Action     string
	Package    string
	ImportPath string // у build-output и build-fail (go 1.24+)
	Test       string
}

// ParseGoTestJSON разбирает вывод `go test -json`. Учитываются итоговые
// события pass и fail; skip считается непройденным тестом.
//
// failures — упавшие тесты, пакеты и сборки в порядке появления: отчёт
// dm-coverage считает каждое падение проблемой, даже если тест не покрывает
// ни одной строки матрицы (иначе упавший e2e давал «0 проблем»; G2 этапа 5).
// Из упавших тестов называются самые глубокие: родитель упавшего подтеста
// падает вместе с ним. Пакет называется отдельно, только если в нём не упал
// ни один тест (паника вне теста, таймаут, сбой TestMain).
func ParseGoTestJSON(data []byte) (results []Result, failures []string, err error) {
	if len(data) > maxReport {
		return nil, nil, fmt.Errorf("отчёт тестов больше %d байт", maxReport)
	}
	type failed struct{ pkg, test string }
	var tests []failed
	var pkgs, builds []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue // строки сборки и прочий вывод go test
		}
		var ev testEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, nil, fmt.Errorf("строка %d отчёта тестов: %w", n, err)
		}
		switch {
		case ev.Action == "build-fail":
			builds = append(builds, cmp.Or(ev.ImportPath, ev.Package))
		case ev.Test == "":
			if ev.Action == "fail" {
				pkgs = append(pkgs, ev.Package)
			}
		case ev.Action == "pass":
			results = append(results, Result{Name: ev.Test, Passed: true})
		case ev.Action == "fail":
			results = append(results, Result{Name: ev.Test, Passed: false})
			tests = append(tests, failed{ev.Package, ev.Test})
		case ev.Action == "skip":
			results = append(results, Result{Name: ev.Test, Passed: false})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	for _, b := range builds {
		failures = append(failures, fmt.Sprintf("сборка %s не прошла", cmp.Or(b, "(без имени)")))
	}
	withTests := map[string]bool{}
	for i, f := range tests {
		withTests[f.pkg] = true
		if slices.ContainsFunc(tests, func(o failed) bool {
			return o.pkg == f.pkg && strings.HasPrefix(o.test, f.test+"/")
		}) {
			continue
		}
		if slices.ContainsFunc(tests[:i], func(o failed) bool { return o == f }) {
			continue
		}
		failures = append(failures, fmt.Sprintf("тест %s (%s) не прошёл", f.test, cmp.Or(f.pkg, "без пакета")))
	}
	for _, p := range pkgs {
		if !withTests[p] {
			failures = append(failures, fmt.Sprintf("пакет %s не прошёл (сборка, паника вне теста, таймаут или TestMain)", cmp.Or(p, "(без имени)")))
		}
	}
	return results, failures, nil
}

type junitSuites struct {
	Suites []junitSuite `xml:"testsuite"`
	junitSuite
}

type junitSuite struct {
	Cases  []junitCase  `xml:"testcase"`
	Suites []junitSuite `xml:"testsuite"`
}

type junitCase struct {
	Name    string    `xml:"name,attr"`
	Failure *struct{} `xml:"failure"`
	Error   *struct{} `xml:"error"`
	Skipped *struct{} `xml:"skipped"`
}

// ParseJUnit разбирает отчёт JUnit XML (фронтенд и e2e с этапа 2).
func ParseJUnit(data []byte) ([]Result, error) {
	if len(data) > maxReport {
		return nil, fmt.Errorf("отчёт JUnit больше %d байт", maxReport)
	}
	var root junitSuites
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("разбор JUnit: %w", err)
	}
	var out []Result
	var walk func(s junitSuite, depth int)
	walk = func(s junitSuite, depth int) {
		if depth > 16 {
			return
		}
		for _, c := range s.Cases {
			out = append(out, Result{Name: c.Name, Passed: c.Failure == nil && c.Error == nil && c.Skipped == nil})
		}
		for _, sub := range s.Suites {
			walk(sub, depth+1)
		}
	}
	walk(root.junitSuite, 0)
	for _, s := range root.Suites {
		walk(s, 0)
	}
	return out, nil
}

// Coverage — что покрывает тест: ID строки и, если указана, часть.
type Coverage struct {
	ID   string
	Part string // "" — основная часть строки
	// Optional — тест в файле под тегом optionalTag: он идёт только там,
	// где есть внешняя библиотека (ONNX Runtime, docs/cert/build-env.md), и в
	// make dm-coverage не запускается. Если такой тест не запускался, это не
	// ошибка разметки; если запускался — учитывается как обычный.
	Optional bool
}

// optionalTag — сборочный тег тестов с внешней библиотекой.
const optionalTag = "aisec_onnx"

// optionalOnly — файл собирается только с тегом optionalTag: без него
// условие ложно, с ним — истинно; остальные теги — как в окружении сборки
// (ОС, архитектура, unix, gc, версии Go; cgo — всегда). Условие !aisec_onnx или
// aisec_onnx || linux маркеры необязательными не делает (5Н23 ревью 5.r3).
func optionalOnly(expr constraint.Expr) bool {
	env := func(onnx bool) func(string) bool {
		return func(tag string) bool {
			switch tag {
			case optionalTag:
				return onnx
			case build.Default.GOOS, build.Default.GOARCH, "gc":
				return true
			case "unix":
				return build.Default.GOOS != "windows" && build.Default.GOOS != "plan9"
			case "cgo":
				// Тесты с ONNX Runtime идут только с cgo: окружение, где они
				// запускаются, — с cgo, даже если dm-coverage собран без него.
				return true
			}
			return slices.Contains(build.Default.ReleaseTags, tag)
		}
	}
	return !expr.Eval(env(false)) && expr.Eval(env(true))
}

// coversRe разбирает маркер в комментарии теста:
// «Покрывает: DM-38 (оповещение), DM-40».
var (
	coversLineRe = regexp.MustCompile(`^Покрывает:\s*(.+)$`)
	coversItemRe = regexp.MustCompile(`^DM-(\d{2})(?:\s*\(([^()]+)\))?$`)
)

// maxSourceFile ограничивает размер разбираемого файла тестов.
const maxSourceFile = 8 << 20

// CollectMarkers читает маркеры «Покрывает:» из комментариев к функциям
// Test* во всех *_test.go. Возвращает соответствие «имя теста → покрытие»
// и ошибки разметки (например, неверный ID).
func CollectMarkers(fsys fs.FS) (map[string][]Coverage, []string, error) {
	out := map[string][]Coverage{}
	var problems []string
	fset := token.NewFileSet()
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if repofs.Skip(p, d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxSourceFile {
			return fmt.Errorf("%s больше %d байт", p, maxSourceFile)
		}
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, p, src, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("разбор %s: %w", p, err)
		}
		optional := false
		for _, cg := range f.Comments {
			if cg.Pos() > f.Package {
				break
			}
			for _, c := range cg.List {
				if constraint.IsGoBuild(c.Text) {
					expr, err := constraint.Parse(c.Text)
					if err != nil {
						return fmt.Errorf("%s: строка //go:build: %w", p, err)
					}
					optional = optionalOnly(expr)
				}
			}
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Doc == nil || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			covs, bad := ParseCovers(fn.Doc.Text())
			for _, b := range bad {
				problems = append(problems, fmt.Sprintf("%s: %s: %s", p, fn.Name.Name, b))
			}
			for i := range covs {
				covs[i].Optional = optional
			}
			if len(covs) > 0 {
				out[fn.Name.Name] = append(out[fn.Name.Name], covs...)
			}
		}
		return nil
	})
	return out, problems, err
}

// ParseCovers извлекает покрытие из текста комментария.
func ParseCovers(doc string) ([]Coverage, []string) {
	var out []Coverage
	var bad []string
	for _, line := range strings.Split(doc, "\n") {
		m := coversLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		for _, item := range splitCovers(m[1]) {
			item = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(item), "."))
			im := coversItemRe.FindStringSubmatch(item)
			if im == nil {
				bad = append(bad, fmt.Sprintf("не разобран маркер покрытия %q (ожидается «DM-NN» или «DM-NN (часть)»)", item))
				continue
			}
			out = append(out, Coverage{ID: "DM-" + im[1], Part: strings.TrimSpace(im[2])})
		}
	}
	return out, bad
}

// splitCovers делит перечень по запятым вне скобок: часть строки матрицы
// («бюджеты, аномалии и оповещение») сама содержит запятые.
func splitCovers(list string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range list {
		switch r {
		case '(':
			depth++
		case ')':
			depth = max(depth-1, 0)
		case ',':
			if depth == 0 {
				out = append(out, list[start:i])
				start = i + 1
			}
		}
	}
	return append(out, list[start:])
}
