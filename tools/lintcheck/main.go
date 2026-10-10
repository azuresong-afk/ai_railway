// Команда lintcheck проверяет, что правила линтеров проекта действительно
// срабатывают. Она запускает golangci-lint с конфигурацией репозитория на
// образце testdata/sample и сверяет замечания с маркерами в его исходниках:
//
//	// want:<линтер>  — на этой строке обязано быть замечание линтера;
//	// clean:<линтер> — на этой строке замечания линтера быть не должно.
//
// Это доказательство для лаборатории, что запреты из CLAUDE.md работают.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// maxReportSize ограничивает размер отчёта линтера.
const maxReportSize = 16 << 20

// issue — замечание линтера, приведённое к пути относительно образца.
type issue struct {
	File   string
	Line   int
	Linter string
	Text   string
}

// marker — ожидание из исходника образца.
type marker struct {
	File   string
	Line   int
	Linter string
	Want   bool // true — want, false — clean
}

func main() {
	lint := flag.String("golangci-lint", "bin/golangci-lint", "путь к golangci-lint")
	config := flag.String("config", ".golangci.yml", "конфигурация линтеров")
	sample := flag.String("sample", "tools/lintcheck/testdata/sample", "каталог образца")
	flag.Parse()

	failures, err := run(*lint, *config, *sample)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lintcheck:", err)
		os.Exit(2)
	}
	for _, f := range failures {
		fmt.Fprintln(os.Stderr, f)
	}
	if len(failures) > 0 {
		fmt.Fprintf(os.Stderr, "lintcheck: нарушений ожиданий: %d\n", len(failures))
		os.Exit(1)
	}
	if _, err := fmt.Fprintln(os.Stdout, "lintcheck: все правила сработали как ожидалось"); err != nil {
		os.Exit(2)
	}
}

func run(lint, config, sample string) ([]string, error) {
	lint, err := filepath.Abs(lint)
	if err != nil {
		return nil, err
	}
	config, err = filepath.Abs(config)
	if err != nil {
		return nil, err
	}
	sample, err = filepath.Abs(sample)
	if err != nil {
		return nil, err
	}
	markers, err := collectMarkers(sample)
	if err != nil {
		return nil, err
	}
	if len(markers) == 0 {
		return nil, errors.New("в образце нет маркеров want/clean")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	//nolint:gosec // G204: путь к линтеру и конфигурации задаёт разработчик флагами утилиты, это не внешний ввод
	cmd := exec.CommandContext(ctx, lint, "run", "--config", config, "--path-mode", "abs", "--modules-download-mode", "readonly",
		"--output.json.path", "stdout", "--output.text.path", "stderr", "--show-stats=false", "./...")
	cmd.Dir = sample
	// Образец собирается только из своих файлов: без сети и без правки go.mod.
	// CGO_ENABLED=1 — чтобы линтеры видели и файлы с cgo.
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly", "GOPROXY=off", "CGO_ENABLED=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	// golangci-lint завершается с кодом 1, когда нашёл замечания, — это ожидаемо.
	var exitErr *exec.ExitError
	if runErr != nil && (!errors.As(runErr, &exitErr) || exitErr.ExitCode() != 1) {
		return nil, fmt.Errorf("golangci-lint: %w\n%s", runErr, stderr.String())
	}
	issues, err := parseReport(stdout.Bytes(), sample)
	if err != nil {
		return nil, fmt.Errorf("%w\n%s", err, stderr.String())
	}
	return compare(markers, issues), nil
}

// reportJSON — нужная часть JSON-отчёта golangci-lint.
type reportJSON struct {
	Issues []struct {
		FromLinter string
		Text       string
		Pos        struct {
			Filename string
			Line     int
		}
	}
}

// parseReport разбирает JSON-отчёт golangci-lint. Пути приводятся к
// относительным от каталога образца.
func parseReport(data []byte, base string) ([]issue, error) {
	if len(data) > maxReportSize {
		return nil, fmt.Errorf("отчёт линтера больше %d байт", maxReportSize)
	}
	var r reportJSON
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("разбор отчёта линтера: %w", err)
	}
	out := make([]issue, 0, len(r.Issues))
	for _, i := range r.Issues {
		name := filepath.ToSlash(i.Pos.Filename)
		if filepath.IsAbs(i.Pos.Filename) {
			if rel, err := filepath.Rel(base, i.Pos.Filename); err == nil {
				name = filepath.ToSlash(rel)
			}
		}
		out = append(out, issue{File: name, Line: i.Pos.Line, Linter: i.FromLinter, Text: i.Text})
	}
	return out, nil
}

var markerRe = regexp.MustCompile(`//\s*(want|clean):([a-z0-9]+)`)

// collectMarkers находит маркеры want/clean во всех .go-файлах образца.
func collectMarkers(root string) ([]marker, error) {
	var out []marker
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path) //nolint:gosec // путь получен обходом каталога образца в репозитории
		if err != nil {
			return err
		}
		out = append(out, parseMarkers(filepath.ToSlash(rel), data)...)
		return nil
	})
	return out, err
}

// parseMarkers извлекает маркеры из одного файла.
func parseMarkers(file string, data []byte) []marker {
	var out []marker
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		for _, m := range markerRe.FindAllStringSubmatch(sc.Text(), -1) {
			out = append(out, marker{File: file, Line: n, Linter: m[2], Want: m[1] == "want"})
		}
	}
	return out
}

// compare сверяет замечания с ожиданиями и возвращает описания расхождений.
func compare(markers []marker, issues []issue) []string {
	type key struct {
		file   string
		line   int
		linter string
	}
	found := map[key][]string{}
	for _, i := range issues {
		k := key{i.File, i.Line, i.Linter}
		found[k] = append(found[k], i.Text)
	}
	var out []string
	for _, m := range markers {
		texts, ok := found[key{m.File, m.Line, m.Linter}]
		switch {
		case m.Want && !ok:
			out = append(out, fmt.Sprintf("%s:%d: ожидалось замечание %s, его нет", m.File, m.Line, m.Linter))
		case !m.Want && ok:
			out = append(out, fmt.Sprintf("%s:%d: лишнее замечание %s: %s", m.File, m.Line, m.Linter, strings.Join(texts, "; ")))
		}
	}
	sort.Strings(out)
	return out
}
