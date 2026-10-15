// Команда dm-coverage строит отчёт о покрытии матрицы обнаружения (ТЗ, 5.16)
// тестами. Строки берутся из docs/SPEC.md, результаты — из `go test -json`
// и JUnit XML, маркеры «Покрывает: DM-NN (часть)» — из комментариев к тестам.
//
// Правила (ТЗ, 5.16): строка и её части с этапом не выше текущего обязаны
// быть покрыты прошедшим тестом; имя теста содержит ID строки
// (TestDM07_IndirectInjectionRAG) или тест размечен маркером. Утилита
// падает, если покрытия нет, тест не проходит, ID в тесте не существует или
// матрица размечена с ошибками.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	spec := flag.String("spec", "docs/SPEC.md", "ТЗ с матрицей 5.16")
	stage := flag.Int("stage", 0, "текущий этап (ТЗ, раздел 14)")
	goTest := flag.String("gotest", "", "отчёты `go test -json` через запятую")
	junit := flag.String("junit", "", "отчёты JUnit XML через запятую (необязательно)")
	root := flag.String("root", ".", "корень репозитория для поиска маркеров в тестах")
	out := flag.String("out", "build/dm-coverage", "префикс файлов отчёта (.md и .json)")
	flag.Parse()

	if err := run(*spec, *stage, split(*goTest), split(*junit), *root, *out); err != nil {
		fmt.Fprintln(os.Stderr, "dm-coverage:", err)
		os.Exit(1)
	}
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readLimited(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s больше %d байт", path, limit)
	}
	return os.ReadFile(path) //nolint:gosec // G304: пути к отчётам задаёт Makefile
}

func run(specPath string, stage int, goTests, junits []string, root, out string) error {
	if stage < 0 || stage > 6 {
		return fmt.Errorf("этап %d вне диапазона 0–6", stage)
	}
	spec, err := readLimited(specPath, int64(maxMatrix))
	if err != nil {
		return err
	}
	rows, err := ParseMatrix(string(spec))
	if err != nil {
		return err
	}
	var results []Result
	for _, p := range goTests {
		data, err := readLimited(p, maxReport)
		if err != nil {
			return err
		}
		r, err := ParseGoTestJSON(data)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		results = append(results, r...)
	}
	for _, p := range junits {
		data, err := readLimited(p, maxReport)
		if err != nil {
			return err
		}
		r, err := ParseJUnit(data)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		results = append(results, r...)
	}
	markers, markerProblems, err := CollectMarkers(os.DirFS(root))
	if err != nil {
		return err
	}
	rep := Compute(rows, stage, results, markers)
	rep.Problems = append(markerProblems, rep.Problems...)

	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(out+".md", []byte(rep.Markdown()), 0o600); err != nil {
		return err
	}
	js, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out+".json", append(js, '\n'), 0o600); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(os.Stdout, "dm-coverage: этап %d, строк %d, требований %d, проблем %d (%s.md)\n",
		stage, len(rows), len(rep.Items), len(rep.Problems), out); err != nil {
		return err
	}
	if len(rep.Problems) > 0 {
		return errors.New("покрытие матрицы не выполнено:\n" + strings.Join(rep.Problems, "\n"))
	}
	return nil
}
