// Команда docs-check проверяет, что относительные ссылки в markdown-документах
// репозитория ведут на существующие файлы. Внешние ссылки не проверяются:
// утилита не обращается в сеть.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxDocSize ограничивает размер проверяемого документа.
const maxDocSize = 4 << 20

func main() {
	root := flag.String("root", ".", "корень репозитория")
	flag.Parse()

	broken, err := checkTree(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "docs-check:", err)
		os.Exit(2)
	}
	for _, b := range broken {
		fmt.Fprintln(os.Stderr, b)
	}
	if len(broken) > 0 {
		fmt.Fprintf(os.Stderr, "docs-check: битых ссылок: %d\n", len(broken))
		os.Exit(1)
	}
}

// checkTree проверяет README.md, CLAUDE.md и все markdown-файлы в docs/.
func checkTree(root string) ([]string, error) {
	files := []string{}
	for _, f := range []string{"README.md", "CLAUDE.md"} {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			files = append(files, f)
		}
	}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, rel)
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	var broken []string
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			return nil, err
		}
		if len(data) > maxDocSize {
			return nil, fmt.Errorf("%s: документ больше %d байт", f, maxDocSize)
		}
		for _, l := range localLinks(string(data)) {
			target := filepath.Join(root, filepath.Dir(f), l)
			if _, err := os.Stat(target); err != nil {
				broken = append(broken, fmt.Sprintf("%s: ссылка на несуществующий файл %q", f, l))
			}
		}
	}
	return broken, nil
}

// localLinks возвращает относительные пути из markdown-ссылок вида [текст](путь)
// без якорей. Внешние ссылки, почта и якоря внутри документа пропускаются.
func localLinks(text string) []string {
	var out []string
	for {
		i := strings.Index(text, "](")
		if i < 0 {
			return out
		}
		text = text[i+2:]
		j := strings.IndexAny(text, ")\n")
		if j < 0 {
			return out
		}
		target := strings.TrimSpace(text[:j])
		text = text[j:]
		if strings.HasPrefix(target, "<") {
			// Путь в угловых скобках может содержать пробелы: [текст](<путь с пробелом>).
			if k := strings.IndexByte(target, '>'); k > 0 {
				target = target[1:k]
			} else {
				target = target[1:]
			}
		} else if k := strings.IndexByte(target, ' '); k >= 0 {
			// Заголовок ссылки: [текст](путь "заголовок").
			target = target[:k]
		}
		if k := strings.IndexByte(target, '#'); k >= 0 {
			target = target[:k]
		}
		if target == "" || strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
			continue
		}
		out = append(out, target)
	}
}
