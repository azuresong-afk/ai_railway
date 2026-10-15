// Команда repocheck проверяет структурные правила репозитория, которые не
// выражаются настройками линтеров:
//   - каталог internal/crypto в модуле ровно один — ./internal/crypto; иначе
//     вложенный .../internal/crypto снял бы запрет depguard на криптографию;
//   - файлы с cgo (import "C") есть только в путях, разрешённых через ADR.
package main

import (
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/azuresong-afk/ai_railway/tools/internal/repofs"
)

// cryptoDir — единственный разрешённый каталог с криптографией.
const cryptoDir = "internal/crypto"

// maxGoFile ограничивает размер разбираемого файла.
const maxGoFile = 8 << 20

func main() {
	root := flag.String("root", ".", "корень репозитория")
	cgoAllowed := flag.String("cgo-allowed", "", "пути (через запятую), где cgo разрешён по ADR")
	flag.Parse()

	var allowed []string
	for _, p := range strings.Split(*cgoAllowed, ",") {
		if p = strings.Trim(strings.TrimSpace(p), "/"); p != "" {
			allowed = append(allowed, p)
		}
	}
	problems, err := check(os.DirFS(*root), allowed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "repocheck:", err)
		os.Exit(2)
	}
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "repocheck: нарушений: %d\n", len(problems))
		os.Exit(1)
	}
}

// check обходит дерево и возвращает описания нарушений.
func check(fsys fs.FS, cgoAllowed []string) ([]string, error) {
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
			if d.Name() == "crypto" && path.Base(path.Dir(p)) == "internal" && p != cryptoDir {
				problems = append(problems, fmt.Sprintf("%s: лишний каталог internal/crypto; криптография — только в ./%s", p, cryptoDir))
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxGoFile {
			return fmt.Errorf("%s: файл больше %d байт", p, maxGoFile)
		}
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, p, src, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("разбор %s: %w", p, err)
		}
		for _, imp := range f.Imports {
			if imp.Path.Value == `"C"` && !under(p, cgoAllowed) {
				problems = append(problems, fmt.Sprintf("%s: cgo вне разрешённых путей; cgo — только по ADR (CLAUDE.md)", p))
			}
		}
		return nil
	})
	sort.Strings(problems)
	return problems, err
}

// under сообщает, лежит ли файл p в одном из каталогов dirs.
func under(p string, dirs []string) bool {
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}
