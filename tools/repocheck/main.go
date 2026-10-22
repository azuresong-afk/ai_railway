// Команда repocheck проверяет структурные правила репозитория, которые не
// выражаются настройками линтеров:
//   - каталог internal/crypto в модуле ровно один — ./internal/crypto; иначе
//     вложенный .../internal/crypto снял бы запрет depguard на криптографию;
//   - файлы с cgo (import "C") есть только в путях, разрешённых через ADR;
//   - сетевые клиенты (исходящие HTTP-запросы, net.Dial*, net.Resolver,
//     SMTP, syslog) в cmd/ и internal/ есть только в разрешённых путях:
//     шлюз, провайдеры LLM, отправка событий (ЗИ.2, H-Р11 ревью 2.r5).
package main

import (
	"flag"
	"fmt"
	"go/ast"
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
	netAllowed := flag.String("net-client-allowed", "", "пути (через запятую), где разрешены сетевые клиенты (ЗИ.2)")
	flag.Parse()

	problems, err := check(os.DirFS(*root), Rules{CgoAllowed: splitPaths(*cgoAllowed), NetClientAllowed: splitPaths(*netAllowed)})
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

// splitPaths разбирает список путей через запятую.
func splitPaths(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.Trim(strings.TrimSpace(p), "/"); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Rules — разрешённые пути для правил с исключениями.
type Rules struct {
	CgoAllowed       []string
	NetClientAllowed []string
}

// netClient — функции и типы, через которые компонент может обратиться в
// сеть сам (ЗИ.2: никаких внешних обращений, кроме настроенных
// администратором). Пустое множество — запрещён любой идентификатор пакета.
// Серверная сторона (http.Server, net.Listen) не ограничивается.
var netClient = map[string]map[string]bool{
	"net/http": set("Client", "DefaultClient", "Transport", "DefaultTransport", "Get", "Head", "Post", "PostForm",
		"NewRequest", "NewRequestWithContext"),
	"net": set("Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix", "Dialer", "Resolver", "DefaultResolver",
		"LookupHost", "LookupIP", "LookupAddr", "LookupCNAME", "LookupMX", "LookupNS", "LookupPort", "LookupSRV", "LookupTXT"),
	"crypto/tls":             set("Dial", "DialWithDialer", "Dialer"),
	"net/http/httputil":      set("ReverseProxy", "NewSingleHostReverseProxy"),
	"net/smtp":               {},
	"net/rpc":                {},
	"net/rpc/jsonrpc":        {},
	"log/syslog":             {},
	"golang.org/x/net/proxy": {},
}

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// netScoped — правило сетевых клиентов действует на поставляемый код: cmd/
// и internal/ без тестов (тесты поднимают свои серверы и клиенты).
func netScoped(p string) bool {
	return (strings.HasPrefix(p, "cmd/") || strings.HasPrefix(p, "internal/")) && !strings.HasSuffix(p, "_test.go")
}

// netClientUses — использования сетевых клиентов в файле: «пакет.Имя».
func netClientUses(f *ast.File) []string {
	local := map[string]string{} // имя в файле → путь пакета
	for _, imp := range f.Imports {
		ip := strings.Trim(imp.Path.Value, `"`)
		if _, ok := netClient[ip]; !ok {
			continue
		}
		name := path.Base(ip)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "_" || name == "." {
			// Импорт ради побочного эффекта или в общее пространство имён
			// не проверить по идентификаторам — запрещён целиком.
			return []string{ip + " (импорт " + name + ")"}
		}
		local[name] = ip
	}
	if len(local) == 0 {
		return nil
	}
	var uses []string
	seen := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Obj != nil {
			return true
		}
		ip, ok := local[id.Name]
		if !ok {
			return true
		}
		if names := netClient[ip]; len(names) == 0 || names[sel.Sel.Name] {
			u := ip + "." + sel.Sel.Name
			if !seen[u] {
				seen[u] = true
				uses = append(uses, u)
			}
		}
		return true
	})
	return uses
}

// check обходит дерево и возвращает описания нарушений.
func check(fsys fs.FS, rules Rules) ([]string, error) {
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
		mode := parser.ImportsOnly
		netCheck := netScoped(p) && !under(p, rules.NetClientAllowed)
		if netCheck {
			// Полный разбор с разрешением имён: локальная переменная http не
			// путается с пакетом.
			mode = 0
		}
		f, err := parser.ParseFile(fset, p, src, mode)
		if err != nil {
			return fmt.Errorf("разбор %s: %w", p, err)
		}
		for _, imp := range f.Imports {
			if imp.Path.Value == `"C"` && !under(p, rules.CgoAllowed) {
				problems = append(problems, fmt.Sprintf("%s: cgo вне разрешённых путей; cgo — только по ADR (CLAUDE.md)", p))
			}
		}
		if netCheck {
			for _, u := range netClientUses(f) {
				problems = append(problems, fmt.Sprintf("%s: сетевой клиент %s вне разрешённых путей; исходящие соединения — только настроенные администратором (ЗИ.2)", p, u))
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
