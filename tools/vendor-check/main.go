// Команда vendor-check проверяет неизменность vendor/ (ТЗ, 8.7; замечание
// ревью 1.4 этапа 0).
//
// Хеш h1 из go.sum нельзя пересчитать по vendor/: Go копирует туда только
// нужные пакеты, без тестов и лишних файлов. Поэтому проверка двухуровневая:
//
//   - без сети (по умолчанию): модули и версии в vendor/modules.txt совпадают
//     с go.mod, у каждого есть оба хеша в go.sum, а все файлы vendor/ совпадают
//     с манифестом SHA-256 (docs/cert/vendor.sha256). Лишний, пропавший или
//     изменённый файл — нарушение;
//   - -update: пересчитывает манифест (после go mod vendor, изменение попадает
//     в дифф ревью);
//   - -verify (нужна сеть): go mod vendor во временный каталог и сравнение с
//     vendor/. Это настоящая сверка с go.sum и sum.golang.org.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	manifestPath = "docs/cert/vendor.sha256"
	modulesPath  = "vendor/modules.txt"
	// maxFile и maxManifest ограничивают размер читаемых файлов.
	maxFile     = 32 << 20
	maxManifest = 4 << 20
	verifyLimit = 5 * time.Minute
)

func main() {
	root := flag.String("root", ".", "корень репозитория")
	update := flag.Bool("update", false, "пересчитать манифест "+manifestPath)
	verify := flag.Bool("verify", false, "заново выполнить go mod vendor и сравнить с vendor/ (нужна сеть)")
	flag.Parse()

	fsys := os.DirFS(*root)
	var problems []string
	switch {
	case *update:
		sums, err := hashTree(fsys, "vendor")
		if err != nil {
			fail(err)
		}
		if err := os.WriteFile(filepath.Join(*root, manifestPath), formatManifest(sums), 0o644); err != nil { // #nosec G306 -- публичный документ
			fail(err)
		}
		fmt.Printf("vendor-check: манифест обновлён, файлов: %d\n", len(sums))
		return
	case *verify:
		p, err := verifyRebuild(*root, fsys)
		if err != nil {
			fail(err)
		}
		problems = p
	default:
		p, err := check(fsys)
		if err != nil {
			fail(err)
		}
		problems = p
	}
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "vendor-check: нарушений: %d\n", len(problems))
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "vendor-check:", err)
	os.Exit(2)
}

// module — запись «# путь версия» из vendor/modules.txt.
type module struct{ path, version string }

// check — проверка без сети.
func check(fsys fs.FS) ([]string, error) {
	var problems []string
	mods, err := parseModules(fsys)
	if err != nil {
		return nil, err
	}
	req, err := parseRequires(fsys)
	if err != nil {
		return nil, err
	}
	sums, err := parseGoSum(fsys)
	if err != nil {
		return nil, err
	}
	have := map[string]string{}
	for _, m := range mods {
		have[m.path] = m.version
		if v, ok := req[m.path]; !ok {
			problems = append(problems, fmt.Sprintf("%s: модуль есть в vendor/modules.txt, но не в go.mod", m.path))
		} else if v != m.version {
			problems = append(problems, fmt.Sprintf("%s: в go.mod %s, в vendor/modules.txt %s", m.path, v, m.version))
		}
		if !sums[m.path+" "+m.version] {
			problems = append(problems, fmt.Sprintf("%s %s: нет хеша модуля h1 в go.sum", m.path, m.version))
		}
		if !sums[m.path+" "+m.version+"/go.mod"] {
			problems = append(problems, fmt.Sprintf("%s %s: нет хеша go.mod в go.sum", m.path, m.version))
		}
	}
	for p := range req {
		if _, ok := have[p]; !ok {
			problems = append(problems, fmt.Sprintf("%s: модуль есть в go.mod, но не в vendor/modules.txt (выполните go mod vendor)", p))
		}
	}

	want, err := readManifest(fsys)
	if err != nil {
		return nil, err
	}
	got, err := hashTree(fsys, "vendor")
	if err != nil {
		return nil, err
	}
	problems = append(problems, diff(want, got, "манифест "+manifestPath, "vendor/")...)
	sort.Strings(problems)
	return problems, nil
}

// diff сравнивает два набора «путь → SHA-256».
func diff(want, got map[string]string, wantName, gotName string) []string {
	var out []string
	for p, h := range want {
		g, ok := got[p]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s: файл есть в %s, но отсутствует в %s", p, wantName, gotName))
		case g != h:
			out = append(out, fmt.Sprintf("%s: содержимое отличается (%s и %s)", p, wantName, gotName))
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			out = append(out, fmt.Sprintf("%s: файл есть в %s, но отсутствует в %s", p, gotName, wantName))
		}
	}
	return out
}

// hashTree возвращает SHA-256 всех обычных файлов дерева dir; пути — от корня
// fsys. Символические ссылки и прочие не обычные файлы — ошибка: в vendor/
// их быть не должно.
func hashTree(fsys fs.FS, dir string) (map[string]string, error) {
	res := map[string]string{}
	err := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: не обычный файл", p)
		}
		b, err := readLimited(fsys, p, maxFile)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		res[p] = hex.EncodeToString(sum[:])
		return nil
	})
	return res, err
}

func readLimited(fsys fs.FS, p string, limit int64) ([]byte, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // чтение
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s: размер %d больше предела %d", p, st.Size(), limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: размер больше предела %d", p, limit)
	}
	return b, nil
}

// formatManifest — формат sha256sum: «<hex>  <путь>», строки по возрастанию пути.
func formatManifest(sums map[string]string) []byte {
	paths := make([]string, 0, len(sums))
	for p := range sums {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var b bytes.Buffer
	for _, p := range paths {
		fmt.Fprintf(&b, "%s  %s\n", sums[p], p)
	}
	return b.Bytes()
}

func readManifest(fsys fs.FS) (map[string]string, error) {
	b, err := readLimited(fsys, manifestPath, maxManifest)
	if err != nil {
		return nil, fmt.Errorf("манифест: %w (создайте: make vendor-manifest)", err)
	}
	res := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" {
			continue
		}
		h, p, ok := strings.Cut(line, "  ")
		if !ok || len(h) != 64 || !isHex(h) || !strings.HasPrefix(p, "vendor/") || path.Clean(p) != p {
			return nil, fmt.Errorf("%s:%d: неверная строка манифеста", manifestPath, n)
		}
		if _, dup := res[p]; dup {
			return nil, fmt.Errorf("%s:%d: путь %s повторяется", manifestPath, n, p)
		}
		res[p] = h
	}
	return res, sc.Err()
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// parseModules читает строки «# путь версия» из vendor/modules.txt.
func parseModules(fsys fs.FS) ([]module, error) {
	b, err := readLimited(fsys, modulesPath, maxManifest)
	if err != nil {
		return nil, err
	}
	var mods []module
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		f := strings.Fields(line[2:])
		if len(f) < 2 {
			return nil, fmt.Errorf("%s: неверная строка %q", modulesPath, line)
		}
		mods = append(mods, module{f[0], f[1]})
	}
	return mods, nil
}

// parseRequires читает require из go.mod (одиночные и блочные), без замен.
func parseRequires(fsys fs.FS) (map[string]string, error) {
	b, err := readLimited(fsys, "go.mod", maxManifest)
	if err != nil {
		return nil, err
	}
	res := map[string]string{}
	inBlock := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "//", 2)[0])
		switch {
		case line == "require (":
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case inBlock && line != "":
			if f := strings.Fields(line); len(f) == 2 {
				res[f[0]] = f[1]
			}
		case strings.HasPrefix(line, "require "):
			if f := strings.Fields(line); len(f) == 3 {
				res[f[1]] = f[2]
			}
		}
	}
	return res, nil
}

// parseGoSum возвращает множество «путь версия» и «путь версия/go.mod»,
// для которых есть хеш h1.
func parseGoSum(fsys fs.FS) (map[string]bool, error) {
	b, err := readLimited(fsys, "go.sum", maxManifest)
	if err != nil {
		return nil, err
	}
	res := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && strings.HasPrefix(f[2], "h1:") {
			res[f[0]+" "+f[1]] = true
		}
	}
	return res, nil
}

// verifyRebuild выполняет go mod vendor во временный каталог (с сетью и
// проверкой по go.sum / sum.golang.org) и сравнивает результат с vendor/.
func verifyRebuild(root string, fsys fs.FS) ([]string, error) {
	tmp, err := os.MkdirTemp("", "vendor-verify-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp) //nolint:errcheck // временный каталог
	out := filepath.Join(tmp, "vendor")

	ctx, cancel := context.WithTimeout(context.Background(), verifyLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "mod", "vendor", "-o", out) // #nosec G204 -- фиксированные аргументы
	cmd.Dir = root
	// Сеть нужна, vendor/ при этом не читается: -mod=mod.
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if msg, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("go mod vendor: %w\n%s", err, msg)
	}
	want, err := hashTree(os.DirFS(tmp), "vendor")
	if err != nil {
		return nil, err
	}
	got, err := hashTree(fsys, "vendor")
	if err != nil {
		return nil, err
	}
	p := diff(want, got, "свежей сборке", "vendor/")
	sort.Strings(p)
	return p, nil
}
