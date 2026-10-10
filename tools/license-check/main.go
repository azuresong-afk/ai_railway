// Команда license-check сверяет реестр заимствованных компонентов
// docs/cert/components.yaml с фактическим составом сборки (ТЗ, 8.6):
//   - каждый модуль из vendor/modules.txt есть в реестре с той же версией;
//   - в реестре нет модулей, которых уже нет в vendor/;
//   - лицензия каждого компонента допустима по политике CLAUDE.md;
//   - у каждого вендоренного модуля есть файл лицензии, а SHA-256 файлов
//     лицензий совпадает с license_files в реестре (смена текста при
//     обновлении версии требует пересмотра);
//   - license_decision ссылается на существующий ADR;
//   - версия Go toolchain совпадает с go.mod, версии инструментов — с Makefile.
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/tools/internal/components"
	"github.com/azuresong-afk/ai_railway/tools/internal/repofs"
)

func main() {
	root := flag.String("root", ".", "корень репозитория")
	flag.Parse()

	problems, err := run(os.DirFS(*root))
	if err != nil {
		fmt.Fprintln(os.Stderr, "license-check:", err)
		os.Exit(2)
	}
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "license-check: нарушений: %d\n", len(problems))
		os.Exit(1)
	}
}

// Пути внутри репозитория.
const (
	registryPath = "docs/cert/components.yaml"
	modulesPath  = "vendor/modules.txt"
	goModPath    = "go.mod"
	makefilePath = "Makefile"
)

// readLimited читает файл, если он не больше предела.
func readLimited(fsys fs.FS, name string) ([]byte, error) {
	info, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, err
	}
	if info.Size() > components.MaxFileSize {
		return nil, fmt.Errorf("%s больше %d байт", name, components.MaxFileSize)
	}
	return fs.ReadFile(fsys, name)
}

func run(fsys fs.FS) ([]string, error) {
	regData, err := readLimited(fsys, registryPath)
	if err != nil {
		return nil, err
	}
	reg, err := components.Parse(bytes.NewReader(regData))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", registryPath, err)
	}

	var modules []components.Module
	data, err := readLimited(fsys, modulesPath)
	switch {
	case err == nil:
		if modules, err = components.ParseModulesTxt(data); err != nil {
			return nil, err
		}
	case errors.Is(err, fs.ErrNotExist):
		// Без зависимостей vendor/ не создаётся.
	default:
		return nil, err
	}
	goMod, err := readLimited(fsys, goModPath)
	if err != nil {
		return nil, err
	}
	makefile, err := readLimited(fsys, makefilePath)
	if err != nil {
		return nil, err
	}

	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return nil, err
	}
	hasher, err := p.Hasher()
	if err != nil {
		return nil, err
	}

	byModule := map[string]components.Component{}
	for _, c := range reg.Components {
		if err := components.CheckLicense(c); err != nil {
			add("%s %s: %v", c.Name, c.Version, err)
		}
		if n := components.DecisionADR(c.LicenseDecision); n != "" {
			matches, err := fs.Glob(fsys, "docs/adr/"+n+"-*.md")
			if err != nil {
				return nil, err
			}
			if len(matches) == 0 {
				add("%s: license_decision ссылается на ADR-%s, которого нет в docs/adr/", c.Name, n)
			}
		}
		if c.Type == components.TypeGoModule {
			if c.Scope != components.ScopeProduct {
				add("%s: модуль Go в vendor/ — это часть продукта, scope должен быть product", c.Name)
			}
			byModule[c.Name] = c
		}
	}

	inVendor := map[string]bool{}
	for _, m := range modules {
		inVendor[m.Path] = true
		if m.Replace != "" {
			add("%s: замена модуля (%s) требует отдельного решения и записи в реестре", m.Path, m.Replace)
		}
		c, ok := byModule[m.Path]
		if !ok {
			add("%s %s: модуля нет в %s", m.Path, m.Version, registryPath)
			continue
		}
		if c.Version != m.Version {
			add("%s: в реестре версия %s, в vendor/ — %s", m.Path, c.Version, m.Version)
		}
		got, err := licenseFiles(fsys, "vendor/"+m.Path, hasher)
		if err != nil {
			return nil, err
		}
		if len(got) == 0 {
			add("%s: в vendor/%s нет файла лицензии", m.Path, m.Path)
			continue
		}
		for name, sum := range got {
			if want, ok := c.LicenseFiles[name]; !ok {
				add("%s: файла лицензии %s нет в license_files реестра (SHA-256 %s)", m.Path, name, sum)
			} else if want != sum {
				add("%s: текст %s изменился (SHA-256 %s, в реестре %s) — пересмотрите лицензию", m.Path, name, sum, want)
			}
		}
		for name := range c.LicenseFiles {
			if _, ok := got[name]; !ok {
				add("%s: в vendor/ нет файла %s из license_files", m.Path, name)
			}
		}
	}
	for name := range byModule {
		if !inVendor[name] {
			add("%s: модуль есть в реестре, но его нет в vendor/ — удалите запись", name)
		}
	}

	toolchain := goDirective(goMod, "toolchain")
	makeVars := makefileVars(makefile)
	toolchainFound := false
	for _, c := range reg.Components {
		switch {
		case c.Type == components.TypeToolchain:
			toolchainFound = true
			if "go"+strings.TrimPrefix(c.Version, "go") != toolchain {
				add("Go toolchain: в реестре %s, в go.mod — %s", c.Version, toolchain)
			}
		case c.MakefileVar != "":
			if v, ok := makeVars[c.MakefileVar]; !ok {
				add("%s: переменной %s нет в Makefile", c.Name, c.MakefileVar)
			} else if v != c.Version {
				add("%s: в реестре версия %s, в Makefile (%s) — %s", c.Name, c.Version, c.MakefileVar, v)
			}
		}
	}
	if !toolchainFound {
		add("в реестре нет записи о Go toolchain (type: toolchain)")
	}
	pinProblems, err := checkPins(fsys, reg)
	if err != nil {
		return nil, err
	}
	problems = append(problems, pinProblems...)
	sort.Strings(problems)
	return problems, nil
}

// licenseFiles считает SHA-256 файлов лицензий в корне каталога модуля:
// LICENSE*, LICENCE*, COPYING*, NOTICE*.
func licenseFiles(fsys fs.FS, dir string, hasher aisecCrypto.Hasher) (map[string]string, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		n := strings.ToUpper(e.Name())
		isLicense := strings.HasPrefix(n, "LICENSE") || strings.HasPrefix(n, "LICENCE") ||
			strings.HasPrefix(n, "COPYING") || strings.HasPrefix(n, "NOTICE")
		if e.IsDir() || !isLicense {
			continue
		}
		data, err := readLimited(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, err
		}
		out[e.Name()] = hex.EncodeToString(hasher.Sum(data))
	}
	return out, nil
}

var (
	usesRe   = regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*["']?([^\s"'#]+)`)
	shaRe    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestRe = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	fromRe   = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?`)
	argRe    = regexp.MustCompile(`(?im)^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)`)
	varRe    = regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$`)
)

// checkPins сверяет закреплённые версии в CI и Dockerfile с реестром:
//   - каждое действие GitHub (в workflow и составных действиях) — по SHA
//     коммита и с тем же SHA, что в реестре; docker://-действия — по digest;
//   - каждый образ в FROM любого Dockerfile — по digest и записан в реестре
//     (имя записи — репозиторий образа, версия — «тег@sha256:…»);
//   - записи github-action и image, которые нигде не используются, — ошибка.
func checkPins(fsys fs.FS, reg *components.Registry) ([]string, error) {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	actions := map[string]string{}
	images := map[string]string{} // репозиторий → «тег@sha256:…»
	usedActions, usedImages := map[string]bool{}, map[string]bool{}
	for _, c := range reg.Components {
		switch c.Type {
		case components.TypeGitHubAction:
			i := strings.LastIndexByte(c.Version, '@')
			if i < 0 || !shaRe.MatchString(c.Version[i+1:]) {
				add("%s: версия действия в реестре — «тег@SHA коммита»", c.Name)
				continue
			}
			actions[c.Name] = c.Version[i+1:]
		case components.TypeImage:
			if !digestRe.MatchString(c.Version) {
				add("%s: версия образа в реестре — «тег@sha256:<64 hex>»", c.Name)
				continue
			}
			images[c.Name] = c.Version
		}
	}

	var ciFiles []string
	err := fs.WalkDir(fsys, ".github", func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return fs.SkipDir
		}
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml") {
			ciFiles = append(ciFiles, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, f := range ciFiles {
		data, err := readLimited(fsys, f)
		if err != nil {
			return nil, err
		}
		for _, m := range usesRe.FindAllStringSubmatch(string(data), -1) {
			ref := m[1]
			switch {
			case strings.HasPrefix(ref, "./"):
				// Локальное действие из репозитория — проверяется как его файлы.
			case strings.HasPrefix(ref, "docker://"):
				if !digestRe.MatchString(ref) {
					add("%s: %s — образ действия закрепляется по digest", f, ref)
				}
			default:
				i := strings.LastIndexByte(ref, '@')
				if i < 0 || !shaRe.MatchString(ref[i+1:]) {
					add("%s: %s — действие закрепляется по SHA коммита (ADR-0002)", f, ref)
					continue
				}
				name, sha := ref[:i], ref[i+1:]
				usedActions[name] = true
				switch {
				case actions[name] == "":
					add("%s: действия %s нет в реестре (type: github-action)", f, name)
				case actions[name] != sha:
					add("%s: %s@%s, а в реестре SHA %s", f, name, sha, actions[name])
				}
			}
		}
	}

	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if repofs.Skip(p, d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasPrefix(d.Name(), "Dockerfile") || strings.HasSuffix(d.Name(), ".dockerignore") {
			return nil
		}
		data, err := readLimited(fsys, p)
		if err != nil {
			return err
		}
		args := map[string]string{}
		for _, m := range argRe.FindAllStringSubmatch(string(data), -1) {
			args[m[1]] = m[2]
		}
		stages := map[string]bool{}
		for _, m := range fromRe.FindAllStringSubmatch(string(data), -1) {
			img := m[1]
			if v := varRe.FindStringSubmatch(img); v != nil {
				img = args[v[1]]
			}
			switch {
			case img == "":
				add("%s: FROM %s — значение аргумента не задано в Dockerfile", p, m[1])
			case strings.EqualFold(img, "scratch") || stages[img]:
				// Пустой образ или предыдущая стадия сборки.
			case !digestRe.MatchString(img):
				add("%s: образ %s не закреплён по digest (ТЗ, 8.7)", p, img)
			default:
				repo, ver, _ := strings.Cut(img, ":")
				usedImages[repo] = true
				if images[repo] != ver {
					add("%s: образа %s нет в реестре (type: image, name: %s, version: %s)", p, img, repo, ver)
				}
			}
			if m[2] != "" {
				stages[m[2]] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for name := range actions {
		if !usedActions[name] {
			add("%s: действие есть в реестре, но не используется в .github/ — удалите запись", name)
		}
	}
	for name := range images {
		if !usedImages[name] {
			add("%s: образ есть в реестре, но не используется ни в одном Dockerfile — удалите запись", name)
		}
	}
	return problems, nil
}

// goDirective возвращает значение директивы go.mod («go», «toolchain»).
func goDirective(goMod []byte, name string) string {
	for _, line := range strings.Split(string(goMod), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == name {
			return f[1]
		}
	}
	return ""
}

var makeVarLine = regexp.MustCompile(`^([A-Z][A-Z0-9_]*)\s*:?=\s*(\S+)\s*$`)

// makefileVars собирает простые присваивания вида «ИМЯ := значение».
func makefileVars(makefile []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(makefile), "\n") {
		if m := makeVarLine.FindStringSubmatch(line); m != nil {
			out[m[1]] = m[2]
		}
	}
	return out
}
