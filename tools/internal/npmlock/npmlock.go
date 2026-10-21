// Пакет npmlock разбирает web/package.json и web/package-lock.json
// (lockfileVersion 3). Используется утилитами license-check и sbom
// (задача 2.21 этапа 2, ADR-0011).
package npmlock

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// MaxFileSize ограничивает размер package.json и package-lock.json.
const MaxFileSize = 16 << 20

// RegistryPrefix — единственный разрешённый источник пакетов (ADR-0003, п. 5).
const RegistryPrefix = "https://registry.npmjs.org/"

// Package — запись lock-файла.
type Package struct {
	Path      string // «node_modules/a/node_modules/b»
	Name      string // «b» или «@scope/b»
	Version   string
	Resolved  string
	Integrity string
	License   string
	Dev       bool // пакет достижим только из devDependencies
	Link      bool
	deps      []string
}

// Lock — разобранный lock-файл.
type Lock struct {
	Packages []Package // отсортированы по Path
	// Direct — прямые зависимости из package.json корня: имя → точная версия.
	Runtime map[string]string
	Dev     map[string]string
	byPath  map[string]*Package
}

type rawPackage struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved"`
	Integrity    string            `json:"integrity"`
	License      json.RawMessage   `json:"license"`
	Dev          bool              `json:"dev"`
	Link         bool              `json:"link"`
	Dependencies map[string]string `json:"dependencies"`
	Optional     map[string]string `json:"optionalDependencies"`
	Peer         map[string]string `json:"peerDependencies"`
	DevDeps      map[string]string `json:"devDependencies"`
}

type rawLock struct {
	LockfileVersion int                   `json:"lockfileVersion"`
	Packages        map[string]rawPackage `json:"packages"`
}

// Parse разбирает lock-файл. Версии прямых зависимостей берутся из lock,
// а не из package.json: проверка их точности — в ParseManifest.
func Parse(lockData []byte) (*Lock, error) {
	if len(lockData) > MaxFileSize {
		return nil, fmt.Errorf("package-lock.json больше %d байт", MaxFileSize)
	}
	var raw rawLock
	dec := json.NewDecoder(bytes.NewReader(lockData))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("разбор package-lock.json: %w", err)
	}
	if raw.LockfileVersion != 3 {
		return nil, fmt.Errorf("package-lock.json: ожидается lockfileVersion 3, получено %d", raw.LockfileVersion)
	}
	root, ok := raw.Packages[""]
	if !ok {
		return nil, errors.New("package-lock.json: нет корневой записи packages[\"\"]")
	}
	l := &Lock{Runtime: map[string]string{}, Dev: map[string]string{}, byPath: map[string]*Package{}}
	paths := make([]string, 0, len(raw.Packages))
	for p := range raw.Packages {
		if p != "" {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		r := raw.Packages[p]
		name, ok := nameFromPath(p)
		if !ok {
			return nil, fmt.Errorf("package-lock.json: неожиданный путь %q", p)
		}
		pkg := Package{
			Path: p, Name: name, Version: r.Version, Resolved: r.Resolved,
			Integrity: r.Integrity, License: licenseString(r.License), Dev: r.Dev, Link: r.Link,
		}
		for d := range r.Dependencies {
			pkg.deps = append(pkg.deps, d)
		}
		for d := range r.Optional {
			pkg.deps = append(pkg.deps, d)
		}
		sort.Strings(pkg.deps)
		l.Packages = append(l.Packages, pkg)
	}
	for i := range l.Packages {
		l.byPath[l.Packages[i].Path] = &l.Packages[i]
	}
	for _, d := range sortedKeys(root.Dependencies) {
		l.Runtime[d] = root.Dependencies[d]
	}
	for _, d := range sortedKeys(root.DevDeps) {
		l.Dev[d] = root.DevDeps[d]
	}
	return l, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// licenseString приводит поле license к строке SPDX. Устаревшие формы
// (объект, массив) считаются отсутствием лицензии: их разбирают вручную.
func licenseString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	return ""
}

// nameFromPath возвращает имя пакета из пути «…/node_modules/<имя>».
func nameFromPath(p string) (string, bool) {
	const marker = "node_modules/"
	i := strings.LastIndex(p, marker)
	if i < 0 || (i > 0 && p[i-1] != '/') {
		return "", false
	}
	name := p[i+len(marker):]
	if name == "" || strings.HasSuffix(name, "/") {
		return "", false
	}
	return name, true
}

// ResolveDep находит пакет, который подключит Node для зависимости name
// пакета по пути from (поиск вверх по вложенным node_modules). from == ""
// — корень проекта.
func (l *Lock) ResolveDep(from, name string) (*Package, bool) {
	for {
		cand := "node_modules/" + name
		if from != "" {
			cand = from + "/node_modules/" + name
		}
		if p, ok := l.byPath[cand]; ok {
			return p, true
		}
		if from == "" {
			return nil, false
		}
		i := strings.LastIndex(from, "/node_modules/")
		if i < 0 {
			from = ""
		} else {
			from = from[:i]
		}
	}
}

// Deps возвращает пакеты, от которых напрямую зависит p.
func (l *Lock) Deps(p *Package) []*Package {
	var out []*Package
	for _, d := range p.deps {
		if q, ok := l.ResolveDep(p.Path, d); ok {
			out = append(out, q)
		}
	}
	return out
}

// Direct возвращает прямые зависимости корня (runtime или dev) пакетами lock.
func (l *Lock) Direct(dev bool) []*Package {
	src := l.Runtime
	if dev {
		src = l.Dev
	}
	var out []*Package
	for _, n := range sortedKeys(src) {
		if p, ok := l.ResolveDep("", n); ok {
			out = append(out, p)
		}
	}
	return out
}

// Product возвращает пакеты, достижимые из runtime-зависимостей: они
// входят в собранную статику и поставляются заказчику.
func (l *Lock) Product() []*Package {
	seen := map[string]bool{}
	var walk func(p *Package)
	walk = func(p *Package) {
		if seen[p.Path] {
			return
		}
		seen[p.Path] = true
		for _, q := range l.Deps(p) {
			walk(q)
		}
	}
	for _, p := range l.Direct(false) {
		walk(p)
	}
	var out []*Package
	for i := range l.Packages {
		if seen[l.Packages[i].Path] {
			out = append(out, &l.Packages[i])
		}
	}
	return out
}

// Manifest — прямые зависимости из package.json.
type Manifest struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// ParseManifest разбирает package.json.
func ParseManifest(data []byte) (*Manifest, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("package.json больше %d байт", MaxFileSize)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("разбор package.json: %w", err)
	}
	return &m, nil
}

// SHA512Hex переводит integrity («sha512-<base64>») в шестнадцатеричный вид.
func SHA512Hex(integrity string) (string, error) {
	b64, ok := strings.CutPrefix(integrity, "sha512-")
	if !ok {
		return "", fmt.Errorf("integrity %q не в формате sha512", integrity)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 64 {
		return "", fmt.Errorf("integrity %q повреждён", integrity)
	}
	return hex.EncodeToString(raw), nil
}

// PURL — purl пакета npm: pkg:npm/%40scope/name@version.
func PURL(p *Package) string {
	name := strings.Replace(p.Name, "@", "%40", 1)
	return "pkg:npm/" + name + "@" + p.Version
}
