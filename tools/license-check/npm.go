package main

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"github.com/azuresong-afk/ai_railway/tools/internal/components"
	"github.com/azuresong-afk/ai_railway/tools/internal/npmlock"
)

// Пути фронтенда внутри репозитория.
const (
	npmManifestPath = "web/package.json"
	npmLockPath     = "web/package-lock.json"
)

// exactVersionRe — точная версия без диапазонов (CLAUDE.md: версии фиксируются точно).
var exactVersionRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// checkNPM сверяет фронтенд с реестром (задача 2.21, ADR-0011):
//   - версии в package.json точные, а package-lock.json им соответствует;
//   - каждый пакет lock берётся из реестра npm, с контрольной суммой sha512;
//   - лицензия каждого пакета допустима: пакеты поставки — по политике
//     CLAUDE.md, пакеты сборочной среды — ещё и по components.NPMBuildLicenses;
//   - прямые зависимости записаны в реестре компонентов с той же версией,
//     областью (dependencies — product, devDependencies — build) и лицензией.
func checkNPM(fsys fs.FS, reg *components.Registry) ([]string, error) {
	manData, err := readLimited(fsys, npmManifestPath)
	if errors.Is(err, fs.ErrNotExist) {
		return npmEntriesWithoutFrontend(reg), nil
	}
	if err != nil {
		return nil, err
	}
	lockData, err := readLimited(fsys, npmLockPath)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{npmLockPath + ": нет lock-файла рядом с " + npmManifestPath}, nil
	}
	if err != nil {
		return nil, err
	}
	man, err := npmlock.ParseManifest(manData)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", npmManifestPath, err)
	}
	lock, err := npmlock.Parse(lockData)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", npmLockPath, err)
	}

	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	for name, v := range man.Dependencies {
		if !exactVersionRe.MatchString(v) {
			add("%s: %s — версия %q не точная (нужна вида 1.2.3)", npmManifestPath, name, v)
		}
	}
	for name, v := range man.DevDependencies {
		if !exactVersionRe.MatchString(v) {
			add("%s: %s — версия %q не точная (нужна вида 1.2.3)", npmManifestPath, name, v)
		}
	}
	if !sameMap(man.Dependencies, lock.Runtime) || !sameMap(man.DevDependencies, lock.Dev) {
		add("%s не соответствует %s: выполните npm install в web/ и закоммитьте lock-файл", npmLockPath, npmManifestPath)
	}

	product := map[string]bool{}
	for _, p := range lock.Product() {
		product[p.Path] = true
	}
	for i := range lock.Packages {
		p := &lock.Packages[i]
		if p.Link {
			add("%s: %s — ссылка на локальный каталог (link) не допускается", npmLockPath, p.Path)
			continue
		}
		if !strings.HasPrefix(p.Resolved, npmlock.RegistryPrefix) {
			add("%s: %s — источник %q, разрешён только %s", npmLockPath, p.Path, p.Resolved, npmlock.RegistryPrefix)
		}
		if _, err := npmlock.SHA512Hex(p.Integrity); err != nil {
			add("%s: %s — %v", npmLockPath, p.Path, err)
		}
		if err := components.CheckNPMLicense(p.License, product[p.Path]); err != nil && !licenseException(reg, p) {
			add("%s@%s: %v", p.Path, p.Version, err)
		}
	}

	direct := map[string]*npmlock.Package{}
	scopes := map[string]string{}
	for _, p := range lock.Direct(false) {
		direct[p.Name], scopes[p.Name] = p, components.ScopeProduct
	}
	for _, p := range lock.Direct(true) {
		if _, dup := direct[p.Name]; !dup {
			direct[p.Name], scopes[p.Name] = p, components.ScopeBuild
		}
	}
	entries := map[string]components.Component{}
	for _, c := range reg.Components {
		if c.Type != components.TypeNPM {
			continue
		}
		entries[c.Name] = c
		if _, ok := direct[c.Name]; !ok && !licenseException(reg, packageByName(lock, c.Name, c.Version)) {
			add("%s: пакет есть в реестре, но не указан в %s — удалите запись", c.Name, npmManifestPath)
		}
	}
	for name, p := range direct {
		c, ok := entries[name]
		switch {
		case !ok:
			add("%s %s: прямой зависимости нет в %s (type: npm-package)", name, p.Version, registryPath)
		case c.Version != p.Version:
			add("%s: в реестре версия %s, в %s — %s", name, c.Version, npmLockPath, p.Version)
		case c.Scope != scopes[name]:
			add("%s: scope в реестре %s, по %s должен быть %s", name, c.Scope, npmManifestPath, scopes[name])
		case c.License != p.License:
			add("%s: в реестре лицензия %q, в %s — %q", name, c.License, npmLockPath, p.License)
		}
	}
	return problems, nil
}

// licenseException сообщает, что для транзитивного пакета есть запись реестра
// (type: npm-package, та же версия и лицензия) с license_decision: отдельное
// решение о лицензии, не входящей в политику (ADR-0011).
func licenseException(reg *components.Registry, p *npmlock.Package) bool {
	if p == nil {
		return false
	}
	for _, c := range reg.Components {
		if c.Type == components.TypeNPM && c.Name == p.Name && c.Version == p.Version &&
			c.License == p.License && components.DecisionADR(c.LicenseDecision) != "" {
			return true
		}
	}
	return false
}

// packageByName находит в lock пакет с таким именем и версией.
func packageByName(l *npmlock.Lock, name, version string) *npmlock.Package {
	for i := range l.Packages {
		if l.Packages[i].Name == name && l.Packages[i].Version == version {
			return &l.Packages[i]
		}
	}
	return nil
}

// npmEntriesWithoutFrontend: записи npm-package без web/package.json — ошибка.
func npmEntriesWithoutFrontend(reg *components.Registry) []string {
	var out []string
	for _, c := range reg.Components {
		if c.Type == components.TypeNPM {
			out = append(out, fmt.Sprintf("%s: запись npm-package есть, а %s нет", c.Name, npmManifestPath))
		}
	}
	return out
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
