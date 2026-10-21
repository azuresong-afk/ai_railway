package main

import (
	"errors"
	"fmt"
	"sort"

	"github.com/azuresong-afk/ai_railway/tools/internal/components"
	"github.com/azuresong-afk/ai_railway/tools/internal/npmlock"
)

// npmComponents строит компоненты CycloneDX для npm-пакетов поставки — всех,
// достижимых из dependencies веб-консоли (статика встраивается в aisec-server).
// Свойства GOST для прямых зависимостей берутся из реестра, для транзитивных
// — по самому «строгому» из прямых зависимостей, которые их подключают.
// Возвращает компоненты, связи и ссылки прямых зависимостей.
func npmComponents(reg *components.Registry, lock *npmlock.Lock) ([]Component, []Dependency, []string, error) {
	entries := map[string]components.Component{}
	for _, c := range reg.Components {
		if c.Type == components.TypeNPM && c.Scope == components.ScopeProduct {
			entries[c.Name+"@"+c.Version] = c
		}
	}
	pkgs := lock.Product()
	// Для транзитивных пакетов: какие свойства унаследовать.
	attack := map[string]bool{}
	secfn := map[string]bool{}
	for _, d := range lock.Direct(false) {
		c, ok := entries[d.Name+"@"+d.Version]
		if !ok {
			continue
		}
		mark(lock, d, map[string]bool{}, attack, secfn, *c.AttackSurface, *c.SecurityFunction)
	}

	var comps []Component
	var deps []Dependency
	var errs []error
	for _, p := range pkgs {
		hash, err := npmlock.SHA512Hex(p.Integrity)
		if err != nil {
			errs = append(errs, fmt.Errorf("npm %s: %w", p.Path, err))
			continue
		}
		purl := npmlock.PURL(p)
		ref := purl
		if p.Path != "node_modules/"+p.Name {
			ref = purl + "?path=" + p.Path // вложенная копия другой версии/места
		}
		c, direct := entries[p.Name+"@"+p.Version]
		comp := Component{
			Type: "library", BOMRef: ref, Name: p.Name, Version: p.Version, PURL: purl,
			Hashes:   []Hash{{Alg: "SHA-512", Content: hash}},
			Licenses: []License{{Expression: p.License}},
		}
		if direct {
			comp.Description = c.Purpose
			comp.Properties = []Property{
				{propAttackSurface, yesNo(*c.AttackSurface)},
				{propSecurityFunction, yesNo(*c.SecurityFunction)},
				{propProvidedBy, c.ProvidedBy},
			}
			if c.Repository != "" {
				comp.ExternalReferences = []ExternalRef{{Type: "vcs", URL: c.Repository}}
			}
		} else {
			comp.Properties = []Property{
				{propAttackSurface, yesNo(attack[p.Path])},
				{propSecurityFunction, yesNo(secfn[p.Path])},
				{propProvidedBy, "Авторы пакета (реестр npm)"},
			}
		}
		comps = append(comps, comp)
		d := Dependency{Ref: ref}
		for _, q := range lock.Deps(p) {
			if q.Dev {
				continue
			}
			qref := npmlock.PURL(q)
			if q.Path != "node_modules/"+q.Name {
				qref += "?path=" + q.Path
			}
			d.DependsOn = append(d.DependsOn, qref)
		}
		sort.Strings(d.DependsOn)
		if d.DependsOn == nil {
			d.DependsOn = []string{}
		}
		deps = append(deps, d)
	}
	var directRefs []string
	for _, p := range lock.Direct(false) {
		directRefs = append(directRefs, npmlock.PURL(p))
	}
	sort.Strings(directRefs)
	if len(errs) > 0 {
		return nil, nil, nil, errors.Join(errs...)
	}
	return comps, deps, directRefs, nil
}

// mark проходит по зависимостям пакета и накапливает свойства GOST (ИЛИ по
// всем прямым зависимостям, которые подключают пакет).
func mark(lock *npmlock.Lock, p *npmlock.Package, seen, attack, secfn map[string]bool, a, s bool) {
	if seen[p.Path] {
		return
	}
	seen[p.Path] = true
	attack[p.Path] = attack[p.Path] || a
	secfn[p.Path] = secfn[p.Path] || s
	for _, q := range lock.Deps(p) {
		mark(lock, q, seen, attack, secfn, a, s)
	}
}
