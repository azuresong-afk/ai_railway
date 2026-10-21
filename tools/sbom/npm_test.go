package main

import (
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/tools/internal/components"
	"github.com/azuresong-afk/ai_railway/tools/internal/npmlock"
)

const npmIntegrity = "sha512-" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

const npmLockDoc = `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"lib":"1.0.0"},"devDependencies":{"tool":"2.0.0"}},
"node_modules/lib":{"version":"1.0.0","integrity":"` + npmIntegrity + `","license":"MIT","dependencies":{"sub":"1.0.0"}},
"node_modules/sub":{"version":"1.0.0","integrity":"` + npmIntegrity + `","license":"ISC"},
"node_modules/tool":{"version":"2.0.0","dev":true,"integrity":"` + npmIntegrity + `","license":"MIT"}}}`

const npmRegistryDoc = registryDoc + `  - name: lib
    version: 1.0.0
    type: npm-package
    scope: product
    purpose: Библиотека
    license: MIT
    repository: https://example.com/lib
    attack_surface: true
    security_function: false
    provided_by: Авторы
    justification: j
    decision: d
    decided: 2026-10-20
`

func TestBuildWithNPM(t *testing.T) {
	reg, err := components.Parse(strings.NewReader(npmRegistryDoc))
	if err != nil {
		t.Fatal(err)
	}
	_, h := fixtures(t)
	lock, err := npmlock.Parse([]byte(npmLockDoc))
	if err != nil {
		t.Fatal(err)
	}
	bom, err := BuildWithNPM(reg, bins(), lock, "1.0.0", ts, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(bom); err != nil {
		t.Fatal(err)
	}
	byRef := map[string]Component{}
	for _, c := range bom.Components {
		byRef[c.BOMRef] = c
	}
	if _, ok := byRef["pkg:npm/tool@2.0.0"]; ok {
		t.Error("пакет сборочной среды попал в SBOM")
	}
	sub, ok := byRef["pkg:npm/sub@1.0.0"]
	if !ok {
		t.Fatal("нет транзитивного пакета поставки")
	}
	props := map[string]string{}
	for _, p := range sub.Properties {
		props[p.Name] = p.Value
	}
	if props[propAttackSurface] != "yes" || sub.Hashes[0].Alg != "SHA-512" || sub.Hashes[0].Content != strings.Repeat("00", 64) {
		t.Fatalf("транзитивный пакет: %+v", sub)
	}
	var server []string
	for _, d := range bom.Dependencies {
		if d.Ref == "file:aisec-server" {
			server = d.DependsOn
		}
	}
	if !contains(server, "pkg:npm/lib@1.0.0") {
		t.Fatalf("aisec-server не зависит от консоли: %v", server)
	}
}

func TestBuildWithNPMWithoutRegistryEntry(t *testing.T) {
	// Прямой пакет поставки без записи в реестре всё равно попадает в SBOM
	// с унаследованными свойствами, а проверку записей делает license-check.
	reg, _ := fixtures(t)
	_, h := fixtures(t)
	lock, err := npmlock.Parse([]byte(npmLockDoc))
	if err != nil {
		t.Fatal(err)
	}
	bom, err := BuildWithNPM(reg, bins(), lock, "1.0.0", ts, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(bom); err != nil {
		t.Fatal(err)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
