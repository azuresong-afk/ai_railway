package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/tools/internal/components"
)

const registryDoc = `schema_version: 1
components:
  - name: Go
    version: go1.27.1
    type: toolchain
    scope: product
    purpose: p
    license: BSD-3-Clause
    repository: https://go.googlesource.com/go
    attack_surface: true
    security_function: true
    provided_by: Go
    justification: j
    decision: d
    decided: 2026-09-29
  - name: example.com/m
    version: v1.0.0
    type: go-module
    scope: product
    purpose: p
    license: MIT AND Apache-2.0
    repository: https://example.com/m
    attack_surface: false
    security_function: false
    provided_by: x
    justification: j
    decision: d
    decided: 2026-09-29
`

// h1 — корректный хеш модуля (32 нулевых байта в base64).
const h1 = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func fixtures(t *testing.T) (*components.Registry, aisecCrypto.Hasher) {
	t.Helper()
	reg, err := components.Parse(strings.NewReader(registryDoc))
	if err != nil {
		t.Fatal(err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return reg, h
}

func bins() []Binary {
	return []Binary{
		{Name: "aisec-gateway", SHA256: "aa", GoVersion: "go1.27.1", Deps: []Dep{{"example.com/m", "v1.0.0", h1}}},
		{Name: "aisec-server", SHA256: "bb", GoVersion: "go1.27.1"},
	}
}

var ts = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func TestBuild(t *testing.T) {
	reg, h := fixtures(t)
	bom, err := Build(reg, bins(), "1.0.0", ts, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(bom); err != nil {
		t.Fatal(err)
	}
	// stdlib, модуль и два файла.
	if len(bom.Components) != 4 {
		t.Fatalf("компонентов %d: %+v", len(bom.Components), bom.Components)
	}
	mod := bom.Components[1]
	if mod.PURL != "pkg:golang/example.com/m@v1.0.0" || mod.Licenses[0].Expression != "MIT AND Apache-2.0" ||
		mod.Hashes[0].Content != strings.Repeat("00", 32) {
		t.Fatalf("неверный модуль: %+v", mod)
	}
	props := map[string]string{}
	for _, p := range mod.Properties {
		props[p.Name] = p.Value
	}
	if props[propAttackSurface] != "no" || props[propProvidedBy] != "x" || props[propGoModuleHash] != h1 {
		t.Fatalf("неверные свойства: %v", props)
	}
	if bom.Dependencies[0].Ref != productRef || len(bom.Dependencies[0].DependsOn) != 2 {
		t.Fatalf("неверные зависимости продукта: %+v", bom.Dependencies[0])
	}
	if got := bom.Dependencies[1].DependsOn; len(got) != 2 || got[0] != "pkg:golang/example.com/m@v1.0.0" || got[1] != "stdlib" {
		t.Fatalf("неверные зависимости шлюза: %v", got)
	}
	if bom.Metadata.Timestamp != "2026-09-29T12:00:00Z" {
		t.Fatalf("время: %s", bom.Metadata.Timestamp)
	}
}

func TestBuildReproducible(t *testing.T) {
	reg, h := fixtures(t)
	a, err := Build(reg, bins(), "1.0.0", ts, h)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(reg, bins(), "1.0.0", ts, h)
	if err != nil {
		t.Fatal(err)
	}
	ja, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ja) != string(jb) {
		t.Fatal("одинаковый вход дал разные SBOM")
	}
	changed := bins()
	changed[0].SHA256 = "cc"
	c, err := Build(reg, changed, "1.0.0", ts, h)
	if err != nil {
		t.Fatal(err)
	}
	if c.SerialNumber == a.SerialNumber {
		t.Fatal("серийный номер не зависит от содержимого")
	}
	if !strings.HasPrefix(a.SerialNumber, "urn:uuid:") || a.SerialNumber[9+14] != '8' {
		t.Fatalf("серийный номер не UUID версии 8: %s", a.SerialNumber)
	}
}

func TestBuildErrors(t *testing.T) {
	reg, h := fixtures(t)
	cases := map[string]func([]Binary) []Binary{
		"модуля нет в реестре": func(b []Binary) []Binary {
			b[0].Deps = append(b[0].Deps, Dep{"example.com/new", "v0.1.0", h1})
			return b
		},
		"другая версия модуля": func(b []Binary) []Binary { b[0].Deps[0].Version = "v1.0.1"; return b },
		"повреждённый хеш":     func(b []Binary) []Binary { b[0].Deps[0].Sum = "h1:xyz"; return b },
		"хеш не h1":            func(b []Binary) []Binary { b[0].Deps[0].Sum = "h2:abc"; return b },
		"разные версии Go":     func(b []Binary) []Binary { b[1].GoVersion = "go1.26.0"; return b },
		"Go не как в реестре":  func(b []Binary) []Binary { b[0].GoVersion = "go1.27.2"; b[1].GoVersion = "go1.27.2"; return b },
		"модуль в двух версиях": func(b []Binary) []Binary {
			b[1].Deps = []Dep{{"example.com/m", "v0.9.0", h1}}
			return b
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(reg, edit(bins()), "1", ts, h); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
}

func TestCheck(t *testing.T) {
	reg, h := fixtures(t)
	good, err := Build(reg, bins(), "1", ts, h)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*BOM){
		"формат":        func(b *BOM) { b.SpecVersion = "1.4" },
		"серийный":      func(b *BOM) { b.SerialNumber = "" },
		"лицензия":      func(b *BOM) { b.Components[1].Licenses = nil },
		"свойство GOST": func(b *BOM) { b.Components[1].Properties = b.Components[1].Properties[1:] },
		"хеш файла":     func(b *BOM) { b.Components[3].Hashes = nil },
		"purl":          func(b *BOM) { b.Components[0].PURL = "" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(good)
			if err != nil {
				t.Fatal(err)
			}
			bom, err := ParseBOM(data)
			if err != nil {
				t.Fatal(err)
			}
			edit(bom)
			if err := Check(bom); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
}

// Тестовый бинарник сам содержит сведения о сборке: проверяем чтение на нём.
func TestReadBinary(t *testing.T) {
	_, h := fixtures(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := readBinary(exe, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.SHA256) != 64 || !strings.HasPrefix(b.GoVersion, "go") {
		t.Fatalf("неверные сведения: %+v", b)
	}
	notBinary := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(notBinary, []byte("не бинарник"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBinary(notBinary, h); err == nil {
		t.Fatal("ожидалась ошибка для файла без сведений о сборке")
	}
}

func TestRunErrors(t *testing.T) {
	if err := run("docs/cert/components.yaml", t.TempDir()+"/o.json", "1", "", nil); err == nil {
		t.Error("ожидалась ошибка без бинарников")
	}
	if err := run("нет.yaml", t.TempDir()+"/o.json", "1", "вчера", []string{"x"}); err == nil {
		t.Error("ожидалась ошибка времени")
	}
}

func FuzzParseBOM(f *testing.F) {
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"file","name":"a"}]}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, data []byte) {
		bom, err := ParseBOM(data)
		if err != nil {
			return
		}
		// Проверка не должна паниковать на любом разобранном документе; результат
		// для произвольного документа может быть любым.
		if err := Check(bom); err != nil && err.Error() == "" {
			t.Fatal("пустой текст ошибки")
		}
	})
}
