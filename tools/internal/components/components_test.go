package components

import (
	"strings"
	"testing"
)

const validEntry = `
  - name: example.com/m
    version: v1.0.0
    type: go-module
    scope: product
    purpose: п
    license: MIT
    repository: https://example.com/m
    attack_surface: false
    security_function: false
    provided_by: x
    justification: j
    decision: d
    decided: 2026-09-29
`

func TestParseValid(t *testing.T) {
	reg, err := Parse(strings.NewReader("schema_version: 1\ncomponents:" + validEntry))
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Components) != 1 || reg.Components[0].Name != "example.com/m" || *reg.Components[0].AttackSurface {
		t.Fatalf("неверный разбор: %+v", reg)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name, doc, want string
	}{
		{"версия схемы", "schema_version: 2\ncomponents: []", "schema_version"},
		{"неизвестное поле", "schema_version: 1\nextra: 1\ncomponents: []", "extra"},
		{"пропуск поля", "schema_version: 1\ncomponents:" + strings.Replace(validEntry, "    purpose: п\n", "", 1), "purpose"},
		{"пропуск булева", "schema_version: 1\ncomponents:" + strings.Replace(validEntry, "    attack_surface: false\n", "", 1), "attack_surface"},
		{"тип", "schema_version: 1\ncomponents:" + strings.Replace(validEntry, "type: go-module", "type: npm", 1), "type"},
		{"scope", "schema_version: 1\ncomponents:" + strings.Replace(validEntry, "scope: product", "scope: dev", 1), "scope"},
		{"дата", "schema_version: 1\ncomponents:" + strings.Replace(validEntry, "2026-09-29", "29.09.2026", 1), "decided"},
		{"репозиторий", "schema_version: 1\ncomponents:" + strings.Replace(validEntry, "https://example.com/m", "http://example.com/m", 1), "repository"},
		{"дубликат", "schema_version: 1\ncomponents:" + validEntry + validEntry, "дважды"},
		{"два документа", "schema_version: 1\ncomponents: []\n---\nschema_version: 1\n", "один"},
		{"не yaml", "schema_version: [", "разбор"},
		{"переменная", "schema_version: 1\ncomponents:" + strings.Replace(validEntry, "    decided: 2026-09-29\n", "    decided: 2026-09-29\n    makefile_var: bad-name\n", 1), "makefile_var"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(c.doc))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("ожидалась ошибка про %q, получено %v", c.want, err)
			}
		})
	}
}

func TestParseTooLarge(t *testing.T) {
	big := "schema_version: 1\n# " + strings.Repeat("x", MaxFileSize) + "\ncomponents: []\n"
	if _, err := Parse(strings.NewReader(big)); err == nil {
		t.Fatal("ожидалась ошибка размера")
	}
}

func TestParseModulesTxt(t *testing.T) {
	data := []byte("# go.yaml.in/yaml/v3 v3.0.5\n## explicit; go 1.16\ngo.yaml.in/yaml/v3\n" +
		"# example.com/a v1.2.3 => example.com/b v1.0.0\n# example.com/c => ../c\n")
	mods, err := ParseModulesTxt(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []Module{
		{"go.yaml.in/yaml/v3", "v3.0.5", ""},
		{"example.com/a", "v1.2.3", "example.com/b v1.0.0"},
		{"example.com/c", "", "../c"},
	}
	if len(mods) != len(want) {
		t.Fatalf("получено %+v", mods)
	}
	for i := range want {
		if mods[i] != want[i] {
			t.Fatalf("модуль %d: %+v, ожидалось %+v", i, mods[i], want[i])
		}
	}
	if _, err := ParseModulesTxt([]byte("# одно\n")); err == nil {
		t.Fatal("ожидалась ошибка на строке без версии")
	}
	if mods, err := ParseModulesTxt(nil); err != nil || len(mods) != 0 {
		t.Fatalf("пустой файл: %v %v", mods, err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("schema_version: 1\ncomponents:" + validEntry)
	f.Add("schema_version: 1\ncomponents: []")
	f.Add("{")
	f.Fuzz(func(t *testing.T, doc string) {
		reg, err := Parse(strings.NewReader(doc))
		if err == nil && reg.SchemaVersion != 1 {
			t.Fatalf("принят реестр с версией схемы %d", reg.SchemaVersion)
		}
	})
}

func FuzzParseModulesTxt(f *testing.F) {
	f.Add([]byte("# a v1\n## explicit\na\n# b v2 => c v3\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		mods, err := ParseModulesTxt(data)
		if err != nil {
			return
		}
		for _, m := range mods {
			if m.Path == "" || (m.Version == "" && m.Replace == "") {
				t.Fatalf("некорректный модуль %+v", m)
			}
		}
	})
}
