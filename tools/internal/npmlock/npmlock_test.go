package npmlock

import (
	"strings"
	"testing"
)

const sample = `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"@s/lib":"1.0.0"},"devDependencies":{"tool":"2.0.0"}},
"node_modules/@s/lib":{"version":"1.0.0","resolved":"https://registry.npmjs.org/@s/lib/-/lib-1.0.0.tgz","license":"MIT","dependencies":{"dep":"^1.0.0"}},
"node_modules/dep":{"version":"1.2.0","license":"ISC"},
"node_modules/@s/lib/node_modules/dep":{"version":"1.1.0","license":"ISC"},
"node_modules/tool":{"version":"2.0.0","dev":true,"license":"MPL-2.0","dependencies":{"dep":"^1.0.0"}}}}`

func TestParseAndResolve(t *testing.T) {
	l, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if l.Runtime["@s/lib"] != "1.0.0" || l.Dev["tool"] != "2.0.0" {
		t.Fatalf("прямые зависимости: %v %v", l.Runtime, l.Dev)
	}
	lib, ok := l.ResolveDep("", "@s/lib")
	if !ok || lib.Name != "@s/lib" {
		t.Fatalf("пакет не найден: %+v", lib)
	}
	// Вложенная копия ближе к пакету, чем верхняя.
	deps := l.Deps(lib)
	if len(deps) != 1 || deps[0].Version != "1.1.0" {
		t.Fatalf("зависимость должна разрешаться во вложенную копию: %+v", deps)
	}
	tool, _ := l.ResolveDep("", "tool")
	if got := l.Deps(tool); len(got) != 1 || got[0].Version != "1.2.0" {
		t.Fatalf("зависимость инструмента: %+v", got)
	}
	var names []string
	for _, p := range l.Product() {
		names = append(names, p.Path)
	}
	if strings.Join(names, ",") != "node_modules/@s/lib,node_modules/@s/lib/node_modules/dep" {
		t.Fatalf("состав поставки: %v", names)
	}
}

func TestParseErrors(t *testing.T) {
	for name, in := range map[string]string{
		"не JSON":          `{`,
		"версия lock":      `{"lockfileVersion":2,"packages":{"":{}}}`,
		"нет корня":        `{"lockfileVersion":3,"packages":{}}`,
		"странный путь":    `{"lockfileVersion":3,"packages":{"":{},"src/x":{}}}`,
		"пустое имя":       `{"lockfileVersion":3,"packages":{"":{},"node_modules/":{}}}`,
		"прилипшее к пути": `{"lockfileVersion":3,"packages":{"":{},"xnode_modules/a":{}}}`,
		"слишком большой":  `{"lockfileVersion":3,"x":"` + strings.Repeat("a", MaxFileSize) + `"}`,
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestSHA512Hex(t *testing.T) {
	ok := "sha512-" + strings.Repeat("A", 86) + "=="
	if h, err := SHA512Hex(ok); err != nil || h != strings.Repeat("00", 64) {
		t.Fatalf("%q %v", h, err)
	}
	for _, bad := range []string{"", "sha1-AAAA", "sha512-!!!", "sha512-AAAA"} {
		if _, err := SHA512Hex(bad); err == nil {
			t.Errorf("%q: ожидалась ошибка", bad)
		}
	}
}

func TestPURL(t *testing.T) {
	if got := PURL(&Package{Name: "@s/lib", Version: "1.0.0"}); got != "pkg:npm/%40s/lib@1.0.0" {
		t.Fatal(got)
	}
	if got := PURL(&Package{Name: "a", Version: "2.0.0"}); got != "pkg:npm/a@2.0.0" {
		t.Fatal(got)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte(`{"lockfileVersion":3,"packages":{"":{}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := Parse(data)
		if err != nil {
			return
		}
		// Обход графа не должен ни паниковать, ни зацикливаться.
		for i := range l.Packages {
			l.Deps(&l.Packages[i])
		}
		l.Product()
	})
}

func FuzzSHA512Hex(f *testing.F) {
	f.Add("sha512-" + strings.Repeat("A", 86) + "==")
	f.Fuzz(func(t *testing.T, s string) {
		if h, err := SHA512Hex(s); err == nil && len(h) != 128 {
			t.Fatalf("длина хеша %d", len(h))
		}
	})
}
