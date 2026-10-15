package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLocalLinks(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"относительная", "см. [ТЗ](docs/SPEC.md).", []string{"docs/SPEC.md"}},
		{"якорь отбрасывается", "[раздел](SPEC.md#5-функциональные)", []string{"SPEC.md"}},
		{"только якорь", "[выше](#оглавление)", nil},
		{"внешняя", "[сайт](https://example.org/a.md)", nil},
		{"почта", "[почта](mailto:security@example.org)", nil},
		{"с заголовком", `[a](b.md "подсказка")`, []string{"b.md"}},
		{"в угловых скобках", "[a](<c d.md>)", []string{"c d.md"}},
		{"незакрытая угловая", "[a](<c.md)", []string{"c.md"}},
		{"несколько", "[a](x.md) и [b](y/z.md)", []string{"x.md", "y/z.md"}},
		{"незакрытая", "[a](x.md", nil},
		{"перенос строки", "[a](x\n.md)", []string{"x"}},
		{"пусто", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := localLinks(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("localLinks(%q) = %q, ожидалось %q", c.in, got, c.want)
			}
		})
	}
}

func TestCheckTree(t *testing.T) {
	root := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md", "[ТЗ](docs/SPEC.md), [план](docs/plans/nope.md)")
	write("docs/SPEC.md", "[адр](adr/0001.md) [назад](../README.md)")
	write("docs/adr/0001.md", "ok")
	write("docs/escape.md", "[наружу](../../etc/passwd)")

	broken, err := checkTree(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(broken, "\n")
	if len(broken) != 2 || !strings.Contains(joined, "docs/plans/nope.md") || !strings.Contains(joined, "../../etc/passwd") {
		t.Fatalf("ожидались битые ссылки на docs/plans/nope.md и за пределы корня, получено %q", broken)
	}
}

func TestCheckTreeTooLarge(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), make([]byte, maxDocSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkTree(root); err == nil {
		t.Fatal("ожидалась ошибка для слишком большого документа")
	}
}

func FuzzLocalLinks(f *testing.F) {
	for _, s := range []string{"[a](b.md)", "[a](http://x)", "](", "[a](#x)", "[a](<b> \"t\")"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, l := range localLinks(s) {
			if l == "" || strings.Contains(l, "://") || strings.ContainsAny(l, "#\n") {
				t.Fatalf("недопустимая ссылка %q из %q", l, s)
			}
		}
	})
}
