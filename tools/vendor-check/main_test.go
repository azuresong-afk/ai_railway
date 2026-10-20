package main

import (
	"strings"
	"testing"
	"testing/fstest"
)

const (
	modTxt = "# example.com/m v1.0.0\n## explicit; go 1.16\nexample.com/m\n"
	goMod  = "module x\n\ngo 1.27\n\nrequire example.com/m v1.0.0\n"
	goSum  = "example.com/m v1.0.0 h1:aaa=\nexample.com/m v1.0.0/go.mod h1:bbb=\n"
)

// newFS собирает репозиторий с манифестом, посчитанным по vendor/.
func newFS(t *testing.T, mutate func(fstest.MapFS)) fstest.MapFS {
	t.Helper()
	fsys := fstest.MapFS{
		"go.mod":                    {Data: []byte(goMod)},
		"go.sum":                    {Data: []byte(goSum)},
		"vendor/modules.txt":        {Data: []byte(modTxt)},
		"vendor/example.com/m/m.go": {Data: []byte("package m\n")},
	}
	sums, err := hashTree(fsys, "vendor")
	if err != nil {
		t.Fatal(err)
	}
	fsys[manifestPath] = &fstest.MapFile{Data: formatManifest(sums)}
	if mutate != nil {
		mutate(fsys)
	}
	return fsys
}

func run(t *testing.T, fsys fstest.MapFS) string {
	t.Helper()
	p, err := check(fsys)
	if err != nil {
		return "ошибка: " + err.Error()
	}
	return strings.Join(p, "\n")
}

func TestVendorCheck(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(fstest.MapFS)
		want   string // подстрока; пусто — нарушений нет
	}{
		{"чисто", nil, ""},
		{"изменён файл", func(f fstest.MapFS) { f["vendor/example.com/m/m.go"] = &fstest.MapFile{Data: []byte("package evil\n")} }, "содержимое отличается"},
		{"лишний файл", func(f fstest.MapFS) { f["vendor/example.com/m/x.go"] = &fstest.MapFile{Data: []byte("x")} }, "x.go: файл есть в vendor/"},
		{"пропал файл", func(f fstest.MapFS) { delete(f, "vendor/example.com/m/m.go") }, "отсутствует в vendor/"},
		{"версия в go.mod", func(f fstest.MapFS) {
			f["go.mod"] = &fstest.MapFile{Data: []byte("module x\n\nrequire example.com/m v1.0.1\n")}
		}, "в go.mod v1.0.1"},
		{"нет хеша go.sum", func(f fstest.MapFS) {
			f["go.sum"] = &fstest.MapFile{Data: []byte("example.com/m v1.0.0/go.mod h1:bbb=\n")}
		}, "нет хеша модуля h1"},
		{"нет хеша go.mod в go.sum", func(f fstest.MapFS) { f["go.sum"] = &fstest.MapFile{Data: []byte("example.com/m v1.0.0 h1:aaa=\n")} }, "нет хеша go.mod"},
		{"модуль только в go.mod", func(f fstest.MapFS) {
			f["go.mod"] = &fstest.MapFile{Data: []byte("module x\n\nrequire (\n\texample.com/m v1.0.0\n\texample.com/n v1.0.0\n)\n")}
		}, "example.com/n: модуль есть в go.mod"},
		{"модуль только в vendor", func(f fstest.MapFS) { f["go.mod"] = &fstest.MapFile{Data: []byte("module x\n")} }, "не в go.mod"},
		{"нет манифеста", func(f fstest.MapFS) { delete(f, manifestPath) }, "ошибка: манифест"},
		{"битый манифест", func(f fstest.MapFS) { f[manifestPath] = &fstest.MapFile{Data: []byte("zz  vendor/a\n")} }, "неверная строка"},
		{"replace в go.mod", func(f fstest.MapFS) {
			f["go.mod"] = &fstest.MapFile{Data: []byte(goMod + "\nreplace example.com/m => evil.example/m v6.6.6\n")}
		}, "директива replace запрещена"},
		{"replace блоком в go.mod", func(f fstest.MapFS) {
			f["go.mod"] = &fstest.MapFile{Data: []byte(goMod + "\nreplace (\n\texample.com/m => ../m\n)\n")}
		}, "директива replace запрещена (example.com/m => ../m)"},
		{"замена в modules.txt", func(f fstest.MapFS) {
			f["vendor/modules.txt"] = &fstest.MapFile{Data: []byte("# example.com/m v1.0.0 => evil.example/m v6.6.6\n## explicit\nexample.com/m\n")}
		}, "замена модуля в vendor/modules.txt запрещена"},
		{"пробел в пути манифеста", func(f fstest.MapFS) {
			f[manifestPath] = &fstest.MapFile{Data: []byte(strings.Repeat("a", 64) + "  vendor/a  x\n")}
		}, "неверная строка"},
		{"путь манифеста вне vendor", func(f fstest.MapFS) {
			f[manifestPath] = &fstest.MapFile{Data: []byte(strings.Repeat("a", 64) + "  ../etc/passwd\n")}
		}, "неверная строка"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := run(t, newFS(t, tc.mutate))
			if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
				t.Fatalf("получено %q, ждали %q", got, tc.want)
			}
		})
	}
}

func TestReadLimited(t *testing.T) {
	fsys := fstest.MapFS{"a": {Data: []byte("12345")}}
	if _, err := readLimited(fsys, "a", 4); err == nil {
		t.Fatal("ждали отказ по размеру")
	}
	if b, err := readLimited(fsys, "a", 5); err != nil || string(b) != "12345" {
		t.Fatalf("%q %v", b, err)
	}
}

// FuzzReadManifest — разборщик манифеста не паникует на произвольном входе.
func FuzzReadManifest(f *testing.F) {
	f.Add([]byte(strings.Repeat("a", 64) + "  vendor/x\n"))
	f.Add([]byte("\n\n  \n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readManifest(fstest.MapFS{manifestPath: {Data: data}})
	})
}

// FuzzParseGoMod — разборщик go.mod не паникует.
func FuzzParseGoMod(f *testing.F) {
	f.Add([]byte(goMod))
	f.Add([]byte("require (\n\ta b\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = parseRequires(fstest.MapFS{"go.mod": {Data: data}})
	})
}

// FuzzParseModules — разборщик vendor/modules.txt не паникует.
func FuzzParseModules(f *testing.F) {
	f.Add([]byte(modTxt))
	f.Add([]byte("# a v1 => b v2\n# \n#  \n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseModules(fstest.MapFS{modulesPath: {Data: data}})
	})
}

// FuzzParseGoSum — разборщик go.sum не паникует.
func FuzzParseGoSum(f *testing.F) {
	f.Add([]byte(goSum))
	f.Add([]byte("a b\n\n a b h1:\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseGoSum(fstest.MapFS{"go.sum": {Data: data}})
	})
}
