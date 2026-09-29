package main

import (
	"strings"
	"testing"
	"testing/fstest"
)

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

func TestCheckClean(t *testing.T) {
	fsys := fstest.MapFS{
		"internal/crypto/c.go":             file("package crypto\nimport \"crypto/sha256\"\n"),
		"internal/gateway/g.go":            file("package gateway\n"),
		"cmd/aisec-media/m.go":             file("package main\n// int f(void){return 0;}\nimport \"C\"\n"),
		"vendor/x/internal/crypto/v.go":    file("package crypto\n"),
		"tools/x/testdata/internal/crypto": &fstest.MapFile{Mode: 0o755 | 1<<31},
		"README.md":                        file("# x"),
	}
	problems, err := check(fsys, []string{"cmd/aisec-media"})
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Fatalf("ожидалось без нарушений, получено %q", problems)
	}
}

func TestCheckNestedCrypto(t *testing.T) {
	fsys := fstest.MapFS{
		"internal/crypto/c.go":                  file("package crypto\n"),
		"internal/gateway/internal/crypto/x.go": file("package crypto\n"),
		"tools/internal/crypto/y.go":            file("package crypto\n"),
	}
	problems, err := check(fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 2 || !strings.Contains(problems[0], "internal/gateway/internal/crypto") ||
		!strings.Contains(problems[1], "tools/internal/crypto") {
		t.Fatalf("ожидались два лишних каталога crypto, получено %q", problems)
	}
}

func TestCheckCgo(t *testing.T) {
	fsys := fstest.MapFS{
		"internal/gateway/c.go":  file("package gateway\nimport \"C\"\n"),
		"cmd/aisec-media-x/c.go": file("package main\nimport \"C\"\n"),
		"cmd/aisec-media/ok.go":  file("package main\nimport \"C\"\n"),
		"internal/gateway/ok.go": file("package gateway\nimport \"fmt\"\n"),
	}
	problems, err := check(fsys, []string{"cmd/aisec-media"})
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 2 || !strings.Contains(problems[0], "cmd/aisec-media-x/c.go") ||
		!strings.Contains(problems[1], "internal/gateway/c.go") {
		t.Fatalf("ожидались два нарушения cgo, получено %q", problems)
	}
}

func TestCheckSyntaxError(t *testing.T) {
	fsys := fstest.MapFS{"a.go": file("package")}
	if _, err := check(fsys, nil); err == nil {
		t.Fatal("ожидалась ошибка разбора")
	}
}

func TestUnder(t *testing.T) {
	cases := []struct {
		p    string
		dirs []string
		want bool
	}{
		{"cmd/aisec-media/a.go", []string{"cmd/aisec-media"}, true},
		{"cmd/aisec-media-x/a.go", []string{"cmd/aisec-media"}, false},
		{"cmd/aisec-media", []string{"cmd/aisec-media"}, true},
		{"a.go", nil, false},
	}
	for _, c := range cases {
		if got := under(c.p, c.dirs); got != c.want {
			t.Errorf("under(%q, %q) = %v, ожидалось %v", c.p, c.dirs, got, c.want)
		}
	}
}
