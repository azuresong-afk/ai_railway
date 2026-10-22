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
	problems, err := check(fsys, Rules{CgoAllowed: []string{"cmd/aisec-media"}})
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
		"internal/x/build/internal/crypto/z.go": file("package crypto\n"),
	}
	problems, err := check(fsys, Rules{})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(problems, "\n")
	if len(problems) != 3 || !strings.Contains(joined, "internal/gateway/internal/crypto") ||
		!strings.Contains(joined, "tools/internal/crypto") || !strings.Contains(joined, "internal/x/build/internal/crypto") {
		t.Fatalf("ожидались три лишних каталога crypto (в том числе во вложенном build/), получено %q", problems)
	}
}

func TestCheckCgo(t *testing.T) {
	fsys := fstest.MapFS{
		"internal/gateway/c.go":  file("package gateway\nimport \"C\"\n"),
		"cmd/aisec-media-x/c.go": file("package main\nimport \"C\"\n"),
		"cmd/aisec-media/ok.go":  file("package main\nimport \"C\"\n"),
		"internal/gateway/ok.go": file("package gateway\nimport \"fmt\"\n"),
	}
	problems, err := check(fsys, Rules{CgoAllowed: []string{"cmd/aisec-media"}})
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
	if _, err := check(fsys, Rules{}); err == nil {
		t.Fatal("ожидалась ошибка разбора")
	}
}

// ЗИ.2, H-Р11 ревью 2.r5: сетевые клиенты — только в разрешённых путях;
// сервер, тесты и инструменты не ограничиваются; псевдоним импорта и
// локальная переменная с именем пакета не обманывают проверку.
func TestCheckNetClients(t *testing.T) {
	fsys := fstest.MapFS{
		"internal/providers/p.go":   file("package providers\nimport \"net/http\"\nvar c = &http.Client{}\n"),
		"internal/api/server.go":    file("package api\nimport \"net/http\"\nvar s = &http.Server{}\nfunc h(w http.ResponseWriter, r *http.Request) {}\n"),
		"internal/api/x_test.go":    file("package api\nimport \"net/http\"\nvar c = http.DefaultClient\n"),
		"tools/sbom/s.go":           file("package main\nimport \"net/http\"\nvar c = http.Client{}\n"),
		"internal/notify/n.go":      file("package notify\nimport \"net/smtp\"\nvar _ = smtp.PlainAuth\n"),
		"internal/alerting/a.go":    file("package alerting\nimport web \"net/http\"\nfunc f() { _, _ = web.Get(\"http://x\") }\n"),
		"internal/events/e.go":      file("package events\nimport \"net\"\nfunc f() { var d net.Dialer; _ = d; _, _ = net.LookupHost(\"x\") }\n"),
		"cmd/aisec-server/s.go":     file("package main\nimport \"net\"\nfunc f() { _, _ = net.Listen(\"tcp\", \":1\") }\n"),
		"internal/store/shadow.go":  file("package store\nimport \"net/http\"\ntype t struct{ Client int }\nfunc f(http t) int { return http.Client }\nvar _ http.Header\n"),
		"internal/audit/syslog.go":  file("package audit\nimport _ \"log/syslog\"\n"),
		"cmd/aisec-cli/resolver.go": file("package main\nimport \"net\"\nvar r = net.DefaultResolver\n"),
	}
	problems, err := check(fsys, Rules{NetClientAllowed: []string{"internal/providers"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cmd/aisec-cli/resolver.go: сетевой клиент net.DefaultResolver",
		"internal/alerting/a.go: сетевой клиент net/http.Get",
		"internal/audit/syslog.go: сетевой клиент log/syslog (импорт _)",
		"internal/events/e.go: сетевой клиент net.Dialer",
		"internal/events/e.go: сетевой клиент net.LookupHost",
		"internal/notify/n.go: сетевой клиент net/smtp.PlainAuth",
	}
	if len(problems) != len(want) {
		t.Fatalf("ожидалось %d нарушений, получено %q", len(want), problems)
	}
	for i, w := range want {
		if !strings.HasPrefix(problems[i], w) {
			t.Errorf("нарушение %d: %q, ожидалось начало %q", i, problems[i], w)
		}
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
