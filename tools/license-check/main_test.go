package main

import (
	"strings"
	"testing"
	"testing/fstest"
)

const goodRegistry = `schema_version: 1
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
    license: MIT
    repository: https://example.com/m
    attack_surface: false
    security_function: false
    provided_by: x
    justification: j
    decision: d
    decided: 2026-09-29
    license_files:
      LICENSE: e5dcffe836b6ec8a58e492419b550e65fb8cbdc308503979e5dacb33ac7ea3b7
  - name: lint
    version: v2.0.0
    type: tool
    scope: build
    purpose: p
    license: GPL-3.0-only
    license_decision: ADR-0003
    repository: https://example.com/lint
    attack_surface: false
    security_function: false
    provided_by: x
    justification: j
    decision: d
    decided: 2026-09-29
    makefile_var: LINT_VERSION
`

func repo(registry, modules string) fstest.MapFS {
	fsys := fstest.MapFS{
		"docs/cert/components.yaml":    {Data: []byte(registry)},
		"go.mod":                       {Data: []byte("module x\n\ngo 1.27.0\n\ntoolchain go1.27.1\n")},
		"Makefile":                     {Data: []byte("LINT_VERSION := v2.0.0\nOTHER ?= 1\n")},
		"vendor/example.com/m/LICENSE": {Data: []byte("MIT")},
		"docs/adr/0003-instrumenty.md": {Data: []byte("# ADR-0003")},
	}
	if modules != "" {
		fsys["vendor/modules.txt"] = &fstest.MapFile{Data: []byte(modules)}
	}
	return fsys
}

func TestRunClean(t *testing.T) {
	problems, err := run(repo(goodRegistry, "# example.com/m v1.0.0\n## explicit\nexample.com/m\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Fatalf("ожидалось без нарушений: %q", problems)
	}
}

func TestRunProblems(t *testing.T) {
	cases := []struct {
		name       string
		registry   string
		modules    string
		edit       func(fstest.MapFS)
		wantSubstr string
	}{
		{"модуля нет в реестре", goodRegistry, "# example.com/m v1.0.0\n# example.com/new v0.1.0\n", nil, "example.com/new v0.1.0: модуля нет"},
		{"другая версия", goodRegistry, "# example.com/m v1.0.1\n", nil, "в vendor/ — v1.0.1"},
		{"лишняя запись", goodRegistry, "", nil, "удалите запись"},
		{"нет лицензии", goodRegistry, "# example.com/m v1.0.0\n", func(f fstest.MapFS) { delete(f, "vendor/example.com/m/LICENSE") }, "нет файла лицензии"},
		{"замена модуля", goodRegistry, "# example.com/m v1.0.0 => ../m\n", nil, "замена модуля"},
		{"запрещённая лицензия", strings.Replace(goodRegistry, "license: MIT", "license: AGPL-3.0-only", 1), "# example.com/m v1.0.0\n", nil, "запрещена"},
		{"GPL без решения", strings.Replace(goodRegistry, "    license_decision: ADR-0003\n", "", 1), "# example.com/m v1.0.0\n", nil, "запрещена"},
		{"модуль в build", strings.Replace(goodRegistry, "type: go-module\n    scope: product", "type: go-module\n    scope: build", 1), "# example.com/m v1.0.0\n", nil, "scope должен быть product"},
		{"toolchain", goodRegistry, "# example.com/m v1.0.0\n", func(f fstest.MapFS) {
			f["go.mod"] = &fstest.MapFile{Data: []byte("module x\ntoolchain go1.27.2\n")}
		}, "в go.mod — go1.27.2"},
		{"версия инструмента", goodRegistry, "# example.com/m v1.0.0\n", func(f fstest.MapFS) {
			f["Makefile"] = &fstest.MapFile{Data: []byte("LINT_VERSION := v2.1.0\n")}
		}, "в Makefile (LINT_VERSION) — v2.1.0"},
		{"нет переменной", goodRegistry, "# example.com/m v1.0.0\n", func(f fstest.MapFS) {
			f["Makefile"] = &fstest.MapFile{Data: []byte("\n")}
		}, "переменной LINT_VERSION нет"},
		{"текст лицензии изменился", goodRegistry, "# example.com/m v1.0.0\n", func(f fstest.MapFS) {
			f["vendor/example.com/m/LICENSE"] = &fstest.MapFile{Data: []byte("GPL")}
		}, "текст LICENSE изменился"},
		{"новый файл лицензии", goodRegistry, "# example.com/m v1.0.0\n", func(f fstest.MapFS) {
			f["vendor/example.com/m/COPYING"] = &fstest.MapFile{Data: []byte("GPL")}
		}, "файла лицензии COPYING нет в license_files"},
		{"нет ADR решения", goodRegistry, "# example.com/m v1.0.0\n", func(f fstest.MapFS) {
			delete(f, "docs/adr/0003-instrumenty.md")
		}, "ADR-0003, которого нет"},
		{"нет toolchain", strings.Replace(goodRegistry, "type: toolchain", "type: tool", 1), "# example.com/m v1.0.0\n", nil, "нет записи о Go toolchain"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fsys := repo(c.registry, c.modules)
			if c.edit != nil {
				c.edit(fsys)
			}
			problems, err := run(fsys)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(problems, "\n"), c.wantSubstr) {
				t.Fatalf("ожидалось нарушение %q, получено %q", c.wantSubstr, problems)
			}
		})
	}
}

func TestRunBrokenInputs(t *testing.T) {
	fsys := repo("schema_version: 1\ncomponents: [", "")
	if _, err := run(fsys); err == nil {
		t.Fatal("ожидалась ошибка разбора реестра")
	}
	fsys = repo(goodRegistry, "# bad\n")
	if _, err := run(fsys); err == nil {
		t.Fatal("ожидалась ошибка разбора modules.txt")
	}
	fsys = repo(goodRegistry, "")
	delete(fsys, "go.mod")
	if _, err := run(fsys); err == nil {
		t.Fatal("ожидалась ошибка без go.mod")
	}
}

func TestCheckPins(t *testing.T) {
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	reg := goodRegistry + `  - name: actions/checkout
    version: v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1
    type: github-action
    scope: build
    purpose: p
    license: MIT
    repository: https://github.com/actions/checkout
    attack_surface: false
    security_function: false
    provided_by: GitHub
    justification: j
    decision: d
    decided: 2026-10-01
  - name: golang
    version: 1.27.1-bookworm@sha256:` + digest + `
    type: image
    scope: build
    purpose: p
    license: BSD-3-Clause
    repository: https://github.com/docker-library/golang
    attack_surface: false
    security_function: false
    provided_by: Docker
    justification: j
    decision: d
    decided: 2026-10-01
`
	const checkout = "  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
	good := func() fstest.MapFS {
		f := repo(reg, "# example.com/m v1.0.0\n")
		f[".github/workflows/ci.yml"] = &fstest.MapFile{Data: []byte("steps:\n" + checkout + "  - uses: ./.github/actions/local\n")}
		f["deploy/build/Dockerfile"] = &fstest.MapFile{Data: []byte("ARG GO_IMAGE=golang:1.27.1-bookworm@sha256:" + digest +
			"\nFROM ${GO_IMAGE} AS build\nFROM build AS test\nFROM scratch\nCOPY --from=build /x /x\n")}
		return f
	}
	problems, err := run(good())
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Fatalf("ожидалось без нарушений: %q", problems)
	}
	cases := map[string]struct {
		file, data, want string
	}{
		"тег вместо SHA":          {".github/workflows/ci.yml", checkout + "      - uses: actions/cache@v4\n", "по SHA"},
		"другой SHA":              {".github/workflows/ci.yml", "- uses: actions/checkout@0000000000000000000000000000000000000000\n", "в реестре SHA"},
		"нет в реестре":           {".github/workflows/ci.yml", checkout + "- uses: actions/cache@0000000000000000000000000000000000000000\n", "нет в реестре"},
		"workflow .yaml":          {".github/workflows/x.yaml", checkout + "  - uses: actions/cache@v4\n", "x.yaml"},
		"составное действие":      {".github/actions/a/action.yml", "runs:\n  steps:\n    - uses: \"actions/cache@v4\"\n", "action.yml"},
		"docker без digest":       {".github/workflows/x.yml", checkout + "  - uses: docker://alpine:3\n", "по digest"},
		"чужой образ без digest":  {"deploy/x/Dockerfile", "FROM alpine:3\n", "не закреплён"},
		"Dockerfile с суффиксом":  {"deploy/x/Dockerfile.dev", "FROM golang:1.27.1-bookworm\n", "Dockerfile.dev"},
		"Dockerfile вне deploy":   {"tools/x/Dockerfile", "FROM alpine:3\n", "tools/x/Dockerfile"},
		"короткий digest":         {"deploy/x/Dockerfile", "FROM golang:1.27.1-bookworm@sha256:aaaa\n", "не закреплён"},
		"образ не в реестре":      {"deploy/x/Dockerfile", "FROM postgres:17@sha256:" + digest + "\n", "нет в реестре"},
		"неизвестный аргумент":    {"deploy/x/Dockerfile", "FROM ${NOPE}\n", "не задано"},
		"неиспользуемое действие": {".github/workflows/ci.yml", "steps: []\n", "не используется в .github"},
		"неиспользуемый образ":    {"deploy/build/Dockerfile", "FROM scratch\n", "не используется ни в одном Dockerfile"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := good()
			f[c.file] = &fstest.MapFile{Data: []byte(c.data)}
			problems, err := run(f)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(problems, "\n"), c.want) {
				t.Fatalf("ожидалось нарушение %q, получено %q", c.want, problems)
			}
		})
	}
	// Неверный формат версий в самом реестре.
	bad := strings.Replace(reg, "@sha256:"+digest, "@sha256:abc", 1)
	bad = strings.Replace(bad, "v7.0.1@3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1", 1)
	f := good()
	f["docs/cert/components.yaml"] = &fstest.MapFile{Data: []byte(bad)}
	problems, err = run(f)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, "«тег@sha256:<64 hex>»") || !strings.Contains(joined, "«тег@SHA коммита»") {
		t.Fatalf("неверный формат версий в реестре не пойман: %q", problems)
	}
}

func TestMakefileVars(t *testing.T) {
	got := makefileVars([]byte("A := 1\nB ?= x\nC = y\nlower := no\nD := two words\n\tE := tab\n"))
	if got["A"] != "1" || got["C"] != "y" || got["B"] != "" || got["lower"] != "" || got["D"] != "" || got["E"] != "" {
		t.Fatalf("неверный разбор: %v", got)
	}
}
