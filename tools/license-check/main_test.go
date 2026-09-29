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

func TestMakefileVars(t *testing.T) {
	got := makefileVars([]byte("A := 1\nB ?= x\nC = y\nlower := no\nD := two words\n\tE := tab\n"))
	if got["A"] != "1" || got["C"] != "y" || got["B"] != "" || got["lower"] != "" || got["D"] != "" || got["E"] != "" {
		t.Fatalf("неверный разбор: %v", got)
	}
}
