package main

import (
	"strings"
	"testing"
	"testing/fstest"
)

const npmManifest = `{"dependencies":{"lib":"1.0.0"},"devDependencies":{"tool":"2.0.0"}}`

// integrity — корректное значение: 64 нулевых байта в base64.
const integrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

func npmLock(libLicense, toolLicense, resolved string) string {
	return `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"lib":"1.0.0"},"devDependencies":{"tool":"2.0.0"}},
"node_modules/lib":{"version":"1.0.0","resolved":"` + resolved + `lib/-/lib-1.0.0.tgz","integrity":"` + integrity + `","license":"` + libLicense + `"},
"node_modules/tool":{"version":"2.0.0","dev":true,"resolved":"https://registry.npmjs.org/tool/-/tool-2.0.0.tgz","integrity":"` + integrity + `","license":"` + toolLicense + `"}}}`
}

const npmEntries = `
  - name: lib
    version: 1.0.0
    type: npm-package
    scope: product
    purpose: p
    license: MIT
    repository: https://example.com/lib
    attack_surface: true
    security_function: false
    provided_by: x
    justification: j
    decision: d
    decided: 2026-10-20
  - name: tool
    version: 2.0.0
    type: npm-package
    scope: build
    purpose: p
    license: MPL-2.0
    license_decision: ADR-0003
    repository: https://example.com/tool
    attack_surface: false
    security_function: false
    provided_by: x
    justification: j
    decision: d
    decided: 2026-10-20
`

func npmRepo(manifest, lock string) fstest.MapFS {
	f := repo(goodRegistry+npmEntries, "# example.com/m v1.0.0\n")
	f["web/package.json"] = &fstest.MapFile{Data: []byte(manifest)}
	f["web/package-lock.json"] = &fstest.MapFile{Data: []byte(lock)}
	return f
}

const registryURL = "https://registry.npmjs.org/"

func TestNPMClean(t *testing.T) {
	problems, err := run(npmRepo(npmManifest, npmLock("MIT", "MPL-2.0", registryURL)))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Fatalf("ожидалось без нарушений: %q", problems)
	}
}

func TestNPMProblems(t *testing.T) {
	cases := []struct {
		name, manifest, lock, want string
	}{
		{"лицензия вне политики в поставке", npmManifest, npmLock("0BSD", "MPL-2.0", registryURL), "не допускается для этого пакета"},
		{"запрещённая лицензия в сборке", npmManifest, npmLock("MIT", "GPL-3.0-only", registryURL), "не допускается для этого пакета"},
		{"нет лицензии", npmManifest, npmLock("", "MPL-2.0", registryURL), "нет лицензии"},
		{"чужой источник", npmManifest, npmLock("MIT", "MPL-2.0", "https://example.com/"), "разрешён только"},
		{"нет прямой зависимости в реестре", strings.Replace(npmManifest, `"tool":"2.0.0"`, `"tool":"2.0.0","other":"1.0.0"`, 1), npmLock("MIT", "MPL-2.0", registryURL), "не соответствует"},
		{"диапазон версии", strings.Replace(npmManifest, `"lib":"1.0.0"`, `"lib":"^1.0.0"`, 1), npmLock("MIT", "MPL-2.0", registryURL), "не точная"},
		{"лицензия в реестре другая", npmManifest, npmLock("ISC", "MPL-2.0", registryURL), "в реестре лицензия"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			problems, err := run(npmRepo(c.manifest, c.lock))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(problems, "\n"), c.want) {
				t.Fatalf("ожидалось %q, получено %q", c.want, problems)
			}
		})
	}
}

func TestNPMEntryWithoutFrontend(t *testing.T) {
	f := repo(goodRegistry+npmEntries, "# example.com/m v1.0.0\n")
	problems, err := run(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(problems, "\n"), "нет web/package.json") && !strings.Contains(strings.Join(problems, "\n"), "а web/package.json нет") {
		t.Fatalf("ожидалась ошибка об отсутствии фронтенда: %q", problems)
	}
}

func TestNPMLockMissing(t *testing.T) {
	f := npmRepo(npmManifest, "")
	delete(f, "web/package-lock.json")
	problems, err := run(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(problems, "\n"), "нет lock-файла") {
		t.Fatalf("ожидалась ошибка об отсутствии lock-файла: %q", problems)
	}
}
