package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/azuresong-afk/ai_railway/tools/internal/components"
)

const (
	commitA = "402979ac1bef89dcd55add41eaa7277c407599eb"
	commitB = "1d8b82b0740839c0de7f1242a3585e3390ff5f33"
	sumX    = "b4fd73aad7658d7e552f3db7ade701a37fbea7a739cd14def659e4bd2d20a147"
)

func native(name, version, license, decision string) components.Component {
	return components.Component{Name: name, Version: version, Type: components.TypeNative, Scope: components.ScopeProduct,
		License: license, LicenseDecision: decision, Justification: "Встроена в libonnxruntime.so (deploy/build/onnxruntime/deps.lock)."}
}

func goodNative() *components.Registry {
	return &components.Registry{Components: []components.Component{
		native("onnxruntime", "1.31.0 ("+commitA+")", "MIT", ""),
		native("eigen", commitB, "MPL-2.0", "ADR-0024 — Eigen внутри ORT"),
		native("protobuf", "33.6", "BSD-3-Clause AND MIT", ""),
		native("nlohmann-json", "3.11.3 ("+commitA+")", "MIT", ""),
		native("abseil-cpp", "20250814.0 ("+commitB+")", "Apache-2.0", ""),
		{Name: "glibc", Version: "2.36", Type: components.TypeNative, Scope: components.ScopeProduct, License: "LGPL-2.1-or-later",
			LicenseDecision: "ADR-0024", Justification: "Системная библиотека образа."},
	}}
}

func lockLines(lines ...string) string {
	return "# имя;вид;источник;версия;sha256;лицензия\n\n" + strings.Join(lines, "\n") + "\n"
}

var goodLock = []string{
	"onnxruntime;git;https://github.com/microsoft/onnxruntime.git;" + commitA + ";" + sumX + ";MIT",
	"eigen;git;https://github.com/eigen-mirror/eigen.git;" + commitB + ";" + sumX + ";MPL-2.0",
	"protobuf;url;https://github.com/protocolbuffers/protobuf/releases/download/v33.6/protobuf-33.6.tar.gz;-;" + sumX + ";BSD-3-Clause",
	"json;git;https://github.com/nlohmann/json.git;" + commitA + ";" + sumX + ";MIT",
	"abseil_cpp;git;https://github.com/abseil/abseil-cpp.git;" + commitB + ";" + sumX + ";Apache-2.0",
}

func nativeProblems(t *testing.T, reg *components.Registry, lock string) []string {
	t.Helper()
	fsys := fstest.MapFS{}
	if lock != "" {
		fsys[nativeLockPath] = &fstest.MapFile{Data: []byte(lock)}
	}
	problems, err := checkNativeLock(fsys, reg)
	if err != nil {
		t.Fatal(err)
	}
	return problems
}

func wantProblem(t *testing.T, problems []string, substr string) {
	t.Helper()
	for _, p := range problems {
		if strings.Contains(p, substr) {
			return
		}
	}
	t.Fatalf("нет нарушения %q среди %q", substr, problems)
}

// Имена с «_» и псевдонимы (json → nlohmann-json), версия git — коммит в
// скобках или сам коммит, url — версия в имени архива, лицензия записи
// подробнее строки; системная библиотека без ссылки на deps.lock не нужна в нём.
func TestNativeLockClean(t *testing.T) {
	if p := nativeProblems(t, goodNative(), lockLines(goodLock...)); len(p) != 0 {
		t.Fatalf("ожидалось без нарушений: %q", p)
	}
}

func TestNativeLockVersionMismatch(t *testing.T) {
	lock := append([]string{}, goodLock...)
	lock[0] = strings.Replace(lock[0], commitA, commitB, 1)
	lock[2] = strings.Replace(lock[2], "protobuf-33.6.tar.gz", "protobuf-33.7.tar.gz", 1)
	p := nativeProblems(t, goodNative(), lockLines(lock...))
	wantProblem(t, p, "onnxruntime: версия в deps.lock "+commitB)
	wantProblem(t, p, "protobuf: версия в deps.lock protobuf-33.7.tar.gz, в реестре — 33.6")
	if len(p) != 2 {
		t.Fatalf("лишние нарушения: %q", p)
	}
}

// Строка без записи реестра — провал; запись со ссылкой на deps.lock без
// строки — тоже.
func TestNativeLockMissingRecord(t *testing.T) {
	lock := append([]string{}, goodLock...)
	lock = append(lock, "safeint;git;https://github.com/dcleblanc/SafeInt.git;"+commitA+";"+sumX+";MIT")
	p := nativeProblems(t, goodNative(), lockLines(lock...))
	wantProblem(t, p, `safeint: нет записи native-library "safeint"`)

	p = nativeProblems(t, goodNative(), lockLines(goodLock[1:]...))
	wantProblem(t, p, "onnxruntime: запись native-library ссылается на deploy/build/onnxruntime/deps.lock, но строки в нём нет")
	if len(p) != 1 {
		t.Fatalf("лишние нарушения: %q", p)
	}
}

// Запрещённая лицензия в deps.lock — провал, даже если запись реестра её
// «прикрывает»; MPL-2.0 — только с решением владельца в записи; лицензия
// строки, которой нет в записи, — расхождение.
func TestNativeLockLicenses(t *testing.T) {
	reg := goodNative()
	reg.Components = append(reg.Components, native("gplthing", commitA, "GPL-3.0-only", "ADR-0024"))
	lock := append(append([]string{}, goodLock...), "gplthing;git;https://example.com/g.git;"+commitA+";"+sumX+";GPL-3.0-only")
	wantProblem(t, nativeProblems(t, reg, lockLines(lock...)), "gplthing: лицензия")

	reg = goodNative()
	reg.Components[1].LicenseDecision = ""
	wantProblem(t, nativeProblems(t, reg, lockLines(goodLock...)), "eigen: лицензия \"MPL-2.0\" допускается только отдельным решением")

	lock = append([]string{}, goodLock...)
	lock[4] = strings.Replace(lock[4], ";Apache-2.0", ";MIT", 1)
	wantProblem(t, nativeProblems(t, goodNative(), lockLines(lock...)), "abseil_cpp: лицензия в deps.lock MIT, в реестре — Apache-2.0")

	lock[4] = strings.Replace(lock[4], ";MIT", ";Неизвестно-1.0", 1)
	wantProblem(t, nativeProblems(t, goodNative(), lockLines(lock...)), "abseil_cpp: лицензия \"Неизвестно-1.0\"")
}

func TestNativeLockFormat(t *testing.T) {
	cases := map[string]string{
		"onnxruntime;git;https://x;" + commitA + ";" + sumX:                 "ожидается 6 полей",
		"Onnx;git;https://x;" + commitA + ";" + sumX + ";MIT":               "имя — строчные",
		"onnxruntime;git;http://x;" + commitA + ";" + sumX + ";MIT":         "только https",
		"onnxruntime;git;https://x;main;" + sumX + ";MIT":                   "полный коммит",
		"onnxruntime;url;https://x/onnxruntime-1.tar.gz;1;" + sumX + ";MIT": "версия — «-»",
		"onnxruntime;svn;https://x;" + commitA + ";" + sumX + ";MIT":        "ожидается git или url",
		"onnxruntime;git;https://x;" + commitA + ";abc;MIT":                 "sha256",
		goodLock[0] + "\n" + goodLock[0]:                                    "имя повторяется",
	}
	for line, want := range cases {
		wantProblem(t, nativeProblems(t, goodNative(), lockLines(line)), want)
	}
}

// Настоящие deps.lock и components.yaml репозитория сходятся.
func TestNativeLockRepository(t *testing.T) {
	problems, err := run(osRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		if strings.Contains(p, nativeLockPath) {
			t.Errorf("%s", p)
		}
	}
}

// osRepo — корень репозитория (тест запускается в tools/license-check).
func osRepo(t *testing.T) fs.FS {
	t.Helper()
	return os.DirFS(filepath.Join("..", ".."))
}

// FuzzParseNativeLock — разбор deps.lock: без паники, принятая строка —
// допустимые имя, вид и версия.
func FuzzParseNativeLock(f *testing.F) {
	f.Add([]byte(lockLines(goodLock...)))
	f.Add([]byte("a;b;c;d;e;f\n;;;;;\n#\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, _ := parseNativeLock(data)
		for _, e := range entries {
			if !lockNameRe.MatchString(e.name) || !strings.HasPrefix(e.source, "https://") ||
				(e.kind == "git" && !lockCommitRe.MatchString(e.version)) || (e.kind == "url" && e.version != "-") ||
				(e.kind != "git" && e.kind != "url") {
				t.Fatalf("принята неверная строка %+v", e)
			}
		}
	})
}
