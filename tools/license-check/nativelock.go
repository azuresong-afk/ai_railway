package main

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/azuresong-afk/ai_railway/tools/internal/components"
)

// Сверка deploy/build/onnxruntime/deps.lock с реестром (задача 5.11 этапа 5,
// остаток ревью 4.r3–4.r4): каждая строка — исходник библиотеки, которая
// статически встраивается в ONNX Runtime, — обязана иметь запись
// native-library с той же версией и лицензией, а лицензия строки — проходить
// политику CLAUDE.md с решением владельца из записи. Запись native-library,
// которая ссылается на deps.lock, обязана в нём быть.

// nativeLockPath — список исходников сборки ORT без сети (ADR-0024, раздел 8).
const nativeLockPath = "deploy/build/onnxruntime/deps.lock"

// lockAliases — имена deps.lock (первый столбец cmake/deps.txt ORT), которые
// в реестре записаны под общепринятым именем проекта. Остальные имена
// совпадают с реестром после замены «_» на «-».
var lockAliases = map[string]string{
	"json":            "nlohmann-json",
	"pytorch_cpuinfo": "cpuinfo",
}

// lockEntry — строка deps.lock: имя;вид;источник;версия;sha256;лицензия.
type lockEntry struct {
	line                                 int
	name, kind, source, version, license string
}

var (
	lockNameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,63}$`)
	lockCommitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	lockSHA256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// parseNativeLock разбирает deps.lock тем же правилом, что fetch.sh: пустые
// строки и «#» пропускаются, у git — коммит из 40 знаков, у url — https и
// версия «-».
func parseNativeLock(data []byte) ([]lockEntry, []string) {
	var out []lockEntry
	var problems []string
	seen := map[string]bool{}
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ";")
		if len(f) != 6 {
			problems = append(problems, fmt.Sprintf("%s:%d: ожидается 6 полей через «;», получено %d", nativeLockPath, i+1, len(f)))
			continue
		}
		e := lockEntry{line: i + 1, name: f[0], kind: f[1], source: f[2], version: f[3], license: f[5]}
		var errs []string
		if !lockNameRe.MatchString(e.name) {
			errs = append(errs, "имя — строчные латинские буквы, цифры и «_»")
		} else if seen[e.name] {
			errs = append(errs, "имя повторяется")
		}
		if !lockSHA256Re.MatchString(f[4]) {
			errs = append(errs, "sha256 — 64 знака hex")
		}
		if !strings.HasPrefix(e.source, "https://") {
			errs = append(errs, "источник — только https")
		}
		switch e.kind {
		case "git":
			if !lockCommitRe.MatchString(e.version) {
				errs = append(errs, "у git версия — полный коммит из 40 знаков")
			}
		case "url":
			if e.version != "-" {
				errs = append(errs, "у url версия — «-», версию задаёт архив")
			}
		default:
			errs = append(errs, fmt.Sprintf("вид %q: ожидается git или url", e.kind))
		}
		if len(errs) > 0 {
			// Строка с ошибкой формата с реестром не сверяется: её не
			// примет и fetch.sh.
			problems = append(problems, fmt.Sprintf("%s:%d: %s: %s", nativeLockPath, e.line, e.name, strings.Join(errs, "; ")))
			continue
		}
		seen[e.name] = true
		out = append(out, e)
	}
	return out, problems
}

// registryName — имя записи реестра для строки deps.lock.
func registryName(lockName string) string {
	if n, ok := lockAliases[lockName]; ok {
		return n
	}
	return strings.ReplaceAll(lockName, "_", "-")
}

// versionMatches — версия записи реестра соответствует строке deps.lock: у
// git — коммит («<коммит>» или «<версия> (<коммит>)»), у url — имя архива
// без расширения оканчивается на «-<версия>» («protobuf-33.6.tar.gz» для
// 33.6; запись 33 или 3 ему не соответствует — 5Н7 ревью 5.r1 этапа 5).
func versionMatches(e lockEntry, regVersion string) bool {
	if e.kind == "git" {
		return regVersion == e.version || strings.HasSuffix(regVersion, " ("+e.version+")")
	}
	if regVersion == "" || strings.ContainsAny(regVersion, " /") {
		return false
	}
	stem, ok := archiveStem(path.Base(e.source))
	return ok && strings.HasSuffix(stem, "-"+regVersion)
}

// archiveExts — расширения архивов исходников в строках url deps.lock.
var archiveExts = []string{".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".zip"}

// archiveStem — имя архива без расширения; ok = false — расширение не из
// archiveExts.
func archiveStem(name string) (string, bool) {
	for _, ext := range archiveExts {
		if stem, ok := strings.CutSuffix(name, ext); ok {
			return stem, true
		}
	}
	return "", false
}

// licenseCovered — каждая лицензия строки deps.lock есть в выражении записи
// реестра: запись может быть подробнее (у архива protobuf — ещё utf8_range
// под MIT), но не может потерять лицензию исходника.
func licenseCovered(lockLicense, regLicense string) (bool, error) {
	_, lockIDs, err := components.EvalExpression(lockLicense)
	if err != nil {
		return false, err
	}
	_, regIDs, err := components.EvalExpression(regLicense)
	if err != nil {
		return false, err
	}
	have := map[string]bool{}
	for _, id := range regIDs {
		have[id] = true
	}
	for _, id := range lockIDs {
		if !have[id] {
			return false, nil
		}
	}
	return true, nil
}

// checkNativeLock сверяет deps.lock с записями native-library реестра.
func checkNativeLock(fsys fs.FS, reg *components.Registry) ([]string, error) {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	native := map[string]components.Component{}
	for _, c := range reg.Components {
		if c.Type == components.TypeNative {
			native[c.Name] = c
		}
	}
	data, err := readLimited(fsys, nativeLockPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	entries, parseProblems := parseNativeLock(data)
	problems = append(problems, parseProblems...)
	inLock := map[string]bool{}
	for _, e := range entries {
		name := registryName(e.name)
		inLock[name] = true
		c, ok := native[name]
		if !ok {
			add("%s: %s: нет записи native-library %q в %s", nativeLockPath, e.name, name, registryPath)
			continue
		}
		if !versionMatches(e, c.Version) {
			add("%s: %s: версия в deps.lock %s, в реестре — %s", nativeLockPath, e.name, lockVersion(e), c.Version)
		}
		covered, err := licenseCovered(e.license, c.License)
		switch {
		case err != nil:
			add("%s: %s: лицензия %q: %v", nativeLockPath, e.name, e.license, err)
			continue
		case !covered:
			add("%s: %s: лицензия в deps.lock %s, в реестре — %s", nativeLockPath, e.name, e.license, c.License)
		}
		// Лицензия исходника — по политике CLAUDE.md с решением владельца из
		// записи реестра (MPL-2.0 и BSL-1.0 — только с license_decision).
		lockComp := components.Component{Name: name, Type: components.TypeNative, Scope: c.Scope, License: e.license, LicenseDecision: c.LicenseDecision}
		if err := components.CheckLicense(lockComp); err != nil {
			add("%s: %s: %v", nativeLockPath, e.name, err)
		}
	}
	for name, c := range native {
		if !inLock[name] && strings.Contains(c.Justification, nativeLockPath) {
			add("%s: запись native-library ссылается на %s, но строки в нём нет — удалите запись или верните строку", name, nativeLockPath)
		}
	}
	return problems, nil
}

func lockVersion(e lockEntry) string {
	if e.kind == "url" {
		return path.Base(e.source)
	}
	return e.version
}
