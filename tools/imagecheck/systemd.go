package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Юниты systemd установки без Docker (ADR-0034, ЗИ.5, ЗИ.7; задача 6.16):
// у каждой службы свой пользователь, без привилегий, файловая система только
// для чтения, кроме своих каталогов, пределы памяти и числа процессов. У
// aisec-ml и aisec-media — свой корень и никакой сети, у aisec-media —
// список системных вызовов, совпадающий с профилем seccomp пилота
// (deploy/compose/pilot/seccomp/aisec-media.json). Ослабление юнита или
// расхождение списков — нарушение.

const (
	maxUnitFile    = 64 << 10
	maxUnitEntries = 1024
)

// unitFile — разобранный юнит: раздел → ключ → значения в порядке появления.
type unitFile map[string]map[string][]string

// parseUnit разбирает юнит systemd: разделы, «ключ=значение», комментарии
// «#» и «;», продолжение строки «\». Значения не раскрываются. Ключ вне
// раздела, строка без «=» и слишком большой файл — ошибка.
func parseUnit(data []byte) (unitFile, error) {
	if len(data) > maxUnitFile {
		return nil, fmt.Errorf("юнит больше %d байт", maxUnitFile)
	}
	u := unitFile{}
	section := ""
	entries := 0
	var cont strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxUnitFile)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if cont.Len() == 0 && (line == "" || line[0] == '#' || line[0] == ';') {
			continue
		}
		if cont.Len() > 0 && line != "" && (line[0] == '#' || line[0] == ';') {
			// systemd пропускает комментарии внутри продолжения.
			continue
		}
		if strings.HasSuffix(line, `\`) {
			cont.WriteString(strings.TrimSuffix(line, `\`))
			cont.WriteByte(' ')
			continue
		}
		if cont.Len() > 0 {
			cont.WriteString(line)
			line = strings.TrimSpace(cont.String())
			cont.Reset()
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || len(line) < 3 {
				return nil, fmt.Errorf("строка %d: заголовок раздела %q", n, line)
			}
			section = line[1 : len(line)-1]
			if u[section] == nil {
				u[section] = map[string][]string{}
			}
			continue
		}
		if section == "" {
			return nil, fmt.Errorf("строка %d: ключ вне раздела", n)
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return nil, fmt.Errorf("строка %d: ожидается «ключ=значение»", n)
		}
		entries++
		if entries > maxUnitEntries {
			return nil, fmt.Errorf("больше %d значений", maxUnitEntries)
		}
		u[section][k] = append(u[section][k], strings.TrimSpace(v))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cont.Len() > 0 {
		return nil, errors.New("файл кончается продолжением строки")
	}
	return u, nil
}

// last — действующее значение ключа (последнее), ok — ключ задан.
func (u unitFile) last(section, key string) (string, bool) {
	v := u[section][key]
	if len(v) == 0 {
		return "", false
	}
	return v[len(v)-1], true
}

// unitSpec — что требуется от юнита конкретной службы.
type unitSpec struct {
	name, user, group string
	memoryMax         string
	tasksMax          string
	families          string
	isolated          bool // свой корень и без сети: aisec-ml, aisec-media
	state             string
	runtime           string
	syscalls          []string // значения SystemCallFilter=, кроме списка aisec-media
	cpuQuota          string
	// secretFlags — флаги ExecStart= с путями к секретам: только %d/…
	secretFlags []string
	// env — точный список Environment= юнита.
	env []string
}

var packagingUnits = []unitSpec{
	{
		name: "aisec-server", user: "aisec", group: "aisec", memoryMax: "1G", tasksMax: "256",
		families: "AF_UNIX AF_INET AF_INET6", syscalls: []string{"@system-service", "~@privileged @resources"},
		secretFlags: []string{"-tls-cert", "-tls-key"}, env: []string{"PGPASSFILE=%d/db-server-pgpass"},
	},
	{
		name: "aisec-gateway", user: "aisec-gw", group: "aisec-gw", memoryMax: "1G", tasksMax: "256",
		families: "AF_UNIX AF_INET AF_INET6", syscalls: []string{"@system-service", "~@privileged @resources"},
		state:       "aisec-gateway/reg aisec-gateway/state",
		secretFlags: []string{"-tls-cert", "-tls-key", "-server-ca", "-bundle-pub"},
	},
	{
		name: "aisec-ml", user: "aisec-ml", group: "aisec-gw", memoryMax: "2G", tasksMax: "256",
		families: "AF_UNIX", isolated: true, runtime: "aisec-ml",
		syscalls: []string{"@system-service", "~@privileged"},
	},
	{
		name: "aisec-media", user: "aisec-media", group: "aisec-gw", memoryMax: "1G", tasksMax: "64",
		families: "AF_UNIX", isolated: true, runtime: "aisec-media", cpuQuota: "400%",
		env: []string{"AISEC_MEDIA_WORKERS=2", "AISEC_MEDIA_MEM_LIMIT=1g"},
	},
}

// unitRequired — ограничения, общие для всех служб (ADR-0034, раздел 4).
var unitRequired = map[string]string{
	"Type":                    "exec",
	"UMask":                   "0077",
	"NoNewPrivileges":         "yes",
	"CapabilityBoundingSet":   "",
	"AmbientCapabilities":     "",
	"RestrictSUIDSGID":        "yes",
	"ProtectSystem":           "strict",
	"ProtectHome":             "yes",
	"PrivateDevices":          "yes",
	"DevicePolicy":            "closed",
	"ProtectKernelTunables":   "yes",
	"ProtectKernelModules":    "yes",
	"ProtectKernelLogs":       "yes",
	"ProtectControlGroups":    "yes",
	"ProtectClock":            "yes",
	"ProtectHostname":         "yes",
	"ProtectProc":             "invisible",
	"KeyringMode":             "private",
	"LockPersonality":         "yes",
	"MemoryDenyWriteExecute":  "yes",
	"RestrictRealtime":        "yes",
	"RestrictNamespaces":      "yes",
	"RemoveIPC":               "yes",
	"SystemCallArchitectures": "native",
	"SystemCallErrorNumber":   "EPERM",
	"MemorySwapMax":           "0",
}

// unitAllowedKeys — перечень ключей юнитов по разделам. Всё остальное —
// нарушение: так новые способы ослабить изоляцию (ExecStartPre=+…,
// PrivateUsers=, DynamicUser=, ReadWritePaths=, JoinsNamespaceOf=,
// ImportCredential=, NetworkNamespacePath=, Delegate= и т. п.) не проходят
// мимо проверки. PrivateUsers= прятал бы настоящий UID шлюза от SO_PEERCRED,
// DynamicUser= менял бы UID между запусками.
var unitAllowedKeys = map[string][]string{
	"Unit":    {"Description", "After", "Before", "Wants"},
	"Install": {"WantedBy"},
	"Service": {
		"Type", "User", "Group", "EnvironmentFile", "Environment", "LoadCredential", "ExecStart",
		"Restart", "RestartSec", "TimeoutStopSec", "UMask",
		"NoNewPrivileges", "CapabilityBoundingSet", "AmbientCapabilities", "RestrictSUIDSGID",
		"ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices", "DevicePolicy",
		"ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups",
		"ProtectClock", "ProtectHostname", "ProtectProc", "ProcSubset", "KeyringMode", "LockPersonality",
		"MemoryDenyWriteExecute", "RestrictRealtime", "RestrictNamespaces", "RemoveIPC",
		"RestrictAddressFamilies", "PrivateNetwork", "IPAddressDeny",
		"SystemCallArchitectures", "SystemCallFilter", "SystemCallErrorNumber",
		"MemoryMax", "MemorySwapMax", "TasksMax", "CPUQuota",
		"StateDirectory", "StateDirectoryMode", "RuntimeDirectory", "RuntimeDirectoryMode",
		"RootDirectory", "MountAPIVFS", "BindPaths", "TemporaryFileSystem",
	},
}

// systemdDefaultSyscalls — вызовы группы @default systemd 255 для x86-64:
// systemd разрешает их в любом списке, поэтому в aisec-media они доступны
// сверх профиля Docker. Это время, сон, ожидание, завершение и чтение своих
// идентификаторов и пределов — ни один не входит в seccompDenied (проверяет
// TestSystemdDefaultSyscallsHarmless).
var systemdDefaultSyscalls = []string{
	"arch_prctl", "brk", "clock_getres", "clock_gettime", "clock_nanosleep", "execve", "exit", "exit_group",
	"futex", "futex_waitv", "get_robust_list", "get_thread_area", "getegid", "geteuid", "getgid", "getgroups",
	"getpgid", "getpgrp", "getpid", "getppid", "getrandom", "getresgid", "getresuid", "getrlimit", "getsid",
	"gettid", "gettimeofday", "getuid", "membarrier", "mmap", "mprotect", "munmap", "nanosleep", "pause",
	"prlimit64", "restart_syscall", "rseq", "rt_sigreturn", "sched_getaffinity", "sched_yield",
	"set_robust_list", "set_thread_area", "set_tid_address", "time",
}

// checkUnit проверяет юнит службы по её описанию; seccomp — профиль Docker
// aisec-media (нужен только ему).
func checkUnit(spec unitSpec, u unitFile, seccomp []byte) []string {
	var problems []string
	at := func(format string, a ...any) {
		problems = append(problems, spec.name+".service: "+fmt.Sprintf(format, a...))
	}
	// want — ключ задан ровно один раз и с этим значением: многие директивы
	// systemd накапливаются (StateDirectory=, RestrictAddressFamilies=,
	// BindPaths=…), и лишняя строка выше нужной расширила бы права.
	want := func(key, value string) {
		v := u["Service"][key]
		if len(v) != 1 || v[0] != value {
			at("%s= — нужно ровно одно значение %q, получено %q", key, value, v)
		}
	}
	if u["Service"] == nil {
		return []string{spec.name + ".service: нет раздела [Service]"}
	}
	for sec, keys := range u {
		allowed, ok := unitAllowedKeys[sec]
		if !ok {
			at("раздел [%s] не разрешён", sec)
			continue
		}
		for _, k := range slices.Sorted(maps.Keys(keys)) {
			if !slices.Contains(allowed, k) {
				at("[%s] %s= — ключа нет в перечне разрешённых (ADR-0034, раздел 4)", sec, k)
			}
		}
	}
	for _, k := range slices.Sorted(maps.Keys(unitRequired)) {
		want(k, unitRequired[k])
	}
	if got := u["Service"]["Environment"]; !slices.Equal(got, spec.env) {
		at("Environment= — нужно %q, получено %q", spec.env, got)
	}
	want("User", spec.user)
	want("Group", spec.group)
	want("MemoryMax", spec.memoryMax)
	want("TasksMax", spec.tasksMax)
	want("RestrictAddressFamilies", spec.families)
	if spec.cpuQuota != "" {
		want("CPUQuota", spec.cpuQuota)
	}
	if v := u["Install"]["WantedBy"]; !slices.Equal(v, []string{"multi-user.target"}) {
		at("WantedBy= — нужно multi-user.target")
	}
	// Запись — только свои каталоги.
	if spec.state != "" {
		want("StateDirectory", spec.state)
		want("StateDirectoryMode", "0700")
	} else if _, ok := u["Service"]["StateDirectory"]; ok {
		at("StateDirectory= — у службы нет своего состояния")
	}
	if spec.runtime != "" {
		want("RuntimeDirectory", spec.runtime)
		want("RuntimeDirectoryMode", "0750")
		want("BindPaths", "/run/"+spec.runtime)
	} else if _, ok := u["Service"]["RuntimeDirectory"]; ok {
		at("RuntimeDirectory= — у службы нет сокета")
	}
	if spec.isolated {
		want("RootDirectory", "/opt/"+spec.name)
		want("MountAPIVFS", "yes")
		want("PrivateNetwork", "yes")
		want("IPAddressDeny", "any")
		want("TemporaryFileSystem", "/tmp:size=16m,mode=1777,noexec,nosuid,nodev")
		want("EnvironmentFile", "/etc/aisec/peers.env")
	} else {
		want("PrivateTmp", "yes")
		want("ProcSubset", "pid")
		want("EnvironmentFile", "/etc/aisec/"+spec.name+".env")
		for _, k := range []string{"RootDirectory", "MountAPIVFS", "PrivateNetwork", "IPAddressDeny", "TemporaryFileSystem", "BindPaths"} {
			if _, ok := u["Service"][k]; ok {
				at("%s= — только у aisec-ml и aisec-media", k)
			}
		}
	}
	exec, _ := u.last("Service", "ExecStart")
	args := strings.Fields(exec)
	if len(args) == 0 || args[0] != "/opt/aisec/bin/"+spec.name {
		at("ExecStart= — нужно /opt/aisec/bin/%s", spec.name)
	}
	if len(u["Service"]["ExecStart"]) != 1 {
		at("ExecStart= — ровно одна команда")
	}
	for _, a := range args[min(1, len(args)):] {
		k, v, _ := strings.Cut(a, "=")
		switch {
		case slices.Contains(spec.secretFlags, k) && !strings.HasPrefix(v, "%d/"):
			at("%s — только из каталога учётных данных (%%d/…, LoadCredential=)", k)
		case k == "-manifest" || k == "-integrity-action" || k == "-models" || k == "-ort-lib":
			at("%s — манифест, самопроверку, модели и ONNX Runtime задаёт выпуск", k)
		}
	}
	if spec.isolated && (!slices.Contains(args, "-peer-uid=${AISEC_GW_UID}") || !slices.Contains(args, "-peer-gid=${AISEC_GW_GID}")) {
		at("ExecStart= — нужны -peer-uid=${AISEC_GW_UID} и -peer-gid=${AISEC_GW_GID} (SO_PEERCRED)")
	}
	if spec.isolated {
		if _, ok := u["Service"]["LoadCredential"]; ok {
			at("LoadCredential= — у анализаторов секретов нет")
		}
	}
	for _, c := range u["Service"]["LoadCredential"] {
		_, src, _ := strings.Cut(c, ":")
		if !strings.HasPrefix(src, "/etc/aisec/credentials/") || strings.Contains(src, "..") {
			at("LoadCredential=%s — источник только в /etc/aisec/credentials", c)
		}
	}
	if spec.name == "aisec-media" {
		problems = append(problems, checkMediaSyscalls(u, seccomp)...)
	} else if got := u["Service"]["SystemCallFilter"]; !slices.Equal(got, spec.syscalls) {
		at("SystemCallFilter= — нужно %q, получено %q", spec.syscalls, got)
	}
	return problems
}

// checkMediaSyscalls сверяет список системных вызовов юнита aisec-media с
// профилем seccomp пилота: те же разрешённые имена и clone3; правило clone
// с маской пространств имён заменяет RestrictNamespaces=yes, socket только
// AF_UNIX — RestrictAddressFamilies=AF_UNIX (оба требует checkUnit). clone3
// → ENOSYS тоже даёт RestrictNamespaces=yes, поэтому clone3 в списке
// разрешён, а запретов «~…» нет: в режиме списка разрешённых «~clone3:ENOSYS»
// только убирает вызов, и последний установленный фильтр (SystemCallFilter=)
// отвечает EPERM — glibc тогда не создаёт потоки. Сверх профиля systemd
// разрешает только @default.
func checkMediaSyscalls(u unitFile, seccomp []byte) []string {
	var problems []string
	at := func(format string, a ...any) {
		problems = append(problems, "aisec-media.service: "+fmt.Sprintf(format, a...))
	}
	if p := checkSeccomp(seccomp); len(p) > 0 {
		return p
	}
	var prof seccompProfile
	if err := json.Unmarshal(seccomp, &prof); err != nil {
		return []string{"профиль seccomp: " + err.Error()}
	}
	want := map[string]bool{}
	for _, r := range prof.Syscalls {
		if r.Action == "SCMP_ACT_ALLOW" {
			for _, n := range r.Names {
				want[n] = true
			}
		}
	}
	// clone3 в профиле — правило ERRNO(ENOSYS); в юните ENOSYS даёт
	// RestrictNamespaces=yes, а сам вызов должен быть в списке.
	want["clone3"] = true
	got := map[string]bool{}
	for _, line := range u["Service"]["SystemCallFilter"] {
		if strings.HasPrefix(line, "~") {
			at("SystemCallFilter=%s — запретов нет: в режиме списка разрешённых «~» только убирает вызов, код ошибки теряется", line)
			continue
		}
		for _, n := range strings.Fields(line) {
			if strings.HasPrefix(n, "@") || strings.Contains(n, ":") {
				at("SystemCallFilter=: %s — только имена вызовов, без групп и кодов", n)
				continue
			}
			if got[n] {
				at("SystemCallFilter=: %s дважды", n)
			}
			got[n] = true
		}
	}
	for _, n := range slices.Sorted(maps.Keys(want)) {
		if !got[n] {
			at("нет вызова %s из seccomp/aisec-media.json", n)
		}
	}
	for _, n := range slices.Sorted(maps.Keys(got)) {
		if !want[n] {
			at("вызов %s не разрешён в seccomp/aisec-media.json", n)
		}
	}
	return problems
}

// checkDropIn проверяет дополнение юнита шлюза или сервера от пакета
// анализатора: только порядок запуска и путь сокета (Wants=, не Requires=:
// падение анализатора не останавливает шлюз).
func checkDropIn(name string, u unitFile, allowedEnv []string, wants string) []string {
	var problems []string
	at := func(format string, a ...any) { problems = append(problems, name+": "+fmt.Sprintf(format, a...)) }
	for sec, keys := range u {
		for k := range keys {
			ok := (sec == "Unit" && (k == "Wants" || k == "After") && wants != "") || (sec == "Service" && k == "Environment")
			if !ok {
				at("[%s] %s= — в дополнении разрешены только Wants=, After= и Environment=", sec, k)
			}
		}
	}
	if wants != "" {
		for _, k := range []string{"Wants", "After"} {
			if v, _ := u.last("Unit", k); v != wants {
				at("%s= — нужно %s", k, wants)
			}
		}
	}
	if got := u["Service"]["Environment"]; !slices.Equal(got, allowedEnv) {
		at("Environment= — нужно %q, получено %q", allowedEnv, got)
	}
	return problems
}

// packagingDropIns — дополнения юнитов от пакетов aisec-ml и aisec-media.
var packagingDropIns = []struct {
	path  string
	env   []string
	wants string
}{
	{"aisec-gateway.service.d/50-aisec-ml.conf", []string{"AISEC_GATEWAY_ML_SOCKET=/run/aisec-ml/aisec-ml.sock"}, "aisec-ml.service"},
	{"aisec-gateway.service.d/50-aisec-media.conf", []string{"AISEC_GATEWAY_MEDIA_SOCKET=/run/aisec-media/aisec-media.sock"}, "aisec-media.service"},
	{"aisec-server.service.d/50-aisec-ml.conf", []string{"AISEC_SERVER_ML_TEMPLATES=true"}, ""},
}

func readUnitFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: файлы юнитов из репозитория, путь задаёт make
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // файл открыт только для чтения
	data, err := io.ReadAll(io.LimitReader(f, maxUnitFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxUnitFile {
		return nil, fmt.Errorf("%s: больше %d байт", path, maxUnitFile)
	}
	return data, nil
}

// checkUnitsDir проверяет все юниты и дополнения каталога deploy/packaging/systemd.
func checkUnitsDir(dir string, seccomp []byte) []string {
	var problems []string
	for _, spec := range packagingUnits {
		data, err := readUnitFile(filepath.Join(dir, spec.name+".service"))
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		u, err := parseUnit(data)
		if err != nil {
			problems = append(problems, spec.name+".service: "+err.Error())
			continue
		}
		problems = append(problems, checkUnit(spec, u, seccomp)...)
	}
	for _, d := range packagingDropIns {
		data, err := readUnitFile(filepath.Join(dir, d.path))
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		u, err := parseUnit(data)
		if err != nil {
			problems = append(problems, d.path+": "+err.Error())
			continue
		}
		problems = append(problems, checkDropIn(d.path, u, d.env, d.wants)...)
	}
	return problems
}

func runUnits(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("units", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("ожидается: units КАТАЛОГ_ЮНИТОВ ПРОФИЛЬ_SECCOMP (deploy/packaging/systemd deploy/compose/pilot/seccomp/aisec-media.json)")
	}
	seccomp, err := readUnitFile(fs.Arg(1))
	if err != nil {
		return err
	}
	return report(stdout, "юниты "+fs.Arg(0), checkUnitsDir(fs.Arg(0), seccomp))
}
