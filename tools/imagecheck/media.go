package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Изоляция анализатора изображений aisec-media (ЗИ.7, ADR-0032, раздел 3;
// задача 5.38): сверх правил изолированного сервиса (как у aisec-ml) —
// профиль seccomp своим файлом, tmpfs без исполнения, лимиты процессора и
// свопа, свой пользователь, обязательная проверка собеседника по сокету.
// Любое ослабление compose.media.yaml или профиля — нарушение.

const (
	// mediaSeccompOpt — профиль seccomp в security_opt, путь — от каталога
	// compose.yaml (docker compose передаёт содержимое файла демону).
	mediaSeccompOpt  = "seccomp=./seccomp/aisec-media.json"
	mediaSeccompFile = "seccomp/aisec-media.json"
	mediaMaxPids     = 256
	maxSeccomp       = 64 << 10
)

var (
	mediaUserRe    = regexp.MustCompile(`^\$\{AISEC_MEDIA_UID:\?[^}]*\}:\$\{AISEC_GW_GID:\?[^}]*\}$`)
	mediaPeerUIDRe = regexp.MustCompile(`^-peer-uid=\$\{AISEC_GW_UID:\?[^}]*\}$`)
	mediaPeerGIDRe = regexp.MustCompile(`^-peer-gid=\$\{AISEC_GW_GID:\?[^}]*\}$`)
)

// mediaFixedFlags — флаги, которые задаёт образ или которые ослабляют
// самопроверку: манифест выпуска и реакция на нарушение целостности.
var mediaFixedFlags = []string{"manifest", "integrity-action"}

func checkMedia(s composeService, at func(string, ...any)) {
	if !mediaUserRe.MatchString(s.User) {
		at("user %q — нужен «${AISEC_MEDIA_UID:?…}:${AISEC_GW_GID:?…}»: свой пользователь aisec-media с группой шлюза", s.User)
	}
	// Единственный tmpfs — /tmp с размером и noexec, nosuid, nodev.
	if len(s.Tmpfs) != 1 || !strings.HasPrefix(s.Tmpfs[0], "/tmp:") {
		at("tmpfs: ровно один — /tmp с size=…, noexec, nosuid и nodev, получено %v", s.Tmpfs)
	} else {
		opts := strings.Split(strings.TrimPrefix(s.Tmpfs[0], "/tmp:"), ",")
		if !slices.ContainsFunc(opts, func(o string) bool { return strings.HasPrefix(o, "size=") && len(o) > len("size=") }) {
			at("tmpfs /tmp: нужен size=…")
		}
		for _, o := range []string{"noexec", "nosuid", "nodev"} {
			if !slices.Contains(opts, o) {
				at("tmpfs /tmp: нужен %s", o)
			}
		}
		for _, o := range []string{"exec", "suid", "dev"} {
			if slices.Contains(opts, o) {
				at("tmpfs /tmp: %s запрещён", o)
			}
		}
	}
	if s.Cpus == "" {
		at("нужен cpus: лимит процессора")
	}
	if s.MemswapLimit == "" || s.MemswapLimit != s.MemLimit {
		at("memswap_limit должен совпадать с mem_limit (%q, получено %q): своп обходит лимит памяти", s.MemLimit, s.MemswapLimit)
	}
	if s.PidsLimit > mediaMaxPids {
		at("pids_limit %d — не больше %d", s.PidsLimit, mediaMaxPids)
	}
	var socket, peerUID, peerGID bool
	for _, a := range s.Command {
		flagName, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		switch {
		case a == "-socket="+mediaSocketValue:
			socket = true
		case mediaPeerUIDRe.MatchString(a):
			peerUID = true
		case mediaPeerGIDRe.MatchString(a):
			peerGID = true
		case slices.Contains(mediaFixedFlags, flagName):
			at("аргумент %q: манифест выпуска и самопроверку aisec-media задаёт образ", a)
		case flagName == "socket" || flagName == "peer-uid" || flagName == "peer-gid":
			at("аргумент %q: сокет и собеседник — только -socket=%s, -peer-uid=${AISEC_GW_UID:?…}, -peer-gid=${AISEC_GW_GID:?…}", a, mediaSocketValue)
		}
	}
	if !socket || !peerUID || !peerGID {
		at("нужны -socket=%s, -peer-uid=${AISEC_GW_UID:?…} и -peer-gid=${AISEC_GW_GID:?…}: соединения — только от шлюза", mediaSocketValue)
	}
	for k := range s.Environment {
		flagName := strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(k, "AISEC_MEDIA_"), "_", "-"))
		switch {
		case !strings.HasPrefix(k, "AISEC_MEDIA_"):
			at("переменная %s: у aisec-media разрешены только AISEC_MEDIA_*", k)
		case slices.Contains(mediaFixedFlags, flagName) || slices.Contains([]string{"socket", "peer-uid", "peer-gid"}, flagName):
			at("переменная %s: манифест, самопроверку, сокет и собеседника aisec-media задают образ и command", k)
		}
	}
}

// seccompProfile — профиль seccomp в формате Docker; неизвестное поле —
// ошибка разбора.
type seccompProfile struct {
	DefaultAction   string   `json:"defaultAction"`
	DefaultErrnoRet *int     `json:"defaultErrnoRet"`
	Architectures   []string `json:"architectures"`
	Syscalls        []struct {
		Names  []string `json:"names"`
		Action string   `json:"action"`
		Args   []struct {
			Index    int    `json:"index"`
			Value    uint64 `json:"value"`
			ValueTwo uint64 `json:"valueTwo"`
			Op       string `json:"op"`
		} `json:"args"`
	} `json:"syscalls"`
}

// seccompDenied — вызовы, которых в профиле aisec-media быть не должно:
// сеть наружу, отладка и чтение чужой памяти, пространства имён и
// монтирование, загрузка кода в ядро, смена пользователя, io_uring (обходит
// фильтр по отдельным вызовам), clone3 (флаги в структуре — их не проверить).
var seccompDenied = []string{
	"connect", "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
	"ptrace", "process_vm_readv", "process_vm_writev", "perf_event_open", "bpf", "userfaultfd",
	"mount", "umount2", "pivot_root", "chroot", "unshare", "setns", "clone3", "move_mount", "open_tree", "fsopen", "fsmount",
	"init_module", "finit_module", "delete_module", "kexec_load", "kexec_file_load",
	"keyctl", "add_key", "request_key", "open_by_handle_at", "name_to_handle_at",
	"setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "setgroups", "setfsuid", "setfsgid", "capset",
	"io_uring_setup", "io_uring_enter", "io_uring_register",
	"personality", "iopl", "ioperm", "reboot", "swapon", "swapoff", "syslog", "acct", "mknod", "mknodat",
	"execveat", "fork", "vfork", "kill", "ioctl",
}

// cloneNamespaceMask — флаги CLONE_NEW*: clone разрешён только без них.
const cloneNamespaceMask = 0x7e020000

// checkSeccomp проверяет профиль seccomp aisec-media: по умолчанию —
// отказ, только x86-64, разрешения — списком, без опасных вызовов; clone —
// без новых пространств имён, socket — только AF_UNIX.
func checkSeccomp(data []byte) []string {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	if len(data) > maxSeccomp {
		return []string{fmt.Sprintf("профиль seccomp больше %d байт", maxSeccomp)}
	}
	var p seccompProfile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return []string{"профиль seccomp: " + err.Error()}
	}
	if p.DefaultAction != "SCMP_ACT_ERRNO" || p.DefaultErrnoRet == nil || *p.DefaultErrnoRet != 1 {
		add("профиль seccomp: по умолчанию — SCMP_ACT_ERRNO с defaultErrnoRet 1 (EPERM), получено %q", p.DefaultAction)
	}
	if !slices.Equal(p.Architectures, []string{"SCMP_ARCH_X86_64"}) {
		add("профиль seccomp: архитектуры — только SCMP_ARCH_X86_64, получено %v", p.Architectures)
	}
	seen := map[string]bool{}
	for _, r := range p.Syscalls {
		if r.Action != "SCMP_ACT_ALLOW" {
			add("профиль seccomp: правило %v с действием %s — только SCMP_ACT_ALLOW", r.Names, r.Action)
		}
		for _, n := range r.Names {
			if seen[n] {
				add("профиль seccomp: %s дважды", n)
			}
			seen[n] = true
			if slices.Contains(seccompDenied, n) {
				add("профиль seccomp: вызов %s запрещён для aisec-media", n)
			}
		}
		switch {
		case slices.Contains(r.Names, "clone"):
			if len(r.Names) != 1 || len(r.Args) != 1 || r.Args[0].Index != 0 || r.Args[0].Op != "SCMP_CMP_MASKED_EQ" ||
				r.Args[0].Value != cloneNamespaceMask || r.Args[0].ValueTwo != 0 {
				add("профиль seccomp: clone — отдельным правилом с условием «флаги & 0x%x == 0» (без новых пространств имён)", cloneNamespaceMask)
			}
		case slices.Contains(r.Names, "socket"):
			if len(r.Names) != 1 || len(r.Args) != 1 || r.Args[0].Index != 0 || r.Args[0].Op != "SCMP_CMP_EQ" || r.Args[0].Value != 1 {
				add("профиль seccomp: socket — отдельным правилом только для AF_UNIX (аргумент 0 == 1)")
			}
		case len(r.Args) > 0:
			add("профиль seccomp: условия на аргументы — только у clone и socket, получено у %v", r.Names)
		}
	}
	for _, n := range []string{"clone", "socket", "accept4", "read", "write", "futex"} {
		if !seen[n] {
			add("профиль seccomp: нет вызова %s — aisec-media не запустится", n)
		}
	}
	return problems
}
