package main

import (
	"os"
	"strings"
	"testing"
)

const (
	pilotMedia   = "../../deploy/compose/pilot/compose.media.yaml"
	pilotSeccomp = "../../deploy/compose/pilot/seccomp/aisec-media.json"
)

func readFileT(t testing.TB, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: файлы пилота в репозитории
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// ADR-0032, задача 5.38: compose пилота с aisec-media (и вместе с ML)
// проходит все правила, профиль seccomp — тоже.
func TestPilotComposeMedia(t *testing.T) {
	if p := checkWithOverlay(t, readPilot(t), readFileT(t, pilotMedia)); len(p) > 0 {
		t.Fatal(strings.Join(p, "\n"))
	}
	c, err := parseCompose([]byte(readPilot(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []string{readPilotML(t), readFileT(t, pilotMedia)} {
		if err := applyOverlay(c, []byte(o)); err != nil {
			t.Fatal(err)
		}
	}
	if p := checkCompose(c); len(p) > 0 {
		t.Fatal(strings.Join(p, "\n"))
	}
	if p := checkSeccomp([]byte(readFileT(t, pilotSeccomp))); len(p) > 0 {
		t.Fatal(strings.Join(p, "\n"))
	}
	if err := runCompose([]string{pilotCompose, pilotMedia}, &strings.Builder{}, &strings.Builder{}); err != nil {
		t.Fatalf("imagecheck compose с compose.media.yaml: %v", err)
	}
}

// Ни одно ограничение compose.media.yaml нельзя убрать или ослабить молча.
func TestComposeMediaRejects(t *testing.T) {
	media := readFileT(t, pilotMedia)
	const (
		peerUID = "      - \"-peer-uid=${AISEC_GW_UID:?запустите prepare-host.sh}\"\n"
		sock    = "      - \"-socket=/run/aisec-media/aisec-media.sock\"\n"
		netNone = "    network_mode: none\n"
	)
	for name, tc := range map[string]struct {
		old, new, want string
	}{
		"aisec-media в сети":        {netNone, "    networks: [control]\n", "network_mode: none"},
		"network_mode host":         {netNone, "    network_mode: host\n", "network_mode"},
		"без read_only":             {"    read_only: true\n", "", "read_only"},
		"с capabilities":            {"    cap_drop: [ALL]\n", "    cap_drop: [ALL]\n    cap_add: [SYS_PTRACE]\n", "cap_add"},
		"без cap_drop":              {"    cap_drop: [ALL]\n", "", "cap_drop"},
		"без seccomp":               {`["no-new-privileges:true", "seccomp=./seccomp/aisec-media.json"]`, `["no-new-privileges:true"]`, "security_opt"},
		"seccomp unconfined":        {"seccomp=./seccomp/aisec-media.json", "seccomp=unconfined", "security_opt"},
		"без no-new-privileges":     {`"no-new-privileges:true", `, "", "security_opt"},
		"tmpfs без noexec":          {"noexec,", "", "noexec"},
		"tmpfs exec":                {"noexec,", "exec,", "exec запрещён"},
		"tmpfs без размера":         {"size=16m,", "", "size"},
		"второй tmpfs":              {"      - \"/tmp:", "      - \"/run/x:size=1m,noexec,nosuid,nodev\"\n      - \"/tmp:", "ровно один"},
		"без cpus":                  {"    cpus: ${AISEC_MEDIA_CPUS:-2}\n", "", "cpus"},
		"без memswap_limit":         {"    memswap_limit: ${AISEC_MEDIA_MEM_LIMIT:-1g}\n", "", "memswap_limit"},
		"своп больше памяти":        {"    memswap_limit: ${AISEC_MEDIA_MEM_LIMIT:-1g}\n", "    memswap_limit: -1\n", "memswap_limit"},
		"без mem_limit":             {"    mem_limit: ${AISEC_MEDIA_MEM_LIMIT:-1g}\n", "", "mem_limit"},
		"без pids_limit":            {"    pids_limit: 64\n", "", "pids_limit"},
		"pids_limit сверх предела":  {"    pids_limit: 64\n", "    pids_limit: 100000\n", "pids_limit 100000"},
		"от пользователя шлюза":     {"${AISEC_MEDIA_UID:?запустите prepare-host.sh}", "${AISEC_GW_UID:?запустите prepare-host.sh}", "AISEC_MEDIA_UID"},
		"от пользователя aisec-ml":  {"${AISEC_MEDIA_UID:?запустите prepare-host.sh}", "${AISEC_ML_UID:?запустите prepare-host.sh}", "AISEC_MEDIA_UID"},
		"без проверки собеседника":  {peerUID, "", "соединения — только от шлюза"},
		"собеседник root":           {peerUID, "      - \"-peer-uid=0\"\n", "сокет и собеседник"},
		"чужой сокет":               {sock, "      - \"-socket=/tmp/m.sock\"\n", "сокет и собеседник"},
		"самопроверка alert флагом": {sock, sock + "      - \"-integrity-action=alert\"\n", "самопроверку aisec-media задаёт образ"},
		"манифест флагом":           {sock, sock + "      - \"--manifest=/tmp/m.json\"\n", "самопроверку aisec-media задаёт образ"},
		"самопроверка alert в env":  {netNone, netNone + "    environment: {AISEC_MEDIA_INTEGRITY_ACTION: alert}\n", "задают образ и command"},
		"собеседник в env":          {netNone, netNone + "    environment: {AISEC_MEDIA_PEER_UID: \"0\"}\n", "задают образ и command"},
		"чужая переменная":          {netNone, netNone + "    environment: {GODEBUG: x}\n", "только AISEC_MEDIA_*"},
		"LD_PRELOAD":                {netNone, netNone + "    environment: {LD_PRELOAD: /tmp/x.so}\n", "переменные загрузчика"},
		"порт":                      {"    profiles: [media]\n", "    profiles: [media]\n    ports: [\"${X:-127.0.0.1}:9000:9000\"]\n", "публиковать можно только"},
		"ключи у aisec-media":       {"/media/run:/run/aisec-media\n", "/media/run:/run/aisec-media\n      - ${AISEC_DATA_DIR:?задайте AISEC_DATA_DIR}/keys:/etc/aisec/keys:ro\n", "aisec-media: том"},
		"сокет шлюзу на запись":     {"/run/aisec-media:ro\n", "/run/aisec-media\n", "aisec-gateway: том"},
		"шлюз без сокета":           {"      AISEC_GATEWAY_MEDIA_SOCKET: /run/aisec-media/aisec-media.sock\n", "      AISEC_GATEWAY_X: y\n", "AISEC_GATEWAY_MEDIA_SOCKET"},
		"шлюз без тома":             {"      - ${AISEC_DATA_DIR:?задайте AISEC_DATA_DIR}/media/run:/run/aisec-media:ro\n", "      - ${AISEC_DATA_DIR:?задайте AISEC_DATA_DIR}/gateway/reg:/var/lib/aisec-gateway/reg\n", "с aisec-media нужны"},
		"образ не свой":             {"${AISEC_IMAGE_REPO:-aisec}/aisec-media:", "${AISEC_IMAGE_REPO:-aisec}/aisec-gateway:", "образ"},
		"привилегированный":         {netNone, netNone + "    privileged: true\n", "privileged"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(media, tc.old) {
				t.Fatalf("в compose.media.yaml нет фрагмента %q — обновите тест", tc.old)
			}
			problems := checkWithOverlay(t, readPilot(t), strings.Replace(media, tc.old, tc.new, 1))
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Fatalf("ожидалось нарушение %q, получено %v", tc.want, problems)
			}
		})
	}
}

// Шлюзу нельзя оставить том или переменную сокета без сервиса aisec-media.
func TestComposeMediaGatewayWithoutService(t *testing.T) {
	overlay := "services:\n  aisec-gateway:\n    environment:\n      AISEC_GATEWAY_MEDIA_SOCKET: /run/aisec-media/aisec-media.sock\n"
	problems := checkWithOverlay(t, readPilot(t), overlay)
	if !strings.Contains(strings.Join(problems, "\n"), "только вместе с сервисом aisec-media") {
		t.Fatalf("получено %v", problems)
	}
}

// Профиль seccomp нельзя ослабить: разрешение по умолчанию, опасные
// вызовы, socket и clone без условий — нарушения.
func TestSeccompRejects(t *testing.T) {
	prof := readFileT(t, pilotSeccomp)
	for name, tc := range map[string]struct {
		old, new, want string
	}{
		"разрешено по умолчанию": {`"defaultAction": "SCMP_ACT_ERRNO"`, `"defaultAction": "SCMP_ACT_ALLOW"`, "по умолчанию"},
		"журнал вместо отказа":   {`"defaultAction": "SCMP_ACT_ERRNO"`, `"defaultAction": "SCMP_ACT_LOG"`, "по умолчанию"},
		"32-битный ABI":          {`"SCMP_ARCH_X86_64"`, `"SCMP_ARCH_X86_64", "SCMP_ARCH_X86"`, "архитектуры"},
		"ptrace":                 {`"accept4",`, `"accept4", "ptrace",`, "ptrace запрещён"},
		"connect":                {`"accept4",`, `"accept4", "connect",`, "connect запрещён"},
		"io_uring":               {`"accept4",`, `"accept4", "io_uring_setup",`, "io_uring_setup запрещён"},
		"clone3":                 {`"accept4",`, `"accept4", "clone3",`, "clone3 запрещён"},
		"socket без условия":     {`"value": 1,`, `"value": 2,`, "только для AF_UNIX"},
		"clone без условия":      {`"value": 2114060288,`, `"value": 0,`, "без новых пространств имён"},
		"повтор вызова":          {`"accept4",`, `"accept4", "accept4",`, "дважды"},
		"неизвестное поле":       {`"defaultErrnoRet": 1,`, `"defaultErrnoRet": 1, "flags": [],`, "unknown field"},
		"нет read":               {`"read",`, ``, "нет вызова read"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(prof, tc.old) {
				t.Fatalf("в профиле нет фрагмента %q — обновите тест", tc.old)
			}
			problems := checkSeccomp([]byte(strings.Replace(prof, tc.old, tc.new, 1)))
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Fatalf("ожидалось нарушение %q, получено %v", tc.want, problems)
			}
		})
	}
	// Действие правила — только разрешение.
	bad := strings.Replace(prof, `"action": "SCMP_ACT_ALLOW"`, `"action": "SCMP_ACT_TRACE"`, 1)
	if p := checkSeccomp([]byte(bad)); !strings.Contains(strings.Join(p, "\n"), "только SCMP_ACT_ALLOW") {
		t.Fatalf("получено %v", p)
	}
}

// Образ aisec-media — один статический бинарник, без портов.
func TestImageMedia(t *testing.T) {
	fx := &fixture{
		Tag:    "aisec-test/aisec-media:1.0.0-test",
		Config: goodConfig("aisec-media"),
		Layers: [][]layerFile{goodFiles(t, "aisec-media")},
	}
	if p := checkImage(load(t, fx), "test", ""); len(p) > 0 {
		t.Fatal(p)
	}
	fx.Config = goodConfig("aisec-media", "9000/tcp")
	if p := checkImage(load(t, fx), "test", ""); !strings.Contains(strings.Join(p, "\n"), "порты") {
		t.Fatalf("порт у aisec-media принят: %v", p)
	}
	fx.Config = goodConfig("aisec-media")
	fx.Layers = [][]layerFile{goodFiles(t, "aisec-media", "aisec-gateway")}
	if p := checkImage(load(t, fx), "test", ""); len(p) == 0 {
		t.Fatal("лишний бинарник в образе aisec-media принят")
	}
}
