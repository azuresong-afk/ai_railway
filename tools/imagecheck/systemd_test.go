package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Юниты установки без Docker (ADR-0034, задача 6.16).

const packagingSystemd = "../../deploy/packaging/systemd"

func readUnitT(t testing.TB, name string) string {
	t.Helper()
	return readFileT(t, filepath.Join(packagingSystemd, name))
}

func specByName(t testing.TB, name string) unitSpec {
	t.Helper()
	for _, s := range packagingUnits {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("нет описания %s", name)
	return unitSpec{}
}

func checkUnitText(t testing.TB, name, text string) []string {
	t.Helper()
	u, err := parseUnit([]byte(text))
	if err != nil {
		return []string{err.Error()}
	}
	return checkUnit(specByName(t, name), u, []byte(readFileT(t, pilotSeccomp)))
}

// dropKey убирает все строки «Ключ=…» юнита (с продолжениями — нет: такие
// ключи в тестах не убираются).
func dropKey(text, key string) string {
	return regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(key)+`=.*\n`).ReplaceAllString(text, "")
}

// setKey заменяет значение ключа во всех его строках.
func setKey(text, key, value string) string {
	return regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(key)+`=.*$`).ReplaceAllString(text, key+"="+value)
}

// addService добавляет строку в конец раздела [Service].
func addService(text, line string) string {
	return strings.Replace(text, "\n[Install]", "\n"+line+"\n\n[Install]", 1)
}

// Юниты и дополнения из репозитория проходят все правила; команда
// imagecheck units — тоже.
func TestPackagingUnits(t *testing.T) {
	seccomp := []byte(readFileT(t, pilotSeccomp))
	if p := checkUnitsDir(packagingSystemd, seccomp); len(p) > 0 {
		t.Fatal(strings.Join(p, "\n"))
	}
	var out strings.Builder
	if err := run([]string{"units", packagingSystemd, pilotSeccomp}, &out, &strings.Builder{}); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if err := run([]string{"units", packagingSystemd}, &out, &strings.Builder{}); err == nil {
		t.Fatal("units без профиля seccomp принят")
	}
}

// ADR-0034, раздел 6: список вызовов юнита aisec-media совпадает с
// профилем seccomp пилота; лишний или пропущенный вызов, другой запрет и
// группа вместо имён — нарушение.
func TestMediaUnitMatchesSeccomp(t *testing.T) {
	unit := readUnitT(t, "aisec-media.service")
	if p := checkUnitText(t, "aisec-media", unit); len(p) > 0 {
		t.Fatal(strings.Join(p, "\n"))
	}
	const sysLine = "SystemCallFilter=clone clone3 socket"
	cases := map[string]string{
		"пропущен вызов":  strings.Replace(unit, " fchmodat ", " ", 1),
		"лишний вызов":    strings.Replace(unit, sysLine, sysLine+" connect", 1),
		"группа":          strings.Replace(unit, sysLine, sysLine+" @network-io", 1),
		"код у вызова":    strings.Replace(unit, sysLine, "SystemCallFilter=clone clone3 socket:EPERM", 1),
		"нет clone3":      strings.Replace(unit, sysLine, "SystemCallFilter=clone socket", 1),
		"запрет clone3":   strings.Replace(unit, sysLine, "SystemCallFilter=clone socket\nSystemCallFilter=~clone3:ENOSYS", 1),
		"запрет":          strings.Replace(unit, sysLine, sysLine+"\nSystemCallFilter=~ptrace", 1),
		"вызов дважды":    strings.Replace(unit, sysLine, sysLine+" read", 1),
		"без пространств": setKey(unit, "RestrictNamespaces", "no"),
		"не только Unix":  setKey(unit, "RestrictAddressFamilies", "AF_UNIX AF_INET"),
		"убивать процесс": dropKey(unit, "SystemCallErrorNumber"),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if p := checkUnitText(t, "aisec-media", text); len(p) == 0 {
				t.Fatal("нарушение не найдено")
			}
		})
	}
	// Профиль пилота с новым вызовом без правки юнита — расхождение.
	seccomp := strings.Replace(readFileT(t, pilotSeccomp), `"writev"`, `"writev", "fsync"`, 1)
	u, err := parseUnit([]byte(unit))
	if err != nil {
		t.Fatal(err)
	}
	if p := checkMediaSyscalls(u, []byte(seccomp)); !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, "fsync") }) {
		t.Fatalf("новый вызов профиля не замечен: %v", p)
	}
}

// Группа @default systemd, которую юнит aisec-media получает сверх профиля
// Docker, не содержит ни одного опасного вызова.
func TestSystemdDefaultSyscallsHarmless(t *testing.T) {
	for _, n := range systemdDefaultSyscalls {
		if slices.Contains(seccompDenied, n) {
			t.Errorf("%s из @default запрещён для aisec-media", n)
		}
	}
}

// Ослабление любого юнита — нарушение.
func TestUnitRejects(t *testing.T) {
	type tc struct {
		unit, name string
		edit       func(string) string
	}
	cases := []tc{
		{"aisec-server", "PrivateUsers", func(s string) string { return addService(s, "PrivateUsers=yes") }},
		{"aisec-server", "без NoNewPrivileges", func(s string) string { return dropKey(s, "NoNewPrivileges") }},
		{"aisec-server", "capability", func(s string) string { return setKey(s, "CapabilityBoundingSet", "CAP_NET_BIND_SERVICE") }},
		{"aisec-server", "root", func(s string) string { return setKey(s, "User", "root") }},
		{"aisec-server", "запись мимо своих каталогов", func(s string) string { return addService(s, "ReadWritePaths=/var/lib/aisec") }},
		{"aisec-server", "ключ TLS не из учётных данных", func(s string) string {
			return strings.Replace(s, "-tls-key=%d/console-tls-key", "-tls-key=/etc/aisec/console.key", 1)
		}},
		{"aisec-server", "источник учётных данных вне каталога", func(s string) string {
			return strings.Replace(s, "/etc/aisec/credentials/console.key", "/home/admin/console.key", 1)
		}},
		{"aisec-server", "без @resources", func(s string) string { return strings.Replace(s, "~@privileged @resources", "~@privileged", 1) }},
		{"aisec-server", "своя система вызовов", func(s string) string { return addService(s, "SystemCallFilter=ptrace") }},
		{"aisec-server", "память без предела", func(s string) string { return dropKey(s, "MemoryMax") }},
		{"aisec-server", "запись в /etc", func(s string) string { return setKey(s, "ProtectSystem", "full") }},
		{"aisec-server", "свой корень", func(s string) string { return addService(s, "RootDirectory=/opt/aisec") }},
		{"aisec-server", "привилегированный ExecStartPre", func(s string) string { return addService(s, "ExecStartPre=+/bin/true") }},
		{"aisec-server", "манифест флагом", func(s string) string {
			return strings.Replace(s, "-keys-dir=", "-manifest=/tmp/m.json -keys-dir=", 1)
		}},
		{"aisec-gateway", "без своего состояния", func(s string) string { return dropKey(s, "StateDirectory") }},
		{"aisec-gateway", "состояние без родителя root", func(s string) string { return setKey(s, "StateDirectory", "aisec-gateway") }},
		{"aisec-gateway", "якорь не из учётных данных", func(s string) string {
			return strings.Replace(s, "-bundle-pub=%d/gateway-bundle-anchor", "-bundle-pub=/var/lib/aisec/keys/bundle-signing.pub", 1)
		}},
		{"aisec-gateway", "DynamicUser", func(s string) string { return addService(s, "DynamicUser=yes") }},
		{"aisec-ml", "сеть", func(s string) string { return setKey(s, "PrivateNetwork", "no") }},
		{"aisec-ml", "корень хоста", func(s string) string { return dropKey(s, "RootDirectory") }},
		{"aisec-ml", "без собеседника", func(s string) string {
			return strings.Replace(s, "-peer-uid=${AISEC_GW_UID}", "-peer-uid=0", 1)
		}},
		{"aisec-ml", "чужая группа", func(s string) string { return setKey(s, "Group", "aisec-ml") }},
		{"aisec-ml", "своя модель", func(s string) string {
			return strings.Replace(s, "-socket=", "-models=/tmp/m -socket=", 1)
		}},
		{"aisec-media", "tmp с исполнением", func(s string) string {
			return setKey(s, "TemporaryFileSystem", "/tmp:size=16m,mode=1777")
		}},
		{"aisec-media", "больше памяти без проверки", func(s string) string { return setKey(s, "MemoryMax", "8G") }},
		{"aisec-media", "своп", func(s string) string { return dropKey(s, "MemorySwapMax") }},
		{"aisec-media", "без квоты процессора", func(s string) string { return dropKey(s, "CPUQuota") }},
		{"aisec-media", "без peers.env", func(s string) string { return dropKey(s, "EnvironmentFile") }},
		{"aisec-media", "без IPAddressDeny", func(s string) string { return dropKey(s, "IPAddressDeny") }},
		{"aisec-media", "не включается", func(s string) string { return strings.Replace(s, "WantedBy=multi-user.target", "", 1) }},
		// Накапливаемые директивы: лишняя строка выше нужной расширяет права.
		{"aisec-gateway", "второй StateDirectory", func(s string) string { return addService(s, "StateDirectory=aisec") }},
		{"aisec-media", "второй RestrictAddressFamilies", func(s string) string { return addService(s, "RestrictAddressFamilies=AF_INET") }},
		{"aisec-media", "второй BindPaths", func(s string) string { return addService(s, "BindPaths=/var/lib/aisec") }},
		{"aisec-media", "второй TemporaryFileSystem", func(s string) string { return addService(s, "TemporaryFileSystem=/var:exec") }},
		{"aisec-server", "BindPaths", func(s string) string { return addService(s, "BindPaths=/var/lib/aisec-gateway") }},
		{"aisec-server", "своё окружение", func(s string) string { return addService(s, "Environment=AISEC_SERVER_INTEGRITY_ACTION=alert") }},
		{"aisec-media", "учётные данные", func(s string) string { return addService(s, "LoadCredential=x:/etc/aisec/credentials/console.key") }},
		{"aisec-server", "ExecStopPost от root", func(s string) string { return addService(s, "ExecStopPost=+/bin/true") }},
		{"aisec-server", "ImportCredential", func(s string) string { return addService(s, "ImportCredential=*") }},
		{"aisec-server", "чужое пространство имён", func(s string) string {
			return strings.Replace(s, "[Unit]\n", "[Unit]\nJoinsNamespaceOf=aisec-gateway.service\n", 1)
		}},
		{"aisec-server", "свой раздел", func(s string) string { return s + "\n[Socket]\nListenStream=80\n" }},
	}
	for _, c := range cases {
		t.Run(c.unit+"/"+c.name, func(t *testing.T) {
			text := readUnitT(t, c.unit+".service")
			edited := c.edit(text)
			if edited == text {
				t.Fatal("правка не применилась")
			}
			if p := checkUnitText(t, c.unit, edited); len(p) == 0 {
				t.Fatal("нарушение не найдено")
			}
		})
	}
	u, err := parseUnit([]byte("[Unit]\nDescription=x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p := checkUnit(specByName(t, "aisec-server"), u, nil); len(p) == 0 {
		t.Fatal("юнит без [Service] принят")
	}
}

// Дополнения от пакетов анализаторов: только порядок запуска и путь сокета.
func TestDropInRejects(t *testing.T) {
	d := packagingDropIns[1]
	text := readFileT(t, filepath.Join(packagingSystemd, d.path))
	cases := map[string]string{
		"Requires":      strings.Replace(text, "Wants=aisec-media.service", "Requires=aisec-media.service", 1),
		"чужой сокет":   strings.Replace(text, "/run/aisec-media/aisec-media.sock", "/tmp/aisec-media.sock", 1),
		"лишняя строка": strings.Replace(text, "[Service]\n", "[Service]\nUser=root\n", 1),
		"без After":     strings.Replace(text, "After=aisec-media.service\n", "", 1),
	}
	for name, edited := range cases {
		t.Run(name, func(t *testing.T) {
			if edited == text {
				t.Fatal("правка не применилась")
			}
			u, err := parseUnit([]byte(edited))
			if err != nil {
				t.Fatal(err)
			}
			if p := checkDropIn(d.path, u, d.env, d.wants); len(p) == 0 {
				t.Fatal("нарушение не найдено")
			}
		})
	}
	// Нет файла — нарушение.
	dir := t.TempDir()
	if p := checkUnitsDir(dir, []byte(readFileT(t, pilotSeccomp))); len(p) == 0 {
		t.Fatal("пустой каталог принят")
	}
}

func TestParseUnit(t *testing.T) {
	u, err := parseUnit([]byte("# комментарий\n[Service]\n; ещё\nExecStart=/bin/a \\\n\t-x=1 \\\n# внутри\n\t-y=2\nA=1\nA=2\n\n[Install]\nWantedBy=multi-user.target\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := u.last("Service", "ExecStart"); got != "/bin/a  -x=1  -y=2" {
		t.Fatalf("ExecStart=%q", got)
	}
	if got := u["Service"]["A"]; !slices.Equal(got, []string{"1", "2"}) {
		t.Fatalf("A=%v", got)
	}
	if v, ok := u.last("Service", "Нет"); ok || v != "" {
		t.Fatal("нет ключа — ожидается пусто")
	}
	bad := map[string]string{
		"ключ вне раздела":    "A=1\n",
		"без =":               "[Service]\nA\n",
		"пробел в ключе":      "[Service]\nA B=1\n",
		"пустой ключ":         "[Service]\n=1\n",
		"раздел без скобки":   "[Service\nA=1\n",
		"пустой раздел":       "[]\n",
		"продолжение в конце": "[Service]\nA=1 \\\n",
		"слишком большой":     "[Service]\n" + strings.Repeat("A=1\n", maxUnitFile/4+1),
		"слишком много":       "[Service]\n" + strings.Repeat("A=\n", maxUnitEntries+1),
	}
	for name, text := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := parseUnit([]byte(text)); err == nil {
				t.Fatal("ошибка не найдена")
			}
		})
	}
}

// FuzzParseUnit — разбор юнита: без паники, в пределах maxUnitFile и
// maxUnitEntries; проверка принятого юнита тоже без паники, и юнит без
// раздела [Service] никогда не проходит.
func FuzzParseUnit(f *testing.F) {
	for _, s := range packagingUnits {
		data, err := os.ReadFile(filepath.Join(packagingSystemd, s.name+".service")) //nolint:gosec // G304: юниты из репозитория
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte("[Unit]\nA=1 \\\n"))
	seccomp, err := os.ReadFile(pilotSeccomp)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		u, err := parseUnit(data)
		if err != nil {
			return
		}
		n := 0
		for _, keys := range u {
			for _, v := range keys {
				n += len(v)
			}
		}
		if n > maxUnitEntries {
			t.Fatalf("%d значений", n)
		}
		for _, s := range packagingUnits {
			p := checkUnit(s, u, seccomp)
			if u["Service"] == nil && len(p) == 0 {
				t.Fatal("юнит без [Service] принят")
			}
		}
	})
}
