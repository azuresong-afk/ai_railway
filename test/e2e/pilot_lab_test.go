//go:build e2e

package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

// TestE2EPilot_LabInstall — задача 4.32 этапа 4: lab-install.sh без сборки
// (образы уже собраны make images-test) проходит установку одной командой с
// сертификатами от собственного УЦ установки (aisec-cli tls init). Консоль и
// шлюз отвечают по TLS с корнем AISEC_DATA_DIR/ca.crt по имени и по адресу;
// закрытые ключи — у пользователей своих сервисов, временный каталог с
// ключами удалён; повторный запуск ничего не меняет.
func TestE2EPilot_LabInstall(t *testing.T) {
	cfg := pilotConfigFromEnv(t)
	p := newPilotInstall(t, cfg, newPilotTLS(t), "lab")
	s2Copy(t, filepath.Join("..", "..", "deploy", "compose", "pilot", "lab-install.sh"), filepath.Join(p.dir, "lab-install.sh"), 0o755)

	// Порты наложение e2e не публикует: --bind проверяется только по .env.
	out := p.sh("lab-install.sh", "--no-build", "--bind", "127.0.0.2", "--host", pilotConsoleAddr, "--host", pilotConsoleHost+","+pilotGatewayHost)
	for _, want := range []string{"отпечаток SHA-256", "сверьте при импорте", "aisec_setup_", "Шлюз gw-1 зарегистрирован", "НЕ ДЛЯ ПОСТАВКИ"} {
		if !strings.Contains(out, want) {
			t.Errorf("в выводе нет %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "PRIVATE KEY") || strings.Contains(out, "aisec_gwreg_") {
		t.Errorf("в выводе ключ или токен регистрации шлюза:\n%s", out)
	}
	env := string(mustRead(t, filepath.Join(p.dir, ".env")))
	if !strings.Contains(env, "\nAISEC_CONSOLE_HOST="+pilotConsoleHost+"\n") {
		t.Errorf("AISEC_CONSOLE_HOST — не первое имя из --host:\n%s", env)
	}

	ca := mustRead(t, filepath.Join(p.data, "ca.crt"))
	if !bytes.Equal(ca, mustRead(t, filepath.Join(p.data, "secrets", "console-ca.crt"))) {
		t.Error("ca.crt и secrets/console-ca.crt различаются")
	}
	s := p.stand()
	s.roots = ca
	if !s2WaitFor(90*time.Second, func() bool { return p.consoleUp(s) }) {
		t.Fatal("консоль не ответила по TLS с корнем установки за 90 с")
	}
	p.waitGatewayReady(s)
	// По адресу консоли — тот же сертификат: адрес есть в SAN.
	byAddr := p.stand()
	byAddr.roots, byAddr.base, byAddr.dial = ca, "https://"+pilotConsoleAddr+":8444", nil
	if !p.consoleUp(byAddr) {
		t.Error("консоль не отвечает по IP-адресу с корнем установки")
	}

	for name, want := range map[string]string{
		"console.key": "aisec 600", "gateway.key": "aisec-gw 600",
		"console.crt": "aisec 644", "gateway.crt": "aisec-gw 644", "console-ca.crt": "root 644",
	} {
		got, code := p.run(nil, nil, "stat", "-c", "%U %a", filepath.Join(p.data, "secrets", name))
		if code != 0 || strings.TrimSpace(got) != want {
			t.Errorf("%s: %q, ожидалось %q", name, strings.TrimSpace(got), want)
		}
	}
	entries, err := os.ReadDir(p.data)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "tls.") || strings.HasPrefix(e.Name(), "tls-check.") {
			t.Errorf("временный каталог с ключами не удалён: %s", e.Name())
		}
	}

	// Повторный запуск с другим именем консоли — отказ до изменения .env:
	// сертификаты выпущены на прежнее имя.
	envBefore := mustRead(t, filepath.Join(p.dir, ".env"))
	out, code := p.run(nil, nil, filepath.Join(p.dir, "lab-install.sh"), "--no-build", "--host", "other.test")
	if code == 0 || !strings.Contains(out, "--console-name "+pilotConsoleHost) {
		t.Errorf("повторный запуск с другим именем консоли: код %d\n%s", code, out)
	}
	if !bytes.Equal(envBefore, mustRead(t, filepath.Join(p.dir, ".env"))) {
		t.Error("отказ изменил .env")
	}

	// Повторный запуск: сертификаты, ключи, регистрация и адрес интерфейса
	// (без --bind) не меняются.
	out = p.sh("lab-install.sh", "--no-build", "--host", pilotConsoleHost)
	if n := strings.Count(out, "не меняю"); n != 3 {
		t.Errorf("повторный запуск: «не меняю» %d раз вместо 3:\n%s", n, out)
	}
	if strings.Contains(out, "aisec_setup_") {
		t.Error("повторный запуск выпустил токен первичной настройки")
	}
	if !bytes.Equal(ca, mustRead(t, filepath.Join(p.data, "ca.crt"))) {
		t.Error("повторный запуск заменил корень установки")
	}
	env = string(mustRead(t, filepath.Join(p.dir, ".env")))
	for _, want := range []string{"\nAISEC_CONSOLE_BIND=127.0.0.2\n", "\nAISEC_GATEWAY_BIND=127.0.0.2\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("после повторного запуска в .env нет %q:\n%s", strings.TrimSpace(want), env)
		}
	}
	p.waitGatewayReady(s)
}

// TestE2EPilot_LabInstallCustomerCA — задача 4.33 этапа 4: lab-install.sh с
// сертификатами УЦ заказчика (--tls-dir; цепочка с промежуточным УЦ). До
// установки сертификаты проверяет aisec-cli tls check: негодные не попадают
// в secrets. Консоль и шлюз отвечают с корнем заказчика; повторный запуск
// без --tls-dir или с другими сертификатами — отказ, с теми же — проверка и
// без изменений.
func TestE2EPilot_LabInstallCustomerCA(t *testing.T) {
	cfg := pilotConfigFromEnv(t)
	p := newPilotInstall(t, cfg, newPilotTLS(t), "labca")
	s2Copy(t, filepath.Join("..", "..", "deploy", "compose", "pilot", "lab-install.sh"), filepath.Join(p.dir, "lab-install.sh"), 0o755)
	hosts := []string{"--host", pilotConsoleAddr, "--host", pilotConsoleHost + "," + pilotGatewayHost}

	chain, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{pilotConsoleHost, pilotGatewayHost, pilotConsoleAddr}})
	if err != nil {
		t.Fatal(err)
	}
	// Каталог заказчика: root, 0700; у консоли и шлюза одна пара (cryptotest
	// выпускает один лист на корень) — скрипту это безразлично.
	tlsDir := func(name string, c cryptotest.Chain) string {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		cert := append(append([]byte{}, c.Leaf...), c.Intermediate...)
		for f, data := range map[string][]byte{"console.crt": cert, "gateway.crt": cert, "console.key": c.Key, "gateway.key": c.Key, "ca.crt": c.Root} {
			mustWrite(t, filepath.Join(dir, f), data)
		}
		return dir
	}
	good := tlsDir("good", chain)

	// Без IP-адреса в SAN — отказ на шаге 4, в secrets ничего не попадает.
	noIP, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{pilotConsoleHost, pilotGatewayHost}})
	if err != nil {
		t.Fatal(err)
	}
	out, code := p.run(nil, nil, filepath.Join(p.dir, "lab-install.sh"), append([]string{"--no-build", "--tls-dir", tlsDir("noip", noIP)}, hosts...)...)
	if code == 0 || !strings.Contains(out, "[ошибка]") || !strings.Contains(out, "не на имя "+pilotConsoleAddr) {
		t.Fatalf("сертификат без адреса: код %d\n%s", code, out)
	}
	for _, f := range []string{"console.crt", "console.key", "console-ca.crt", "gateway.crt", "gateway.key"} {
		if _, err := os.Stat(filepath.Join(p.data, "secrets", f)); err == nil {
			t.Errorf("после отказа в secrets есть %s", f)
		}
	}

	out = p.sh("lab-install.sh", append([]string{"--no-build", "--tls-dir", good}, hosts...)...)
	for _, want := range []string{"Сертификаты TLS УЦ заказчика", "[в порядке] console.crt", "[в порядке] gateway.crt", "Корень УЦ заказчика", "Шлюз gw-1 зарегистрирован"} {
		if !strings.Contains(out, want) {
			t.Errorf("в выводе нет %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Errorf("в выводе ключ:\n%s", out)
	}
	for _, f := range []string{filepath.Join(p.data, "ca.crt"), filepath.Join(p.data, "secrets", "console-ca.crt")} {
		if !bytes.Equal(mustRead(t, f), chain.Root) {
			t.Errorf("%s — не корень заказчика", f)
		}
	}
	s := p.stand()
	s.roots = chain.Root
	if !s2WaitFor(90*time.Second, func() bool { return p.consoleUp(s) }) {
		t.Fatal("консоль не ответила по TLS с корнем заказчика за 90 с")
	}
	p.waitGatewayReady(s)
	for name, want := range map[string]string{
		"console.key": "aisec 600", "gateway.key": "aisec-gw 600",
		"console.crt": "aisec 644", "gateway.crt": "aisec-gw 644", "console-ca.crt": "root 644",
	} {
		got, code := p.run(nil, nil, "stat", "-c", "%U %a", filepath.Join(p.data, "secrets", name))
		if code != 0 || strings.TrimSpace(got) != want {
			t.Errorf("%s: %q, ожидалось %q", name, strings.TrimSpace(got), want)
		}
	}
	entries, err := os.ReadDir(p.data)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "tls") {
			t.Errorf("временный каталог не удалён: %s", e.Name())
		}
	}
	if env := string(mustRead(t, filepath.Join(p.dir, ".env"))); !strings.Contains(env, "\nAISEC_TLS_SOURCE=customer\n") {
		t.Errorf("в .env нет AISEC_TLS_SOURCE=customer:\n%s", env)
	}

	// Другой источник или другие сертификаты — отказ до изменения .env.
	envBefore := mustRead(t, filepath.Join(p.dir, ".env"))
	other, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{pilotConsoleHost, pilotGatewayHost, pilotConsoleAddr}})
	if err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"без --tls-dir":      append([]string{"--no-build"}, hosts...),
		"другие сертификаты": append([]string{"--no-build", "--tls-dir", tlsDir("other", other)}, hosts...),
	} {
		out, code := p.run(nil, nil, filepath.Join(p.dir, "lab-install.sh"), args...)
		if code == 0 || !strings.Contains(out, "удалите пять файлов") {
			t.Errorf("%s: код %d\n%s", name, code, out)
		}
		if !bytes.Equal(envBefore, mustRead(t, filepath.Join(p.dir, ".env"))) {
			t.Errorf("%s: отказ изменил .env", name)
		}
	}

	// С теми же сертификатами — проверка и без изменений.
	out = p.sh("lab-install.sh", append([]string{"--no-build", "--tls-dir", good}, hosts...)...)
	if n := strings.Count(out, "не меняю"); n != 3 || !strings.Contains(out, "[в порядке] gateway.crt") {
		t.Errorf("повторный запуск: «не меняю» %d раз вместо 3:\n%s", n, out)
	}
	p.waitGatewayReady(s)
}
