//go:build e2e

package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	out := p.sh("lab-install.sh", "--no-build", "--host", pilotConsoleAddr, "--host", pilotConsoleHost+","+pilotGatewayHost)
	for _, want := range []string{"отпечаток SHA-256", "aisec_setup_", "Шлюз gw-1 зарегистрирован", "НЕ ДЛЯ ПОСТАВКИ"} {
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
		if strings.HasPrefix(e.Name(), "tls.") {
			t.Errorf("временный каталог с ключами не удалён: %s", e.Name())
		}
	}

	// Повторный запуск: сертификаты, ключи и регистрация не меняются.
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
	p.waitGatewayReady(s)
}
