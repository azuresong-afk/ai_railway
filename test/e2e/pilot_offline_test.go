//go:build e2e

package e2e

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// pilotCanaryHost — внешнее имя провайдера-ловушки. Зона example.net
// зарезервирована (RFC 2606), в интернет запрос всё равно не уходит.
const pilotCanaryHost = "llm-canary.example.net"

// pilotDBCanaryHost — внешнее имя БД для контроля ловушки в сети db
// (10.231.11.0/24, compose.e2e.yaml).
const (
	pilotDBCanaryHost = "db-canary.example.net"
	pilotDBNet        = "10.231.11."
)

// TestE2EPilot_Offline — задача 3.7 этапа 3 (H-Р11, ЗИ.3, ТЗ 2.2): установка
// пилота в docker compose, где у сетей нет выхода наружу, проходит установку
// по руководству и рабочий путь «приложение → шлюз → провайдер → событие в
// консоли». Ни один контейнер не обращается по имени вне установки, кроме
// провайдера, которого задал администратор.
//
// Ловушка проверяется сама, в двух сетях: провайдер с внешним именем (шлюз,
// сеть gateway) и внешний адрес БД у aisec-cli (сеть db, как у сервера и
// PostgreSQL). Это единственные разрешённые обращения, и ловушка обязана
// увидеть у каждого и запрос имени, и попытку соединения. Без этого пустой
// журнал ничего бы не доказывал.
func TestE2EPilot_Offline(t *testing.T) {
	cfg := pilotConfigFromEnv(t)
	tls := newPilotTLS(t)
	p := newPilotInstall(t, cfg, tls, "offline")
	s, admin := p.install()

	// Рабочий путь целиком внутри установки: провайдер — mock-llm в сети gateway.
	mock := addProvider(t, admin, "mock", "https://mock-llm:9443/v1", tls.ca)
	app := addApp(t, admin, "crm", mock)
	const marker = "секретный-промпт-пилота-e2e"
	p.waitChat(s, 1, app.key, marker)
	if !s2WaitFor(60*time.Second, func() bool { return eventCount(t, admin, app.slug) >= 1 }) {
		t.Fatal("событие запроса не появилось в консоли за 60 с")
	}
	// Проверка установки по манифесту (install-pilot.md, раздел 3) — тоже без сети.
	p.cli("verify")

	// Настроенное обращение наружу: провайдер с внешним именем.
	canary := addProvider(t, admin, "canary", "https://"+pilotCanaryHost, tls.ca)
	capp := addApp(t, admin, "canary-app", canary)
	p.waitBundle(2)
	code, body := p.chat(s, capp.key, "проверка ловушки")
	if code == http.StatusOK {
		t.Fatalf("запрос к провайдеру вне установки прошёл: %s", body)
	}

	// Контроль ловушки в сети db (сервер, aisec-cli, PostgreSQL): aisec-cli с
	// намеренно внешним адресом БД. Подключение обязано не состояться.
	if out, code := p.run(nil, []string{"AISEC_DATABASE_URL=postgres://aisec_owner@" + pilotDBCanaryHost +
		":5432/aisec?sslmode=disable&connect_timeout=5"}, "docker", "compose", "run", "--rm", "-T",
		"-e", "AISEC_DATABASE_URL", "aisec-cli", "migrate"); code == 0 {
		t.Fatalf("aisec-cli подключился к БД вне установки:\n%s", out)
	}

	// Фоновая работа: heartbeat шлюза (не реже раза в 10 с), выдача пакетов,
	// проверки сервера после запуска.
	time.Sleep(30 * time.Second)
	seen := p.assertOffline(func(r trapRecord) bool {
		switch {
		case r.Src == pilotGatewayAddr:
			return r.Kind == "dns" && r.Name == pilotCanaryHost || r.Kind == "conn" && r.Proto == "tcp" && r.Port == 443
		case strings.HasPrefix(r.Src, pilotDBNet):
			return r.Kind == "dns" && r.Name == pilotDBCanaryHost || r.Kind == "conn" && r.Proto == "tcp" && r.Port == 5432
		}
		return false
	})
	// Ловушка обязана увидеть оба контроля: и запрос имени, и попытку
	// соединения в сетях gateway и db.
	got := map[string]bool{}
	for _, r := range seen {
		t.Logf("ловушка: %s", r)
		got[r.Kind+"|"+r.Name+"|"+strconv.Itoa(int(r.Port))] = true
	}
	for _, want := range []string{"dns|" + pilotCanaryHost + "|0", "conn||443", "dns|" + pilotDBCanaryHost + "|0", "conn||5432"} {
		if !got[want] {
			t.Errorf("ловушка не увидела контрольное обращение %s: проверка без интернета ничего не доказывает", want)
		}
	}
	p.assertLogsClean(marker)
}
