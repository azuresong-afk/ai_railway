package main

import (
	"os"
	"strings"
	"testing"
)

const pilotCompose = "../../deploy/compose/pilot/compose.yaml"

func readPilot(t testing.TB) string {
	t.Helper()
	data, err := os.ReadFile(pilotCompose)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// ЗИ.5: compose пилота проходит все правила запуска.
func TestPilotCompose(t *testing.T) {
	c, err := parseCompose([]byte(readPilot(t)))
	if err != nil {
		t.Fatal(err)
	}
	if p := checkCompose(c); len(p) > 0 {
		t.Fatal(strings.Join(p, "\n"))
	}
	// Слияние «<<: *hardening» действительно применилось.
	if s := c.Services["aisec-gateway"]; !s.ReadOnly || s.PidsLimit == 0 {
		t.Fatalf("якорь hardening не применён: %+v", s)
	}
}

func TestComposeRejects(t *testing.T) {
	base := readPilot(t)
	for name, tc := range map[string]struct {
		old, new, want string
	}{
		"без read_only":         {"  read_only: true\n", "  read_only: false\n", "read_only"},
		"без cap_drop":          {"  cap_drop: [ALL]\n", "  cap_drop: [NET_RAW]\n", "cap_drop"},
		"без no-new-privileges": {`  security_opt: ["no-new-privileges:true"]`, `  security_opt: []`, "no-new-privileges"},
		"cap_add":               {"    image: ${AISEC_IMAGE_REPO:-aisec}/aisec-gateway:", "    cap_add: [NET_ADMIN]\n    image: ${AISEC_IMAGE_REPO:-aisec}/aisec-gateway:", "cap_add"},
		"privileged":            {"    profiles: [tools]\n", "    profiles: [tools]\n    privileged: true\n", "privileged"},
		"network_mode host":     {"    profiles: [tools]\n", "    profiles: [tools]\n    network_mode: host\n", "network_mode"},
		"root по умолчанию":     {`user: "${AISEC_GW_UID:?запустите prepare-host.sh}:${AISEC_GW_GID:?запустите prepare-host.sh}"`, `user: "${AISEC_GW_UID:-0}:${AISEC_GW_GID:-0}"`, "user"},
		"порт без адреса":       {`ports: ["${AISEC_GATEWAY_BIND:-127.0.0.1}:${AISEC_GATEWAY_PORT:-8443}:8443"]`, `ports: ["8443:8443"]`, "без адреса"},
		"порт на все адреса":    {`${AISEC_GATEWAY_BIND:-127.0.0.1}`, `${AISEC_GATEWAY_BIND:-0.0.0.0}`, "127.0.0.1"},
		"внутренний порт":       {`ports: ["${AISEC_CONSOLE_BIND:-127.0.0.1}:${AISEC_CONSOLE_PORT:-8444}:8444"]`, `ports: ["${AISEC_CONSOLE_BIND:-127.0.0.1}:8445:8445"]`, "публиковать можно только"},
		"порт PostgreSQL":       {"    profiles: [db]\n", "    profiles: [db]\n    ports: [\"${X:-127.0.0.1}:5432:5432\"]\n", "публиковать можно только"},
		"образ без digest":      {"17.11-alpine3.24@sha256:eee6c6e1b0894fa4fe0075eb054af9fd1cf39a35321c2d4110626cfe506411fb", "17.11-alpine3.24", "digest"},
		"чужой образ продукта":  {"${AISEC_IMAGE_REPO:-aisec}/aisec-gateway:", "evil/aisec-gateway:", "образ"},
		"пароль в окружении":    {"      AISEC_SERVER_INTEGRITY_ACTION:", "      POSTGRES_PASSWORD: x\n      AISEC_SERVER_INTEGRITY_ACTION:", "только файлами"},
		"пароль в строке":       {"postgres://aisec_server@postgres", "postgres://aisec_server:pw@postgres", "passfile"},
		"внешний адрес":         {"      AISEC_SERVER_INTEGRITY_ACTION:", "      AISEC_TELEMETRY: https://example.com/\n      AISEC_SERVER_INTEGRITY_ACTION:", "внешний адрес"},
		"healthcheck curl":      {`test: ["CMD", "pg_isready", "-h", "127.0.0.1", "-U", "aisec_owner", "-d", "aisec"]`, `test: ["CMD", "curl", "-f", "https://example.com/"]`, "healthcheck"},
		"БД с выходом наружу":   {"    networks: [db]\n    environment:\n      POSTGRES_USER", "    networks: [db, console]\n    environment:\n      POSTGRES_USER", "только внутренние"},
		"сокет docker":          {"      - ./initdb:/docker-entrypoint-initdb.d:ro\n", "      - ./initdb:/docker-entrypoint-initdb.d:ro\n      - /var/run/docker.sock:/var/run/docker.sock\n", "том"},
		"запись в ./":           {"./initdb:/docker-entrypoint-initdb.d:ro", "./initdb:/docker-entrypoint-initdb.d", "том"},
		"выход из каталога":     {"}/backups:/var/lib/aisec/backups", "}/../etc:/var/lib/aisec/backups", "«..»"},
		"build":                 {"    profiles: [tools]\n", "    profiles: [tools]\n    build: .\n", "build"},
		"без лимитов":           {"  pids_limit: 256\n", "", "pids_limit"},
		"секрет из окружения":   {"  db-server-pgpass:\n    file: ", "  db-server-pgpass:\n    environment: X\n    file: ", "секрет"},
		"неизвестный сервис":    {"\nsecrets:\n", "\n  shell:\n    image: busybox\n\nsecrets:\n", "неизвестный сервис"},
		"нет сервиса":           {"  aisec-cli:\n", "  aisec-tool:\n", "нет сервиса aisec-cli"},
		"seccomp выключен":      {`  security_opt: ["no-new-privileges:true"]`, `  security_opt: ["no-new-privileges:true", "seccomp=unconfined"]`, "security_opt"},
		"весь каталог данных":   {"}/backups:/var/lib/aisec/backups", "}:/var/lib/aisec/backups", "подкаталог"},
		"каталог секретов":      {"}/backups:/var/lib/aisec/backups", "}/secrets:/var/lib/aisec/backups", "подкаталог"},
		"чужой секрет":          {"    secrets: [db-owner-pgpass]", "    secrets: [db-owner-pgpass, console-tls-key]", "сервису не нужен"},
		"необъявленный секрет":  {"    secrets: [db-owner-pgpass]", "    secrets: [db-owner-pgpass, nope]", "не объявлен"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(base, tc.old) {
				t.Fatalf("в compose нет фрагмента %q — обновите тест", tc.old)
			}
			c, err := parseCompose([]byte(strings.Replace(base, tc.old, tc.new, 1)))
			if err != nil {
				t.Fatal(err)
			}
			problems := checkCompose(c)
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Fatalf("ожидалось нарушение %q, получено %v", tc.want, problems)
			}
		})
	}
}

// TestComposeUnknownFields — неизвестное поле сервиса, сети или секрета —
// ошибка разбора: правила не обходятся полем, которое проверка не видит.
func TestComposeUnknownFields(t *testing.T) {
	base := readPilot(t)
	for name, tc := range map[string]struct{ old, new string }{
		"volumes_from":   {"    profiles: [tools]\n", "    profiles: [tools]\n    volumes_from: [aisec-server]\n"},
		"sysctls":        {"    profiles: [tools]\n", "    profiles: [tools]\n    sysctls: {net.ipv4.ip_forward: 1}\n"},
		"extends":        {"    profiles: [tools]\n", "    profiles: [tools]\n    extends: {service: aisec-server}\n"},
		"внешняя сеть":   {"    internal: true\n", "    internal: true\n    external: true\n"},
		"include":        {"\nsecrets:\n", "\ninclude: [other.yaml]\n\nsecrets:\n"},
		"внешний секрет": {"  db-server-pgpass:\n    file: ", "  db-server-pgpass:\n    external: true\n    file: "},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(base, tc.old) {
				t.Fatalf("в compose нет фрагмента %q — обновите тест", tc.old)
			}
			if _, err := parseCompose([]byte(strings.Replace(base, tc.old, tc.new, 1))); err == nil {
				t.Fatal("неизвестное поле принято")
			}
		})
	}
}

func TestParseComposeLimits(t *testing.T) {
	if _, err := parseCompose(make([]byte, maxCompose+1)); err == nil {
		t.Error("compose больше предела принят")
	}
	if _, err := parseCompose([]byte("services: [")); err == nil {
		t.Error("неверный YAML принят")
	}
}

func FuzzCheckCompose(f *testing.F) {
	f.Add([]byte(readPilot(f)))
	f.Add([]byte("services:\n  postgres:\n    networks: {db: {}}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := parseCompose(data)
		if err != nil {
			return
		}
		// Файл без всех четырёх сервисов никогда не проходит проверку.
		if len(c.Services) < len(composeRules) && len(checkCompose(c)) == 0 {
			t.Fatal("неполный compose прошёл проверку")
		}
	})
}
