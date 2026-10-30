package main

import (
	"os"
	"slices"
	"strings"
	"testing"
)

const (
	pilotCompose = "../../deploy/compose/pilot/compose.yaml"
	pilotML      = "../../deploy/compose/pilot/compose.ml.yaml"
)

func readPilot(t testing.TB) string {
	t.Helper()
	data, err := os.ReadFile(pilotCompose)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func readPilotML(t testing.TB) string {
	t.Helper()
	data, err := os.ReadFile(pilotML)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// checkWithOverlay — нарушения compose пилота с дополнением.
func checkWithOverlay(t *testing.T, base, overlay string) []string {
	t.Helper()
	c, err := parseCompose([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyOverlay(c, []byte(overlay)); err != nil {
		t.Fatal(err)
	}
	return checkCompose(c)
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
	// Без дополнения ML сервиса aisec-ml нет: установка работает как раньше.
	if _, ok := c.Services["aisec-ml"]; ok {
		t.Fatal("aisec-ml в основном compose")
	}
}

// ADR-0024, задача 4.19: compose пилота с дополнением ML проходит все правила.
func TestPilotComposeML(t *testing.T) {
	if p := checkWithOverlay(t, readPilot(t), readPilotML(t)); len(p) > 0 {
		t.Fatal(strings.Join(p, "\n"))
	}
}

// mlSocketArg — аргумент сокета aisec-ml в compose.ml.yaml.
const mlSocketArg = "      - \"-socket=/run/aisec-ml/aisec-ml.sock\"\n"

func TestComposeMLRejects(t *testing.T) {
	ml := readPilotML(t)
	for name, tc := range map[string]struct {
		old, new, want string
	}{
		"aisec-ml в сети":            {"    network_mode: none\n", "    networks: [control]\n", "network_mode: none"},
		"aisec-ml network_mode host": {"    network_mode: none\n", "    network_mode: host\n", "network_mode"},
		"порт у aisec-ml":            {"    profiles: [ml]\n", "    profiles: [ml]\n    ports: [\"${X:-127.0.0.1}:9000:9000\"]\n", "публиковать можно только"},
		"aisec-ml от шлюза":          {"${AISEC_ML_UID:?запустите prepare-host.sh}", "${AISEC_GW_UID:-0}", "user"},
		"aisec-ml без read_only":     {"    read_only: true\n", "", "read_only"},
		"сокет шлюзу на запись":      {"/run/aisec-ml:ro\n", "/run/aisec-ml\n", "aisec-gateway: том"},
		"шлюз без сокета":            {"      AISEC_GATEWAY_ML_SOCKET: /run/aisec-ml/aisec-ml.sock\n", "", "AISEC_GATEWAY_ML_SOCKET"},
		"шлюз без тома":              {"      - ${AISEC_DATA_DIR:?задайте AISEC_DATA_DIR}/ml/run:/run/aisec-ml:ro\n", "      - ${AISEC_DATA_DIR:?задайте AISEC_DATA_DIR}/gateway/reg:/var/lib/aisec-gateway/reg\n", "с aisec-ml нужны"},
		"LD_PRELOAD у aisec-ml":      {"    network_mode: none\n", "    network_mode: none\n    environment: {LD_PRELOAD: /run/aisec-ml/x.so}\n", "переменные загрузчика"},
		"LD_LIBRARY_PATH у шлюза":    {"      AISEC_GATEWAY_ML_SOCKET: /run/aisec-ml/aisec-ml.sock\n", "      AISEC_GATEWAY_ML_SOCKET: /run/aisec-ml/aisec-ml.sock\n      LD_LIBRARY_PATH: /tmp\n", "переменные загрузчика"},
		"самопроверка alert в env":   {"    network_mode: none\n", "    network_mode: none\n    environment: {AISEC_ML_INTEGRITY_ACTION: alert}\n", "ослабление самопроверки"},
		"самопроверка alert флагом":  {mlSocketArg, mlSocketArg + "      - \"-integrity-action=alert\"\n", "ослабление самопроверки"},
		// 4В23: старый подписанный пакет моделей в обход выпуска.
		"каталог моделей флагом": {mlSocketArg, mlSocketArg + "      - \"-models=/run/aisec-ml/pkg\"\n", "пути выпуска"},
		"манифест флагом":        {mlSocketArg, mlSocketArg + "      - \"--manifest\"\n", "пути выпуска"},
		"ORT флагом":             {mlSocketArg, mlSocketArg + "      - \"-ort-lib=/run/aisec-ml/o.so\"\n", "пути выпуска"},
		"каталог моделей в env":  {"    network_mode: none\n", "    network_mode: none\n    environment: {AISEC_ML_MODELS: /run/aisec-ml/pkg}\n", "пути выпуска"},
		"манифест в env":         {"    network_mode: none\n", "    network_mode: none\n    environment: {AISEC_ML_MANIFEST: /run/aisec-ml/m.json}\n", "пути выпуска"},
		"ORT в env":              {"    network_mode: none\n", "    network_mode: none\n    environment: {AISEC_ML_ORT_LIB: /run/aisec-ml/o.so}\n", "пути выпуска"},
		"ключи у aisec-ml":       {"/ml/run:/run/aisec-ml\n", "/ml/run:/run/aisec-ml\n      - ${AISEC_DATA_DIR:?задайте AISEC_DATA_DIR}/keys:/etc/aisec/keys:ro\n", "aisec-ml: том"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(ml, tc.old) {
				t.Fatalf("в compose.ml.yaml нет фрагмента %q — обновите тест", tc.old)
			}
			problems := checkWithOverlay(t, readPilot(t), strings.Replace(ml, tc.old, tc.new, 1))
			if !strings.Contains(strings.Join(problems, "\n"), tc.want) {
				t.Fatalf("ожидалось нарушение %q, получено %v", tc.want, problems)
			}
		})
	}
	// Шлюз с сокетом без aisec-ml: сокет некому открыть.
	gwOnly := ml[:strings.Index(ml, "  aisec-ml:\n")]
	gwOnly = strings.Replace(gwOnly, "    depends_on:\n      aisec-ml: {condition: service_started}\n", "", 1)
	if p := checkWithOverlay(t, readPilot(t), gwOnly); !strings.Contains(strings.Join(p, "\n"), "только вместе с сервисом aisec-ml") {
		t.Fatalf("шлюз с сокетом без aisec-ml: %v", p)
	}
}

// Дополнение не обходит правила: существующему сервису — только
// зависимости, окружение и тома; переменную основного файла не заменить.
func TestApplyOverlayRejects(t *testing.T) {
	for name, overlay := range map[string]string{
		"права шлюзу":                "services:\n  aisec-gateway:\n    privileged: true\n",
		"чужой пользователь":         "services:\n  aisec-gateway:\n    user: \"0:0\"\n",
		"переопределение переменной": "services:\n  aisec-server:\n    environment:\n      AISEC_SERVER_INTEGRITY_ACTION: ignore\n",
		"неизвестная зависимость":    "services:\n  aisec-gateway:\n    depends_on:\n      nope: {condition: service_started}\n",
		"неизвестное поле сервиса":   "services:\n  aisec-ml:\n    sysctls: {a: 1}\n",
		"ключ верхнего уровня":       "include: [x.yaml]\nservices: {}\n",
		"тег !override":              "services:\n  aisec-gateway:\n    volumes: !override [\"/x:/y:ro\"]\n",
		"тег !reset":                 "services:\n  aisec-gateway:\n    environment: !reset {}\n",
		"слишком большое":            strings.Repeat("#", maxCompose+1),
	} {
		t.Run(name, func(t *testing.T) {
			c, err := parseCompose([]byte(readPilot(t)))
			if err != nil {
				t.Fatal(err)
			}
			if err := applyOverlay(c, []byte(overlay)); err == nil {
				t.Fatal("дополнение принято")
			}
		})
	}
}

func TestComposeRejects(t *testing.T) {
	base := readPilot(t)
	for name, tc := range map[string]struct {
		old, new, want string
	}{
		"без read_only":               {"  read_only: true\n", "  read_only: false\n", "read_only"},
		"без cap_drop":                {"  cap_drop: [ALL]\n", "  cap_drop: [NET_RAW]\n", "cap_drop"},
		"без no-new-privileges":       {`  security_opt: ["no-new-privileges:true"]`, `  security_opt: []`, "no-new-privileges"},
		"cap_add":                     {"    image: ${AISEC_IMAGE_REPO:-aisec}/aisec-gateway:", "    cap_add: [NET_ADMIN]\n    image: ${AISEC_IMAGE_REPO:-aisec}/aisec-gateway:", "cap_add"},
		"privileged":                  {"    profiles: [tools]\n", "    profiles: [tools]\n    privileged: true\n", "privileged"},
		"network_mode host":           {"    profiles: [tools]\n", "    profiles: [tools]\n    network_mode: host\n", "network_mode"},
		"aisec-cli network_mode none": {"    profiles: [tools]\n", "    profiles: [tools]\n    network_mode: none\n", "network_mode"},
		"root по умолчанию":           {`user: "${AISEC_GW_UID:?запустите prepare-host.sh}:${AISEC_GW_GID:?запустите prepare-host.sh}"`, `user: "${AISEC_GW_UID:-0}:${AISEC_GW_GID:-0}"`, "user"},
		"порт без адреса":             {`ports: ["${AISEC_GATEWAY_BIND:-127.0.0.1}:${AISEC_GATEWAY_PORT:-8443}:8443"]`, `ports: ["8443:8443"]`, "без адреса"},
		"порт на все адреса":          {`${AISEC_GATEWAY_BIND:-127.0.0.1}`, `${AISEC_GATEWAY_BIND:-0.0.0.0}`, "127.0.0.1"},
		"внутренний порт":             {`ports: ["${AISEC_CONSOLE_BIND:-127.0.0.1}:${AISEC_CONSOLE_PORT:-8444}:8444"]`, `ports: ["${AISEC_CONSOLE_BIND:-127.0.0.1}:8445:8445"]`, "публиковать можно только"},
		"порт PostgreSQL":             {"    profiles: [db]\n", "    profiles: [db]\n    ports: [\"${X:-127.0.0.1}:5432:5432\"]\n", "публиковать можно только"},
		"образ без digest":            {"17.11-alpine3.24@sha256:eee6c6e1b0894fa4fe0075eb054af9fd1cf39a35321c2d4110626cfe506411fb", "17.11-alpine3.24", "digest"},
		"чужой образ продукта":        {"${AISEC_IMAGE_REPO:-aisec}/aisec-gateway:", "evil/aisec-gateway:", "образ"},
		"пароль в окружении":          {"      AISEC_SERVER_INTEGRITY_ACTION:", "      POSTGRES_PASSWORD: x\n      AISEC_SERVER_INTEGRITY_ACTION:", "только файлами"},
		"пароль в строке":             {"postgres://aisec_server@postgres", "postgres://aisec_server:pw@postgres", "passfile"},
		"внешний адрес":               {"      AISEC_SERVER_INTEGRITY_ACTION:", "      AISEC_TELEMETRY: https://example.com/\n      AISEC_SERVER_INTEGRITY_ACTION:", "внешний адрес"},
		"healthcheck curl":            {`test: ["CMD", "pg_isready", "-h", "127.0.0.1", "-U", "aisec_owner", "-d", "aisec"]`, `test: ["CMD", "curl", "-f", "https://example.com/"]`, "healthcheck"},
		"БД с выходом наружу":         {"    networks: [db]\n    environment:\n      POSTGRES_USER", "    networks: [db, console]\n    environment:\n      POSTGRES_USER", "только внутренние"},
		"сокет docker":                {"      - ./initdb:/docker-entrypoint-initdb.d:ro\n", "      - ./initdb:/docker-entrypoint-initdb.d:ro\n      - /var/run/docker.sock:/var/run/docker.sock\n", "том"},
		"запись в ./":                 {"./initdb:/docker-entrypoint-initdb.d:ro", "./initdb:/docker-entrypoint-initdb.d", "том"},
		"выход из каталога":           {"}/backups:/var/lib/aisec/backups", "}/../etc:/var/lib/aisec/backups", "«..»"},
		"build":                       {"    profiles: [tools]\n", "    profiles: [tools]\n    build: .\n", "build"},
		"без лимитов":                 {"  pids_limit: 256\n", "", "pids_limit"},
		"секрет из окружения":         {"  db-server-pgpass:\n    file: ", "  db-server-pgpass:\n    environment: X\n    file: ", "секрет"},
		"неизвестный сервис":          {"\nsecrets:\n", "\n  shell:\n    image: busybox\n\nsecrets:\n", "неизвестный сервис"},
		"нет сервиса":                 {"  aisec-cli:\n", "  aisec-tool:\n", "нет сервиса aisec-cli"},
		"seccomp выключен":            {`  security_opt: ["no-new-privileges:true"]`, `  security_opt: ["no-new-privileges:true", "seccomp=unconfined"]`, "security_opt"},
		"весь каталог данных":         {"}/backups:/var/lib/aisec/backups", "}:/var/lib/aisec/backups", "не из списка"},
		"каталог секретов":            {"}/backups:/var/lib/aisec/backups", "}/secrets:/var/lib/aisec/backups", "не из списка"},
		// 3В8 ревью 3.r1: тома и файлы секретов привязаны к сервису.
		"ключи у шлюза": {"      - ${AISEC_DATA_DIR:?задайте AISEC_DATA_DIR}/gateway/state:/var/lib/aisec-gateway/state\n",
			"      - ${AISEC_DATA_DIR:?задайте AISEC_DATA_DIR}/gateway/state:/var/lib/aisec-gateway/state\n      - ${AISEC_DATA_DIR:?задайте AISEC_DATA_DIR}/keys:/etc/aisec/keys:ro\n",
			"aisec-gateway: том"},
		"ключи сервера на запись":    {"}/keys:/etc/aisec/keys:ro", "}/keys:/etc/aisec/keys", "aisec-server: том"},
		"нет тома шлюза":             {"      - ${AISEC_DATA_DIR:?задайте AISEC_DATA_DIR}/gateway/state:/var/lib/aisec-gateway/state\n", "", "нет тома DATA/gateway/state"},
		"том в другую цель":          {"}/gateway/reg:/var/lib/aisec-gateway/reg", "}/gateway/reg:/var/lib/aisec-gateway/state", "aisec-gateway: том"},
		"секрет — мастер-ключ":       {"}/secrets/gateway-bundle-anchor.pub", "}/keys/master.key", "секрет gateway-bundle-anchor: файл DATA/keys/master.key"},
		"якорь шлюза — файл сервера": {"}/secrets/gateway-bundle-anchor.pub", "}/keys/bundle-signing.pub", "ожидается DATA/secrets/gateway-bundle-anchor.pub"},
		"секреты переставлены":       {"}/secrets/console.key\n", "}/secrets/db-server.pgpass\n", "секрет console-tls-key"},
		"чужой секрет":               {"    secrets: [db-owner-pgpass]", "    secrets: [db-owner-pgpass, console-tls-key]", "сервису не нужен"},
		"необъявленный секрет":       {"    secrets: [db-owner-pgpass]", "    secrets: [db-owner-pgpass, nope]", "не объявлен"},
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
		"тег !reset":     {"    profiles: [tools]\n", "    profiles: [tools]\n    tmpfs: !reset []\n"},
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
		problems := checkCompose(c)
		// Файл без обязательных сервисов никогда не проходит проверку.
		required := 0
		for _, r := range composeRules {
			if !r.Optional {
				required++
			}
		}
		if len(c.Services) < required && len(problems) == 0 {
			t.Fatal("неполный compose прошёл проверку")
		}
		if len(problems) > 0 {
			return
		}
		// Прошедший проверку файл: тома и секреты — ровно из правил (3В8).
		for name, s := range c.Services {
			for _, v := range s.Volumes {
				if r := composeRules[name]; !slices.Contains(r.Volumes, normVolume(v)) && !slices.Contains(r.OptionalVolumes, normVolume(v)) {
					t.Fatalf("%s: том %q вне правил прошёл проверку", name, v)
				}
			}
		}
		for name, sec := range c.Secrets {
			if f, _ := dataPath(sec.File); f != secretFiles[name] {
				t.Fatalf("секрет %s: файл %q вне правил прошёл проверку", name, sec.File)
			}
		}
	})
}
