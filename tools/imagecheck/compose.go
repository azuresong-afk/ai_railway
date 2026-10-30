package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Проверка compose пилота (ЗИ.5, ADR-0019) по исходному файлу, до подстановки
// переменных: правила должны держаться при любом .env. Нарушение любого
// правила — ошибка; исключений нет.

// maxCompose ограничивает размер compose-файла.
const maxCompose = 1 << 20

// Разбор строгий (KnownFields): поле, которого нет в этих структурах
// (extends, include, volumes_from, group_add, sysctls, external, name сети и
// т. п.), — ошибка разбора, а не молчаливый пропуск. Верхнего уровня
// x-расширения (якоря) собираются в Extensions.
type composeFile struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services"`
	Networks map[string]struct {
		Internal bool   `yaml:"internal"`
		Driver   string `yaml:"driver"`
	} `yaml:"networks"`
	Secrets map[string]struct {
		File        string `yaml:"file"`
		Environment string `yaml:"environment"`
	} `yaml:"secrets"`
	Extensions map[string]yaml.Node `yaml:",inline"`
}

type composeService struct {
	Image       string            `yaml:"image"`
	Build       yaml.Node         `yaml:"build"`
	User        string            `yaml:"user"`
	ReadOnly    bool              `yaml:"read_only"`
	CapDrop     []string          `yaml:"cap_drop"`
	CapAdd      []string          `yaml:"cap_add"`
	SecurityOpt []string          `yaml:"security_opt"`
	Privileged  bool              `yaml:"privileged"`
	NetworkMode string            `yaml:"network_mode"`
	Pid         string            `yaml:"pid"`
	Ipc         string            `yaml:"ipc"`
	UsernsMode  string            `yaml:"userns_mode"`
	Devices     []string          `yaml:"devices"`
	Volumes     []string          `yaml:"volumes"`
	Ports       []string          `yaml:"ports"`
	PidsLimit   int               `yaml:"pids_limit"`
	MemLimit    string            `yaml:"mem_limit"`
	Environment map[string]string `yaml:"environment"`
	Networks    yaml.Node         `yaml:"networks"`
	Secrets     []string          `yaml:"secrets"`
	Healthcheck struct {
		Test        []string `yaml:"test"`
		Interval    string   `yaml:"interval"`
		Timeout     string   `yaml:"timeout"`
		StartPeriod string   `yaml:"start_period"`
		Retries     int      `yaml:"retries"`
	} `yaml:"healthcheck"`
	// Поля без правил проверки: разрешены, но только они.
	Restart         string    `yaml:"restart"`
	Logging         yaml.Node `yaml:"logging"`
	DependsOn       yaml.Node `yaml:"depends_on"`
	Command         []string  `yaml:"command"`
	Profiles        []string  `yaml:"profiles"`
	Tmpfs           []string  `yaml:"tmpfs"`
	ShmSize         string    `yaml:"shm_size"`
	StopGracePeriod string    `yaml:"stop_grace_period"`
}

// Сервисы пилота: опубликованные порты контейнера и право на сеть с выходом
// наружу. Сервер публикует консоль, шлюз — порт приложений и ходит к
// провайдерам LLM; PostgreSQL и aisec-cli — только во внутренних сетях.
// Secrets — какие секреты сервису можно получить: пароль или passfile
// роли БД видит только тот, кто под ней входит. Volumes — точный список
// томов сервиса «источник:цель:ro|rw» (DATA — ${AISEC_DATA_DIR}): каталог
// ключей видят только сервер (только чтение) и aisec-cli, шлюз — только
// свои reg/ и state/ (3В8 ревью 3.r1).
var composeRules = map[string]struct {
	Ports    []string
	External bool
	Product  bool
	Secrets  []string
	Volumes  []string
	// OptionalVolumes — тома, которые сервису можно, но не обязательно иметь.
	OptionalVolumes []string
	// Isolated — сервис без сети вовсе (network_mode: none, ADR-0024):
	// ни одной сети, ни одного порта, связь только через том с сокетом.
	Isolated bool
	// Optional — сервиса может не быть: он приходит из дополнения compose.
	Optional bool
}{
	"aisec-server": {Ports: []string{"8444"}, External: true, Product: true,
		Secrets: []string{"console-tls-cert", "console-tls-key", "db-server-pgpass"},
		Volumes: []string{"DATA/keys:/etc/aisec/keys:ro"}},
	"aisec-gateway": {Ports: []string{"8443"}, External: true, Product: true,
		Secrets: []string{"gateway-tls-cert", "gateway-tls-key", "console-ca", "gateway-bundle-anchor"},
		Volumes: []string{"DATA/gateway/reg:/var/lib/aisec-gateway/reg:rw", "DATA/gateway/state:/var/lib/aisec-gateway/state:rw"},
		// Каталог сокета aisec-ml — только чтение: шлюз лишь подключается.
		OptionalVolumes: []string{mlRunGateway}},
	"aisec-cli": {Product: true, Secrets: []string{"db-owner-pgpass"},
		Volumes: []string{"DATA/keys:/etc/aisec/keys:rw", "DATA/backups:/var/lib/aisec/backups:rw"}},
	// Процесс ML-детекторов (ADR-0024): только сокет в общем со шлюзом
	// каталоге, модели — внутри образа. Приходит из compose.ml.yaml.
	"aisec-ml": {Product: true, Isolated: true, Optional: true, Volumes: []string{"DATA/ml/run:/run/aisec-ml:rw"}},
	"postgres": {Secrets: []string{"db-postgres-password", "db-owner-password", "db-server-password"},
		Volumes: []string{"DATA/pg:/var/lib/postgresql/data:rw", "./initdb:/docker-entrypoint-initdb.d:ro"}},
}

// Подключение шлюза к aisec-ml (compose.ml.yaml): том каталога сокета и путь
// сокета в окружении шлюза.
const (
	mlRunGateway  = "DATA/ml/run:/run/aisec-ml:ro"
	mlSocketEnv   = "AISEC_GATEWAY_ML_SOCKET"
	mlSocketValue = "/run/aisec-ml/aisec-ml.sock"
)

// secretFiles — файл каждого секрета (DATA — ${AISEC_DATA_DIR}). Якорь
// проверки пакетов шлюза — своя копия в secrets/, не файл каталога ключей
// сервера: её замена при компрометации не трогает якорь сервера (3В6, 3В8
// ревью 3.r1).
var secretFiles = map[string]string{
	"console-tls-cert":      "DATA/secrets/console.crt",
	"console-tls-key":       "DATA/secrets/console.key",
	"console-ca":            "DATA/secrets/console-ca.crt",
	"gateway-tls-cert":      "DATA/secrets/gateway.crt",
	"gateway-tls-key":       "DATA/secrets/gateway.key",
	"gateway-bundle-anchor": "DATA/secrets/gateway-bundle-anchor.pub",
	"db-postgres-password":  "DATA/secrets/db-postgres-password",
	"db-owner-password":     "DATA/secrets/db-owner-password",
	"db-server-password":    "DATA/secrets/db-server-password",
	"db-owner-pgpass":       "DATA/secrets/db-owner.pgpass",
	"db-server-pgpass":      "DATA/secrets/db-server.pgpass",
}

// dataPath заменяет ведущее ${AISEC_DATA_DIR:?…} на DATA; ok = false — путь
// не начинается с него.
// mlFixedPaths — флаги aisec-ml с путями выпуска (4В23): каталог моделей,
// манифест и библиотека ONNX Runtime — только из образа, иначе старый
// подписанный пакет моделей подкладывается в обход привязки к выпуску.
var mlFixedPaths = []string{"models", "manifest", "ort-lib"}

func dataPath(p string) (string, bool) {
	if !strings.HasPrefix(p, dataDirRef) {
		return p, false
	}
	i := strings.Index(p, "}")
	if i < 0 {
		return p, false
	}
	return "DATA" + p[i+1:], true
}

// normVolume — том в виде «источник:цель:ro|rw» с DATA вместо
// ${AISEC_DATA_DIR:?…}; режим по умолчанию — rw.
func normVolume(v string) string {
	src, _ := dataPath(v)
	parts := strings.Split(src, ":")
	if len(parts) == 2 {
		parts = append(parts, "rw")
	}
	return strings.Join(parts, ":")
}

var (
	// userRe — пользователь и группа из обязательных переменных ${ИМЯ:?…}: пустым
	// оно не бывает, поэтому сервис не запустится от root «по умолчанию».
	userRe     = regexp.MustCompile(`^\$\{[A-Z0-9_]+:\?[^}]*\}:\$\{[A-Z0-9_]+:\?[^}]*\}$`)
	varRe      = regexp.MustCompile(`\$\{[^}]*\}`)
	defaultRe  = regexp.MustCompile(`^\$\{[A-Z0-9_]+:-([^}]*)\}`)
	digestRe   = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	bindLocal  = regexp.MustCompile(`^\$\{[A-Z0-9_]+:-127\.0\.0\.1\}:`)
	secretName = regexp.MustCompile(`(?i)(password|passwd|secret|token|key)`)
	dataDirRef = "${AISEC_DATA_DIR:?"
)

// parseCompose разбирает compose-файл: YAML с якорями и слиянием «<<».
func parseCompose(data []byte) (*composeFile, error) {
	if len(data) > maxCompose {
		return nil, fmt.Errorf("compose больше %d байт", maxCompose)
	}
	if err := checkTags(data); err != nil {
		return nil, fmt.Errorf("разбор compose: %w", err)
	}
	var c composeFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("разбор compose: %w", err)
	}
	for k := range c.Extensions {
		if !strings.HasPrefix(k, "x-") {
			return nil, fmt.Errorf("разбор compose: неизвестный ключ верхнего уровня %q", k)
		}
	}
	return &c, nil
}

// checkTags отвергает теги YAML, кроме стандартных (!!str, !!map, …):
// docker compose понимает свои теги (!override, !reset), которые меняют
// слияние файлов — проверка видела бы объединение, а docker — замену.
func checkTags(data []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	var walk func(n *yaml.Node) error
	walk = func(n *yaml.Node) error {
		if n.Tag != "" && !strings.HasPrefix(n.Tag, "!!") {
			return fmt.Errorf("строка %d: тег YAML %s запрещён", n.Line, n.Tag)
		}
		for _, c := range n.Content {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(&root)
}

// composeOverlay — дополнение compose (compose.ml.yaml): новые сервисы целиком,
// а существующим — только зависимости, окружение и тома.
type composeOverlay struct {
	Services map[string]yaml.Node `yaml:"services"`
}

// overlayPatch — что дополнение может добавить существующему сервису.
type overlayPatch struct {
	DependsOn   map[string]yaml.Node `yaml:"depends_on"`
	Environment map[string]string    `yaml:"environment"`
	Volumes     []string             `yaml:"volumes"`
}

// strictDecode разбирает узел YAML так же строго, как файл: неизвестное поле
// — ошибка.
func strictDecode(n *yaml.Node, v any) error {
	data, err := yaml.Marshal(n)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(v)
}

// applyOverlay накладывает дополнение на разобранный compose так же, как
// docker compose -f основной -f дополнение: окружение и тома добавляются,
// зависимости объединяются. Переопределять переменную основного файла
// дополнению нельзя: проверка не должна зависеть от порядка файлов.
func applyOverlay(c *composeFile, data []byte) error {
	if len(data) > maxCompose {
		return fmt.Errorf("дополнение compose больше %d байт", maxCompose)
	}
	if err := checkTags(data); err != nil {
		return fmt.Errorf("разбор дополнения compose: %w", err)
	}
	var o composeOverlay
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&o); err != nil {
		return fmt.Errorf("разбор дополнения compose: %w", err)
	}
	names := make([]string, 0, len(o.Services))
	for name := range o.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		node := o.Services[name]
		base, ok := c.Services[name]
		if !ok {
			var s composeService
			if err := strictDecode(&node, &s); err != nil {
				return fmt.Errorf("дополнение compose, сервис %s: %w", name, err)
			}
			if c.Services == nil {
				c.Services = map[string]composeService{}
			}
			c.Services[name] = s
			continue
		}
		var p overlayPatch
		if err := strictDecode(&node, &p); err != nil {
			return fmt.Errorf("дополнение compose, сервис %s: только depends_on, environment и volumes: %w", name, err)
		}
		for k, v := range p.Environment {
			if _, dup := base.Environment[k]; dup {
				return fmt.Errorf("дополнение compose, сервис %s: переменная %s уже задана", name, k)
			}
			if base.Environment == nil {
				base.Environment = map[string]string{}
			}
			base.Environment[k] = v
		}
		base.Volumes = append(base.Volumes, p.Volumes...)
		for dep := range p.DependsOn {
			if _, ok := o.Services[dep]; !ok {
				if _, ok := c.Services[dep]; !ok {
					return fmt.Errorf("дополнение compose, сервис %s: зависимость от неизвестного сервиса %s", name, dep)
				}
			}
		}
		c.Services[name] = base
	}
	return nil
}

// serviceNetworks — сети сервиса: список или отображение «сеть: настройки».
func serviceNetworks(n yaml.Node) ([]string, error) {
	switch n.Kind {
	case 0:
		return nil, nil
	case yaml.SequenceNode:
		var out []string
		if err := n.Decode(&out); err != nil {
			return nil, err
		}
		return out, nil
	case yaml.MappingNode:
		var out []string
		for i := 0; i+1 < len(n.Content); i += 2 {
			out = append(out, n.Content[i].Value)
		}
		return out, nil
	}
	return nil, errors.New("networks: ожидается список или отображение")
}

// checkCompose возвращает нарушения правил.
func checkCompose(c *composeFile) []string {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	for name, rule := range composeRules {
		if _, ok := c.Services[name]; !ok && !rule.Optional {
			add("нет сервиса %s", name)
		}
	}
	// Шлюз подключён к aisec-ml тогда и только тогда, когда aisec-ml есть:
	// иначе сокет либо некому открыть, либо шлюз о нём не знает.
	if gw, ok := c.Services["aisec-gateway"]; ok {
		_, hasML := c.Services["aisec-ml"]
		vol := slices.ContainsFunc(gw.Volumes, func(v string) bool { return normVolume(v) == mlRunGateway })
		env, hasEnv := gw.Environment[mlSocketEnv]
		switch {
		case hasML && (!vol || env != mlSocketValue):
			add("aisec-gateway: с aisec-ml нужны том %s и %s=%s", mlRunGateway, mlSocketEnv, mlSocketValue)
		case !hasML && (vol || hasEnv):
			add("aisec-gateway: том %s и %s — только вместе с сервисом aisec-ml", mlRunGateway, mlSocketEnv)
		}
	}
	for name, s := range c.Services {
		rule, ok := composeRules[name]
		if !ok {
			add("%s: неизвестный сервис", name)
			continue
		}
		at := func(format string, a ...any) { add(name+": "+format, a...) }
		if !s.ReadOnly {
			at("нужен read_only: true")
		}
		if !slices.Contains(s.CapDrop, "ALL") {
			at("нужен cap_drop: [ALL]")
		}
		if len(s.CapAdd) > 0 {
			at("cap_add запрещён: %v", s.CapAdd)
		}
		if !slices.Equal(s.SecurityOpt, []string{"no-new-privileges:true"}) {
			at("security_opt: ровно [no-new-privileges:true], получено %v", s.SecurityOpt)
		}
		for _, sec := range s.Secrets {
			if _, ok := c.Secrets[sec]; !ok {
				at("секрет %s не объявлен", sec)
			}
			if !slices.Contains(rule.Secrets, sec) {
				at("секрет %s сервису не нужен (разрешены %v)", sec, rule.Secrets)
			}
		}
		if !userRe.MatchString(s.User) {
			at("user %q — нужен «${UID:?…}:${GID:?…}» отдельного пользователя хоста", s.User)
		}
		isolatedOK := rule.Isolated && s.NetworkMode == "none"
		if s.Privileged || (s.NetworkMode != "" && !isolatedOK) || s.Pid != "" || s.Ipc != "" || s.UsernsMode != "" || len(s.Devices) > 0 {
			at("privileged, network_mode, pid, ipc, userns_mode и devices запрещены")
		}
		if rule.Isolated && !isolatedOK {
			at("нужен network_mode: none: сервису сеть не нужна")
		}
		if s.PidsLimit <= 0 || s.MemLimit == "" {
			at("нужны pids_limit и mem_limit")
		}
		if s.Build.Kind != 0 {
			at("build запрещён: пилот ставится только из образов")
		}
		checkImageRef(name, s.Image, rule.Product, at)
		var vols []string
		for _, v := range s.Volumes {
			n := normVolume(v)
			vols = append(vols, n)
			switch {
			case strings.Contains(v, ".."):
				at("том %q: «..» в пути", v)
			case !slices.Contains(rule.Volumes, n) && !slices.Contains(rule.OptionalVolumes, n):
				at("том %q: не из списка сервиса %v (источник, цель и режим ro/rw)", v, slices.Concat(rule.Volumes, rule.OptionalVolumes))
			}
		}
		for _, want := range rule.Volumes {
			if !slices.Contains(vols, want) {
				at("нет тома %s", want)
			}
		}
		for _, p := range s.Ports {
			flat := varRe.ReplaceAllString(p, "X")
			parts := strings.Split(flat, ":")
			switch {
			case len(parts) != 3:
				at("порт %q: нужен «адрес:порт:порт контейнера» — без адреса docker слушает все интерфейсы", p)
			case !bindLocal.MatchString(p):
				at("порт %q: адрес по умолчанию — 127.0.0.1", p)
			case !slices.Contains(rule.Ports, parts[2]):
				at("порт %q: публиковать можно только %v", p, rule.Ports)
			}
		}
		// Переменные загрузчика (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH…) подменяют
		// код динамического aisec-ml в обход хеша библиотеки и манифеста.
		for k := range s.Environment {
			if strings.HasPrefix(strings.ToUpper(k), "LD_") {
				at("переменная %s: переменные загрузчика запрещены", k)
			}
		}
		if name == "aisec-ml" {
			for k := range s.Environment {
				if !strings.HasPrefix(k, "AISEC_ML_") || k == "AISEC_ML_INTEGRITY_ACTION" {
					at("переменная %s: у aisec-ml разрешены только AISEC_ML_*, кроме AISEC_ML_INTEGRITY_ACTION (ослабление самопроверки)", k)
				}
				if slices.Contains(mlFixedPaths, strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(k, "AISEC_ML_"), "_", "-"))) {
					at("переменная %s: пути выпуска aisec-ml (модели, манифест, ONNX Runtime) задаёт образ", k)
				}
			}
			for _, a := range s.Command {
				flagName, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
				switch {
				case flagName == "integrity-action":
					at("аргумент %q: ослабление самопроверки aisec-ml запрещено", a)
				case slices.Contains(mlFixedPaths, flagName):
					at("аргумент %q: пути выпуска aisec-ml (модели, манифест, ONNX Runtime) задаёт образ", a)
				}
			}
		}
		for k, v := range s.Environment {
			val := v
			if m := defaultRe.FindStringSubmatch(v); m != nil {
				val = m[1]
			}
			if secretName.MatchString(k) && !strings.HasSuffix(k, "_FILE") {
				at("переменная %s: секреты — только файлами (secrets), не в окружении", k)
			}
			if strings.Contains(val, "://") {
				u, err := url.Parse(val)
				switch {
				case err != nil:
					at("переменная %s: неразбираемый адрес", k)
				case u.Scheme != "postgres" && u.Scheme != "postgresql":
					at("переменная %s: внешний адрес %s://… запрещён", k, u.Scheme)
				default:
					if _, has := u.User.Password(); has {
						at("переменная %s: пароль в строке подключения — только passfile", k)
					}
				}
			}
		}
		for _, t := range s.Healthcheck.Test {
			if strings.Contains(t, "://") || strings.Contains(t, "curl") || strings.Contains(t, "wget") {
				at("healthcheck %q: только локальная проверка без сетевых клиентов", t)
			}
		}
		nets, err := serviceNetworks(s.Networks)
		if err != nil {
			at("%v", err)
		}
		switch {
		case rule.Isolated && len(nets) > 0:
			at("сети запрещены: сервис работает без сети (network_mode: none)")
		case !rule.Isolated && len(nets) == 0:
			at("нужны явные сети (сеть по умолчанию имеет выход наружу)")
		}
		external := 0
		for _, n := range nets {
			def, ok := c.Networks[n]
			if !ok {
				at("сеть %s не объявлена", n)
				continue
			}
			if !def.Internal {
				external++
			}
		}
		if external > 0 && !rule.External {
			at("только внутренние сети (internal: true): сервису не нужен выход наружу")
		}
		if external > 1 {
			at("не больше одной сети с выходом наружу")
		}
	}
	for name, s := range c.Secrets {
		file, inData := dataPath(s.File)
		want, known := secretFiles[name]
		switch {
		case s.Environment != "" || !inData:
			add("секрет %s: только файл в ${AISEC_DATA_DIR}", name)
		case !known:
			add("секрет %s: неизвестный секрет", name)
		case file != want:
			add("секрет %s: файл %s, ожидается %s", name, file, want)
		}
	}
	sort.Strings(problems)
	return problems
}

// checkImageRef: свой образ — ${AISEC_IMAGE_REPO…}/<сервис>:${AISEC_VERSION…},
// чужой — закреплён по digest (ТЗ 8.7).
func checkImageRef(name, ref string, product bool, at func(string, ...any)) {
	if product {
		want := regexp.MustCompile(`^\$\{AISEC_IMAGE_REPO:-aisec\}/` + regexp.QuoteMeta(name) + `:\$\{AISEC_VERSION:\?[^}]*\}$`)
		if !want.MatchString(ref) {
			at("образ %q: ожидается ${AISEC_IMAGE_REPO:-aisec}/%s:${AISEC_VERSION:?…}", ref, name)
		}
		return
	}
	if !digestRe.MatchString(ref) {
		at("образ %q: сторонний образ закрепляется по digest", ref)
	}
}
