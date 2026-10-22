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
// роли БД видит только тот, кто под ней входит.
var composeRules = map[string]struct {
	Ports    []string
	External bool
	Product  bool
	Secrets  []string
}{
	"aisec-server":  {Ports: []string{"8444"}, External: true, Product: true, Secrets: []string{"console-tls-cert", "console-tls-key", "db-server-pgpass"}},
	"aisec-gateway": {Ports: []string{"8443"}, External: true, Product: true, Secrets: []string{"gateway-tls-cert", "gateway-tls-key", "console-ca", "bundle-signing-pub"}},
	"aisec-cli":     {Product: true, Secrets: []string{"db-owner-pgpass"}},
	"postgres":      {Secrets: []string{"db-postgres-password", "db-owner-password", "db-server-password"}},
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
	for name := range composeRules {
		if _, ok := c.Services[name]; !ok {
			add("нет сервиса %s", name)
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
		if s.Privileged || s.NetworkMode != "" || s.Pid != "" || s.Ipc != "" || s.UsernsMode != "" || len(s.Devices) > 0 {
			at("privileged, network_mode, pid, ipc, userns_mode и devices запрещены")
		}
		if s.PidsLimit <= 0 || s.MemLimit == "" {
			at("нужны pids_limit и mem_limit")
		}
		if s.Build.Kind != 0 {
			at("build запрещён: пилот ставится только из образов")
		}
		checkImageRef(name, s.Image, rule.Product, at)
		for _, v := range s.Volumes {
			src := v
			if i := strings.Index(v, "}"); strings.HasPrefix(v, "${") && i > 0 {
				src = v[:i+1] + strings.SplitN(v[i+1:], ":", 2)[0]
			} else {
				src = strings.SplitN(v, ":", 2)[0]
			}
			switch {
			case strings.Contains(src, ".."):
				at("том %q: «..» в пути", v)
			case strings.HasPrefix(src, dataDirRef):
				// Только подкаталог сервиса: не весь каталог данных и не secrets/.
				sub := src[strings.Index(src, "}")+1:]
				if !strings.HasPrefix(sub, "/") || len(sub) < 2 || strings.HasPrefix(sub, "/secrets") {
					at("том %q: только подкаталог ${AISEC_DATA_DIR}, кроме secrets/", v)
				}
			case strings.HasPrefix(src, "./") && strings.HasSuffix(v, ":ro"):
			default:
				at("том %q: только каталоги ${AISEC_DATA_DIR} или ./… только для чтения", v)
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
		if len(nets) == 0 {
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
		if s.Environment != "" || !strings.HasPrefix(s.File, dataDirRef) {
			add("секрет %s: только файл в ${AISEC_DATA_DIR}", name)
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
