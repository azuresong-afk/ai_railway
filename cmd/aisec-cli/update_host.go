package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/cliclient"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Исполнение шагов обновления на хосте с systemd (ADR-0036, раздел 6):
// службы, временное дополнение юнита сервера, запуск aisec-cli нового
// выпуска, проверка /readyz. Программы — по абсолютным путям, окружение —
// только нужные переменные; пароли в аргументы не попадают.

// unitState — состояние службы для проверки устойчивости.
type unitState struct {
	Active   bool
	Enabled  bool
	Restarts int
}

// updateHost — действия на хосте; в тестах — подмена.
type updateHost interface {
	// State — состояние службы; нет такой службы — не активна и не включена.
	State(ctx context.Context, unit string) (unitState, error)
	Stop(ctx context.Context, unit string) error
	Start(ctx context.Context, unit string) error
	Restart(ctx context.Context, unit string) error
	// Gate закрывает (on) или открывает приём событий сервером: временное
	// дополнение юнита с внутренним портом 127.0.0.1:0.
	Gate(ctx context.Context, on bool) error
	// PackageOwned — файлы установки числятся в dpkg или rpm.
	PackageOwned(ctx context.Context) (bool, error)
	// RunCLI запускает aisec-cli нового выпуска (миграции, проверка
	// целостности) и возвращает его вывод для администратора.
	RunCLI(ctx context.Context, exe string, args ...string) (string, error)
	// Journal — запись итога в journald там, где нет журнала аудита в БД.
	Journal(ctx context.Context, msg string) error
	// Ready — /readyz сервера отвечает 200.
	Ready(ctx context.Context) error
}

// Пути на хосте с установкой без Docker (ADR-0034).
const (
	systemctlPath   = "/usr/bin/systemctl"
	systemdCatPath  = "/usr/bin/systemd-cat"
	dpkgListPath    = "/var/lib/dpkg/info/aisec.list"
	rpmPath         = "/usr/bin/rpm"
	gateDropInDir   = "/etc/systemd/system/aisec-server.service.d"
	gateDropInFile  = "zz-aisec-update.conf"
	gateEnvDir      = "/etc/aisec"
	gateEnvFile     = "aisec-update-gate.env"
	serverEnvPath   = "/etc/aisec/aisec-server.env"
	cliEnvPath      = "/etc/aisec/aisec-cli.env"
	ownerPGPassPath = "/etc/aisec/credentials/db-owner.pgpass" //nolint:gosec // G101: путь к файлу паролей, не секрет
	healthCAPath    = "/etc/aisec/credentials/console-ca.crt"
	cmdTimeout      = 2 * time.Minute
	migrateTimeout  = 6 * time.Hour // миграции на большой БД (индексы по событиям)
	maxCmdOutput    = 64 << 10
	maxEnvFile      = 64 << 10
)

// systemdHost — исполнение на хосте с systemd.
type systemdHost struct {
	p         aisecCrypto.Provider
	env       []string // окружение запускаемых программ: PATH, строка подключения, PGPASSFILE
	healthURL string
	healthCA  string
}

func (h *systemdHost) systemctl(ctx context.Context, args ...string) (string, error) {
	return runCmd(ctx, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}, nil, systemctlPath, args...)
}

func (h *systemdHost) State(ctx context.Context, unit string) (unitState, error) {
	if !knownUnits[unit] {
		return unitState{}, errors.New("неизвестная служба")
	}
	out, err := h.systemctl(ctx, "show", "--property=ActiveState,UnitFileState,NRestarts", "--", unit+".service")
	if err != nil {
		return unitState{}, err
	}
	kv, err := parseEnvFile([]byte(out))
	if err != nil {
		return unitState{}, err
	}
	n, err := strconv.Atoi(kv["NRestarts"])
	if err != nil && kv["NRestarts"] != "" {
		return unitState{}, errors.New("systemctl: неверное NRestarts")
	}
	return unitState{Active: kv["ActiveState"] == "active", Enabled: kv["UnitFileState"] == "enabled", Restarts: n}, nil
}

func (h *systemdHost) Stop(ctx context.Context, unit string) error {
	_, err := h.systemctl(ctx, "stop", "--", unit+".service")
	return err
}

func (h *systemdHost) Start(ctx context.Context, unit string) error {
	_, err := h.systemctl(ctx, "start", "--", unit+".service")
	return err
}

func (h *systemdHost) Restart(ctx context.Context, unit string) error {
	_, err := h.systemctl(ctx, "restart", "--", unit+".service")
	return err
}

// Gate: EnvironmentFile= дополнения читается после файла юнита и других
// дополнений (имя zz-… — последнее по порядку) и переопределяет
// AISEC_SERVER_INTERNAL_LISTEN. Дополнение лежит в /etc, а не в /run:
// после перезагрузки посреди обновления сервер тоже стартует с закрытым
// приёмом; удаляет его итог или откат (журнал шагов).
func (h *systemdHost) Gate(ctx context.Context, on bool) error {
	if on {
		for _, d := range []string{gateDropInDir, gateEnvDir} {
			if err := os.MkdirAll(d, 0o755); err != nil { //nolint:gosec // G301: /etc/aisec и каталог дополнения юнита читает systemd, root 0755
				return err
			}
			if err := checkOwnedDir(d, 0o755, 0); err != nil {
				return err
			}
		}
		if err := updWriteAtomic(gateEnvDir, gateEnvFile, []byte("# Временно: приём событий закрыт на время проверки обновления (ADR-0036).\nAISEC_SERVER_INTERNAL_LISTEN=127.0.0.1:0\n"), 0o644); err != nil {
			return err
		}
		if err := updWriteAtomic(gateDropInDir, gateDropInFile, []byte("# Временно: aisec-cli update (ADR-0036), удаляется после проверки здоровья.\n[Service]\nEnvironmentFile="+filepath.Join(gateEnvDir, gateEnvFile)+"\n"), 0o644); err != nil {
			return err
		}
	} else {
		for _, f := range []string{filepath.Join(gateDropInDir, gateDropInFile), filepath.Join(gateEnvDir, gateEnvFile)} {
			if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	_, err := h.systemctl(ctx, "daemon-reload")
	return err
}

func (h *systemdHost) Journal(ctx context.Context, msg string) error {
	_, err := runCmd(ctx, []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}, strings.NewReader(msg+"\n"), systemdCatPath, "--identifier=aisec-cli-update", "--priority=notice")
	return err
}

func (h *systemdHost) PackageOwned(ctx context.Context) (bool, error) {
	if _, err := os.Lstat(dpkgListPath); err == nil {
		return true, nil
	}
	if _, err := os.Lstat(rpmPath); errors.Is(err, os.ErrNotExist) {
		return false, nil // нет rpm — не пакетная установка
	} else if err != nil {
		return false, err
	}
	_, err := runCmd(ctx, []string{"PATH=/usr/bin:/bin", "LANG=C"}, nil, rpmPath, "-q", "--quiet", "aisec")
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return false, nil
	}
	return err == nil, err
}

func (h *systemdHost) RunCLI(ctx context.Context, exe string, args ...string) (string, error) {
	if len(args) > 0 && args[0] == "migrate" {
		ctx, cancel := context.WithTimeout(ctx, migrateTimeout)
		defer cancel()
		return runCmdTimeout(ctx, 0, h.env, nil, exe, args...)
	}
	return runCmd(ctx, h.env, nil, exe, args...)
}

// Ready — GET /readyz сервера по TLS с доверием только корню healthCA.
func (h *systemdHost) Ready(ctx context.Context) error {
	return cliclient.Ready(ctx, h.p, h.healthURL, h.healthCA)
}

// healthURLFromEnv — https://<AISEC_SERVER_LISTEN>/readyz; адрес «все
// интерфейсы» заменяется петлевым.
func healthURLFromEnv(env map[string]string) (string, error) {
	listen := env["AISEC_SERVER_LISTEN"]
	if listen == "" {
		listen = "127.0.0.1:8444"
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", errors.New("AISEC_SERVER_LISTEN: ожидается адрес:порт")
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return (&url.URL{Scheme: "https", Host: net.JoinHostPort(host, port), Path: "/readyz"}).String(), nil
}

// healthURL — адрес проверки здоровья: только https без учётных данных;
// без пути — дополняется /readyz.
func healthURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("health-url: ожидается https://узел:порт без учётных данных")
	}
	switch u.Path {
	case "", "/":
		u.Path = "/readyz"
	case "/readyz":
	default:
		return "", errors.New("health-url: путь — только /readyz")
	}
	return u.String(), nil
}

// runCmd запускает программу с заданным окружением и пределом времени;
// вывод (stdout и stderr вместе) — не больше maxCmdOutput.
func runCmd(ctx context.Context, env []string, stdin io.Reader, name string, args ...string) (string, error) {
	return runCmdTimeout(ctx, cmdTimeout, env, stdin, name, args...)
}

// runCmdTimeout — runCmd со своим пределом (0 — только предел ctx).
// Дочерний процесс — в своей группе: Ctrl+C и обрыв сеанса, которые
// терминал шлёт всей группе, не убивают pg_dump, psql и миграции посреди
// шага (ADR-0036, раздел 5).
func runCmdTimeout(ctx context.Context, timeout time.Duration, env []string, stdin io.Reader, name string, args ...string) (string, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: программа — константа или проверенный по манифесту aisec-cli
	cmd.SysProcAttr = ownGroup()
	cmd.Env = env
	cmd.Stdin = stdin
	var out limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Dir = "/"
	err := cmd.Run()
	text := strings.TrimSpace(out.String())
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("%s: %w: %s", filepath.Base(name), err, lastLine(text))
		}
		return text, fmt.Errorf("%s: %w", filepath.Base(name), err)
	}
	return text, nil
}

// ownGroup — дочерний процесс в своей группе процессов.
func ownGroup() *syscall.SysProcAttr { //nolint:forbidigo // ADR-0036, раздел 6: тип атрибутов процесса
	return &syscall.SysProcAttr{Setpgid: true} //nolint:forbidigo // ADR-0036, раздел 6: своя группа процессов
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// limitedBuffer — буфер вывода с пределом: лишнее отбрасывается.
type limitedBuffer struct{ b bytes.Buffer }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxCmdOutput - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.b.String() }

// parseEnvFile разбирает файл настроек KEY=VALUE (как EnvironmentFile=
// systemd, без продолжения строк): комментарии «#» и «;», пустые строки,
// значение в одинарных или двойных кавычках. Недоверенный ввод:
// FuzzParseEnvFile.
func parseEnvFile(data []byte) (map[string]string, error) {
	if len(data) > maxEnvFile {
		return nil, errors.New("файл настроек больше предела")
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxEnvFile)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || s[0] == '#' || s[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		k = strings.TrimSpace(k)
		if !ok || !envKeyOK(k) {
			return nil, fmt.Errorf("файл настроек, строка %d: ожидается ИМЯ=значение", line)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if strings.ContainsAny(v, "\x00") {
			return nil, fmt.Errorf("файл настроек, строка %d: недопустимый символ", line)
		}
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, errors.New("файл настроек: слишком длинная строка")
	}
	return out, nil
}

func envKeyOK(k string) bool {
	if k == "" || len(k) > 128 {
		return false
	}
	for i, c := range k {
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// readSmallFile — обычный файл не больше limit.
func readSmallFile(name string, limit int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("не обычный файл или больше предела")
	}
	return os.ReadFile(name) //nolint:gosec // G304: фиксированный путь настроек или флаг администратора
}
