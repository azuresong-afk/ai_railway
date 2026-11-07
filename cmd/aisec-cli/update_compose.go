package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/cliclient"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// Обновление установки в docker compose (задача 6.21, ADR-0036, раздел 7):
// тот же aisec-cli update, те же шаги, журнал и откат; меняются только
// реализации «выпуска» (образы docker из подписанного каталога вместо
// каталогов версий) и «служб» (сервисы docker compose вместо юнитов
// systemd). Работает на хосте от root: копия aisec-cli установленной
// версии, извлечённая из её образа сценарием update.sh.

const (
	// updateHostCompose — значение AISEC_UPDATE_HOST для compose.
	updateHostCompose = "compose"
	// composeServiceDB — сервис PostgreSQL установки.
	composeServiceDB = "postgres"
	// composeCLIService — служебный сервис aisec-cli (профиль tools).
	composeCLIService = "aisec-cli"
	// composeGateEnv — переменная, которой compose.yaml задаёт внутренний
	// адрес сервера для шлюзов; значение 127.0.0.1:0 закрывает приём.
	composeGateEnv   = "AISEC_SERVER_INTERNAL_LISTEN"
	composeGateValue = "127.0.0.1:0"
	// composeStagingPref — копии архивов образов в каталоге обновления.
	composeStagingPref = "images-"
	composeStateDir    = "/var/lib/aisec/update"
	dockerRmTimeout    = 5 * time.Minute
	dockerLoadTimeout  = 30 * time.Minute
)

var (
	composeBinaries = []string{"/usr/bin/docker", "/usr/local/bin/docker"}
	// dockerTagRe — допустимый тег образа.
	dockerTagRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
	containerRe = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
)

// ---- Запуск docker ----

// dockerCall — один вызов docker (compose — первым аргументом).
type dockerCall struct {
	Args    []string
	Env     []string // переменные compose поверх чистого окружения
	Stdin   io.Reader
	Stdout  io.Writer // не nil — вывод пишется сюда, а не возвращается
	Timeout time.Duration
}

// dockerRunner — запуск docker; в тестах — подделка.
type dockerRunner interface {
	Run(ctx context.Context, c dockerCall) (string, error)
}

// execDocker запускает настоящий docker в каталоге установки с чистым
// окружением: переменные AISEC_* из окружения root не должны переопределять
// .env (docker compose берёт окружение раньше .env).
type execDocker struct {
	bin string
	dir string
}

func findDocker() (string, error) {
	for _, b := range composeBinaries {
		if info, err := os.Stat(b); err == nil && info.Mode().IsRegular() {
			return b, nil
		}
	}
	return "", errors.New("docker не найден (ожидается /usr/bin/docker или /usr/local/bin/docker)")
}

func (d *execDocker) Run(ctx context.Context, c dockerCall) (string, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = cmdTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, d.bin, c.Args...) //nolint:gosec // G204: программа — найденный docker, аргументы собирает aisec-cli (имена сервисов и образов проверены)
	cmd.SysProcAttr = ownGroup()
	cmd.Dir = d.dir
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin", "HOME=/root", "LANG=C.UTF-8"}, c.Env...)
	cmd.Stdin = c.Stdin
	var out, errOut limitedBuffer
	if c.Stdout != nil {
		cmd.Stdout = c.Stdout
	} else {
		cmd.Stdout = &out
	}
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		text := strings.TrimSpace(errOut.String())
		if text == "" {
			text = strings.TrimSpace(out.String())
		}
		return out.String(), fmt.Errorf("docker %s: %w: %s", firstArgs(c.Args), err, lastLine(text))
	}
	return strings.TrimSpace(out.String()), nil
}

// firstArgs — начало команды для сообщения об ошибке, без значений.
func firstArgs(args []string) string {
	n := min(len(args), 2)
	return strings.Join(args[:n], " ")
}

// ---- Настройки установки (.env) ----

// composeEnv — .env установки.
type composeEnv struct {
	path string
	data []byte
	vals map[string]string
}

func readComposeEnv(file string) (*composeEnv, error) {
	data, err := readSmallFile(file, maxEnvFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	vals, err := parseEnvFile(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return &composeEnv{path: file, data: data, vals: vals}, nil
}

func (e *composeEnv) version() string { return e.vals["AISEC_VERSION"] }

func (e *composeEnv) repo() string {
	if r := e.vals["AISEC_IMAGE_REPO"]; r != "" {
		return r
	}
	return "aisec"
}

// suffix — суффикс тега: сборка с тестовым ключом называется ВЕРСИЯ-test.
func (e *composeEnv) suffix() (string, error) {
	switch e.repo() {
	case "aisec":
		return "", nil
	case "aisec-test":
		return "-test", nil
	}
	return "", fmt.Errorf("AISEC_IMAGE_REPO: ожидается aisec или aisec-test, а не %s", shortName(e.repo()))
}

// withVersion — .env с AISEC_VERSION=tag: строка заменяется, остальные
// остаются как были; нет строки — добавляется.
func (e *composeEnv) withVersion(tag string) ([]byte, error) {
	if !dockerTagRe.MatchString(tag) {
		return nil, errors.New("версия не годится для тега образа")
	}
	return e.withVar("AISEC_VERSION", tag), nil
}

// withGate — .env с закрытым приёмом событий (AISEC_SERVER_INTERNAL_LISTEN)
// или без него. Закрытие хранится в .env, а не только в команде созданного
// контейнера: тогда любой запуск сервера посреди обновления, в том числе
// docker compose up -d после перезагрузки хоста, приём не откроет.
func (e *composeEnv) withGate(on bool) []byte {
	if on {
		return e.withVar(composeGateEnv, composeGateValue)
	}
	return e.withVar(composeGateEnv, "")
}

// withVar — .env со значением переменной key: каждая строка заменяется
// (последняя из повторов побеждает при чтении, поэтому заменяются все), нет строки — добавляется; пустое значение удаляет
// строку. Остальные строки и комментарии остаются как были.
func (e *composeEnv) withVar(key, value string) []byte {
	var out bytes.Buffer
	replaced := false
	for _, line := range strings.SplitAfter(string(e.data), "\n") {
		if line == "" {
			continue
		}
		k, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == key {
			if value != "" {
				out.WriteString(key + "=" + value + "\n")
			}
			replaced = true
			continue
		}
		out.WriteString(line)
	}
	if !replaced && value != "" {
		if out.Len() > 0 && !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
			out.WriteByte('\n')
		}
		out.WriteString(key + "=" + value + "\n")
	}
	return out.Bytes()
}

// writeComposeEnv записывает .env атомарно с прежними правами.
func writeComposeEnv(path string, data []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return updWriteAtomic(filepath.Dir(path), filepath.Base(path), data, info.Mode().Perm())
}

// ---- Операции над docker и compose ----

// composeSys — смысловые операции над docker и docker compose.
type composeSys struct {
	r        dockerRunner
	stateDir string
	services []string // активные сервисы (профили), кэш
}

func (c *composeSys) docker(ctx context.Context, args ...string) (string, error) {
	return c.r.Run(ctx, dockerCall{Args: args})
}

func (c *composeSys) compose(ctx context.Context, env []string, args ...string) (string, error) {
	return c.r.Run(ctx, dockerCall{Args: append([]string{"compose"}, args...), Env: env})
}

// activeServices — сервисы установки с учётом COMPOSE_FILE и
// COMPOSE_PROFILES из .env.
func (c *composeSys) activeServices(ctx context.Context) ([]string, error) {
	if c.services != nil {
		return c.services, nil
	}
	out, err := c.compose(ctx, nil, "config", "--services")
	if err != nil {
		return nil, err
	}
	svc := []string{}
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			svc = append(svc, l)
		}
	}
	c.services = svc
	return svc, nil
}

// container — состояние контейнера сервиса.
func (c *composeSys) container(ctx context.Context, svc string) (exists, running bool, restarts int, err error) {
	out, err := c.compose(ctx, nil, "ps", "-a", "-q", svc)
	if err != nil {
		return false, false, 0, err
	}
	id, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	if id == "" {
		return false, false, 0, nil
	}
	if !containerRe.MatchString(id) {
		return false, false, 0, errors.New("docker compose ps: неожиданный идентификатор контейнера")
	}
	st, err := c.docker(ctx, "inspect", "--format", "{{.State.Running}} {{.RestartCount}}", id)
	if err != nil {
		return false, false, 0, err
	}
	f := strings.Fields(st)
	if len(f) != 2 {
		return false, false, 0, errors.New("docker inspect: неожиданный ответ")
	}
	n, err := strconv.Atoi(f[1])
	if err != nil {
		return false, false, 0, errors.New("docker inspect: неверный RestartCount")
	}
	return true, f[0] == "true", n, nil
}

func (c *composeSys) imageExists(ctx context.Context, ref string) (bool, error) {
	out, err := c.docker(ctx, "image", "inspect", "--format", "{{.Id}}", ref)
	if err != nil {
		if strings.Contains(err.Error(), "No such image") || strings.Contains(out, "No such image") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *composeSys) removeImage(ctx context.Context, ref string) error {
	ok, err := c.imageExists(ctx, ref)
	if err != nil || !ok {
		return err
	}
	_, err = c.r.Run(ctx, dockerCall{Args: []string{"rmi", ref}, Timeout: dockerRmTimeout})
	return err
}

// imageFile читает файл из образа: контейнер создаётся, но не запускается.
func (c *composeSys) imageFile(ctx context.Context, ref, file string, limit int64) ([]byte, error) {
	id, err := c.docker(ctx, "create", "--pull", "never", ref)
	if err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	if !containerRe.MatchString(id) {
		return nil, errors.New("docker create: неожиданный идентификатор контейнера")
	}
	defer c.docker(context.WithoutCancel(ctx), "rm", id) //nolint:errcheck,gosec // G104: временный контейнер, ошибка уборки не меняет итога
	tmp, err := os.MkdirTemp(c.stateDir, ".img-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp) //nolint:errcheck // временный каталог
	if _, err := c.docker(ctx, "cp", "-q", id+":"+file, tmp+"/"); err != nil {
		return nil, err
	}
	return readSmallFile(filepath.Join(tmp, path.Base(file)), limit)
}

// ---- Выпуск compose ----

// composeImage — образ выпуска: архив на носителе и что в нём обязано быть.
type composeImage struct {
	Spec imageSpec
	Tar  string // путь архива относительно каталога выпуска
	Size int64
}

// composeRelease — образы выпуска.
type composeRelease struct {
	Images []composeImage
	Media  *releaseInfo // выпуск aisec-media из подкаталога media/, если есть
	Tag    string
}

// ---- Раскладка ----

// composeLayout — установка в docker compose как раскладка обновления.
type composeLayout struct {
	sys      *composeSys
	p        aisecCrypto.Provider
	dir      string // каталог установки: compose.yaml и .env
	stateDir string
	ownerUID int
	// rootDir — каталог данных docker для проверки места; пусто — спросить.
	rootDir string
}

func (l *composeLayout) env() (*composeEnv, error) {
	e, err := readComposeEnv(filepath.Join(l.dir, ".env"))
	if err != nil {
		return nil, err
	}
	if _, err := e.suffix(); err != nil {
		return nil, err
	}
	return e, nil
}

func (l *composeLayout) tagOf(e *composeEnv, version string) (string, error) {
	suf, err := e.suffix()
	if err != nil {
		return "", err
	}
	tag := version + suf
	if !dockerTagRe.MatchString(tag) {
		return "", errors.New("версия выпуска не годится для тега образа")
	}
	return tag, nil
}

// tagFromID — тег образов по идентификатору выпуска «версия-12 знаков».
func (l *composeLayout) tagFromID(e *composeEnv, id string) (string, error) {
	if len(id) <= 13 || id[len(id)-13] != '-' {
		return "", errors.New("версия выпуска не годится для тега образа")
	}
	return l.tagOf(e, id[:len(id)-13])
}

func (l *composeLayout) ref(e *composeEnv, name, tag string) string {
	return e.repo() + "/" + name + ":" + tag
}

func (l *composeLayout) checkDirs() error {
	if err := checkOwnedDir(l.dir, 0o755, l.ownerUID); err != nil {
		return fmt.Errorf("каталог установки: %w", err)
	}
	for _, f := range []string{".env", "compose.yaml"} {
		info, err := os.Lstat(filepath.Join(l.dir, f))
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s: не обычный файл или права допускают запись группе и остальным", f)
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != l.ownerUID { //nolint:forbidigo // ADR-0036, раздел 6: владелец из результата Lstat
			return fmt.Errorf("%s: владелец — не root", f)
		}
	}
	return nil
}

func (l *composeLayout) installed() (string, bool, error) {
	rel, err := l.installedRelease(l.p)
	if err != nil {
		return "", false, err
	}
	return rel.ID, false, nil
}

// installedRelease — манифест из образа aisec-cli установленной версии
// (AISEC_VERSION): подпись проверяется тем же ключом, что и у нового выпуска.
func (l *composeLayout) installedRelease(p aisecCrypto.Provider) (*releaseInfo, error) {
	e, err := l.env()
	if err != nil {
		return nil, err
	}
	tag := e.version()
	if !dockerTagRe.MatchString(tag) {
		return nil, errors.New("в .env нет AISEC_VERSION установленной версии")
	}
	ctx := context.Background()
	ref := l.ref(e, "aisec-cli", tag)
	data, err := l.sys.imageFile(ctx, ref, "/"+imgInstall+"/"+integrity.ManifestFile, integrity.MaxManifestSize)
	if err != nil {
		return nil, fmt.Errorf("образ %s: %w", ref, err)
	}
	sig, err := l.sys.imageFile(ctx, ref, "/"+imgInstall+"/"+integrity.SignatureFile, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("образ %s: %w", ref, err)
	}
	rel, err := parseSignedManifest(p, data, sig)
	if err != nil {
		return nil, fmt.Errorf("образ %s: %w", ref, err)
	}
	if want, err := l.tagOf(e, rel.Manifest.Version); err != nil || want != tag {
		return nil, fmt.Errorf("образ %s: версия манифеста %s не соответствует AISEC_VERSION", ref, shortName(rel.Manifest.Version))
	}
	return rel, nil
}

func (l *composeLayout) spaceDir() string { return l.stateDir }

func (l *composeLayout) needSpace(rel *releaseInfo) []spaceNeed {
	var sum, biggest int64
	if rel.Compose != nil {
		for _, im := range rel.Compose.Images {
			sum += im.Size
			biggest = max(biggest, im.Size)
		}
	}
	root := l.rootDir
	if root == "" {
		root = "/var/lib/docker"
		if out, err := l.sys.docker(context.Background(), "info", "--format", "{{.DockerRootDir}}"); err == nil && filepath.IsAbs(out) {
			root = out
		}
	}
	// Копия одного архива в каталоге обновления и все образы у docker.
	return []spaceNeed{{Dir: l.stateDir, Bytes: biggest + spaceMargin}, {Dir: root, Bytes: sum + spaceMargin}}
}

func (l *composeLayout) units(*releaseInfo) []string {
	units := []string{unitGateway, unitServer}
	if svc, err := l.sys.activeServices(context.Background()); err == nil && slices.Contains(svc, unitMedia) {
		units = append(units, unitMedia)
	}
	return units
}

func (l *composeLayout) stageText(id string) string {
	return fmt.Sprintf("Загрузка образов выпуска %s со сверкой хешей…", id)
}

func (l *composeLayout) cliPath(id string) string { return "docker:aisec-cli:" + id }

func (l *composeLayout) link() string { return "" }

func (l *composeLayout) adopt(string) error { return nil }

// prepare — проверки выпуска для установки (только чтение): настройки,
// состав сервисов, возможность закрыть приём событий, образы выпуска
// (подпись, составы и хеши) до любой загрузки.
func (l *composeLayout) prepare(ctx context.Context, p aisecCrypto.Provider, rel, cur *releaseInfo) error {
	e, err := l.env()
	if err != nil {
		return err
	}
	if _, set := e.vals[composeGateEnv]; set {
		return fmt.Errorf("в .env задана %s: переменную ставит только aisec-cli update на время обновления; удалите строку и пересоздайте сервер (docker compose up -d --force-recreate aisec-server), затем повторите", composeGateEnv)
	}
	tag, err := l.tagOf(e, rel.Manifest.Version)
	if err != nil {
		return rejected(err)
	}
	if tag == e.version() {
		return rejected(fmt.Errorf("образы версии %s уже установлены, а манифест другой: у каждого выпуска должна быть своя версия", shortName(tag)))
	}
	if err := l.checkVendorKey(p, e); err != nil {
		return err
	}
	svc, err := l.sys.activeServices(ctx)
	if err != nil {
		return err
	}
	switch {
	case !slices.Contains(svc, composeServiceDB):
		return errors.New("своя СУБД заказчика: aisec-cli update копирует БД сервисом postgres установки; обновляйте по руководству вручную (копия БД средствами СУБД, verify-release.sh)")
	case !slices.Contains(svc, unitServer) || !slices.Contains(svc, unitGateway):
		return errors.New("в установке нет сервисов aisec-server и aisec-gateway")
	case slices.Contains(svc, unitML):
		return errors.New("в установке включён aisec-ml: его образ проверяется вручную (README.md, «ML-детекторы»); aisec-cli update его не обновляет")
	}
	if err := l.checkGate(ctx); err != nil {
		return err
	}
	cr, err := l.releaseImages(p, e, rel, tag, slices.Contains(svc, unitMedia))
	if err != nil {
		return err
	}
	rel.Compose = cr
	// Образы читаются с носителя без записи: подпись выпуска уже проверена,
	// здесь — составы и хеши слоёв (stage повторит это для копии).
	src, err := os.OpenRoot(rel.Dir)
	if err != nil {
		return err
	}
	defer src.Close() //nolint:errcheck // каталог только читается
	for _, im := range cr.Images {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := verifyImageArchive(p, func() (*os.File, error) { return src.Open(im.Tar) }, im.Spec); err != nil {
			return rejected(fmt.Errorf("образ %s: %w", im.Spec.Name, err))
		}
	}
	return nil
}

// checkVendorKey — отпечаток ключа в установленном aisec-cli совпадает с
// опубликованным производителем (AISEC_VENDOR_FINGERPRINT, ADR-0022).
func (l *composeLayout) checkVendorKey(p aisecCrypto.Provider, e *composeEnv) error {
	fp, _, err := integrity.EmbeddedFingerprint(p)
	if err != nil {
		return err
	}
	want := strings.ToLower(e.vals["AISEC_VENDOR_FINGERPRINT"])
	switch {
	case want == "" && e.repo() == "aisec":
		return errors.New("в .env нет AISEC_VENDOR_FINGERPRINT — отпечатка ключа производителя из руководства установки")
	case want != "" && want != fp:
		return fmt.Errorf("подпись проверяется ключом с отпечатком %s, а в руководстве (AISEC_VENDOR_FINGERPRINT) — %s: это не ключ производителя", fp, shortName(want))
	}
	return nil
}

// checkGate: compose.yaml установки умеет закрывать приём событий. Старый
// файл (без AISEC_SERVER_INTERNAL_LISTEN) молча оставил бы приём открытым, и
// откат с восстановлением БД стёр бы принятые события.
func (l *composeLayout) checkGate(ctx context.Context) error {
	out, err := l.sys.compose(ctx, []string{composeGateEnv + "=" + composeGateValue}, "config")
	if err != nil {
		return err
	}
	if !strings.Contains(out, "-internal-listen="+composeGateValue) {
		return errors.New("compose.yaml установки не закрывает приём событий на время обновления (нет " + composeGateEnv + "): замените файлы установки файлами из поставки, сохранив .env")
	}
	return nil
}

// releaseImages: архивы образов выпуска и подкаталог media/.
func (l *composeLayout) releaseImages(p aisecCrypto.Provider, e *composeEnv, rel *releaseInfo, tag string, mediaOn bool) (*composeRelease, error) {
	root, err := os.OpenRoot(rel.Dir)
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck // каталог только читается
	cr := &composeRelease{Tag: tag}
	var all []string
	for _, e := range rel.Manifest.Files {
		if e.Kind == integrity.KindBinary {
			all = append(all, path.Base(e.Path))
		}
	}
	specs := []imageSpec{
		{Name: "aisec-server", Rel: rel, Bins: []string{"aisec-server"}, Ports: []string{"8444/tcp", "8445/tcp"}},
		{Name: "aisec-gateway", Rel: rel, Bins: []string{"aisec-gateway"}, Ports: []string{"8443/tcp"}},
		{Name: composeCLIService, Rel: rel, Bins: all},
	}
	tars := []string{"images/aisec-server.tar", "images/aisec-gateway.tar", "images/aisec-cli.tar"}
	if info, err := root.Lstat("media"); err == nil {
		if !info.IsDir() {
			return nil, rejected(errors.New("media — не каталог (ссылка или файл)"))
		}
		media, err := readManifestPair(p, filepath.Join(rel.Dir, "media"))
		if err != nil {
			return nil, rejected(fmt.Errorf("выпуск aisec-media (media/): %w", err))
		}
		if c, err := componentOf(media.Manifest); err != nil || c != componentMedia {
			return nil, rejected(errors.New("media/: в манифесте не ровно bin/aisec-media"))
		}
		if media.Manifest.Version != rel.Manifest.Version {
			return nil, rejected(fmt.Errorf("версия выпуска aisec-media %s не совпадает с версией выпуска %s", shortName(media.Manifest.Version), shortName(rel.Manifest.Version)))
		}
		media.Dir = filepath.Join(rel.Dir, "media")
		if err := copyRelease(context.Background(), p, media, ""); err != nil {
			return nil, rejected(fmt.Errorf("выпуск aisec-media: %w", err))
		}
		cr.Media = media
		specs = append(specs, imageSpec{Name: unitMedia, Rel: media, All: true})
		tars = append(tars, "media/images/aisec-media.tar")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	} else if mediaOn {
		return nil, rejected(errors.New("в установке включён aisec-media, а в выпуске нет подкаталога media/ с его образом"))
	}
	for i, s := range specs {
		s.Ref = l.ref(e, s.Name, tag)
		info, err := root.Lstat(tars[i])
		if err != nil {
			return nil, rejected(fmt.Errorf("в выпуске нет %s", tars[i]))
		}
		if !info.Mode().IsRegular() {
			return nil, rejected(fmt.Errorf("%s — не обычный файл (ссылка или каталог)", tars[i]))
		}
		cr.Images = append(cr.Images, composeImage{Spec: s, Tar: tars[i], Size: info.Size()})
	}
	return cr, nil
}

// imageConfigLine — настройки образа, как их показывает docker inspect
// (формат verify-release.sh); по ней проверяется загруженный образ.
const imageConfigFormat = "{{.Os}}/{{.Architecture}} {{.Config.User}} {{json .Config.Entrypoint}} {{json .Config.Cmd}} {{json .Config.Env}} {{json .Config.Volumes}} {{json .Config.ExposedPorts}} {{json .Config.Healthcheck}} {{json .Config.OnBuild}} {{json .Config.Shell}}"

func wantConfigLine(s imageSpec) string {
	ports := "null"
	if len(s.Ports) > 0 {
		m := map[string]struct{}{}
		for _, p := range s.Ports {
			m[p] = struct{}{}
		}
		b, _ := json.Marshal(m) //nolint:errchkjson,gosec // G104: карта строк в пустые структуры сериализуется всегда
		ports = string(b)
	}
	return fmt.Sprintf(`linux/amd64 %s ["/%s/bin/%s"] null ["%s"] null %s null null null`, imgUser, imgInstall, s.Name, imgPath, ports)
}

// stage копирует архивы образов на диск обновления (root 0700), проверяет
// копии и загружает их в docker. Любой сбой удаляет уже загруженные образы.
func (l *composeLayout) stage(ctx context.Context, p aisecCrypto.Provider, rel *releaseInfo) (err error) {
	cr := rel.Compose
	if cr == nil {
		return errors.New("образы выпуска не подготовлены")
	}
	staging := filepath.Join(l.stateDir, composeStagingPref+rel.ID)
	if err := os.RemoveAll(staging); err != nil { //nolint:gosec // G703: ID выпуска проверен releaseIDRe, каталог — свой
		return err
	}
	if err := ensureOwnedDir(staging, 0o700, l.ownerUID); err != nil {
		return err
	}
	defer os.RemoveAll(staging) //nolint:errcheck // копии больше не нужны
	var loaded []string
	defer func() {
		if err != nil {
			for _, ref := range loaded {
				_ = l.sys.removeImage(context.WithoutCancel(ctx), ref) //nolint:gosec // G104: исходная ошибка важнее
			}
		}
	}()
	src, err := os.OpenRoot(rel.Dir)
	if err != nil {
		return err
	}
	defer src.Close() //nolint:errcheck // каталог только читается
	for _, im := range cr.Images {
		if err := ctx.Err(); err != nil {
			return err
		}
		if ok, err := l.sys.imageExists(ctx, im.Spec.Ref); err != nil {
			return err
		} else if ok {
			return fmt.Errorf("%s уже загружен: удалите его (docker rmi) и повторите", im.Spec.Ref)
		}
		copyPath := filepath.Join(staging, im.Spec.Name+".tar")
		if err := copyImageArchive(src, im.Tar, copyPath, im.Size); err != nil {
			return fmt.Errorf("%s: %w", im.Tar, err)
		}
		v, err := verifyImageArchive(p, func() (*os.File, error) { return os.Open(copyPath) }, im.Spec) //nolint:gosec // G304: копия в каталоге обновления root 0700
		if err != nil {
			return fmt.Errorf("образ %s: копия не прошла проверку: %w", im.Spec.Name, err)
		}
		loaded = append(loaded, im.Spec.Ref)
		if _, err := l.sys.r.Run(ctx, dockerCall{Args: []string{"load", "-q", "-i", copyPath}, Timeout: dockerLoadTimeout}); err != nil {
			return fmt.Errorf("образ %s: загрузка: %w", im.Spec.Name, err)
		}
		if err := l.checkLoaded(ctx, im.Spec, v); err != nil {
			return fmt.Errorf("образ %s: %w", im.Spec.Name, err)
		}
		if err := os.Remove(copyPath); err != nil {
			return err
		}
	}
	return nil
}

// checkLoaded: то, что docker загрузил, — проверенный образ: слои по
// diff_id и настройки.
func (l *composeLayout) checkLoaded(ctx context.Context, s imageSpec, v *verifiedImage) error {
	out, err := l.sys.docker(ctx, "image", "inspect", "--format", "{{json .RootFS.Layers}}", s.Ref)
	if err != nil {
		return err
	}
	var layers []string
	if err := json.Unmarshal([]byte(out), &layers); err != nil || !slices.Equal(layers, v.DiffIDs) {
		return errors.New("после загрузки слои образа отличаются от проверенных")
	}
	out, err = l.sys.docker(ctx, "image", "inspect", "--format", imageConfigFormat, s.Ref)
	if err != nil {
		return err
	}
	if out != wantConfigLine(s) {
		return errors.New("после загрузки настройки образа отличаются от ожидаемых")
	}
	return nil
}

// copyImageArchive копирует архив с носителя в каталог обновления: файл
// только обычный, размер как при проверке, запись с O_EXCL.
func copyImageArchive(src *os.Root, name, dst string, size int64) error {
	info, err := src.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != size {
		return errors.New("файл изменился после проверки")
	}
	in, err := src.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()                                                                          //nolint:errcheck // файл только читается
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:forbidigo,gosec // ADR-0036, раздел 6: без перехода по ссылке; G304: путь в каталоге обновления root 0700
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(in, size+1))
	if err != nil {
		_ = out.Close() //nolint:gosec // G104: исходная ошибка важнее
		return err
	}
	if n != size {
		_ = out.Close() //nolint:gosec // G104: исходная ошибка важнее
		return errors.New("размер изменился при копировании")
	}
	if err := out.Sync(); err != nil {
		_ = out.Close() //nolint:gosec // G104: исходная ошибка важнее
		return err
	}
	return out.Close()
}

// switchTo: установленным становится выпуск id — AISEC_VERSION в .env.
// Образы обязаны быть загружены. Запись атомарна (временный файл и
// переименование).
func (l *composeLayout) switchTo(id string) error {
	e, err := l.env()
	if err != nil {
		return err
	}
	tag, err := l.tagFromID(e, id)
	if err != nil {
		return err
	}
	ctx := context.Background()
	for _, name := range []string{"aisec-server", "aisec-gateway", composeCLIService} {
		ok, err := l.sys.imageExists(ctx, l.ref(e, name, tag))
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("образа %s нет", l.ref(e, name, tag))
		}
	}
	data, err := e.withVersion(tag)
	if err != nil {
		return err
	}
	return writeComposeEnv(e.path, data)
}

func (l *composeLayout) imageNames() []string {
	return []string{"aisec-server", "aisec-gateway", composeCLIService, unitMedia}
}

// drop удаляет образы выпуска id и копии архивов (после отката).
func (l *composeLayout) drop(id string) error {
	e, err := l.env()
	if err != nil {
		return err
	}
	tag, err := l.tagFromID(e, id)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range l.imageNames() {
		errs = append(errs, l.sys.removeImage(context.Background(), l.ref(e, name, tag)))
	}
	errs = append(errs, os.RemoveAll(filepath.Join(l.stateDir, composeStagingPref+id))) //nolint:gosec // G703: ID выпуска проверен releaseIDRe, каталог — свой
	return errors.Join(errs...)
}

// prune удаляет образы продукта других версий, кроме keep.
func (l *composeLayout) prune(keep ...string) error {
	e, err := l.env()
	if err != nil {
		return err
	}
	keepTags := map[string]bool{}
	for _, id := range keep {
		tag, err := l.tagFromID(e, id)
		if err != nil {
			return err
		}
		keepTags[tag] = true
	}
	ctx := context.Background()
	var errs []error
	for _, name := range l.imageNames() {
		repo := e.repo() + "/" + name
		out, err := l.sys.docker(ctx, "image", "ls", "--format", "{{.Tag}}", repo)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, tag := range strings.Fields(out) {
			if keepTags[tag] || !dockerTagRe.MatchString(tag) {
				continue
			}
			errs = append(errs, l.sys.removeImage(ctx, repo+":"+tag))
		}
	}
	return errors.Join(errs...)
}

// ---- Службы ----

// composeHost — службы установки в docker compose.
type composeHost struct {
	sys       *composeSys
	p         aisecCrypto.Provider
	healthURL string
	healthCA  string
	// readyFn — подмена проверки /readyz в тестах.
	readyFn func(ctx context.Context) error
	// gated — новые контейнеры сервера создаются с закрытым приёмом
	// событий. Контейнер хранит команду, с которой создан: перезагрузка
	// хоста посреди обновления не открывает приём.
	gated bool
	// envPath — .env установки, куда записывается закрытие приёма; пусто — не
	// записывать (тесты с подделкой docker).
	envPath string
}

func (h *composeHost) env(unit string) []string {
	if unit == unitServer && h.gated {
		return []string{composeGateEnv + "=" + composeGateValue}
	}
	return nil
}

func (h *composeHost) State(ctx context.Context, unit string) (unitState, error) {
	if !knownUnits[unit] {
		return unitState{}, errors.New("неизвестная служба")
	}
	svc, err := h.sys.activeServices(ctx)
	if err != nil {
		return unitState{}, err
	}
	exists, running, restarts, err := h.sys.container(ctx, unit)
	if err != nil {
		return unitState{}, err
	}
	st := unitState{Enabled: slices.Contains(svc, unit)}
	if exists {
		st.Active, st.Restarts = running, restarts
	}
	return st, nil
}

func (h *composeHost) Stop(ctx context.Context, unit string) error {
	if !knownUnits[unit] {
		return errors.New("неизвестная служба")
	}
	_, err := h.sys.compose(ctx, nil, "stop", unit)
	return err
}

func (h *composeHost) Start(ctx context.Context, unit string) error {
	if !knownUnits[unit] {
		return errors.New("неизвестная служба")
	}
	_, err := h.sys.compose(ctx, h.env(unit), "up", "-d", "--no-deps", "--pull", "never", unit)
	return err
}

// Restart пересоздаёт контейнер: команда сервера с закрытым и открытым
// приёмом разная, а простой restart её не меняет.
func (h *composeHost) Restart(ctx context.Context, unit string) error {
	if !knownUnits[unit] {
		return errors.New("неизвестная служба")
	}
	_, err := h.sys.compose(ctx, h.env(unit), "up", "-d", "--no-deps", "--pull", "never", "--force-recreate", unit)
	return err
}

// Gate: закрытый приём записывается в .env (AISEC_SERVER_INTERNAL_LISTEN) и
// действует на любые контейнеры сервера, созданные после вызова: и на Start
// и Restart обновления, и на ручной docker compose up. Открытие убирает
// строку (повтор безопасен). Контейнер, созданный раньше, закрывается
// пересозданием (Restart). Совместимость compose.yaml проверил prepare.
func (h *composeHost) Gate(_ context.Context, on bool) error {
	if h.envPath != "" {
		e, err := readComposeEnv(h.envPath)
		if err != nil {
			return err
		}
		if err := writeComposeEnv(h.envPath, e.withGate(on)); err != nil {
			return err
		}
	}
	h.gated = on
	return nil
}

func (h *composeHost) PackageOwned(context.Context) (bool, error) { return false, nil }

// RunCLI запускает aisec-cli выпуска из .env в одноразовом контейнере;
// путь exe — только метка.
func (h *composeHost) RunCLI(ctx context.Context, _ string, args ...string) (string, error) {
	timeout := cmdTimeout
	if len(args) > 0 && args[0] == "migrate" {
		timeout = migrateTimeout
	}
	return h.sys.r.Run(ctx, dockerCall{Args: append([]string{"compose", "run", "--rm", "--no-deps", "-T", composeCLIService}, args...), Timeout: timeout})
}

func (h *composeHost) Journal(context.Context, string) error {
	return errors.New("в установке compose журнал аудита ведётся в БД")
}

func (h *composeHost) Ready(ctx context.Context) error {
	if h.readyFn != nil {
		return h.readyFn(ctx)
	}
	return cliclient.Ready(ctx, h.p, h.healthURL, h.healthCA)
}

// composeHealthURL — адрес консоли из .env: https://AISEC_CONSOLE_HOST:порт.
func composeHealthURL(e *composeEnv) (string, error) {
	host := e.vals["AISEC_CONSOLE_HOST"]
	if host == "" {
		return "", errors.New("в .env нет AISEC_CONSOLE_HOST; задайте -health-url")
	}
	port := e.vals["AISEC_CONSOLE_PORT"]
	if port == "" {
		port = "8444"
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", errors.New("AISEC_CONSOLE_PORT: ожидается номер порта")
	}
	u := &url.URL{Scheme: "https", Host: host + ":" + port, Path: "/readyz"}
	return healthURL(u.String())
}

// ---- Сборка обновления ----

// newComposeUpdater — updater для установки в docker compose.
func newComposeUpdater(f updateFlags, dir string, out io.Writer) (*updater, func(), error) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return nil, nil, err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return nil, nil, err
	}
	if !filepath.IsAbs(dir) {
		return nil, nil, errors.New("compose-dir: ожидается абсолютный путь каталога установки (с compose.yaml и .env)")
	}
	bin, err := findDocker()
	if err != nil {
		return nil, nil, err
	}
	e, err := readComposeEnv(filepath.Join(dir, ".env"))
	if err != nil {
		return nil, nil, err
	}
	rawHealth := f.healthURL
	if rawHealth == "" {
		if rawHealth, err = composeHealthURL(e); err != nil {
			return nil, nil, err
		}
	}
	hu, err := healthURL(rawHealth)
	if err != nil {
		return nil, nil, err
	}
	ca := f.healthCA
	if ca == healthCAPath { // умолчание systemd: в compose корень лежит в каталоге данных
		data := e.vals["AISEC_DATA_DIR"]
		if data == "" {
			data = "/srv/aisec"
		}
		ca = filepath.Join(data, "secrets", "console-ca.crt")
	}
	sys := &composeSys{r: &execDocker{bin: bin, dir: dir}, stateDir: composeStateDir}
	lay := &composeLayout{sys: sys, p: p, dir: dir, stateDir: composeStateDir, ownerUID: 0}
	state := &stateStore{dir: composeStateDir, ownerUID: 0}
	dbTag, err := trustedCLITag(lay, e, state)
	if err != nil {
		return nil, nil, err
	}
	u := &updater{
		p: p, host: &composeHost{sys: sys, p: p, healthURL: hu, healthCA: ca, envPath: e.path}, custom: lay,
		db:    &composeDB{sys: sys, p: p, tag: dbTag},
		state: state,
		roots: map[string]string{componentMain: "/"},
		out:   out, now: func() time.Time { return time.Now() }, settle: f.settle, healthTimeout: f.healthTimeout, poll: 2 * time.Second,
	}
	return u, func() {}, nil
}

// trustedCLITag — тег образа aisec-cli версии, установленной до обновления:
// по журналу незавершённого обновления (выпуск «было»), иначе по .env
// (обновление ещё не начато, AISEC_VERSION — установленная версия).
func trustedCLITag(l *composeLayout, e *composeEnv, state *stateStore) (string, error) {
	st, err := state.load()
	if err != nil {
		// Нет каталога обновления — обновления ещё не было.
		if errors.Is(err, fs.ErrNotExist) {
			return e.version(), nil
		}
		return "", fmt.Errorf("журнал обновления: %w", err)
	}
	if st == nil || st.Component != componentMain {
		return e.version(), nil
	}
	return l.tagFromID(e, st.FromID)
}
