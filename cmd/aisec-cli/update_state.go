package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Журнал обновления (ADR-0036, раздел 5): какие шаги пройдены, чтобы
// повторный запуск после прерывания довёл обновление или откатил его.
// Файл пишет root в каталоге 0700, но разбирается как недоверенный ввод:
// строгий JSON, пределы, известные значения (FuzzUpdateState).

const (
	updateStateFormat = "aisec-update-state-v1"
	updateStateFile   = "state.json"
	updateLockFile    = "lock"
	maxUpdateState    = 64 << 10
	maxUpdateUnits    = 8
)

// Шаги обновления по порядку (ADR-0036, раздел 3). Журнал хранит последний
// пройденный шаг.
const (
	stepChecked  = "checked"
	stepBackedUp = "backed_up"
	stepStopped  = "stopped"
	stepAdopted  = "adopted"
	stepStaged   = "staged"
	stepSwitched = "switched"
	stepMigrated = "migrated"
	stepStarted  = "started"
	stepHealthy  = "healthy"
	stepOpened   = "opened"
)

var updateSteps = []string{stepChecked, stepBackedUp, stepStopped, stepAdopted, stepStaged, stepSwitched, stepMigrated, stepStarted, stepHealthy, stepOpened}

// stepIndex — номер шага; -1 — неизвестный.
func stepIndex(s string) int {
	for i, v := range updateSteps {
		if v == s {
			return i
		}
	}
	return -1
}

// Компоненты: основной выпуск и анализаторы со своими корнями (ADR-0034).
const (
	componentMain  = "aisec"
	componentML    = "aisec-ml"
	componentMedia = "aisec-media"
)

// Службы systemd, которые знает обновление.
const (
	unitGateway = "aisec-gateway"
	unitServer  = "aisec-server"
	unitML      = "aisec-ml"
	unitMedia   = "aisec-media"
)

var knownUnits = map[string]bool{unitGateway: true, unitServer: true, unitML: true, unitMedia: true}

// releaseIDRe — имя каталога версии: версия манифеста и 12 знаков SHA-256.
var releaseIDRe = regexp.MustCompile(`^[0-9A-Za-z._+~-]{1,64}-[0-9a-f]{12}$|^[0-9a-f]{12}$`)

// updateIDRe — ID обновления: время начала в UTC.
var updateIDRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

// updateState — журнал обновления.
type updateState struct {
	Format    string    `json:"format"`
	ID        string    `json:"id"`
	Component string    `json:"component"`
	StartedAt time.Time `json:"started_at"`
	Step      string    `json:"step"`
	// FromID и ToID — каталоги выпусков «было» и «стало»; FromSHA и ToSHA —
	// SHA-256 их манифестов.
	FromID      string `json:"from_id"`
	FromVersion string `json:"from_version"`
	FromSHA     string `json:"from_sha256"`
	ToID        string `json:"to_id"`
	ToVersion   string `json:"to_version"`
	ToSHA       string `json:"to_sha256"`
	// Adopt — установка была каталогом (раскладка ADR-0034), при обновлении
	// он переименовывается в каталог версии FromID.
	Adopt bool `json:"adopt"`
	// Units — службы, работавшие до обновления: их останавливают и затем
	// запускают снова (свой выпуск или прежний при откате).
	Units []string `json:"units"`
	// DB — обновление со своей БД (узел сервера): копия, миграции, аудит.
	DB bool `json:"db"`
	// AppliedBefore — число применённых миграций до обновления: больше —
	// миграции нового выпуска применились, откат восстанавливает копию.
	AppliedBefore int  `json:"applied_before"`
	AllowOlder    bool `json:"allow_older"`
	// Gated — приём событий закрыт временным дополнением юнита сервера.
	Gated bool `json:"gated"`
}

// validate — правила разбора журнала: неизвестное значение — отказ, а не
// догадка, что делать при восстановлении.
func (s *updateState) validate() error {
	switch {
	case s.Format != updateStateFormat:
		return errors.New("журнал обновления: неизвестный формат")
	case !updateIDRe.MatchString(s.ID):
		return errors.New("журнал обновления: неверный ID")
	case s.Component != componentMain && s.Component != componentML && s.Component != componentMedia:
		return errors.New("журнал обновления: неизвестный компонент")
	case s.StartedAt.IsZero():
		return errors.New("журнал обновления: нет времени начала")
	case stepIndex(s.Step) < 0:
		return errors.New("журнал обновления: неизвестный шаг")
	case !releaseIDRe.MatchString(s.FromID) || !releaseIDRe.MatchString(s.ToID) || s.FromID == s.ToID:
		return errors.New("журнал обновления: неверные каталоги выпусков")
	case !hexSHA256(s.FromSHA) || !hexSHA256(s.ToSHA):
		return errors.New("журнал обновления: неверный хеш манифеста")
	case !printable(s.FromVersion, 128) || !printable(s.ToVersion, 128):
		return errors.New("журнал обновления: неверная версия")
	case len(s.Units) > maxUpdateUnits:
		return errors.New("журнал обновления: слишком много служб")
	case s.AppliedBefore < 0 || s.AppliedBefore > 100000:
		return errors.New("журнал обновления: неверное число миграций")
	case s.DB && s.Component != componentMain:
		return errors.New("журнал обновления: БД — только у основного выпуска")
	case s.Gated && !s.DB:
		return errors.New("журнал обновления: приём событий закрывается только на узле сервера")
	}
	seen := map[string]bool{}
	for _, u := range s.Units {
		if !knownUnits[u] || seen[u] {
			return errors.New("журнал обновления: неизвестная или повторная служба")
		}
		seen[u] = true
	}
	return nil
}

func hexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func printable(s string, limit int) bool {
	if s == "" || len(s) > limit {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return false
		}
	}
	return true
}

// parseUpdateState разбирает журнал.
func parseUpdateState(data []byte) (*updateState, error) {
	if len(data) > maxUpdateState {
		return nil, errors.New("журнал обновления больше предела")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s updateState
	if err := dec.Decode(&s); err != nil {
		return nil, errors.New("журнал обновления: неверный JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("журнал обновления: данные после объекта")
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// stateStore — каталог журнала (/var/lib/aisec/update): журнал, блокировка
// и копии БД. Каталог принадлежит root, 0700: пользователь сервера не может
// подменить копию, которую затем восстановит root (ADR-0036, раздел 5).
type stateStore struct {
	dir      string
	ownerUID int
	lock     *os.File
}

// open создаёт каталог при необходимости, проверяет владельца и права и
// берёт блокировку: два обновления одновременно не работают.
func (st *stateStore) open() error {
	if err := ensureOwnedDir(st.dir, 0o700, st.ownerUID); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(st.dir, updateLockFile), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: фиксированное имя в каталоге root 0700
	if err != nil {
		return fmt.Errorf("блокировка обновления: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: дескриптор файла помещается в int
		_ = f.Close() //nolint:gosec // G104: файл не использовался
		return errors.New("другое обновление уже выполняется (блокировка занята)")
	}
	st.lock = f
	return nil
}

func (st *stateStore) close() {
	if st.lock != nil {
		_ = st.lock.Close() //nolint:gosec // G104: закрытие снимает блокировку
		st.lock = nil
	}
}

// load читает журнал; нет журнала — nil без ошибки.
func (st *stateStore) load() (*updateState, error) {
	root, err := os.OpenRoot(st.dir)
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck // каталог только читается
	info, err := root.Lstat(updateStateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxUpdateState {
		return nil, errors.New("журнал обновления: не обычный файл или больше предела")
	}
	data, err := root.ReadFile(updateStateFile)
	if err != nil {
		return nil, err
	}
	return parseUpdateState(data)
}

// save пишет журнал атомарно: временный файл, fsync, переименование, fsync
// каталога.
func (st *stateStore) save(s *updateState) error {
	if err := s.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return updWriteAtomic(st.dir, updateStateFile, append(data, '\n'), 0o600)
}

// remove удаляет журнал: обновление завершено или откачено.
func (st *stateStore) remove() error {
	if err := os.Remove(filepath.Join(st.dir, updateStateFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return updSyncDir(st.dir)
}

// dumpDir — каталог копии БД обновления id.
func (st *stateStore) dumpDir(id string) string { return filepath.Join(st.dir, id) }

// writeFileAtomic — запись файла name в dir через временный файл с O_EXCL.
func updWriteAtomic(dir, name string, data []byte, mode os.FileMode) error {
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode) //nolint:gosec // G304: имя — константа в своём каталоге
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close() //nolint:gosec // G104: исходная ошибка важнее
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close() //nolint:gosec // G104: исходная ошибка важнее
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	return updSyncDir(dir)
}

// syncDir — fsync каталога: переименование и удаление переживают сбой питания.
func updSyncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: каталог установки или журнала, не ввод
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close() //nolint:gosec // G104: исходная ошибка важнее
		return err
	}
	return d.Close()
}

// ensureOwnedDir создаёт каталог (если его нет) и проверяет: каталог, не
// ссылка, владелец ownerUID, нет записи группе и остальным; права не шире
// mode.
func ensureOwnedDir(dir string, mode os.FileMode, ownerUID int) error {
	if err := os.Mkdir(dir, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return checkOwnedDir(dir, mode, ownerUID)
}

func checkOwnedDir(dir string, mode os.FileMode, ownerUID int) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s — не каталог (ссылка или файл)", dir)
	}
	if info.Mode().Perm()&^mode != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: права %#o шире допустимых %#o", dir, info.Mode().Perm(), mode)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != ownerUID {
		return fmt.Errorf("%s: владелец — не root", dir)
	}
	return nil
}

// stepAfter — пройден ли шаг want (журнал на шаге s или дальше).
func stepAfter(s, want string) bool { return stepIndex(s) >= stepIndex(want) }

// joinUnits — службы через запятую для вывода.
func joinUnits(u []string) string {
	if len(u) == 0 {
		return "нет"
	}
	return strings.Join(u, ", ")
}
