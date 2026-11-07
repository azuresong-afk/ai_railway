package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Тесты обновления и отката (задачи 6.19, 6.20; ADR-0036): шаги на
// временном каталоге с подменой служб и БД, отказ на каждом шаге, прерывание
// и повторный запуск. Живая PostgreSQL — update_pg_test.go.

var errCrash = errors.New("имитация обрыва процесса")

// relSpec — выпуск для теста.
type relSpec struct {
	version    string
	created    time.Time
	bins       []string
	migrations string // каталог *.sql; пусто — без миграций
	body       string // содержимое исполняемых файлов
}

func mainSpec(version string, created time.Time, migrations string) relSpec {
	return relSpec{version: version, created: created, bins: []string{"aisec-cli", "aisec-gateway", "aisec-server"}, migrations: migrations,
		body: "синтетический бинарник " + version}
}

// writeRelease — каталог выпуска с манифестом, подписанным тестовым ключом
// репозитория (его принимает сборка без aisec_release).
func writeRelease(t *testing.T, dir string, s relSpec) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, b := range s.bins {
		if err := os.WriteFile(filepath.Join(dir, "bin", b), []byte(s.body+" "+b), 0o755); err != nil { //nolint:gosec // G306: тестовый «бинарник»
			t.Fatal(err)
		}
	}
	p := standardProvider(t)
	srcs := []integrity.Source{{Kind: integrity.KindBinary, Dir: filepath.Join(dir, "bin"), Files: s.bins}}
	if s.migrations != "" {
		srcs = append(srcs, integrity.Source{Kind: integrity.KindMigration, Dir: s.migrations, Glob: "*.sql"})
	}
	m, err := integrity.Build(p, integrity.BuildInput{Version: s.version, Created: s.created, Sources: srcs})
	if err != nil {
		t.Fatal(err)
	}
	data, err := integrity.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile("../../testdata/integrity/manifest-test.signkey")
	if err != nil {
		t.Fatal(err)
	}
	_, seed, err := aisecCrypto.DecodeKeyPEM(keyPEM, aisecCrypto.KeyKindManifestSigning)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := p.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := integrity.Sign(signer, data)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{integrity.ManifestFile: data, integrity.SignatureFile: sig} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil { //nolint:gosec // G306: манифест открыт для чтения, как в выпуске
			t.Fatal(err)
		}
	}
}

// migrationsDir — каталог с n синтетическими миграциями.
func migrationsDir(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	for i := 1; i <= n; i++ {
		body := fmt.Sprintf("CREATE TABLE t%d (id int);\n", i)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%04d_m%d.sql", i, i)), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// fakeHost — службы и aisec-cli нового выпуска в памяти. Сбои одноразовые:
// откат вызывает те же действия ещё раз и должен их выполнить.
type fakeHost struct {
	states   map[string]*unitState
	calls    []string
	fail     map[string]error
	started  bool
	gated    bool
	packaged bool
	db       *fakeDB
	// migrateTo — миграции в БД после успешного migrate.
	migrateTo []store.Applied
	onStop    func()
	onVerify  func()
	migrate   func(ctx context.Context) error
	// readyFail и unstable — постоянные сбои после запуска нового выпуска:
	// проверка здоровья прежнего при откате тоже их видит и только сообщает.
	readyFail error
	unstable  map[string]bool
}

func newFakeHost(db *fakeDB) *fakeHost {
	return &fakeHost{states: map[string]*unitState{
		unitGateway: {Active: true, Enabled: true}, unitServer: {Active: true, Enabled: true},
	}, fail: map[string]error{}, db: db}
}

func (h *fakeHost) take(key string) error {
	err := h.fail[key]
	delete(h.fail, key)
	return err
}

func (h *fakeHost) State(_ context.Context, unit string) (unitState, error) {
	s, ok := h.states[unit]
	if !ok {
		return unitState{}, nil
	}
	if s.Active && h.unstable[unit] {
		s.Restarts++
	}
	return *s, nil
}

func (h *fakeHost) Stop(_ context.Context, unit string) error {
	h.calls = append(h.calls, "stop:"+unit)
	if h.onStop != nil {
		f := h.onStop
		h.onStop = nil
		f()
	}
	if err := h.take("stop:" + unit); err != nil {
		return err
	}
	if s, ok := h.states[unit]; ok {
		s.Active = false
	}
	return nil
}

func (h *fakeHost) Start(_ context.Context, unit string) error {
	h.calls = append(h.calls, "start:"+unit)
	if err := h.take("start:" + unit); err != nil {
		return err
	}
	h.started = true
	if s, ok := h.states[unit]; ok {
		s.Active = true
	}
	return nil
}

func (h *fakeHost) Restart(_ context.Context, unit string) error {
	h.calls = append(h.calls, "restart:"+unit)
	return h.take("restart:" + unit)
}

func (h *fakeHost) Gate(_ context.Context, on bool) error {
	h.calls = append(h.calls, fmt.Sprintf("gate:%v", on))
	key := "gate:off"
	if on {
		key = "gate:on"
	}
	if err := h.take(key); err != nil {
		return err
	}
	h.gated = on
	return nil
}

func (h *fakeHost) PackageOwned(context.Context) (bool, error) { return h.packaged, nil }

func (h *fakeHost) RunCLI(ctx context.Context, exe string, args ...string) (string, error) {
	h.calls = append(h.calls, "cli:"+strings.Join(args, " "))
	if _, err := os.Stat(exe); err != nil {
		return "", fmt.Errorf("нет %s", exe)
	}
	switch args[0] {
	case "migrate":
		if err := h.take("migrate"); err != nil {
			return "", err
		}
		if h.migrate != nil {
			return "применено", h.migrate(ctx)
		}
		if h.db != nil {
			h.db.applied = append([]store.Applied(nil), h.migrateTo...)
		}
		return "применено миграций", nil
	case "verify":
		if h.onVerify != nil {
			h.onVerify()
		}
		return "Целостность не нарушена.", h.take("verify")
	}
	return "", errors.New("неожиданная команда")
}

func (h *fakeHost) Ready(context.Context) error {
	h.calls = append(h.calls, "ready")
	if h.started {
		return h.readyFail
	}
	return h.take("ready:before")
}

// fakeDB — БД в памяти: копия — снимок списка миграций.
type fakeDB struct {
	applied, dumped []store.Applied
	audits          []string
	restores        int
	fail            map[string]error
}

func (d *fakeDB) take(k string) error { err := d.fail[k]; delete(d.fail, k); return err }

func (d *fakeDB) Applied(context.Context) ([]store.Applied, error) {
	return append([]store.Applied(nil), d.applied...), nil
}
func (d *fakeDB) Size(context.Context) (int64, error) { return 1 << 20, nil }
func (d *fakeDB) Dump(_ context.Context, file string) error {
	if err := d.take("dump"); err != nil {
		return err
	}
	d.dumped = append([]store.Applied(nil), d.applied...)
	return os.WriteFile(file, []byte("копия"), 0o600)
}

func (d *fakeDB) Restore(_ context.Context, file string) error {
	if _, err := os.Stat(file); err != nil {
		return err
	}
	if err := d.take("restore"); err != nil {
		return err
	}
	d.restores++
	d.applied = append([]store.Applied(nil), d.dumped...)
	return nil
}

func (d *fakeDB) Audit(_ context.Context, e audit.Entry) error {
	d.audits = append(d.audits, e.Action)
	return nil
}
func (d *fakeDB) Close() {}

// updEnv — установка во временном каталоге: прежний выпуск 1.0 каталогом
// (раскладка ADR-0034), новый 2.0 на «носителе», БД с двумя миграциями из
// трёх.
type updEnv struct {
	u          *updater
	host       *fakeHost
	db         *fakeDB
	root, src  string
	out        *bytes.Buffer
	fromID     string
	toID       string
	migrations []store.Applied
}

var (
	updOld = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	updNew = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
)

func newUpdEnv(t *testing.T) *updEnv {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "host")
	if err := os.MkdirAll(filepath.Join(root, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	m3 := migrationsDir(t, 3)
	m2 := t.TempDir()
	for _, n := range []string{"0001_m1.sql", "0002_m2.sql"} {
		data, err := os.ReadFile(filepath.Join(m3, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(m2, n), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeRelease(t, filepath.Join(root, "opt", "aisec"), mainSpec("1.0", updOld, m2))
	src := filepath.Join(base, "media", "release")
	writeRelease(t, src, mainSpec("2.0", updNew, m3))
	p := standardProvider(t)
	newRel, err := readManifestPair(p, src)
	if err != nil {
		t.Fatal(err)
	}
	oldRel, err := readManifestPair(p, filepath.Join(root, "opt", "aisec"))
	if err != nil {
		t.Fatal(err)
	}
	all, err := migrationEntries(newRel.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	db := &fakeDB{applied: all[:2], fail: map[string]error{}}
	host := newFakeHost(db)
	host.migrateTo = all
	out := &bytes.Buffer{}
	u := &updater{p: p, host: host, db: db, state: &stateStore{dir: filepath.Join(base, "update"), ownerUID: os.Getuid()},
		roots: map[string]string{componentMain: root, componentML: filepath.Join(base, "ml"), componentMedia: filepath.Join(base, "mediaroot")},
		owner: os.Getuid(), out: out, now: time.Now, healthTimeout: 50 * time.Millisecond, poll: time.Millisecond,
		free: func(string) (int64, error) { return 1 << 40, nil }}
	return &updEnv{u: u, host: host, db: db, root: root, src: src, out: out, fromID: oldRel.ID, toID: newRel.ID, migrations: all}
}

func (e *updEnv) link(t *testing.T) string {
	t.Helper()
	target, err := os.Readlink(filepath.Join(e.root, "opt", "aisec"))
	if err != nil {
		t.Fatalf("ссылка установки: %v", err)
	}
	return target
}

func (e *updEnv) apply(t *testing.T, args ...string) error {
	t.Helper()
	allow := len(args) > 0 && args[0] == "-allow-older"
	return e.u.run("apply", e.src, allow)
}

// Обновление проходит все шаги: копия, остановка, переход на каталоги
// версий, копия выпуска, переключение, миграции новым aisec-cli, запуск с
// закрытым приёмом, проверка, открытие, итог в журнале аудита.
func TestUpdateApplyOK(t *testing.T) {
	e := newUpdEnv(t)
	if err := e.apply(t); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if got := e.link(t); got != "aisec-releases/"+e.toID {
		t.Fatalf("ссылка: %s", got)
	}
	if _, err := os.Stat(filepath.Join(e.root, "opt", "aisec-releases", e.fromID, "bin", "aisec-cli")); err != nil {
		t.Fatal("прежний выпуск не сохранён")
	}
	info, err := os.Stat(filepath.Join(e.root, "opt", "aisec", "bin", "aisec-server"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("права бинарника: %v %v", info, err)
	}
	want := []string{"ready", "stop:aisec-gateway", "stop:aisec-server", "cli:migrate", "start:aisec-gateway", "gate:true",
		"start:aisec-server", "ready", "cli:verify", "gate:false", "restart:aisec-server", "ready"}
	if got := strings.Join(e.host.calls, ","); got != strings.Join(want, ",") {
		t.Fatalf("порядок действий:\n%s\nожидалось\n%s", got, strings.Join(want, ","))
	}
	if got := strings.Join(e.db.audits, ","); got != "update.started,update.install" {
		t.Fatalf("аудит: %s", got)
	}
	if len(e.db.applied) != 3 || e.host.gated {
		t.Fatal("миграции не применены или приём не открыт")
	}
	if st, _ := e.u.state.load(); st != nil {
		t.Fatal("журнал не удалён")
	}
	if _, err := os.Stat(filepath.Join(e.u.state.dir, "")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.out.String(), "Обновление завершено: установлен выпуск 2.0") {
		t.Fatal(e.out.String())
	}
	// Повтор того же выпуска — без действий.
	e.host.calls = nil
	if err := e.apply(t); err != nil || len(e.host.calls) != 0 || !strings.Contains(e.out.String(), "уже установлен") {
		t.Fatalf("повтор: %v %v", err, e.host.calls)
	}
}

// Отказ на каждом шаге (6.20): прежний выпуск работает, БД в прежнем
// состоянии (копия восстановлена, если миграции применились), приём
// событий открыт, журнал удалён, в аудите — начало и откат.
func TestUpdateRollbackOnEachStep(t *testing.T) {
	boom := errors.New("сбой")
	cases := []struct {
		name        string
		setup       func(e *updEnv)
		wantRestore bool
	}{
		{"копия БД", func(e *updEnv) { e.db.fail["dump"] = boom }, false},
		{"остановка шлюза", func(e *updEnv) { e.host.fail["stop:aisec-gateway"] = boom }, false},
		{"остановка сервера", func(e *updEnv) { e.host.fail["stop:aisec-server"] = boom }, false},
		{"подмена файла после проверки", func(e *updEnv) {
			e.host.onStop = func() {
				_ = os.WriteFile(filepath.Join(e.src, "bin", "aisec-server"), []byte("подменённый бинарник 2.0 aisec-server"), 0o755) //nolint:gosec // G306: тест
			}
		}, false},
		{"сбой миграции посреди транзакции", func(e *updEnv) { e.host.fail["migrate"] = boom }, false},
		{"запуск шлюза", func(e *updEnv) { e.host.fail["start:aisec-gateway"] = boom }, true},
		{"закрытие приёма", func(e *updEnv) { e.host.fail["gate:on"] = boom }, true},
		{"запуск сервера", func(e *updEnv) { e.host.fail["start:aisec-server"] = boom }, true},
		{"сервер не готов", func(e *updEnv) { e.host.readyFail = boom }, true},
		{"служба перезапускалась", func(e *updEnv) { e.host.unstable = map[string]bool{unitGateway: true} }, true},
		{"контроль целостности", func(e *updEnv) { e.host.fail["verify"] = boom }, true},
		{"перезапуск после открытия приёма", func(e *updEnv) { e.host.fail["restart:aisec-server"] = boom }, true},
		{"сигнал остановки", func(e *updEnv) {
			var f atomic.Bool
			e.u.stopFlag = &f
			e.host.onStop = func() { f.Store(true) }
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newUpdEnv(t)
			c.setup(e)
			if c.name == "сигнал остановки" {
				// run ставит свой флаг сигналов; здесь — сразу шаги.
				if err := e.u.state.open(); err != nil {
					t.Fatal(err)
				}
				pl, err := e.u.check(context.Background(), e.src, false)
				if err != nil {
					t.Fatal(err)
				}
				err = e.u.apply(context.Background(), pl)
				e.u.state.close()
				if !errors.Is(err, errUpdateRolledBack) {
					t.Fatalf("%v\n%s", err, e.out)
				}
			} else if err := e.apply(t); !errors.Is(err, errUpdateRolledBack) {
				t.Fatalf("ожидался откат: %v\n%s", err, e.out)
			}
			assertRolledBack(t, e, c.wantRestore)
		})
	}
}

// Сигнал после проверки здоровья не откатывает исправное обновление: оно
// доводится, как при повторном запуске.
func TestUpdateSignalAfterHealthFinishes(t *testing.T) {
	e := newUpdEnv(t)
	var f atomic.Bool
	e.u.stopFlag = &f
	e.host.onVerify = func() { f.Store(true) }
	if err := e.u.state.open(); err != nil {
		t.Fatal(err)
	}
	pl, err := e.u.check(context.Background(), e.src, false)
	if err != nil {
		t.Fatal(err)
	}
	err = e.u.apply(context.Background(), pl)
	e.u.state.close()
	if err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if got := e.link(t); got != "aisec-releases/"+e.toID || e.host.gated {
		t.Fatalf("ссылка %s, приём закрыт: %v", got, e.host.gated)
	}
	if got := strings.Join(e.db.audits, ","); got != "update.started,update.install" {
		t.Fatalf("аудит: %s", got)
	}
}

func assertRolledBack(t *testing.T, e *updEnv, wantRestore bool) {
	t.Helper()
	// Сбой до перехода на каталоги версий оставляет установку каталогом.
	if info, err := os.Lstat(filepath.Join(e.root, "opt", "aisec")); err != nil || !info.IsDir() {
		if got := e.link(t); got != "aisec-releases/"+e.fromID {
			t.Fatalf("ссылка после отката: %s\n%s", got, e.out)
		}
	}
	m, err := readManifestPair(e.u.p, filepath.Join(e.root, "opt", "aisec"))
	if err != nil || m.ID != e.fromID {
		t.Fatalf("установлен не прежний выпуск: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(e.root, "opt", "aisec-releases"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, en := range entries {
		if en.Name() != e.fromID {
			t.Fatalf("в каталоге версий осталось лишнее: %v", entries)
		}
	}
	if len(e.db.applied) != 2 {
		t.Fatalf("БД не в прежнем состоянии: %d миграций", len(e.db.applied))
	}
	if (e.db.restores == 1) != wantRestore || e.db.restores > 1 {
		t.Fatalf("восстановлений копии: %d, ожидалось %v\n%s", e.db.restores, wantRestore, e.out)
	}
	for _, unit := range []string{unitGateway, unitServer} {
		if !e.host.states[unit].Active {
			t.Fatalf("%s не запущен после отката\n%s", unit, e.out)
		}
	}
	if e.host.gated {
		t.Fatal("приём событий остался закрытым")
	}
	if got := strings.Join(e.db.audits, ","); got != "update.started,update.rollback" {
		t.Fatalf("аудит: %s", got)
	}
	if st, err := e.u.state.load(); err != nil || st != nil {
		t.Fatalf("журнал не удалён: %v", err)
	}
	if !strings.Contains(e.out.String(), "Откат выполнен: работает выпуск 1.0") {
		t.Fatal(e.out.String())
	}
}

// Прерывание процесса между шагами: повторный запуск без каталога
// откатывает, если проверка здоровья не пройдена, и доводит, если пройдена.
func TestUpdateResumeAfterCrash(t *testing.T) {
	crash := func(t *testing.T, e *updEnv) {
		t.Helper()
		if err := e.u.state.open(); err != nil {
			t.Fatal(err)
		}
		defer e.u.state.close()
		pl, err := e.u.check(context.Background(), e.src, false)
		if err != nil {
			t.Fatal(err)
		}
		st := e.u.newState(pl)
		if err := e.u.state.save(st); err != nil {
			t.Fatal(err)
		}
		if err := e.u.forward(context.Background(), st, pl); !errors.Is(err, errCrash) {
			t.Fatalf("ожидался обрыв: %v", err)
		}
	}
	t.Run("до проверки здоровья — откат", func(t *testing.T) {
		e := newUpdEnv(t)
		e.host.fail["start:aisec-server"] = errCrash
		crash(t, e)
		if err := e.u.run("status", "", false); err != nil || !strings.Contains(e.out.String(), "выполнит: откат") {
			t.Fatalf("status: %v %s", err, e.out)
		}
		if err := e.u.run("check", e.src, false); err == nil {
			t.Fatal("check при незавершённом обновлении")
		}
		if err := e.u.run("apply", "", false); !errors.Is(err, errUpdateRolledBack) {
			t.Fatalf("%v\n%s", err, e.out)
		}
		// Запись update.started пишет apply, crash её не делает.
		e.db.audits = append([]string{"update.started"}, e.db.audits...)
		assertRolledBack(t, e, true)
	})
	t.Run("после проверки здоровья — завершение", func(t *testing.T) {
		e := newUpdEnv(t)
		e.host.fail["gate:off"] = errCrash
		crash(t, e)
		if err := e.u.run("apply", "", false); err != nil {
			t.Fatalf("%v\n%s", err, e.out)
		}
		if got := e.link(t); got != "aisec-releases/"+e.toID || e.host.gated {
			t.Fatalf("не доведено: %s", got)
		}
		if got := strings.Join(e.db.audits, ","); got != "update.install" {
			t.Fatalf("аудит: %s", got)
		}
	})
	t.Run("обрыв посреди перехода на каталоги версий", func(t *testing.T) {
		e := newUpdEnv(t)
		l := e.u.layout(componentMain)
		e.host.onStop = func() {}
		crashAdopt := func() {
			// Каталог уже переименован, ссылки ещё нет.
			if err := os.MkdirAll(l.releases(), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(l.link(), l.release(e.fromID)); err != nil {
				t.Fatal(err)
			}
		}
		e.host.fail["stop:aisec-server"] = errCrash
		crash(t, e)
		crashAdopt()
		if err := e.u.run("apply", "", false); !errors.Is(err, errUpdateRolledBack) {
			t.Fatalf("%v\n%s", err, e.out)
		}
		if got := e.link(t); got != "aisec-releases/"+e.fromID {
			t.Fatalf("ссылка: %s", got)
		}
	})
}

// Проверка до действий (ОБН.1, ОБН.3): отказ ничего не меняет.
func TestUpdateCheckRejects(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, e *updEnv)
		reject bool // ошибка выпуска (код 3), а не окружения
		want   string
	}{
		{"подпись", func(t *testing.T, e *updEnv) {
			if err := os.WriteFile(filepath.Join(e.src, integrity.SignatureFile), []byte("не подпись"), 0o644); err != nil { //nolint:gosec // G306: тест
				t.Fatal(err)
			}
		}, true, "подпис"},
		{"изменённый файл", func(t *testing.T, e *updEnv) {
			if err := os.WriteFile(filepath.Join(e.src, "bin", "aisec-cli"), []byte("синтетический бинарник 2.0 aisec-clX"), 0o755); err != nil { //nolint:gosec // G306: тест
				t.Fatal(err)
			}
		}, true, "не совпадает с подписанным манифестом"},
		{"ссылка вместо файла", func(t *testing.T, e *updEnv) { linkTo(t, filepath.Join(e.src, "bin"), "aisec-gateway") }, true, "не обычный файл"},
		{"ссылка вместо манифеста", func(t *testing.T, e *updEnv) { linkTo(t, e.src, integrity.ManifestFile) }, true, "не обычный файл"},
		{"старый выпуск", func(t *testing.T, e *updEnv) {
			_ = os.RemoveAll(e.src) //nolint:gosec // G104: тест
			writeRelease(t, e.src, mainSpec("0.9", updOld.Add(-time.Hour), ""))
		}, true, "-allow-older"},
		{"база новее выпуска", func(t *testing.T, e *updEnv) {
			_ = os.RemoveAll(e.src) //nolint:gosec // G104: тест
			writeRelease(t, e.src, mainSpec("2.0", updNew, migrationsDir(t, 1)))
		}, true, "база новее выпуска"},
		{"изменённая миграция", func(t *testing.T, e *updEnv) { e.db.applied[1].Checksum = strings.Repeat("0", 64) }, true, "изменена после применения"},
		{"нет места", func(t *testing.T, e *updEnv) { e.u.free = func(string) (int64, error) { return 1 << 20, nil } }, false, "мало места"},
		{"установка из пакета", func(t *testing.T, e *updEnv) { e.host.packaged = true }, false, "пакет"},
		{"проверка здоровья не настроена", func(t *testing.T, e *updEnv) { e.host.fail["ready:before"] = errors.New("x509") }, false, "проверка здоровья не настроена"},
		{"нет строки подключения", func(t *testing.T, e *updEnv) { e.u.db = nil }, false, "строка подключения"},
		{"анализатор вместо основного", func(t *testing.T, e *updEnv) {
			_ = os.RemoveAll(e.src) //nolint:gosec // G104: тест
			writeRelease(t, e.src, relSpec{version: "2.0", created: updNew, bins: []string{"aisec-cli", "aisec-media"}, body: "x"})
		}, true, "набора исполняемых файлов"},
		{"каталог версий доступен на запись группе", func(t *testing.T, e *updEnv) {
			if err := os.Chmod(filepath.Join(e.root, "opt"), 0o775); err != nil { //nolint:gosec // G302: проверка отказа
				t.Fatal(err)
			}
		}, false, "права"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newUpdEnv(t)
			c.setup(t, e)
			err := e.apply(t)
			if err == nil || errors.Is(err, errReleaseRejected) != c.reject {
				t.Fatalf("ошибка %v, отказ выпуска %v\n%s", err, c.reject, e.out)
			}
			if !strings.Contains(err.Error()+e.out.String(), c.want) {
				t.Fatalf("нет %q: %v\n%s", c.want, err, e.out)
			}
			for _, call := range e.host.calls {
				if call != "ready" {
					t.Fatalf("при отказе проверки выполнено действие %s", call)
				}
			}
			if info, err := os.Lstat(filepath.Join(e.root, "opt", "aisec")); err != nil || !info.IsDir() {
				t.Fatal("установка изменена")
			}
			if len(e.db.audits) > 0 && (e.db.audits[0] != "update.install" || !c.reject) {
				t.Fatalf("аудит: %v", e.db.audits)
			}
		})
	}
}

// Источник — только локальный каталог (ОБН.3).
func TestUpdateSourceLocalOnly(t *testing.T) {
	for _, dir := range []string{"https://example.invalid/release", "relative/dir", "/нет/такого/каталога"} {
		if err := checkSourceDir(dir); err == nil {
			t.Fatalf("%s принят", dir)
		}
	}
	if err := checkSourceDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

// Намеренный откат (-allow-older): разрешён, если схема БД совпадает;
// целостность проверяется с -accept-rollback.
func TestUpdateAllowOlder(t *testing.T) {
	e := newUpdEnv(t)
	if err := e.apply(t); err != nil {
		t.Fatal(err)
	}
	// Назад на 1.0 нельзя: в БД уже три миграции.
	writeOld := filepath.Join(t.TempDir(), "old")
	writeRelease(t, writeOld, mainSpec("1.0", updOld, migrationsDir(t, 2)))
	e.src = writeOld
	if err := e.apply(t, "-allow-older"); !errors.Is(err, errReleaseRejected) {
		t.Fatalf("откат через схему: %v", err)
	}
	// Выпуск 1.5 старше 2.0, но с той же схемой — с флагом.
	mid := filepath.Join(t.TempDir(), "mid")
	all := migrationsDir(t, 3)
	writeRelease(t, mid, mainSpec("1.5", updOld.Add(time.Hour), all))
	e.src = mid
	e.db.applied = e.migrations // тот же текст миграций, что в 2.0
	if err := e.apply(t); !errors.Is(err, errReleaseRejected) {
		t.Fatalf("без флага: %v", err)
	}
	e.host.calls = nil
	if err := e.apply(t, "-allow-older"); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if !strings.Contains(strings.Join(e.host.calls, ","), "cli:verify -accept-rollback") {
		t.Fatalf("нет -accept-rollback: %v", e.host.calls)
	}
}

// Анализатор: только своя служба, без БД; не новее основного выпуска.
func TestUpdateMediaComponent(t *testing.T) {
	e := newUpdEnv(t)
	mroot := e.u.roots[componentMedia]
	if err := os.MkdirAll(filepath.Join(mroot, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(mroot, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	media := func(v string, at time.Time) relSpec {
		return relSpec{version: v, created: at, bins: []string{"aisec-media"}, body: "media " + v}
	}
	writeRelease(t, filepath.Join(mroot, "opt", "aisec"), media("0.9", updOld.Add(-2*time.Hour)))
	e.host.states[unitMedia] = &unitState{Active: true}
	newer := filepath.Join(t.TempDir(), "m3")
	writeRelease(t, newer, media("3.0", updNew.Add(time.Hour)))
	e.src = newer
	if err := e.apply(t); !errors.Is(err, errReleaseRejected) || !strings.Contains(e.out.String(), "сначала обновите aisec") {
		t.Fatalf("новее основного: %v\n%s", err, e.out)
	}
	ok := filepath.Join(t.TempDir(), "m09")
	writeRelease(t, ok, media("1.0", updOld.Add(-time.Hour)))
	e.src = ok
	e.host.calls = nil
	e.db.audits = nil // отказ выпуска выше записан как update.install с failure
	if err := e.apply(t); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if got := strings.Join(e.host.calls, ","); got != "stop:aisec-media,start:aisec-media" {
		t.Fatalf("действия: %s", got)
	}
	if len(e.db.audits) != 0 {
		t.Fatal("анализатор пишет в БД")
	}
	target, err := os.Readlink(filepath.Join(mroot, "opt", "aisec"))
	if err != nil || !strings.HasPrefix(target, "aisec-releases/1.0-") {
		t.Fatalf("ссылка анализатора: %s %v", target, err)
	}
}

// Узел только со шлюзом: без БД и аудита, шлюз останавливается и
// запускается, приём событий не закрывается.
func TestUpdateGatewayOnlyNode(t *testing.T) {
	e := newUpdEnv(t)
	delete(e.host.states, unitServer)
	e.u.db = nil
	if err := e.apply(t); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if got := strings.Join(e.host.calls, ","); got != "stop:aisec-gateway,start:aisec-gateway,cli:verify" {
		t.Fatalf("действия: %s", got)
	}
}

// Команда: только через обёртку и только от root.
func TestUpdateCmdGuards(t *testing.T) {
	t.Setenv(updateEnvMarker, "")
	var out, errOut strings.Builder
	if code := run([]string{"update", "status"}, &out, &errOut, now); code != 1 || !strings.Contains(errOut.String(), "/usr/sbin/aisec-cli") {
		t.Fatalf("без обёртки: %d %s", code, errOut.String())
	}
	if os.Geteuid() != 0 {
		t.Setenv(updateEnvMarker, "systemd")
		errOut.Reset()
		if code := run([]string{"update", "status"}, &out, &errOut, now); code != 1 || !strings.Contains(errOut.String(), "root") {
			t.Fatalf("не root: %d %s", code, errOut.String())
		}
	}
	for _, args := range [][]string{{"update"}, {"update", "frob"}, {"update", "check"}, {"update", "check", "a", "b"}, {"update", "status", "x"}} {
		errOut.Reset()
		if code := run(args, &out, &errOut, now); code != 1 {
			t.Fatalf("%v: код %d", args, code)
		}
	}
}

// Журнал: правила разбора.
func TestParseUpdateState(t *testing.T) {
	e := newUpdEnv(t)
	if err := e.u.state.open(); err != nil {
		t.Fatal(err)
	}
	defer e.u.state.close()
	pl, err := e.u.check(context.Background(), e.src, false)
	if err != nil {
		t.Fatal(err)
	}
	st := e.u.newState(pl)
	if err := e.u.state.save(st); err != nil {
		t.Fatal(err)
	}
	got, err := e.u.state.load()
	if err != nil || got.ToID != e.toID || got.AppliedBefore != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	info, err := os.Stat(filepath.Join(e.u.state.dir, updateStateFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("права журнала: %v", info)
	}
	data, _ := os.ReadFile(filepath.Join(e.u.state.dir, updateStateFile)) //nolint:gosec // G304: тест
	for _, bad := range []string{
		strings.Replace(string(data), `"step": "checked"`, `"step": "unknown"`, 1),
		strings.Replace(string(data), `"component": "aisec"`, `"component": "x"`, 1),
		strings.Replace(string(data), `"format"`, `"extra": 1, "format"`, 1),
		strings.Replace(string(data), e.toID, "../../etc", 1),
		strings.Replace(string(data), `"aisec-gateway"`, `"sshd"`, 1),
		string(data) + "{}",
	} {
		if _, err := parseUpdateState([]byte(bad)); err == nil {
			t.Fatalf("принят неверный журнал:\n%s", bad)
		}
	}
	// Вторая блокировка — отказ.
	other := &stateStore{dir: e.u.state.dir, ownerUID: os.Getuid()}
	if err := other.open(); err == nil || !strings.Contains(err.Error(), "уже выполняется") {
		t.Fatalf("вторая блокировка: %v", err)
	}
}

func TestParseEnvFile(t *testing.T) {
	m, err := parseEnvFile([]byte("# комментарий\nAISEC_SERVER_LISTEN=0.0.0.0:8444\n; ещё\nA='x y'\nB=\"z\"\n\nActiveState=active\n"))
	if err != nil || m["AISEC_SERVER_LISTEN"] != "0.0.0.0:8444" || m["A"] != "x y" || m["B"] != "z" || m["ActiveState"] != "active" {
		t.Fatalf("%v %v", m, err)
	}
	for _, bad := range []string{"=x", "1A=x", "A B=x", "только текст"} {
		if _, err := parseEnvFile([]byte(bad)); err == nil {
			t.Fatalf("принято %q", bad)
		}
	}
	u, err := healthURLFromEnv(m)
	if err != nil || u != "https://127.0.0.1:8444/readyz" {
		t.Fatalf("%s %v", u, err)
	}
	if u, _ := healthURLFromEnv(map[string]string{"AISEC_SERVER_LISTEN": "[::]:9443"}); u != "https://[::1]:9443/readyz" {
		t.Fatal(u)
	}
	for _, bad := range []string{"http://127.0.0.1/readyz", "https://u:p@h/readyz", "https:///x"} {
		if checkHealthURL(bad) == nil {
			t.Fatalf("принят %s", bad)
		}
	}
}

func TestFilterTOC(t *testing.T) {
	list := ";\n; Archive created\n;\n215; 2615 2200 SCHEMA - public pg_database_owner\n3; 2615 1 SCHEMA - other x\n216; 0 0 COMMENT - SCHEMA public pg_database_owner\n217; 1259 1 TABLE public t aisec_owner\n"
	got := filterTOC(list, "public")
	if strings.Contains(got, "SCHEMA - public") || !strings.Contains(got, "SCHEMA - other") || !strings.Contains(got, "COMMENT - SCHEMA public") ||
		!strings.Contains(got, "TABLE public t") {
		t.Fatal(got)
	}
	if roleIdent(`"Ро""ль"`) != `"Ро""ль"` || roleIdent("aisec_owner") != `"aisec_owner"` {
		t.Fatal(roleIdent(`"Ро""ль"`))
	}
}

func FuzzUpdateState(f *testing.F) {
	f.Add([]byte(`{"format":"aisec-update-state-v1","id":"20261107T000000Z","component":"aisec","started_at":"2026-11-07T00:00:00Z","step":"checked","from_id":"1.0-0123456789ab","from_version":"1.0","from_sha256":"` +
		strings.Repeat("a", 64) + `","to_id":"2.0-0123456789ab","to_version":"2.0","to_sha256":"` + strings.Repeat("b", 64) + `","adopt":false,"units":["aisec-gateway"],"db":true,"applied_before":2,"allow_older":false,"gated":false}`))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := parseUpdateState(data)
		if err != nil {
			return
		}
		if s.validate() != nil || !releaseIDRe.MatchString(s.ToID) || strings.Contains(s.ToID, "/") || strings.Contains(s.FromID, "..") {
			t.Fatalf("принят неверный журнал: %+v", s)
		}
	})
}

func FuzzParseEnvFile(f *testing.F) {
	f.Add([]byte("A=1\n# x\nB='2'\n"))
	f.Add([]byte("ActiveState=active\nNRestarts=0\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := parseEnvFile(data)
		if err != nil {
			return
		}
		for k, v := range m {
			if !envKeyOK(k) || strings.ContainsRune(v, 0) || strings.ContainsRune(v, '\n') {
				t.Fatalf("неверная пара %q=%q", k, v)
			}
		}
	})
}
