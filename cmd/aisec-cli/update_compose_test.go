package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Тесты обновления установки в docker compose (задача 6.21, ADR-0036,
// раздел 7): тот же updater, те же шаги и отказы, что в 6.19–6.20, но
// раскладка — образы, а службы и БД — подделка docker. Работа с настоящим
// docker — ручная проверка 11.

// fakeImg — образ в хранилище подделки.
type fakeImg struct {
	layers        []string
	cfgLine       string
	manifest, sig []byte
}

// fakeCont — контейнер сервиса.
type fakeCont struct {
	id       string
	running  bool
	restarts int
	tag      string // тег образа, из которого создан
	gated    bool
}

// fakeDocker — docker и docker compose установки в памяти. Сбои
// одноразовые: откат вызывает те же действия ещё раз и должен их выполнить.
type fakeDocker struct {
	t         testing.TB
	envPath   string
	services  []string
	images    map[string]*fakeImg
	conts     map[string]*fakeCont
	tmp       map[string]string // временные контейнеры create → ссылка образа
	n         int
	ev        []string // изменяющие действия и запуски aisec-cli по порядку
	calls     []string
	fail      map[string]error
	gateOK    bool
	dbTags    []string // теги образов aisec-cli, которыми вызван update-db
	brokenTag string   // aisec-cli этого тега не запускается
	ports     map[string][]string
	rootDir   string
	// БД.
	applied, dumped, migrateTo []store.Applied
	audits                     []string
	restores                   int
	// Крючки.
	onStop   func()
	onVerify func()
	unstable map[string]bool
	started  bool
	readyErr error
}

func (f *fakeDocker) take(key string) error {
	err := f.fail[key]
	delete(f.fail, key)
	return err
}

// envGate — в .env записано закрытие приёма: compose подставит его в
// команду любого нового контейнера сервера.
func (f *fakeDocker) envGate() bool {
	data, err := os.ReadFile(f.envPath) //nolint:gosec // G304: файл теста
	if err != nil {
		f.t.Fatal(err)
	}
	vals, err := parseEnvFile(data)
	if err != nil {
		f.t.Fatal(err)
	}
	return vals[composeGateEnv] == composeGateValue
}

func (f *fakeDocker) envTag() string {
	data, err := os.ReadFile(f.envPath) //nolint:gosec // G304: файл теста
	if err != nil {
		f.t.Fatal(err)
	}
	vals, err := parseEnvFile(data)
	if err != nil {
		f.t.Fatal(err)
	}
	return vals["AISEC_VERSION"]
}

func (f *fakeDocker) newID() string {
	f.n++
	return fmt.Sprintf("%012x", f.n)
}

func (f *fakeDocker) byID(id string) (string, *fakeCont) {
	for svc, c := range f.conts {
		if c.id == id {
			return svc, c
		}
	}
	return "", nil
}

func (f *fakeDocker) Run(_ context.Context, c dockerCall) (string, error) {
	a := c.Args
	f.calls = append(f.calls, strings.Join(a[:min(len(a), 4)], " "))
	if len(a) == 0 {
		return "", errors.New("пустая команда")
	}
	if a[0] == "compose" {
		return f.compose(c)
	}
	switch a[0] {
	case "image":
		return f.image(a)
	case "inspect": // inspect --format … id
		_, ct := f.byID(a[len(a)-1])
		if ct == nil {
			return "", errors.New("No such object")
		}
		if f.unstable[f.svcOf(ct)] && ct.running {
			ct.restarts++
		}
		return fmt.Sprintf("%v %d", ct.running, ct.restarts), nil
	case "create":
		ref := a[len(a)-1]
		if _, ok := f.images[ref]; !ok {
			return "", errors.New("Error: No such image: " + ref)
		}
		id := f.newID()
		f.tmp[id] = ref
		return id, nil
	case "rm":
		delete(f.tmp, a[1])
		return "", nil
	case "cp": // cp -q id:/путь каталог/
		id, file, _ := strings.Cut(a[2], ":")
		img := f.images[f.tmp[id]]
		if img == nil {
			return "", errors.New("нет контейнера")
		}
		data := img.manifest
		if strings.HasSuffix(file, ".sig") {
			data = img.sig
		}
		return "", os.WriteFile(filepath.Join(strings.TrimSuffix(a[3], "/"), path.Base(file)), data, 0o600) //nolint:gosec // G703: путь — в t.TempDir(), подделка docker cp
	case "load":
		return "", f.load(a[len(a)-1])
	case "rmi":
		f.ev = append(f.ev, "rmi:"+a[1])
		if err := f.take("rmi"); err != nil {
			return "", err
		}
		delete(f.images, a[1])
		return "", nil
	case "info":
		return f.rootDir, nil
	}
	return "", fmt.Errorf("неожиданная команда docker %v", a)
}

func (f *fakeDocker) svcOf(c *fakeCont) string {
	for svc, v := range f.conts {
		if v == c {
			return svc
		}
	}
	return ""
}

func (f *fakeDocker) image(a []string) (string, error) {
	switch a[1] {
	case "ls": // image ls --format {{.Tag}} repo
		repo := a[len(a)-1]
		var tags []string
		for ref := range f.images {
			if r, tag, _ := strings.Cut(ref, ":"); r == repo {
				tags = append(tags, tag)
			}
		}
		return strings.Join(tags, "\n"), nil
	case "inspect":
		ref := a[len(a)-1]
		img, ok := f.images[ref]
		if !ok {
			return "", errors.New("Error: No such image: " + ref)
		}
		switch a[3] {
		case "{{.Id}}":
			return "sha256:" + strings.Repeat("a", 64), nil
		case "{{json .RootFS.Layers}}":
			b, _ := json.Marshal(img.layers) //nolint:gosec // G104: тест, срез строк сериализуется всегда
			return string(b), nil
		case imageConfigFormat:
			return img.cfgLine, nil
		}
	}
	return "", fmt.Errorf("неожиданная команда docker %v", a)
}

// load читает архив настоящим разбором: ссылка, слои и файлы /opt/aisec.
func (f *fakeDocker) load(file string) error {
	f.ev = append(f.ev, "load:?")
	if err := f.take("load"); err != nil {
		return err
	}
	open := func() (*os.File, error) { return os.Open(file) } //nolint:gosec // G304: копия в каталоге теста
	small := map[string][]byte{}
	if _, err := walkImageArchive(open, func(name string, sz int64, r io.Reader) error {
		if sz > imgMaxJSON {
			return nil
		}
		data, err := io.ReadAll(r)
		small[name] = data
		return err
	}); err != nil {
		return err
	}
	var ms []dockerManifestEntry
	if err := json.Unmarshal(small["manifest.json"], &ms); err != nil || len(ms) != 1 {
		return errors.New("fake load: нет manifest.json")
	}
	var cfg imageConfigJSON
	if err := json.Unmarshal(small[ms[0].Config], &cfg); err != nil {
		return err
	}
	ref := ms[0].RepoTags[0]
	_, base, _ := strings.Cut(ref, "/")
	name, _, _ := strings.Cut(base, ":")
	img := &fakeImg{layers: cfg.RootFS.DiffIDs, cfgLine: wantConfigLine(imageSpec{Name: name, Ports: f.ports[name]})}
	f.ev[len(f.ev)-1] = "load:" + name
	for _, l := range ms[0].Layers {
		blob := small[l]
		var r io.Reader = bytes.NewReader(blob)
		if len(blob) > 2 && blob[0] == 0x1f && blob[1] == 0x8b {
			gz, err := gzip.NewReader(r)
			if err != nil {
				return err
			}
			r = gz
		}
		tr := tar.NewReader(r)
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			data, _ := io.ReadAll(tr) //nolint:gosec // G104: тест
			switch h.Name {
			case imgInstall + "/aisec-manifest.json":
				img.manifest = data
			case imgInstall + "/aisec-manifest.json.sig":
				img.sig = data
			}
		}
	}
	f.images[ref] = img
	return nil
}

func (f *fakeDocker) compose(c dockerCall) (string, error) {
	a := c.Args[1:]
	switch a[0] {
	case "config":
		if len(a) > 1 && a[1] == "--services" {
			return strings.Join(f.services, "\n"), nil
		}
		listen := "0.0.0.0:8445"
		if f.gateOK && slices.Contains(c.Env, composeGateEnv+"="+composeGateValue) {
			listen = composeGateValue
		}
		return "services:\n  aisec-server:\n    command:\n      - -internal-listen=" + listen + "\n", nil
	case "ps": // ps -a -q сервис
		if ct := f.conts[a[len(a)-1]]; ct != nil {
			return ct.id, nil
		}
		return "", nil
	case "stop":
		svc := a[1]
		f.ev = append(f.ev, "stop:"+svc)
		if f.onStop != nil {
			h := f.onStop
			f.onStop = nil
			h()
		}
		if err := f.take("stop:" + svc); err != nil {
			return "", err
		}
		if ct := f.conts[svc]; ct != nil {
			ct.running = false
		}
		return "", nil
	case "up":
		svc := a[len(a)-1]
		recreate := slices.Contains(a, "--force-recreate")
		gated := slices.Contains(c.Env, composeGateEnv+"="+composeGateValue) || (svc == "aisec-server" && f.envGate())
		ev := "up:" + svc
		if recreate {
			ev = "recreate:" + svc
		}
		if gated {
			ev += ":gated"
		}
		f.ev = append(f.ev, ev)
		key := "up:" + svc
		if recreate {
			key = "recreate:" + svc
		}
		if err := f.take(key); err != nil {
			return "", err
		}
		tag := f.envTag()
		if _, ok := f.images["aisec-test/"+svc+":"+tag]; !ok {
			return "", errors.New("Error: No such image: " + svc + ":" + tag)
		}
		f.started = true
		old := f.conts[svc]
		if old != nil && !recreate && old.tag == tag && old.gated == gated {
			old.running = true
			return "", nil
		}
		f.conts[svc] = &fakeCont{id: f.newID(), running: true, tag: tag, gated: gated}
		return "", nil
	case "run": // run --rm --no-deps -T aisec-cli …
		return f.runCLI(c, a[5:])
	case "exec": // exec -T postgres …
		return f.execDB(c, a[3:])
	}
	return "", fmt.Errorf("неожиданная команда compose %v", a)
}

func (f *fakeDocker) runCLI(c dockerCall, args []string) (string, error) {
	switch args[0] {
	case "migrate":
		f.ev = append(f.ev, "migrate")
		if err := f.take("migrate"); err != nil {
			return "", err
		}
		f.applied = slices.Clone(f.migrateTo)
		return "применено миграций", nil
	case "verify":
		f.ev = append(f.ev, "verify")
		if f.onVerify != nil {
			f.onVerify()
		}
		return "Целостность не нарушена.", f.take("verify")
	case "update-db":
		// Образ берётся по AISEC_VERSION из окружения вызова, иначе из .env.
		tag := f.envTag()
		for _, kv := range c.Env {
			if v, ok := strings.CutPrefix(kv, "AISEC_VERSION="); ok {
				tag = v
			}
		}
		f.dbTags = append(f.dbTags, tag)
		if f.brokenTag != "" && tag == f.brokenTag {
			return "", errors.New("aisec-cli этого выпуска не запускается")
		}
		switch args[1] {
		case "info":
			in := dbInfo{Schema: "public", Size: 1 << 20, Applied: []dbInfoMigrat{}}
			for _, a := range f.applied {
				in.Applied = append(in.Applied, dbInfoMigrat{Version: a.Version, Name: a.Name, Checksum: a.Checksum})
			}
			b, _ := json.Marshal(in) //nolint:gosec // G104: тест, структура сериализуется всегда
			return string(b), nil
		case "header":
			return "DROP SCHEMA \"public\" CASCADE;\nCREATE SCHEMA \"public\";", nil
		case "audit":
			data, _ := io.ReadAll(c.Stdin) //nolint:gosec // G104: тест, подделка docker читает поток
			e, err := parseUpdateAudit(data)
			if err != nil {
				return "", err
			}
			if err := f.take("audit:" + e.Action); err != nil {
				return "", err
			}
			f.audits = append(f.audits, e.Action)
			f.ev = append(f.ev, "audit:"+e.Action)
			return "", nil
		}
	}
	return "", fmt.Errorf("неожиданная команда aisec-cli %v", args)
}

func (f *fakeDocker) execDB(c dockerCall, args []string) (string, error) {
	switch {
	case len(args) >= 4 && args[0] == "sh" && args[2] == dumpScript:
		f.ev = append(f.ev, "dump")
		if err := f.take("dump"); err != nil {
			return "", err
		}
		f.dumped = slices.Clone(f.applied)
		_, err := io.WriteString(c.Stdout, "копия")
		return "", err
	case len(args) >= 3 && args[0] == "sh" && args[2] == restoreScript:
		f.ev = append(f.ev, "restore")
		if err := f.take("restore"); err != nil {
			return "", err
		}
		f.restores++
		f.applied = slices.Clone(f.dumped)
		return "", nil
	case len(args) >= 3 && args[0] == "sh" && strings.HasPrefix(args[2], "umask 077; cat >"):
		_, _ = io.Copy(io.Discard, c.Stdin) //nolint:gosec // G104: тест
		return "", nil
	case len(args) == 2 && args[0] == "pg_restore" && args[1] == "-l":
		if c.Stdin != nil {
			_, _ = io.Copy(io.Discard, c.Stdin) //nolint:gosec // G104: тест
		}
		return "; список\n1; 1 1 SCHEMA - public owner\n2; 1 2 TABLE public t1 owner", nil
	}
	return "", fmt.Errorf("неожиданная команда postgres %v", args)
}

// ---- Установка и выпуски ----

var imageNames = []string{"aisec-server", "aisec-gateway", "aisec-cli"}

var imagePorts = map[string][]string{
	"aisec-server":  {"8444/tcp", "8445/tcp"},
	"aisec-gateway": {"8443/tcp"},
	"aisec-cli":     nil,
	"aisec-media":   nil,
}

// writeComposeRelease — каталог выпуска для compose: манифест, подпись,
// bin/ и images/*.tar; с media — подкаталог media/.
func writeComposeRelease(t testing.TB, p aisecCrypto.Provider, dir string, s relSpec, media bool) {
	t.Helper()
	writeRelease(t, dir, s)
	rel, err := readManifestPair(p, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "images"), 0o755); err != nil { //nolint:gosec // G301: каталог выпуска теста
		t.Fatal(err)
	}
	tag := s.version + "-test"
	for _, name := range imageNames {
		bins := []string{name}
		if name == "aisec-cli" {
			bins = s.bins
		}
		spec := imageSpec{Ref: "aisec-test/" + name + ":" + tag, Name: name, Rel: rel, Bins: bins, Ports: imagePorts[name]}
		b := imgBuild{ref: spec.Ref, name: name, ports: spec.Ports, files: specFiles(t, p, spec, dir)}
		if err := os.WriteFile(filepath.Join(dir, "images", name+".tar"), buildImage(t, p, b), 0o644); err != nil { //nolint:gosec // G306: каталог выпуска теста
			t.Fatal(err)
		}
	}
	if !media {
		return
	}
	md := filepath.Join(dir, "media")
	writeRelease(t, md, relSpec{version: s.version, created: s.created, bins: []string{"aisec-media"}, body: "синтетический бинарник " + s.version})
	mrel, err := readManifestPair(p, md)
	if err != nil {
		t.Fatal(err)
	}
	spec := imageSpec{Ref: "aisec-test/aisec-media:" + tag, Name: "aisec-media", Rel: mrel, All: true}
	if err := os.MkdirAll(filepath.Join(md, "images"), 0o755); err != nil { //nolint:gosec // G301: каталог выпуска теста
		t.Fatal(err)
	}
	b := imgBuild{ref: spec.Ref, name: spec.Name, files: specFiles(t, p, spec, md)}
	if err := os.WriteFile(filepath.Join(md, "images", "aisec-media.tar"), buildImage(t, p, b), 0o644); err != nil { //nolint:gosec // G306: каталог выпуска теста
		t.Fatal(err)
	}
}

// cmpEnv — установка compose во временных каталогах: версия 1.0 работает,
// выпуск 2.0 на «носителе», БД с двумя миграциями из трёх.
type cmpEnv struct {
	u          *updater
	d          *fakeDocker
	host       *composeHost
	lay        *composeLayout
	dir, src   string
	stateDir   string
	out        *bytes.Buffer
	fromID     string
	toID       string
	migrations []store.Applied
	p          aisecCrypto.Provider
}

func newCmpEnv(t *testing.T, media bool) *cmpEnv {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "install")
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // G301: каталог установки теста
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: umask не должен менять права
		t.Fatal(err)
	}
	envText := "# установка пилота\nAISEC_VERSION=1.0-test\nAISEC_IMAGE_REPO=aisec-test\nAISEC_CONSOLE_HOST=aisec.example\nAISEC_DATA_DIR=/srv/aisec\nCOMPOSE_PROFILES=db\n"
	for name, text := range map[string]string{".env": envText, "compose.yaml": "name: aisec\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil { //nolint:gosec // G306: файлы установки читает docker compose
			t.Fatal(err)
		}
	}
	p := standardProvider(t)
	m3 := migrationsDir(t, 3)
	m2 := t.TempDir()
	for _, n := range []string{"0001_m1.sql", "0002_m2.sql"} {
		data, err := os.ReadFile(filepath.Join(m3, n)) //nolint:gosec // G304: временный каталог теста
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(m2, n), data, 0o600); err != nil { //nolint:gosec // G703: временный каталог теста
			t.Fatal(err)
		}
	}
	oldDir := filepath.Join(base, "old")
	writeComposeRelease(t, p, oldDir, mainSpec("1.0", updOld, m2), false)
	src := filepath.Join(base, "media", "release")
	writeComposeRelease(t, p, src, mainSpec("2.0", updNew, m3), media)
	oldRel, err := readManifestPair(p, oldDir)
	if err != nil {
		t.Fatal(err)
	}
	newRel, err := readManifestPair(p, src)
	if err != nil {
		t.Fatal(err)
	}
	all, err := migrationEntries(newRel.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	services := []string{"postgres", "aisec-server", "aisec-gateway"}
	if media {
		services = append(services, "aisec-media")
	}
	d := &fakeDocker{t: t, envPath: filepath.Join(dir, ".env"), services: services, images: map[string]*fakeImg{}, conts: map[string]*fakeCont{},
		tmp: map[string]string{}, fail: map[string]error{}, gateOK: true, ports: imagePorts, rootDir: filepath.Join(base, "docker"),
		applied: all[:2], migrateTo: all}
	for _, name := range imageNames {
		d.images["aisec-test/"+name+":1.0-test"] = &fakeImg{manifest: oldRel.Data, sig: oldRel.Sig}
	}
	for _, svc := range []string{"aisec-gateway", "aisec-server"} {
		d.conts[svc] = &fakeCont{id: d.newID(), running: true, tag: "1.0-test"}
	}
	stateDir := filepath.Join(base, "update")
	sys := &composeSys{r: d, stateDir: stateDir}
	lay := &composeLayout{sys: sys, p: p, dir: dir, stateDir: stateDir, ownerUID: os.Getuid(), rootDir: d.rootDir}
	host := &composeHost{sys: sys, p: p, healthURL: "https://aisec.example:8444/readyz", healthCA: "ca", envPath: filepath.Join(dir, ".env"),
		readyFn: func(context.Context) error {
			d.calls = append(d.calls, "ready")
			if d.started {
				return d.readyErr
			}
			return d.take("ready:before")
		}}
	out := &bytes.Buffer{}
	u := &updater{p: p, host: host, custom: lay, db: &composeDB{sys: sys, p: p, tag: "1.0-test"}, state: &stateStore{dir: stateDir, ownerUID: os.Getuid()},
		roots: map[string]string{componentMain: "/"}, owner: os.Getuid(), out: out, now: time.Now,
		healthTimeout: 50 * time.Millisecond, poll: time.Millisecond, free: func(string) (int64, error) { return 1 << 40, nil }}
	return &cmpEnv{u: u, d: d, host: host, lay: lay, dir: dir, src: src, stateDir: stateDir, out: out, fromID: oldRel.ID, toID: newRel.ID, migrations: all, p: p}
}

func (e *cmpEnv) apply() error { return e.u.run("apply", e.src, false) }

func (e *cmpEnv) version(t *testing.T) string {
	t.Helper()
	return e.d.envTag()
}

func imageTags(d *fakeDocker) []string {
	var refs []string
	for ref := range d.images {
		refs = append(refs, ref)
	}
	slices.Sort(refs)
	return refs
}

// Обновление проходит все шаги и в том же порядке, что установка без
// Docker: копия БД, остановка, образы, миграции, запуск с закрытым
// приёмом, проверка, открытие, итог.
func TestComposeUpdateApplyOK(t *testing.T) {
	e := newCmpEnv(t, false)
	if err := e.apply(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	want := []string{"audit:update.started", "stop:aisec-gateway", "stop:aisec-server", "dump", "load:aisec-server", "load:aisec-gateway", "load:aisec-cli",
		"migrate", "up:aisec-gateway", "up:aisec-server:gated", "verify", "recreate:aisec-server", "audit:update.install"}
	if got := strings.Join(e.d.ev, ","); got != strings.Join(want, ",") {
		t.Fatalf("порядок действий:\n%s\nожидалось\n%s", got, strings.Join(want, ","))
	}
	if got := e.version(t); got != "2.0-test" {
		t.Fatalf("AISEC_VERSION: %s", got)
	}
	data, _ := os.ReadFile(filepath.Join(e.dir, ".env")) //nolint:gosec // G104: тест
	if !strings.Contains(string(data), "# установка пилота\n") || !strings.Contains(string(data), "COMPOSE_PROFILES=db\n") || strings.Count(string(data), "AISEC_VERSION") != 1 {
		t.Fatalf(".env испорчен:\n%s", data)
	}
	// Прежний выпуск остаётся для отката, новый загружен.
	if got := len(e.d.images); got != 6 {
		t.Fatalf("образы: %v", imageTags(e.d))
	}
	srv := e.d.conts["aisec-server"]
	if !srv.running || srv.tag != "2.0-test" || srv.gated {
		t.Fatalf("сервер после обновления: %+v", srv)
	}
	if gw := e.d.conts["aisec-gateway"]; !gw.running || gw.tag != "2.0-test" {
		t.Fatalf("шлюз после обновления: %+v", gw)
	}
	if len(e.d.applied) != 3 || e.d.restores != 0 {
		t.Fatalf("миграции: %d, восстановлений %d", len(e.d.applied), e.d.restores)
	}
	if st, _ := e.u.state.load(); st != nil { //nolint:gosec // G104: журнал проверяется на отсутствие
		t.Fatal("журнал не удалён")
	}
	if entries, _ := os.ReadDir(e.stateDir); len(entries) > 2 { //nolint:gosec // G104: тест
		for _, en := range entries {
			if strings.HasPrefix(en.Name(), composeStagingPref) {
				t.Fatalf("копии архивов остались: %s", en.Name())
			}
		}
	}
	if !strings.Contains(e.out.String(), "Обновление завершено: установлен выпуск 2.0") {
		t.Fatal(e.out.String())
	}
	// Повтор того же выпуска — без действий.
	e.d.ev, e.d.calls = nil, nil
	if err := e.apply(); err != nil || len(e.d.ev) != 0 || !strings.Contains(e.out.String(), "уже установлен") {
		t.Fatalf("повтор: %v %v", err, e.d.ev)
	}
}

// С media/ в выпуске и включённым aisec-media образ анализатора грузится
// вместе с основными и запускается после них.
func TestComposeUpdateWithMedia(t *testing.T) {
	e := newCmpEnv(t, true)
	e.d.conts["aisec-media"] = &fakeCont{id: e.d.newID(), running: true, tag: "1.0-test"}
	e.d.images["aisec-test/aisec-media:1.0-test"] = &fakeImg{}
	if err := e.apply(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	for _, want := range []string{"load:aisec-media", "stop:aisec-media", "up:aisec-media"} {
		if !slices.Contains(e.d.ev, want) {
			t.Fatalf("нет %s: %v", want, e.d.ev)
		}
	}
	if c := e.d.conts["aisec-media"]; !c.running || c.tag != "2.0-test" {
		t.Fatalf("aisec-media: %+v", c)
	}
}

func assertComposeRolledBack(t *testing.T, e *cmpEnv, wantRestore bool) {
	t.Helper()
	if got := e.version(t); got != "1.0-test" {
		t.Fatalf("AISEC_VERSION после отката: %s\n%s", got, e.out)
	}
	for _, ref := range imageTags(e.d) {
		if !strings.HasSuffix(ref, ":1.0-test") {
			t.Fatalf("образы нового выпуска остались: %v", imageTags(e.d))
		}
	}
	for _, svc := range []string{"aisec-gateway", "aisec-server"} {
		c := e.d.conts[svc]
		if !c.running || c.tag != "1.0-test" || c.gated {
			t.Fatalf("%s после отката: %+v\n%s", svc, c, e.out)
		}
	}
	if len(e.d.applied) != 2 {
		t.Fatalf("БД не в прежнем состоянии: %d миграций", len(e.d.applied))
	}
	if (e.d.restores == 1) != wantRestore || e.d.restores > 1 {
		t.Fatalf("восстановлений копии: %d, ожидалось %v\n%s", e.d.restores, wantRestore, e.out)
	}
	if got := strings.Join(e.d.audits, ","); got != "update.started,update.rollback" {
		t.Fatalf("аудит: %s", got)
	}
	if st, err := e.u.state.load(); err != nil || st != nil {
		t.Fatalf("журнал не удалён: %v", err)
	}
	entries, _ := os.ReadDir(e.stateDir) //nolint:gosec // G104: тест
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), composeStagingPref) {
			t.Fatalf("копии архивов остались: %s", en.Name())
		}
	}
	if !strings.Contains(e.out.String(), "Откат выполнен: работает выпуск 1.0") {
		t.Fatal(e.out.String())
	}
}

// Отказ на каждом шаге (6.20 для compose): прежний выпуск работает, БД в
// прежнем состоянии, приём событий открыт, новые образы удалены, журнал
// удалён, в аудите — начало и откат.
func TestComposeRollbackOnEachStep(t *testing.T) {
	boom := errors.New("сбой")
	cases := []struct {
		name        string
		setup       func(e *cmpEnv)
		wantRestore bool
	}{
		{"копия БД", func(e *cmpEnv) { e.d.fail["dump"] = boom }, false},
		{"остановка шлюза", func(e *cmpEnv) { e.d.fail["stop:aisec-gateway"] = boom }, false},
		{"остановка сервера", func(e *cmpEnv) { e.d.fail["stop:aisec-server"] = boom }, false},
		{"загрузка образа", func(e *cmpEnv) { e.d.fail["load"] = boom }, false},
		{"подмена архива после проверки", func(e *cmpEnv) {
			e.d.onStop = func() {
				data, err := os.ReadFile(filepath.Join(e.src, "images", "aisec-gateway.tar")) //nolint:gosec // G304: тест
				if err != nil {
					t.Error(err)
					return
				}
				i := bytes.Index(data, []byte("синтетический бинарник"))
				data[i+2] ^= 0xff
				if err := os.WriteFile(filepath.Join(e.src, "images", "aisec-gateway.tar"), data, 0o644); err != nil { //nolint:gosec // G306: тест
					t.Error(err)
				}
			}
		}, false},
		{"сбой миграции", func(e *cmpEnv) { e.d.fail["migrate"] = boom }, false},
		{"запуск шлюза", func(e *cmpEnv) { e.d.fail["up:aisec-gateway"] = boom }, true},
		{"запуск сервера", func(e *cmpEnv) { e.d.fail["up:aisec-server"] = boom }, true},
		{"сервер не готов", func(e *cmpEnv) { e.d.readyErr = boom }, true},
		{"служба перезапускалась", func(e *cmpEnv) { e.d.unstable = map[string]bool{"aisec-gateway": true} }, true},
		{"контроль целостности", func(e *cmpEnv) { e.d.fail["verify"] = boom }, true},
		{"пересоздание сервера после открытия приёма", func(e *cmpEnv) { e.d.fail["recreate:aisec-server"] = boom }, true},
		{"сигнал остановки", func(e *cmpEnv) {
			var f atomic.Bool
			e.u.stopFlag = &f
			e.d.onStop = func() { f.Store(true) }
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newCmpEnv(t, false)
			c.setup(e)
			if c.name == "сигнал остановки" {
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
			} else if err := e.apply(); !errors.Is(err, errUpdateRolledBack) {
				t.Fatalf("ожидался откат: %v\n%s", err, e.out)
			}
			assertComposeRolledBack(t, e, c.wantRestore)
		})
	}
}

// Закрытый приём — свойство контейнера сервера: новый сервер создаётся с
// 127.0.0.1:0, а после открытия пересоздаётся с обычным адресом; шлюз
// закрытие не затрагивает.
func TestComposeGateOnServerContainers(t *testing.T) {
	e := newCmpEnv(t, false)
	seen := map[string]bool{}
	e.d.onVerify = func() {
		seen["gated"] = e.d.conts["aisec-server"].gated
		seen["gw"] = e.d.conts["aisec-gateway"].gated
	}
	if err := e.apply(); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if !seen["gated"] || seen["gw"] {
		t.Fatalf("при проверке здоровья сервер закрыт: %v, шлюз закрыт: %v", seen["gated"], seen["gw"])
	}
	if e.d.conts["aisec-server"].gated {
		t.Fatal("приём остался закрытым")
	}
}

// Закрытие приёма записано в .env: сервер, поднятый вручную (docker compose
// up -d после перезагрузки хоста посреди обновления), приём не откроет; итог
// и откат убирают строку из .env, остальное в нём не меняется.
func TestComposeGatePersistsInEnv(t *testing.T) {
	e := newCmpEnv(t, false)
	before, err := os.ReadFile(filepath.Join(e.dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.host.Gate(ctx, true); err != nil {
		t.Fatal(err)
	}
	if !e.d.envGate() {
		t.Fatal("закрытие приёма не записано в .env")
	}
	if err := e.host.Gate(ctx, true); err != nil || strings.Count(e.envText(t), composeGateEnv) != 1 {
		t.Fatalf("повторное закрытие: %v\n%s", err, e.envText(t))
	}
	// Ручной запуск без переменных окружения команды.
	if _, err := e.d.compose(dockerCall{Args: []string{"compose", "up", "-d", "--no-deps", "--force-recreate", "aisec-server"}}); err != nil {
		t.Fatal(err)
	}
	if !e.d.conts["aisec-server"].gated {
		t.Fatal("сервер, поднятый вручную, принимает события")
	}
	if err := e.host.Gate(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := e.host.Gate(ctx, false); err != nil {
		t.Fatal("повторное открытие должно быть безопасным: ", err)
	}
	if got := e.envText(t); got != string(before) {
		t.Fatalf(".env после открытия отличается от исходного:\n%s\n---\n%s", got, before)
	}
}

func (e *cmpEnv) envText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Обновление, прерванное после закрытия приёма, не оставляет закрытие в .env
// после отката, а переменная, заданная оператором, отвергается проверкой.
func TestComposeGateRemovedAfterRollback(t *testing.T) {
	e := newCmpEnv(t, false)
	e.d.fail["migrate"] = errors.New("boom")
	if err := e.apply(); err == nil {
		t.Fatal("ожидался откат")
	}
	if strings.Contains(e.envText(t), composeGateEnv) {
		t.Fatalf("после отката в .env осталось закрытие приёма:\n%s", e.envText(t))
	}
	e2 := newCmpEnv(t, false)
	data := append([]byte(e2.envText(t)), []byte(composeGateEnv+"=0.0.0.0:9999\n")...)
	if err := os.WriteFile(filepath.Join(e2.dir, ".env"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e2.u.run("check", e2.src, false); err == nil || !strings.Contains(err.Error(), composeGateEnv) {
		t.Fatalf("check с переменной в .env: %v", err)
	}
}

// Служебные операции с БД (список миграций, заголовок восстановления) при
// откате выполняет aisec-cli установленной версии, а не образ нового выпуска:
// если новый aisec-cli не запускается, откат всё равно проходит.
func TestComposeRollbackUsesTrustedCLI(t *testing.T) {
	e := newCmpEnv(t, false)
	e.d.brokenTag = "2.0-test"
	e.d.fail["verify"] = errors.New("boom") // сбой после миграций: нужен откат с восстановлением БД
	if err := e.apply(); err == nil {
		t.Fatal("ожидался откат")
	}
	assertComposeRolledBack(t, e, true)
	for _, tag := range e.d.dbTags {
		if tag != "1.0-test" {
			t.Fatalf("update-db выполнен образом %s, ожидался установленный 1.0-test: %v", tag, e.d.dbTags)
		}
	}
	if len(e.d.dbTags) == 0 {
		t.Fatal("update-db не вызывался")
	}
}

// Сбой записи итога после открытия приёма не откатывает работающий
// выпуск: журнал остаётся, повторный запуск дописывает итог.
func TestComposeCompleteFailureKeepsRelease(t *testing.T) {
	e := newCmpEnv(t, false)
	e.d.fail["audit:update.install"] = errors.New("БД недоступна")
	err := e.apply()
	if err == nil || errors.Is(err, errUpdateRolledBack) || !strings.Contains(err.Error(), "завершит обновление") {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if got := e.version(t); got != "2.0-test" || e.d.restores != 0 {
		t.Fatalf("версия %s, восстановлений %d", got, e.d.restores)
	}
	e.d.ev = nil
	if err := e.u.run("apply", "", false); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if got := strings.Join(e.d.audits, ","); got != "update.started,update.install" {
		t.Fatalf("аудит: %s", got)
	}
	if st, _ := e.u.state.load(); st != nil { //nolint:gosec // G104: журнал проверяется на отсутствие
		t.Fatal("журнал не удалён")
	}
}

// Прерывание процесса между шагами: повторный запуск откатывает, если
// проверка здоровья не пройдена, и доводит, если пройдена. Новый процесс
// не знает о закрытии приёма в памяти — сервер пересоздаётся открытым.
func TestComposeResumeAfterCrash(t *testing.T) {
	crash := func(t *testing.T, e *cmpEnv) {
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
		if err := e.u.forward(context.Background(), st, pl); err != nil && !errors.Is(err, errCrash) {
			t.Fatalf("ожидался обрыв: %v", err)
		}
		e.host.gated = false // новый процесс
	}
	t.Run("до проверки здоровья — откат", func(t *testing.T) {
		e := newCmpEnv(t, false)
		e.d.fail["up:aisec-server"] = errCrash
		crash(t, e)
		if err := e.u.run("status", "", false); err != nil || !strings.Contains(e.out.String(), "выполнит: откат") {
			t.Fatalf("status: %v %s", err, e.out)
		}
		if err := e.u.run("apply", "", false); !errors.Is(err, errUpdateRolledBack) {
			t.Fatalf("%v\n%s", err, e.out)
		}
		e.d.audits = append([]string{"update.started"}, e.d.audits...)
		assertComposeRolledBack(t, e, true)
	})
	t.Run("после проверки здоровья — завершение", func(t *testing.T) {
		e := newCmpEnv(t, false)
		crash(t, e)
		if err := e.u.run("status", "", false); err != nil || !strings.Contains(e.out.String(), "выполнит: завершение") {
			t.Fatalf("status: %v %s", err, e.out)
		}
		if err := e.u.run("apply", "", false); err != nil {
			t.Fatalf("%v\n%s", err, e.out)
		}
		if got := e.version(t); got != "2.0-test" {
			t.Fatalf("не доведено: %s", got)
		}
		if srv := e.d.conts["aisec-server"]; srv.gated || srv.tag != "2.0-test" {
			t.Fatalf("сервер после завершения: %+v", srv)
		}
	})
}

// Проверка до действий (ОБН.1, ОБН.3): отказ ничего не меняет.
func TestComposeCheckRejects(t *testing.T) {
	cases := []struct {
		name   string
		media  bool
		setup  func(t *testing.T, e *cmpEnv)
		reject bool // ошибка выпуска (код 3), а не окружения
		want   string
	}{
		{"подпись", false, func(t *testing.T, e *cmpEnv) {
			if err := os.WriteFile(filepath.Join(e.src, "aisec-manifest.json.sig"), []byte("не подпись"), 0o644); err != nil { //nolint:gosec // G306: тест
				t.Fatal(err)
			}
		}, true, "подпис"},
		{"изменённый бинарник", false, func(t *testing.T, e *cmpEnv) {
			if err := os.WriteFile(filepath.Join(e.src, "bin", "aisec-cli"), []byte("синтетический бинарник 2.0 aisec-clX"), 0o755); err != nil { //nolint:gosec // G306: тест
				t.Fatal(err)
			}
		}, true, "не совпадает с подписанным манифестом"},
		{"подменённый слой образа", false, func(t *testing.T, e *cmpEnv) {
			f := filepath.Join(e.src, "images", "aisec-server.tar")
			data, err := os.ReadFile(f) //nolint:gosec // G304: тест
			if err != nil {
				t.Fatal(err)
			}
			data[bytes.Index(data, []byte("синтетический бинарник"))+2] ^= 0xff
			if err := os.WriteFile(f, data, 0o644); err != nil { //nolint:gosec // G306: тест
				t.Fatal(err)
			}
		}, true, "aisec-server"},
		{"нет архива образа", false, func(t *testing.T, e *cmpEnv) {
			if err := os.Remove(filepath.Join(e.src, "images", "aisec-gateway.tar")); err != nil {
				t.Fatal(err)
			}
		}, true, "images/aisec-gateway.tar"},
		{"архив образа — ссылка", false, func(t *testing.T, e *cmpEnv) {
			f := filepath.Join(e.src, "images", "aisec-cli.tar")
			if err := os.Rename(f, f+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("aisec-cli.tar.real", f); err != nil {
				t.Fatal(err)
			}
		}, true, "не обычный файл"},
		{"архив не того образа", false, func(t *testing.T, e *cmpEnv) {
			dir := filepath.Join(e.src, "images")
			if err := os.Rename(filepath.Join(dir, "aisec-server.tar"), filepath.Join(dir, "x.tar")); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(dir, "aisec-gateway.tar"), filepath.Join(dir, "aisec-server.tar")); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(dir, "x.tar"), filepath.Join(dir, "aisec-gateway.tar")); err != nil {
				t.Fatal(err)
			}
		}, true, "образ aisec-server"},
		{"старый выпуск", false, func(t *testing.T, e *cmpEnv) {
			_ = os.RemoveAll(e.src) //nolint:gosec // G104: тест
			writeComposeRelease(t, e.p, e.src, mainSpec("0.9", updOld.Add(-time.Hour), ""), false)
		}, true, "-allow-older"},
		{"база новее выпуска", false, func(t *testing.T, e *cmpEnv) {
			_ = os.RemoveAll(e.src) //nolint:gosec // G104: тест
			writeComposeRelease(t, e.p, e.src, mainSpec("2.0", updNew, migrationsDir(t, 1)), false)
		}, true, "база новее выпуска"},
		{"та же версия, другой манифест", false, func(t *testing.T, e *cmpEnv) {
			_ = os.RemoveAll(e.src) //nolint:gosec // G104: тест
			writeComposeRelease(t, e.p, e.src, mainSpec("1.0", updNew, migrationsDir(t, 2)), false)
		}, true, "уже установлены"},
		{"нет места под образы", false, func(t *testing.T, e *cmpEnv) { e.u.free = func(string) (int64, error) { return 1 << 20, nil } }, false, "мало места"},
		{"своя СУБД", false, func(t *testing.T, e *cmpEnv) { e.d.services = []string{"aisec-server", "aisec-gateway"} }, false, "своя СУБД"},
		{"включён aisec-ml", false, func(t *testing.T, e *cmpEnv) { e.d.services = append(e.d.services, "aisec-ml") }, false, "aisec-ml"},
		{"aisec-media включён, а media/ нет", false, func(t *testing.T, e *cmpEnv) { e.d.services = append(e.d.services, "aisec-media") }, true, "media/"},
		{"compose.yaml не закрывает приём", false, func(t *testing.T, e *cmpEnv) { e.d.gateOK = false }, false, "не закрывает приём"},
		{"проверка здоровья не настроена", false, func(t *testing.T, e *cmpEnv) { e.d.fail["ready:before"] = errors.New("x509") }, false, "проверка здоровья не настроена"},
		{"media другой версии", true, func(t *testing.T, e *cmpEnv) {
			_ = os.RemoveAll(filepath.Join(e.src, "media")) //nolint:gosec // G104: тест
			writeRelease(t, filepath.Join(e.src, "media"), relSpec{version: "9.9", created: updNew, bins: []string{"aisec-media"}, body: "x"})
		}, true, "не совпадает с версией"},
		{"каталог установки доступен на запись группе", false, func(t *testing.T, e *cmpEnv) {
			if err := os.Chmod(e.dir, 0o775); err != nil { //nolint:gosec // G302: проверка отказа
				t.Fatal(err)
			}
		}, false, "права"},
		{"неизвестный репозиторий образов", false, func(t *testing.T, e *cmpEnv) {
			if err := os.WriteFile(filepath.Join(e.dir, ".env"), []byte("AISEC_VERSION=1.0\nAISEC_IMAGE_REPO=evil.example/x\n"), 0o644); err != nil { //nolint:gosec // G306: тест
				t.Fatal(err)
			}
		}, false, "AISEC_IMAGE_REPO"},
		{"нет отпечатка ключа производителя", false, func(t *testing.T, e *cmpEnv) {
			if err := os.WriteFile(filepath.Join(e.dir, ".env"), []byte("AISEC_VERSION=1.0\nAISEC_IMAGE_REPO=aisec\n"), 0o644); err != nil { //nolint:gosec // G306: тест
				t.Fatal(err)
			}
			for _, n := range imageNames {
				e.d.images["aisec/"+n+":1.0"] = e.d.images["aisec-test/"+n+":1.0-test"]
			}
		}, false, "AISEC_VENDOR_FINGERPRINT"},
		{"неверный отпечаток ключа", false, func(t *testing.T, e *cmpEnv) {
			if err := os.WriteFile(filepath.Join(e.dir, ".env"), []byte("AISEC_VERSION=1.0\nAISEC_IMAGE_REPO=aisec\nAISEC_VENDOR_FINGERPRINT=aa:bb\n"), 0o644); err != nil { //nolint:gosec // G306: тест
				t.Fatal(err)
			}
			for _, n := range imageNames {
				e.d.images["aisec/"+n+":1.0"] = e.d.images["aisec-test/"+n+":1.0-test"]
			}
		}, false, "это не ключ производителя"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newCmpEnv(t, c.media)
			c.setup(t, e)
			err := e.apply()
			if err == nil || errors.Is(err, errReleaseRejected) != c.reject {
				t.Fatalf("ошибка %v, отказ выпуска %v\n%s", err, c.reject, e.out)
			}
			if !strings.Contains(err.Error()+e.out.String(), c.want) {
				t.Fatalf("нет %q: %v\n%s", c.want, err, e.out)
			}
			// Проверка ничего не меняет: ни остановок, ни загрузок, ни запусков.
			for _, ev := range e.d.ev {
				if ev != "audit:update.install" { // отказ выпуска записывается в аудит
					t.Fatalf("при отказе проверки выполнены действия: %v", e.d.ev)
				}
			}
			if len(e.d.audits) != 0 && (len(e.d.audits) != 1 || e.d.audits[0] != "update.install") {
				t.Fatalf("аудит: %v", e.d.audits)
			}
			if e.version(t) != "1.0-test" && !strings.Contains(c.name, "репозиторий") && !strings.Contains(c.name, "отпечат") && !strings.Contains(c.name, "версия") {
				t.Fatal("AISEC_VERSION изменён")
			}
		})
	}
}

// Файл .env: заменяется только строка версии, остальное сохраняется.
func TestComposeEnvWithVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"AISEC_VERSION=1.0\nA=b\n", "AISEC_VERSION=2.0\nA=b\n"},
		{"# версия\nAISEC_VERSION=\"1.0\"\n\nA=b", "# версия\nAISEC_VERSION=2.0\n\nA=b"},
		{"A=b", "A=b\nAISEC_VERSION=2.0\n"},
		{"A=b\n", "A=b\nAISEC_VERSION=2.0\n"},
		{"AISEC_VERSION=1\nAISEC_VERSION=3\n", "AISEC_VERSION=2.0\nAISEC_VERSION=2.0\n"},
	}
	for _, c := range cases {
		e := &composeEnv{data: []byte(c.in)}
		got, err := e.withVersion("2.0")
		if err != nil || string(got) != c.want {
			t.Fatalf("%q → %q (%v), ожидалось %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "a b", "a\nb", "../x", strings.Repeat("a", 70), "-x"} {
		if _, err := (&composeEnv{}).withVersion(bad); err == nil {
			t.Fatalf("тег %q принят", bad)
		}
	}
}

// Запись аудита на проводе хост → контейнер — недоверенный ввод.
func TestParseUpdateAudit(t *testing.T) {
	good := `{"action":"update.install","result":"success","object_id":"2.0-0123456789ab","details":{"component":"aisec"}}`
	if e, err := parseUpdateAudit([]byte(good)); err != nil || e.Action != "update.install" || e.Object.ID != "2.0-0123456789ab" {
		t.Fatalf("%v %+v", err, e)
	}
	for _, bad := range []string{
		``, `{}`, `[]`, good + `{}`,
		`{"action":"user.delete","result":"success","object_id":"rejected"}`,
		`{"action":"update.install","result":"denied","object_id":"rejected"}`,
		`{"action":"update.install","result":"success","object_id":"../x"}`,
		`{"action":"update.install","result":"success","object_id":"rejected","extra":1}`,
	} {
		if _, err := parseUpdateAudit([]byte(bad)); err == nil {
			t.Fatalf("запись %q принята", bad)
		}
	}
}

func FuzzParseUpdateAudit(f *testing.F) {
	f.Add([]byte(`{"action":"update.started","result":"success","object_id":"rejected","details":{"a":1}}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := parseUpdateAudit(data)
		if err == nil && !updateAuditActions[e.Action] {
			t.Fatalf("принят неизвестный код %q", e.Action)
		}
	})
}
