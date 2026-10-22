//go:build e2e

package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Отказы backup.sh и restore.sh (задача 3.8, 3В3 ревью потока B1): скрипты
// работают от root с недоверенными путями и архивом копии. Docker не
// нужен — вместо него заглушка, которая отвечает только на вопросы о составе
// и состоянии установки; любой другой вызов значит, что проверка пропустила
// плохую копию. Нужен root (скрипты сами его требуют), иначе тест пропускается.

const scriptStubDocker = `#!/bin/sh
case "$*" in
"compose config --services") echo postgres ;;
"compose ps -q") [ -z "${STUB_RUNNING:-}" ] || echo 0123456789ab ;;
*) echo "заглушка docker: неожиданный вызов: $*" >&2; exit 99 ;;
esac
`

// scriptInstall — каталог compose со скриптами и пустая установка.
type scriptInstall struct {
	t               *testing.T
	root, dir, data string
}

func newScriptInstall(t *testing.T) *scriptInstall {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("скрипты установки пилота работают только от root")
	}
	root := t.TempDir()
	s := &scriptInstall{t: t, root: root, dir: filepath.Join(root, "pilot"), data: filepath.Join(root, "data")}
	for _, d := range []string{s.dir, filepath.Join(root, "bin"), filepath.Join(s.data, "keys"), filepath.Join(s.data, "secrets"),
		filepath.Join(s.data, "gateway", "reg"), filepath.Join(s.data, "gateway", "state"), filepath.Join(s.data, "pg")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"backup.sh", "restore.sh"} {
		s2Copy(t, filepath.Join("..", "..", "deploy", "compose", "pilot", f), filepath.Join(s.dir, f), 0o755)
	}
	mustWrite(t, filepath.Join(s.dir, "compose.yaml"), []byte("services: {}\n"))
	mustWrite(t, filepath.Join(s.dir, ".env"), []byte(s.env(pilotConsoleHost)))
	s2Copy(t, writeTemp(t, scriptStubDocker), filepath.Join(root, "bin", "docker"), 0o755)
	return s
}

func (s *scriptInstall) env(host string) string {
	return "AISEC_DATA_DIR=" + s.data + "\nAISEC_CONSOLE_HOST=" + host + "\nCOMPOSE_PROFILES=db\n"
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	mustWrite(t, p, []byte(content))
	return p
}

// run запускает скрипт с заглушкой docker первой в PATH.
func (s *scriptInstall) run(env []string, script string, args ...string) (string, int) {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(s.dir, script), args...) //nolint:gosec // G204: тест запускает скрипты установки из копии
	cmd.Dir = s.dir
	cmd.Env = append(os.Environ(), append([]string{"PATH=" + filepath.Join(s.root, "bin") + ":" + os.Getenv("PATH")}, env...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	}
	s.t.Fatal(err)
	return "", 0
}

// tarEntry — запись поддельного архива files.tar.
type tarEntry struct {
	name, link string
	typ        byte
	mode       int64
}

// makeCopy собирает каталог копии: files.tar из entries, env, db.dump и
// SHA256SUMS; mutate меняет его после подсчёта сумм.
func (s *scriptInstall) makeCopy(entries []tarEntry, env string, mutate func(dir string)) string {
	s.t.Helper()
	dir := filepath.Join(s.t.TempDir(), "aisec-copy")
	if err := os.Mkdir(dir, 0o700); err != nil {
		s.t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: e.typ, Mode: e.mode, Uname: "root", Gname: "root",
			ModTime: time.Unix(1792700000, 0)}
		var body []byte
		if e.typ == tar.TypeReg {
			body = []byte("синтетическое содержимое\n")
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(h); err != nil {
			s.t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			s.t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		s.t.Fatal(err)
	}
	mustWrite(s.t, filepath.Join(dir, "files.tar"), buf.Bytes())
	mustWrite(s.t, filepath.Join(dir, "env"), []byte(env))
	mustWrite(s.t, filepath.Join(dir, "db.dump"), []byte("PGDMP синтетическая копия"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sha256sum", "files.tar", "env", "db.dump")
	cmd.Dir = dir
	sums, err := cmd.Output()
	if err != nil {
		s.t.Fatal(err)
	}
	mustWrite(s.t, filepath.Join(dir, "SHA256SUMS"), sums)
	if mutate != nil {
		mutate(dir)
	}
	return dir
}

// goodEntries — допустимый состав files.tar.
var goodEntries = []tarEntry{
	{name: "keys/", typ: tar.TypeDir, mode: 0o700},
	{name: "keys/master.key", typ: tar.TypeReg, mode: 0o400},
	{name: "secrets/", typ: tar.TypeDir, mode: 0o700},
	{name: "secrets/console.crt", typ: tar.TypeReg, mode: 0o644},
	{name: "gateway/reg/", typ: tar.TypeDir, mode: 0o700},
	{name: "gateway/state/", typ: tar.TypeDir, mode: 0o700},
}

func withEntry(e tarEntry) []tarEntry {
	return append(append([]tarEntry{}, goodEntries...), e)
}

func TestE2EPilotScripts_RestoreRefuses(t *testing.T) {
	s := newScriptInstall(t)
	goodEnv := s.env(pilotConsoleHost)
	cases := []struct {
		name, want string
		src        func() string
		env        []string
		prepare    func()
	}{
		{name: "относительный путь", want: "абсолютный путь", src: func() string { return "aisec-copy" }},
		{name: "files.tar — ссылка", want: "нет обычного файла files.tar", src: func() string {
			return s.makeCopy(goodEntries, goodEnv, func(dir string) {
				p := filepath.Join(dir, "files.tar")
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/etc/passwd", p); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{name: "символьная ссылка в архиве", want: "не обычный файл",
			src: func() string {
				return s.makeCopy(withEntry(tarEntry{name: "keys/link", link: "/etc/shadow", typ: tar.TypeSymlink, mode: 0o777}), goodEnv, nil)
			}},
		{name: "жёсткая ссылка в архиве", want: "не обычный файл",
			src: func() string {
				return s.makeCopy(withEntry(tarEntry{name: "keys/hard", link: "keys/master.key", typ: tar.TypeLink, mode: 0o400}), goodEnv, nil)
			}},
		{name: "«..» в пути", want: "«..»",
			src: func() string {
				return s.makeCopy(withEntry(tarEntry{name: "keys/../../escape", typ: tar.TypeReg, mode: 0o600}), goodEnv, nil)
			}},
		{name: "путь вне каталогов установки", want: "лишний путь",
			src: func() string {
				return s.makeCopy(withEntry(tarEntry{name: "pg/pgdata/PG_VERSION", typ: tar.TypeReg, mode: 0o600}), goodEnv, nil)
			}},
		{name: "перевод строки в имени", want: "лишний путь",
			src: func() string {
				return s.makeCopy(withEntry(tarEntry{name: "keys/a\nb", typ: tar.TypeReg, mode: 0o600}), goodEnv, nil)
			}},
		{name: "бит setuid", want: "недопустимые права",
			src: func() string {
				return s.makeCopy(withEntry(tarEntry{name: "keys/suid", typ: tar.TypeReg, mode: 0o4755}), goodEnv, nil)
			}},
		{name: "запись для группы", want: "недопустимые права",
			src: func() string {
				return s.makeCopy(withEntry(tarEntry{name: "secrets/gw", typ: tar.TypeReg, mode: 0o664}), goodEnv, nil)
			}},
		{name: "неверная сумма", want: "контрольные суммы", src: func() string {
			return s.makeCopy(goodEntries, goodEnv, func(dir string) { mustWrite(t, filepath.Join(dir, "env"), []byte(goodEnv+"#\n")) })
		}},
		{name: "чужой файл в SHA256SUMS", want: "не тот список", src: func() string {
			return s.makeCopy(goodEntries, goodEnv, func(dir string) {
				p := filepath.Join(dir, "SHA256SUMS")
				mustWrite(t, p, append(mustRead(t, p), []byte(strings.Repeat("0", 64)+"  /etc/shadow\n")...))
			})
		}},
		{name: "другое имя консоли", want: "не совпадает с копией", src: func() string {
			return s.makeCopy(goodEntries, s.env("other.example.ru"), nil)
		}},
		{name: "AISEC_DATA_DIR окружения", want: "не совпадает с .env", env: []string{"AISEC_DATA_DIR=/srv/other"},
			src: func() string { return s.makeCopy(goodEntries, goodEnv, nil) }},
		{name: "сервисы запущены", want: "сервисы установки запущены", env: []string{"STUB_RUNNING=1"},
			src: func() string { return s.makeCopy(goodEntries, goodEnv, nil) }},
		{name: "ключи уже есть", want: "уже есть ключи", src: func() string { return s.makeCopy(goodEntries, goodEnv, nil) },
			prepare: func() { mustWrite(t, filepath.Join(s.data, "keys", "master.key"), []byte("x")) }},
		{name: "БД не пуста", want: "не пуст", src: func() string { return s.makeCopy(goodEntries, goodEnv, nil) },
			prepare: func() { mustWrite(t, filepath.Join(s.data, "pg", "PG_VERSION"), []byte("17")) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, d := range []string{"keys", "pg"} {
				if err := os.RemoveAll(filepath.Join(s.data, d)); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(s.data, d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if c.prepare != nil {
				c.prepare()
			}
			out, code := s.run(c.env, "restore.sh", c.src())
			if code == 0 || code == 99 || !strings.Contains(out, c.want) {
				t.Fatalf("ожидался отказ «%s», код %d:\n%s", c.want, code, out)
			}
			if c.prepare == nil {
				if left, _ := os.ReadDir(filepath.Join(s.data, "keys")); len(left) != 0 {
					t.Fatalf("после отказа в keys/ появились файлы: %v", left)
				}
			}
		})
	}
}

// TestE2EPilotScripts_RestoreAcceptsGood — положительный контроль: годная
// копия проходит все проверки, распаковывается и доходит до запуска БД
// (заглушка docker отказывает), а скрипт подсказывает, как вернуть установку
// к пустой. Нужны пользователи хоста prepare-host.sh.
func TestE2EPilotScripts_RestoreAcceptsGood(t *testing.T) {
	s := newScriptInstall(t)
	for _, u := range []string{"aisec", "aisec-gw"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := exec.CommandContext(ctx, "id", u).Run() //nolint:gosec // G204: имя пользователя — константа теста
		cancel()
		if err != nil {
			t.Skipf("нет пользователя %s (его создаёт prepare-host.sh)", u)
		}
	}
	out, code := s.run(nil, "restore.sh", s.makeCopy(goodEntries, s.env(pilotConsoleHost), nil))
	if code != 99 || !strings.Contains(out, "восстановлены") || !strings.Contains(out, "восстановление не завершено") {
		t.Fatalf("годная копия не дошла до запуска БД (код %d):\n%s", code, out)
	}
	if len(mustRead(t, filepath.Join(s.data, "keys", "master.key"))) == 0 {
		t.Fatal("ключ из копии не распакован")
	}
}

func TestE2EPilotScripts_BackupRefuses(t *testing.T) {
	s := newScriptInstall(t)
	mustWrite(t, filepath.Join(s.data, "keys", "master.key"), []byte("синтетический ключ"))
	open := filepath.Join(s.root, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil { //nolint:gosec // G302: каталог, открытый для записи всем, — сценарий отказа
		t.Fatal(err)
	}
	foreign := filepath.Join(s.root, "foreign")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(foreign, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.root, "link")
	if err := os.Symlink(s.root, link); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, out, want string
		env             []string
	}{
		{"относительный путь", "backups", "абсолютный путь", nil},
		{"внутри AISEC_DATA_DIR", filepath.Join(s.data, "backups"), "внутри AISEC_DATA_DIR", nil},
		{"символьная ссылка", link, "символьная ссылка", nil},
		{"каталог не root", foreign, "не root", nil},
		{"родитель открыт для записи", filepath.Join(open, "copies"), "не только root", nil},
		{"AISEC_DATA_DIR окружения", filepath.Join(s.root, "copies"), "не совпадает с .env", []string{"AISEC_DATA_DIR=/srv/other"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, code := s.run(c.env, "backup.sh", c.out)
			if code == 0 || code == 99 || !strings.Contains(out, c.want) {
				t.Fatalf("ожидался отказ «%s», код %d:\n%s", c.want, code, out)
			}
		})
	}
}
