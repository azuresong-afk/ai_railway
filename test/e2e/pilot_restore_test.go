//go:build e2e

package e2e

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pilotPassphrase — синтетическая парольная фраза копии конфигурации.
const pilotPassphrase = "lunar-Copper-meadow-91-quietly" //nolint:gosec // G101: синтетическая фраза стенда e2e

// TestE2EPilot_BackupRestore — задача 3.8 этапа 3 (РВ.2, ТЗ 14 «восстановление
// из резервной копии проверено»): копия работающей установки пилота
// (backup.sh: файлы и pg_dump), потеря установки, восстановление
// restore.sh в пустую установку на другом каталоге данных. После
// восстановления: вход прежним паролем и вторым фактором, события до копии на
// месте, изменений после копии нет, цепочка журнала аудита сходится, шлюз
// принимает пакет восстановленного сервера и пропускает запросы. Обе
// установки работают без выхода наружу (ловушка 3.7).
func TestE2EPilot_BackupRestore(t *testing.T) {
	cfg := pilotConfigFromEnv(t)
	tls := newPilotTLS(t)
	a := newPilotInstall(t, cfg, tls, "a")
	s, admin := a.install()
	mock := addProvider(t, admin, "mock", "https://mock-llm:9443/v1", tls.ca)
	app := addApp(t, admin, "crm", mock)
	a.waitChat(s, 1, app.key, "запрос до копии")
	if !s2WaitFor(60*time.Second, func() bool { return eventCount(t, admin, app.slug) >= 1 }) {
		t.Fatal("событие запроса не появилось в консоли за 60 с")
	}
	before := eventCount(t, admin, app.slug)

	// Копия конфигурации aisec-cli backup в compose (руководство
	// администратора, раздел 12): фраза — файл 0400 пользователя aisec.
	pass := filepath.Join(a.data, "backups", "passphrase")
	mustWrite(t, pass, []byte(pilotPassphrase+"\n"))
	if err := os.Chown(pass, a.ids["AISEC_UID"], a.ids["AISEC_GID"]); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pass, 0o400); err != nil {
		t.Fatal(err)
	}
	a.cli("backup", "create", "-keys", "/etc/aisec/keys", "-out", "/var/lib/aisec/backups/config.aisec-backup",
		"-no-user-hmac-key", "-passphrase-file", "/var/lib/aisec/backups/passphrase")
	if len(mustRead(t, filepath.Join(a.data, "backups", "config.aisec-backup"))) == 0 {
		t.Fatal("копия конфигурации пуста")
	}

	// Полная копия установки.
	store := t.TempDir()
	out := a.sh("backup.sh", store)
	copies, err := filepath.Glob(filepath.Join(store, "aisec-*"))
	if err != nil || len(copies) != 1 {
		t.Fatalf("backup.sh не создал каталог копии (%v):\n%s", err, out)
	}
	dir := copies[0]
	for _, f := range []string{"files.tar", "env", "db.dump", "SHA256SUMS"} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil || st.Size() == 0 {
			t.Fatalf("в копии нет %s: %v", f, err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s доступен не только root: %v", f, st.Mode().Perm())
		}
	}

	// После копии: приложение, которого в копии нет.
	late := addApp(t, admin, "late", mock)
	a.waitChat(s, 2, late.key, "запрос после копии")
	a.assertOffline(nil)

	// Авария: установка и её каталог данных потеряны.
	a.down()
	if err := os.RemoveAll(a.data); err != nil {
		t.Fatal(err)
	}

	// Пустая установка на другом каталоге данных: prepare-host.sh, затем
	// restore.sh (сертификаты и пароли БД приходят из копии).
	b := newPilotInstall(t, cfg, tls, "b")
	if out, code := b.run(nil, nil, filepath.Join(b.dir, "restore.sh"), filepath.Join(store, "нет-такой-копии")); code == 0 {
		t.Fatalf("restore.sh принял несуществующую копию:\n%s", out)
	}
	b.sh("restore.sh", dir)
	b.compose("up", "-d")
	sb := b.stand()
	b.waitGatewayReady(sb)

	// Вход прежним паролем и вторым фактором.
	c := sb.client("198.51.100.10")
	if me := c.signIn(s.admin); me.User.Login != s2AdminLogin {
		t.Fatalf("вход после восстановления: %+v", me)
	}
	// События до копии на месте; приложения после копии нет.
	if n := eventCount(t, c, app.slug); n < before {
		t.Fatalf("после восстановления событий %d, до копии было %d", n, before)
	}
	if r := c.do("GET", "/api/v1/applications/"+late.id, nil); r.code != http.StatusNotFound {
		t.Fatalf("приложение, созданное после копии, есть после восстановления: %s", r)
	}
	// Шлюз из копии принимает пакет восстановленного сервера: прежнее
	// приложение работает, ключ из «после копии» — нет, новое приложение
	// приходит новым пакетом.
	// Шлюз уже применил пакет из восстановленного состояния (тот же, что у
	// сервера: сервер отвечает «не изменился»).
	if code, body := b.chat(sb, app.key, "запрос после восстановления"); code != http.StatusOK {
		t.Fatalf("шлюз после восстановления не пропустил запрос: %d %s", code, body)
	}
	if code, body := b.chat(sb, late.key, "ключ после копии"); code != http.StatusUnauthorized {
		t.Fatalf("ключ приложения, созданного после копии, принят: %d %s", code, body)
	}
	fresh := addApp(t, c, "fresh", mock)
	b.waitChat(sb, 2, fresh.key, "новое приложение после восстановления")
	b.cli("audit", "verify", "-keys", "/etc/aisec/keys")
	b.assertOffline(nil)
	b.assertLogsClean("запрос после восстановления")
}
