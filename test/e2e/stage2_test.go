//go:build e2e

package e2e

// Сквозные тесты этапа 2 (задача 2.28, часть 1): настоящие aisec-server и
// aisec-cli, PostgreSQL, вход по HTTPS. Имя теста содержит ID строки матрицы
// обнаружения (DM-NN). Часть 2 (пакет политик, экраны 2.25–2.27) — после 2.13.

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// problemKey — устойчивые поля Problem Details: по ним сравниваются отказы.
type problemKey struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

func s2Problem(t *testing.T, r s2Resp) problemKey {
	t.Helper()
	var p problemKey
	r.json(t, &p)
	return p
}

// Сквозные тесты этапа 2 названы без ID строки матрицы (TestE2EStage2_…):
// без PostgreSQL, как в CI, они пропускаются, а dm-coverage считает пропуск
// провалом. Строки DM-39, DM-42 и DM-43 покрывают модульные тесты.

// DM-39: перебор паролей в консоли. После порога неудач учётная запись
// блокируется (даже верный пароль не пускает), отказ не выдаёт, есть ли такой
// логин, события попадают в журнал аудита и «Состояние системы», а снимает
// блокировку только аварийная команда aisec-cli. Частота попыток ограничена.
func TestE2EStage2_ConsoleBruteForce(t *testing.T) {
	s := s2NewStand(t)
	s.mustStart()
	admin := s.setupAdmin()
	victim := admin.createUser("e2e-analyst", auth.RoleAnalyst)
	s.client("198.51.100.20").signIn(victim)
	good := victim.pass

	attacker := s.client("203.0.113.7")
	login := func(c *s2Client, name, pass string) s2Resp {
		return c.do("POST", "/api/v1/auth/login", map[string]string{"login": name, "password": pass})
	}

	// Отказ для несуществующего логина и для неверного пароля неотличим.
	unknown := login(attacker, "e2e-nobody", "Wrong-Passw0rd-1")
	if unknown.code != http.StatusUnauthorized {
		t.Fatalf("несуществующий логин: %s", unknown)
	}
	wrong := login(attacker, victim.login, "Wrong-Passw0rd-1")
	if wrong.code != http.StatusUnauthorized || s2Problem(t, wrong) != s2Problem(t, unknown) {
		t.Fatalf("неверный пароль отличим от несуществующего логина:\n%s\n%s", wrong, unknown)
	}

	// Порог по умолчанию — 5 неудач (ИАФ.4); первая уже была.
	for i := 2; i <= 5; i++ {
		if r := login(attacker, victim.login, "Wrong-Passw0rd-"+strconv.Itoa(i)); r.code != http.StatusUnauthorized {
			t.Fatalf("попытка %d: %s", i, r)
		}
	}
	// Учётная запись заблокирована: верный пароль не пускает, ответ прежний.
	blocked := login(attacker, victim.login, good)
	if blocked.code != http.StatusUnauthorized || s2Problem(t, blocked) != s2Problem(t, unknown) {
		t.Fatalf("после порога верный пароль: %s", blocked)
	}
	// Законный вход с другого адреса тоже закрыт: блокируется запись.
	if r := login(s.client("198.51.100.21"), victim.login, good); r.code != http.StatusUnauthorized {
		t.Fatalf("вход заблокированной записи с другого адреса: %s", r)
	}

	// Журнал аудита: неудачи и блокировка с адресом нападающего.
	ctx := context.Background()
	if n := s.auditCount("auth.login_failed"); n < 5 {
		t.Errorf("auth.login_failed: %d записей, ожидалось не меньше 5", n)
	}
	var lockIP string
	if err := s.pg().QueryRow(ctx, `SELECT host(source_ip) FROM audit_log WHERE action = 'auth.locked' ORDER BY seq DESC LIMIT 1`).Scan(&lockIP); err != nil {
		t.Fatalf("запись auth.locked: %v", err)
	}
	if lockIP != "203.0.113.7" {
		t.Errorf("адрес в записи auth.locked: %q, ожидался 203.0.113.7", lockIP)
	}

	// «Состояние системы»: уведомление ИАФ.4 с числом блокировок за сутки.
	var status struct {
		Notifications []struct {
			Condition string
			Active    bool
			Count     *int
		}
	}
	seen := s2WaitFor(30*time.Second, func() bool {
		r := admin.do("GET", "/api/v1/system/status", nil)
		if r.code != http.StatusOK {
			t.Fatalf("/system/status: %s", r)
		}
		r.json(t, &status)
		for _, n := range status.Notifications {
			if n.Condition == "account_lockout" && n.Count != nil && *n.Count >= 1 {
				return true
			}
		}
		return false
	})
	if !seen {
		t.Errorf("в «Состоянии системы» нет уведомления account_lockout: %+v", status.Notifications)
	}

	// Предел частоты (ЗИ.6): серия попыток с одного адреса упирается в 429.
	flood := s.client("203.0.113.99")
	limited := false
	for i := 0; i < 30 && !limited; i++ {
		r := login(flood, "e2e-nobody", "Wrong-Passw0rd-1")
		if r.code == http.StatusTooManyRequests {
			limited = r.hdr.Get("Retry-After") != ""
		}
	}
	if !limited {
		t.Error("30 попыток входа с одного адреса не получили 429 с Retry-After")
	}

	// Снятие блокировки — только аварийной командой; вход снова работает.
	if out, code := s.cli("user", "unlock", "-login", victim.login); code != 0 {
		t.Fatalf("user unlock: код %d\n%s", code, out)
	}
	if r := login(s.client("198.51.100.22"), victim.login, good); r.code != http.StatusOK {
		t.Fatalf("вход после снятия блокировки: %s", r)
	}
	if n := s.auditCount("auth.unlocked"); n < 1 {
		t.Error("снятие блокировки не записано в аудит (auth.unlocked)")
	}
}

// s2IntItem — элемент ответа /system/integrity.
type s2IntItem struct {
	Component string
	OK        bool
	Reason    string
}

// integrityRow — последняя запись integrity_checks компонента.
func (s *s2Stand) integrityRow(component string) (ok bool, reason, failures string) {
	s.t.Helper()
	err := s.pg().QueryRow(context.Background(), `SELECT ok, reason, failures::text FROM integrity_checks
		WHERE component = $1 ORDER BY ts DESC, id DESC LIMIT 1`, component).Scan(&ok, &reason, &failures)
	if err != nil {
		s.t.Fatalf("нет итога проверки целостности %s: %v", component, err)
	}
	return ok, reason, failures
}

// DM-42 (бинарник и статика): подмена исполняемого файла, встроенной статики
// или манифеста обнаруживается при запуске и по команде; реакция — по настройке
// (оповещение или остановка). Подмена пакета политик — часть 2 задачи (после 2.13).
func TestE2EStage2_BinaryTampered(t *testing.T) {
	cliEnv := func(s *s2Stand) []string { return []string{"AISEC_DATABASE_URL=" + s.suDSN} }

	t.Run("чистая установка", func(t *testing.T) {
		s := s2NewStand(t)
		if out, code := s2Run(t, s.in.path("aisec-cli"), cliEnv(s), "verify"); code != 0 {
			t.Fatalf("verify чистой установки: код %d\n%s", code, out)
		}
		s.mustStart("-integrity-action", "stop")
		admin := s.setupAdmin()
		if ok, reason, _ := s.integrityRow("server"); !ok {
			t.Fatalf("чистый сервер: итог проверки при запуске %s", reason)
		}
		var list struct{ Items []s2IntItem }
		r := admin.do("GET", "/api/v1/system/integrity", nil)
		if r.code != http.StatusOK {
			t.Fatalf("/system/integrity: %s", r)
		}
		r.json(t, &list)
		if !slices.ContainsFunc(list.Items, func(i s2IntItem) bool { return i.Component == "server" && i.OK }) {
			t.Errorf("/system/integrity: нет успешной проверки сервера: %s", r)
		}
		var verify struct{ OK bool }
		r = admin.do("POST", "/api/v1/system/integrity/verify", nil)
		r.json(t, &verify)
		if r.code != http.StatusOK || !verify.OK {
			t.Fatalf("проверка по команде на чистой установке: %s", r)
		}
	})

	t.Run("подменён aisec-server", func(t *testing.T) {
		s := s2NewStand(t)
		s.mustStart()
		admin := s.setupAdmin()
		s.srv.stop()

		bad := s.in.clone(t)
		s2Append(t, bad.path("aisec-server"))
		out, code := s2Run(t, bad.path("aisec-cli"), cliEnv(s), "verify")
		if code != 3 || !strings.Contains(out, "aisec-server") {
			t.Errorf("aisec-cli verify: код %d (ожидался 3), вывод называет подменённый файл: %v\n%s", code, strings.Contains(out, "aisec-server"), out)
		}

		// Реакция «остановка»: сервер не начинает слушать порт.
		p, ok := s.startServer(bad, "-integrity-action", "stop")
		if ok {
			t.Fatal("сервер с подменённым бинарником и реакцией stop запустился")
		}
		if c := p.exitCode(10 * time.Second); c <= 0 {
			t.Errorf("код завершения сервера: %d, ожидалась ошибка", c)
		}
		if !strings.Contains(p.log(), "нарушена целостность") {
			t.Errorf("в журнале сервера нет причины остановки:\n%s", p.log())
		}
		if ok, reason, _ := s.integrityRow("server"); ok || reason != "files_mismatch" {
			t.Errorf("итог в БД: ok=%v reason=%s", ok, reason)
		}

		// Реакция «оповещение»: сервер работает, нарушение видно в консоли,
		// проверка по команде повторяет итог.
		if _, ok := s.startServer(bad, "-integrity-action", "alert"); !ok {
			t.Fatal("сервер с реакцией alert не запустился")
		}
		var list struct{ Items []s2IntItem }
		r := admin.do("GET", "/api/v1/system/integrity", nil)
		r.json(t, &list)
		if r.code != http.StatusOK || !slices.ContainsFunc(list.Items,
			func(i s2IntItem) bool { return i.Component == "server" && !i.OK && i.Reason == "files_mismatch" }) {
			t.Errorf("/system/integrity не показывает нарушение: %s", r)
		}
		var verify struct{ OK bool }
		r = admin.do("POST", "/api/v1/system/integrity/verify", nil)
		r.json(t, &verify)
		if r.code != http.StatusOK || verify.OK {
			t.Errorf("проверка по команде не нашла подмену: %s", r)
		}
		if r = s.client("198.51.100.30").do("GET", "/healthz", nil); r.code != http.StatusOK {
			t.Errorf("сервер с реакцией alert перестал отвечать: %s", r)
		}
		if n := s.auditCount("integrity.check"); n < 1 {
			t.Error("проверка по команде не записана в аудит (integrity.check)")
		}
	})

	t.Run("подменён aisec-cli", func(t *testing.T) {
		s := s2NewStand(t)
		bad := s.in.clone(t)
		s2Append(t, bad.path("aisec-cli"))
		out, code := s2Run(t, bad.path("aisec-cli"), nil, "verify")
		if code != 3 || !strings.Contains(out, "aisec-cli") {
			t.Errorf("verify подменённого CLI: код %d\n%s", code, out)
		}
	})

	t.Run("подменена встроенная статика", func(t *testing.T) {
		page, err := os.ReadFile("../../web/dist/index.html")
		if err != nil || len(page) < 64 {
			t.Skip("консоль не собрана (make web-build до make build): встроенной статики нет")
		}
		s := s2NewStand(t)
		bad := s.in.clone(t)
		exe, err := os.ReadFile(bad.path("aisec-server"))
		if err != nil {
			t.Fatal(err)
		}
		at := bytes.Index(exe, page)
		if at < 0 {
			t.Skip("index.html не найден в бинарнике: сервер собран без этой сборки консоли")
		}
		// Меняем один знак встроенной страницы, как при подмене статики в бинарнике.
		exe[at+len(page)/2] ^= 0x01
		if err := os.WriteFile(bad.path("aisec-server"), exe, 0o700); err != nil { //nolint:gosec // G306, G703: исполняемый файл в копии установки во временном каталоге теста
			t.Fatal(err)
		}
		if _, ok := s.startServer(bad, "-integrity-action", "stop"); ok {
			t.Fatal("сервер с подменённой статикой и реакцией stop запустился")
		}
		ok, reason, failures := s.integrityRow("server")
		if ok || reason != "files_mismatch" || !strings.Contains(failures, "web/dist/index.html") {
			t.Errorf("итог в БД: ok=%v reason=%s failures=%s", ok, reason, failures)
		}
	})

	t.Run("статика не совпадает с манифестом", func(t *testing.T) {
		if _, err := exec.LookPath("go"); err != nil {
			t.Skip("нет go в PATH: манифест со своей статикой собирается tools/manifest")
		}
		s := s2NewStand(t)
		bad := s.in.clone(t)
		// Манифест подписан тестовым ключом и описывает файл статики, которого
		// во встроенной сборке нет: как если бы статику подменили или убрали.
		dist := t.TempDir()
		if err := os.WriteFile(dist+"/app.js", []byte("console.log('e2e')\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, code := s2RunDir(t, "../..", "go", nil, "run", "./tools/manifest", "build", "-out", bad.manifest(),
			"-test-key", "testdata/integrity/manifest-test.signkey", "-version", "e2e", "-created", "2026-01-01T00:00:00Z",
			"-bin", bad.bin, "-cmds", "aisec-gateway aisec-server aisec-cli aisec-media", "-static", dist, "-migrations", "migrations"); code != 0 {
			t.Fatalf("сборка манифеста: код %d\n%s", code, out)
		}
		if _, ok := s.startServer(bad, "-integrity-action", "stop"); ok {
			t.Fatal("сервер с несовпадающей статикой и реакцией stop запустился")
		}
		ok, reason, failures := s.integrityRow("server")
		if ok || reason != "files_mismatch" || !strings.Contains(failures, "web/dist/app.js") {
			t.Errorf("итог в БД: ok=%v reason=%s failures=%s", ok, reason, failures)
		}
	})

	t.Run("подделан манифест", func(t *testing.T) {
		s := s2NewStand(t)
		bad := s.in.clone(t)
		raw, err := os.ReadFile(bad.manifest())
		if err != nil {
			t.Fatal(err)
		}
		i := strings.Index(string(raw), `"sha256`)
		if i < 0 {
			i = len(raw) / 2
		}
		// Меняем один знак внутри подписанного содержимого.
		j := i + strings.IndexAny(string(raw[i:]), "0123456789abcdef")
		if raw[j] == '0' {
			raw[j] = '1'
		} else {
			raw[j] = '0'
		}
		if err := os.WriteFile(bad.manifest(), raw, 0o600); err != nil { //nolint:gosec // G703: манифест копии установки во временном каталоге теста
			t.Fatal(err)
		}
		if out, code := s2Run(t, bad.path("aisec-cli"), nil, "verify"); code != 3 {
			t.Errorf("verify с подделанным манифестом: код %d\n%s", code, out)
		}
		if _, ok := s.startServer(bad, "-integrity-action", "stop"); ok {
			t.Error("сервер с подделанным манифестом и реакцией stop запустился")
		}
		if ok, reason, _ := s.integrityRow("server"); ok || (reason != "signature_invalid" && reason != "manifest_invalid") {
			t.Errorf("итог в БД: ok=%v reason=%s", ok, reason)
		}
	})
}

// tamperAudit правит журнал аудита в обход продукта: суперпользователь СУБД
// отключает триггеры запрета (session_replication_role = replica) и меняет
// данные, как сделал бы злоумышленник с доступом к базе.
func (s *s2Stand) tamperAudit(stmt string, args ...any) {
	s.t.Helper()
	ctx := context.Background()
	conn := s.pg()
	if _, err := conn.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		s.t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, stmt, args...); err != nil {
		s.t.Fatalf("подмена журнала: %v", err)
	}
}

var auditBreak = regexp.MustCompile(`запись (\d+), причина (\w+)`)

// auditSeqs — крайние номера записей журнала.
func (s *s2Stand) auditSeqs() (first, last int64) {
	s.t.Helper()
	if err := s.pg().QueryRow(context.Background(), `SELECT min(seq), max(seq) FROM audit_log`).Scan(&first, &last); err != nil {
		s.t.Fatal(err)
	}
	return first, last
}

// DM-43: правка или удаление записей аудита в обход продукта. Обнаруживает
// проверка по команде, проверка при запуске сервера и периодическая; сервер при
// этом не останавливается, нарушение видно в «Состоянии системы».
func TestE2EStage2_AuditTampered(t *testing.T) {
	cases := []struct {
		name    string
		tamper  func(s *s2Stand, first, last int64)
		reasons []string
		// seq — номер записи, на которой цепочка должна оборваться (0 — любой).
		seq func(first, last int64) int64
	}{
		{"правка записи", func(s *s2Stand, first, last int64) {
			s.tamperAudit(`UPDATE audit_log SET actor_name = 'mallory' WHERE seq = $1`, (first+last)/2)
		}, []string{"hash_mismatch"}, func(first, last int64) int64 { return (first + last) / 2 }},
		{"удаление записи из середины", func(s *s2Stand, first, last int64) {
			s.tamperAudit(`DELETE FROM audit_log WHERE seq = $1`, (first+last)/2)
		}, []string{"gap", "prev_mismatch"}, nil},
		// Одна причина и сразу после обрезки, и после дописанных записей
		// (CLI, запуск сервера): проверенная раньше запись пропала или
		// изменилась — rewritten (задача 2.4a).
		{"обрезан хвост журнала", func(s *s2Stand, first, last int64) {
			s.tamperAudit(`DELETE FROM audit_log WHERE seq > $1`, last-3)
		}, []string{"rewritten"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := s2NewStand(t)
			s.mustStart()
			admin := s.setupAdmin()
			auditor := admin.createUser("e2e-auditor", auth.RoleAuditor)
			s.srv.stop()
			keys := []string{"audit", "verify", "-keys", s.keysDir}

			// До подмены цепочка цела.
			if out, code := s.cli(keys...); code != 0 {
				t.Fatalf("audit verify до подмены: код %d\n%s", code, out)
			}
			first, last := s.auditSeqs()
			if last-first < 8 {
				t.Fatalf("в журнале мало записей для сценария: %d..%d", first, last)
			}
			tc.tamper(s, first, last)

			// По команде: код 3, причина и номер записи.
			out, code := s.cli(keys...)
			m := auditBreak.FindStringSubmatch(out)
			if code != 3 || m == nil {
				t.Fatalf("audit verify после подмены: код %d\n%s", code, out)
			}
			if !slices.Contains(tc.reasons, m[2]) {
				t.Errorf("причина %q, ожидалась одна из %v\n%s", m[2], tc.reasons, out)
			}
			if tc.seq != nil && m[1] != strconv.FormatInt(tc.seq(first, last), 10) {
				t.Errorf("цепочка оборвана на записи %s, ожидалась %d", m[1], tc.seq(first, last))
			}

			// При запуске: сервер поднимается, нарушение — в «Состоянии системы».
			s.mustStart()
			var st struct {
				AuditChain *struct {
					OK        bool
					Reason    string
					BrokenSeq *int64 `json:"broken_seq"`
				} `json:"audit_chain"`
				Notifications []struct {
					Condition string
					Active    bool
				}
			}
			found := s2WaitFor(30*time.Second, func() bool {
				r := admin.do("GET", "/api/v1/system/status", nil)
				if r.code != http.StatusOK {
					t.Fatalf("/system/status: %s", r)
				}
				r.json(t, &st)
				return st.AuditChain != nil && !st.AuditChain.OK
			})
			if !found {
				t.Fatalf("после запуска «Состояние системы» не показало нарушение цепочки: %+v", st)
			}
			if !slices.Contains(tc.reasons, st.AuditChain.Reason) {
				t.Errorf("причина в консоли %q, ожидалась одна из %v", st.AuditChain.Reason, tc.reasons)
			}
			if !slices.ContainsFunc(st.Notifications, func(n struct {
				Condition string
				Active    bool
			}) bool {
				return n.Condition == "audit_chain" && n.Active
			}) {
				t.Errorf("нет активного уведомления audit_chain: %+v", st.Notifications)
			}
			if r := s.client("198.51.100.31").do("GET", "/healthz", nil); r.code != http.StatusOK {
				t.Errorf("сервер остановился из-за нарушения цепочки: %s", r)
			}

			// По команде из консоли (задача 2.4a): аудитор проверяет цепочку
			// через API; пока идёт фоновая проверка — 409, при исчерпании
			// предела частоты — 429: ждём и повторяем, затем итог. Проверка
			// при запуске моложе 10 минут, поэтому ответ — её итог с cached
			// (Н31 ревью 2.r3b).
			ac := s.client("198.51.100.32")
			ac.signIn(auditor)
			var v struct {
				OK        bool
				Reason    string
				BrokenSeq *int64 `json:"broken_seq"`
				Cached    bool
			}
			done := s2WaitFor(90*time.Second, func() bool {
				r := ac.do("POST", "/api/v1/audit/verify", nil)
				if r.code == http.StatusConflict || r.code == http.StatusTooManyRequests {
					time.Sleep(5 * time.Second)
					return false
				}
				if r.code != http.StatusOK {
					t.Fatalf("/audit/verify: %s", r)
				}
				r.json(t, &v)
				return true
			})
			if !done || v.OK || !v.Cached || v.BrokenSeq == nil || !slices.Contains(tc.reasons, v.Reason) {
				t.Errorf("проверка через API: %+v, ожидалась одна из %v", v, tc.reasons)
			}
			if tc.seq != nil && v.BrokenSeq != nil && *v.BrokenSeq != tc.seq(first, last) {
				t.Errorf("через API цепочка оборвана на записи %d, ожидалась %d", *v.BrokenSeq, tc.seq(first, last))
			}
			// Итог — от проверки при запуске: в журнале от имени сервера,
			// повтор аудитора новой записи не добавил.
			r := ac.do("GET", "/api/v1/audit?action=audit.chain_broken", nil)
			var page struct {
				Items []struct {
					Actor   struct{ Type, Name string }
					Details struct {
						Reason string
					}
				}
			}
			if r.code != http.StatusOK {
				t.Fatalf("/audit: %s", r)
			}
			r.json(t, &page)
			if len(page.Items) == 0 || page.Items[0].Actor.Type != "system" || page.Items[0].Details.Reason != v.Reason ||
				slices.ContainsFunc(page.Items, func(it struct {
					Actor   struct{ Type, Name string }
					Details struct {
						Reason string
					}
				}) bool {
					return it.Actor.Name == "e2e-auditor"
				}) {
				t.Errorf("итог проверки в журнале: %s", r)
			}
		})
	}

	// Периодическая проверка: подмена на работающем сервере находится без
	// перезапуска, за период -audit-verify-interval (минимум — 1 минута).
	t.Run("периодическая проверка", func(t *testing.T) {
		if testing.Short() {
			t.Skip("ждёт период проверки — минуту")
		}
		s := s2NewStand(t)
		s.mustStart("-audit-verify-interval", "1m")
		admin := s.setupAdmin()
		first, last := s.auditSeqs()
		s.tamperAudit(`UPDATE audit_log SET actor_name = 'mallory' WHERE seq = $1`, (first+last)/2)
		found := s2WaitFor(100*time.Second, func() bool {
			var st struct {
				AuditChain *struct{ OK bool } `json:"audit_chain"`
			}
			r := admin.do("GET", "/api/v1/system/status", nil)
			r.json(t, &st)
			return st.AuditChain != nil && !st.AuditChain.OK
		})
		if !found {
			t.Error("периодическая проверка не нашла подмену за 100 с")
		}
	})
}

// openapiSpec — часть api/openapi.yaml, нужная матрице.
type openapiSpec struct {
	Paths map[string]map[string]struct {
		Permission string `yaml:"x-permission"`
	} `yaml:"paths"`
}

// permissionNeed — что говорят права роли о доступе к разрешению маршрута.
type permissionNeed int

const (
	needDeny   permissionNeed = iota // у роли разрешения нет: ждём 403
	needReach                        // право есть целиком: обработчик достижим
	needUnsure                       // область own: достижимость зависит от маршрута
)

func s2Need(g auth.Grants, perm string) permissionNeed {
	switch {
	case g.Full(perm):
		return needReach
	case g.Allows(perm):
		return needUnsure
	}
	return needDeny
}

// Матрица «роль × эндпоинт» на настоящем сервере и БД (УПД.3): права берутся
// из x-permission в api/openapi.yaml и из встроенных ролей. Где у роли нет
// разрешения — 403 и запись access.denied; где есть — не 401, не 403 и не 5xx;
// без входа — 401 везде. Содержательные проверки каждого маршрута — в тестах пакета api.
func TestE2EAuthz_RoleEndpointMatrix(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec openapiSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	s := s2NewStand(t)
	s.mustStart()
	adminC := s.setupAdmin()

	type actor struct {
		role auth.Role
		c    *s2Client
		g    auth.Grants
	}
	grants := map[auth.Role]auth.Grants{}
	for _, r := range auth.BuiltinRoles() {
		grants[r.ID] = r.Grants
	}
	actors := []actor{{auth.RoleSecurityAdmin, adminC, grants[auth.RoleSecurityAdmin]}}
	for i, role := range []auth.Role{auth.RoleSystemAdmin, auth.RoleAnalyst, auth.RoleAuditor, auth.RoleAppOwner} {
		u := adminC.createUser("e2e-"+strings.ReplaceAll(string(role), "_", "-"), role)
		c := s.client("198.51.100." + strconv.Itoa(40+i))
		c.signIn(u)
		actors = append(actors, actor{role, c, grants[role]})
	}
	anon := s.client("198.51.100.60")
	deniedBefore := s.auditCount("access.denied")

	// Маршруты, у которых «разрешение» — не право, а состояние сессии: их
	// вызовы меняют саму сессию (выход, смена пароля, второй фактор), поэтому
	// с вошедшей ролью не вызываются; без входа проверяются как все.
	sessionOnly := func(perm string) bool { return perm == "session" || perm == "self" }

	ops, pairs, denials := 0, 0, 0
	for path, methods := range spec.Paths {
		for method, op := range methods {
			if op.Permission == "" || strings.HasPrefix(path, "/internal/") {
				continue
			}
			method = strings.ToUpper(method)
			ops++
			target := strings.ReplaceAll(path, "{id}", "01900000-0000-7000-8000-00000000f001")
			if strings.HasPrefix(path, "/api/v1/roles/") {
				target = strings.ReplaceAll(path, "{id}", "e2e_missing_role")
			}
			var body any
			if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
				body = `{}`
			}
			if r := anon.do(method, target, body); r.code != http.StatusUnauthorized {
				t.Errorf("%s %s без входа: %s, ожидалось 401", method, path, r)
			}
			if sessionOnly(op.Permission) {
				continue
			}
			for _, a := range actors {
				pairs++
				r := a.c.do(method, target, body)
				switch s2Need(a.g, op.Permission) {
				case needDeny:
					denials++
					if r.code != http.StatusForbidden {
						t.Errorf("%s %s, роль %s: ожидался отказ 403, ответ %s", method, path, a.role, r)
					}
				case needReach:
					if r.code == http.StatusUnauthorized || r.code == http.StatusForbidden || r.code >= 500 {
						t.Errorf("%s %s, роль %s: ожидался доступ, ответ %s", method, path, a.role, r)
					}
				case needUnsure:
					if r.code == http.StatusUnauthorized || r.code >= 500 {
						t.Errorf("%s %s, роль %s (область own): ответ %s", method, path, a.role, r)
					}
				}
			}
		}
	}
	if ops < 40 || denials == 0 {
		t.Fatalf("матрица пуста: маршрутов %d, пар %d, отказов %d", ops, pairs, denials)
	}
	// Каждый отказ записан в аудит (УПД.6).
	if got := s.auditCount("access.denied") - deniedBefore; got != denials {
		t.Errorf("записей access.denied %d, отказов %d", got, denials)
	}
	// Ни один вызов матрицы не завершил сессию роли.
	for _, a := range actors {
		if r := a.c.do("GET", "/api/v1/me", nil); r.code != http.StatusOK {
			t.Errorf("роль %s: сессия потеряна после матрицы: %s", a.role, r)
		}
	}
	t.Logf("маршрутов %d, пар «роль × эндпоинт» %d, из них отказов %d", ops, pairs, denials)

	// Токен API несёт только выданные права: events.read даёт чтение событий и
	// не даёт чтения пользователей; изменяющий запрос токену недоступен.
	r := adminC.do("POST", "/api/v1/api-tokens", map[string]any{"name": "e2e", "password": s2AdminPass,
		"permissions": []map[string]string{{"permission": "events.read"}}})
	if r.code != http.StatusCreated {
		t.Fatalf("выпуск токена API: %s", r)
	}
	var tok struct{ Token string }
	r.json(t, &tok)
	bearer := s.client("198.51.100.61")
	bearer.bearer = tok.Token
	if r := bearer.do("GET", "/api/v1/events", nil); r.code != http.StatusOK {
		t.Errorf("токен events.read, чтение событий: %s", r)
	}
	if r := bearer.do("GET", "/api/v1/users", nil); r.code != http.StatusForbidden {
		t.Errorf("токен events.read, чтение пользователей: %s, ожидалось 403", r)
	}
	if r := bearer.do("POST", "/api/v1/users", `{}`); r.code != http.StatusUnauthorized && r.code != http.StatusForbidden {
		t.Errorf("токен events.read, создание пользователя: %s", r)
	}
}

// Строгий CSP консоли (ТЗ, 6.9): заголовки безопасности есть на каждом ответе
// сервера — страница консоли, ошибки, API; политика запрещает inline и внешние
// источники. Поведение интерфейса под CSP в браузере проверяет web/e2e/csp.spec.ts.
func TestE2EConsole_CSP(t *testing.T) {
	s := s2NewStand(t)
	s.mustStart()
	c := s.client("198.51.100.70")

	paths := []string{"/", "/healthz", "/api/v1/me", "/no-such-page", "/api/v1/no-such"}
	for _, p := range paths {
		r := c.do("GET", p, nil)
		csp := r.hdr.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'self'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s (%d): в CSP нет %q: %s", p, r.code, want, csp)
			}
		}
		for _, bad := range []string{"unsafe-inline", "unsafe-eval", "data:", "*", "http:", "https:"} {
			// data: допустим только для изображений.
			if bad == "data:" {
				for _, d := range strings.Split(csp, ";") {
					if strings.Contains(d, "data:") && !strings.HasPrefix(strings.TrimSpace(d), "img-src") {
						t.Errorf("%s: data: разрешён не только для изображений: %s", p, csp)
					}
				}
				continue
			}
			if strings.Contains(csp, bad) {
				t.Errorf("%s: CSP содержит %q: %s", p, bad, csp)
			}
		}
		for h, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
			if got := r.hdr.Get(h); got != want {
				t.Errorf("%s: %s = %q, ожидалось %q", p, h, got, want)
			}
		}
		if !strings.Contains(r.hdr.Get("Strict-Transport-Security"), "max-age=") {
			t.Errorf("%s: нет Strict-Transport-Security", p)
		}
	}

	// Если консоль встроена в бинарник (сборка после make web-build), страница
	// не содержит inline-скриптов, стилей и внешних адресов.
	r := c.do("GET", "/", nil)
	if r.code != http.StatusOK {
		t.Logf("консоль не встроена в сборку (/ отвечает %d): проверка страницы пропущена", r.code)
		return
	}
	page := string(r.body)
	for _, bad := range []string{"<style", "javascript:", "http://", "https://"} {
		if strings.Contains(page, bad) {
			t.Errorf("index.html содержит %q", bad)
		}
	}
	for _, m := range regexp.MustCompile(`(?is)<script\b[^>]*>`).FindAllString(page, -1) {
		if !strings.Contains(m, "src=") {
			t.Errorf("inline-скрипт в index.html: %s", m)
		}
	}
	if m := regexp.MustCompile(`(?i)\son[a-z]+\s*=`).FindString(page); m != "" {
		t.Errorf("обработчик события в атрибуте: %q", m)
	}
}
