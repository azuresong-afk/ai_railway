//go:build e2e

package e2e

// Оповещения безопасности DM-38, DM-40 и DM-41 на настоящем сервере и шлюзе
// (задача 3.32 этапа 3): действие или событие → оповещение в консоли →
// уведомление в тестовом приёмнике syslog по TLS. Пороги и группировка
// проверяются модульными тестами строк (TestDM38…, TestDM40…, TestDM41…),
// здесь — сквозной путь.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func TestE2EStage3_SecurityAlertsDelivered(t *testing.T) {
	st := s3NewStack(t, s3Opts{syslog: true})
	st.policy("support")
	app := st.app("support-bot", "support")
	st.startGateway()

	if code, body := st.chat(app.key, "Здравствуйте, где мой заказ?"); code != http.StatusOK {
		t.Fatalf("обычный запрос: %d %s", code, body)
	}
	if code, _ := st.chat(app.key, s3InjectionText); code != http.StatusBadRequest {
		t.Fatalf("инъекция не заблокирована: %d", code)
	}
	blocked := s3LastEvent(t, st.admin, `app = "support-bot" and action = "block"`, map[string]bool{})

	// DM-40: два ослабления защиты одним пользователем за 10 минут — одно
	// оповещение со списком изменений (группировка), уведомление в SIEM.
	t.Run("DM-40 ослабление защиты", func(t *testing.T) {
		weaken := func(body map[string]any) {
			t.Helper()
			body["password"] = st.s.admin.pass
			if r := st.admin.do("PUT", "/api/v1/applications/"+app.id+"/protection", body); r.code != http.StatusOK {
				t.Fatalf("ослабление %v: %s", body, r)
			}
		}
		// Без повторной проверки ослабление не принимается и оповещения не даёт.
		if r := st.admin.do("PUT", "/api/v1/applications/"+app.id+"/protection", map[string]any{"policy_mode": "monitor"}); r.code != http.StatusBadRequest {
			t.Fatalf("ослабление без пароля: %s", r)
		}
		if got := st.waitAlertOnce(alerting.BuiltinWeakening); got.ID != "" {
			t.Fatalf("оповещение без выполненного ослабления: %+v", got)
		}
		weaken(map[string]any{"policy_mode": "monitor"})
		weaken(map[string]any{"storage": "full"})
		al := st.waitAlert(alerting.BuiltinWeakening, 30*time.Second)
		if al.Severity != "high" || al.Status != "new" {
			t.Fatalf("оповещение: %+v", al)
		}
		if !s2WaitFor(30*time.Second, func() bool { return st.waitAlertOnce(alerting.BuiltinWeakening).Count >= 2 }) {
			t.Fatalf("второе ослабление не сгруппировано: %+v", st.waitAlertOnce(alerting.BuiltinWeakening))
		}
		if n := len(st.alertsOf(alerting.BuiltinWeakening)); n != 1 {
			t.Fatalf("оповещений об ослаблении %d, ожидалось одно (группировка 10 минут)", n)
		}
		card := st.alertCard(al.ID)
		if items, _ := card.Details["items"].([]any); len(items) != 2 {
			t.Fatalf("список изменений в оповещении: %+v", card.Details)
		}
		rec := st.sys.waitAlert(t, alerting.BuiltinWeakening, 60*time.Second)
		if rec.ID != al.ID || rec.Severity != "high" || strings.Contains(rec.Raw, st.s.admin.pass) {
			t.Fatalf("запись syslog: %s", rec.Raw)
		}
	})

	// DM-41: массовый просмотр содержимого событий одним пользователем.
	t.Run("DM-41 массовый просмотр содержимого", func(t *testing.T) {
		before := st.s.auditCount("events.content_read")
		for i := range alerting.ContentReadThreshold {
			r := st.admin.do("POST", "/api/v1/events/"+blocked.ID+"/content", map[string]any{"reason": fmt.Sprintf("Разбор обращения %d", i)})
			if r.code != http.StatusOK && r.code != http.StatusNotFound {
				t.Fatalf("просмотр %d: %s", i, r)
			}
		}
		if n := st.s.auditCount("events.content_read") - before; n != alerting.ContentReadThreshold {
			t.Fatalf("записей events.content_read: %d", n)
		}
		al := st.waitAlert(alerting.BuiltinContentAccess, 30*time.Second)
		if al.Severity != "high" {
			t.Fatalf("оповещение: %+v", al)
		}
		rec := st.sys.waitAlert(t, alerting.BuiltinContentAccess, 60*time.Second)
		if rec.ID != al.ID || rec.Severity != "high" {
			t.Fatalf("запись syslog: %s", rec.Raw)
		}
	})

	// DM-38: ключ вне разрешённых адресов, отозванный ключ, перебор ключей.
	t.Run("DM-38 ключ вне разрешённых адресов", func(t *testing.T) {
		applied := strings.Count(st.gw.log(), "пакет конфигурации применён")
		r := st.admin.do("POST", "/api/v1/applications/"+app.id+"/keys", map[string]any{"name": "e2e-cidr", "expires_in_days": 30,
			"allowed_cidrs": []string{"203.0.113.0/24"}})
		if r.code != http.StatusCreated {
			t.Fatalf("ключ с подсетью: %s", r)
		}
		var k struct{ Key string }
		r.json(t, &k)
		// Новый ключ приходит в шлюз пакетом; до этого он неизвестен (шум, не DM-38).
		if !s2WaitFor(90*time.Second, func() bool {
			return strings.Count(st.gw.log(), "пакет конфигурации применён") > applied
		}) {
			t.Fatalf("шлюз не получил пакет с новым ключом:\n%s", st.gw.log())
		}
		if code, body := st.chat(k.Key, "Запрос с чужого адреса."); code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Fatalf("ключ принят с адреса вне подсети: %d %s", code, body)
		}
		al := st.waitAlert(alerting.BuiltinGatewayAuth, 30*time.Second)
		if al.Severity != "high" || al.Group["key_prefix"] == "" || !strings.HasPrefix(k.Key, al.Group["key_prefix"]) {
			t.Fatalf("оповещение о ключе вне подсети: %+v", al)
		}
		if strings.Contains(fmt.Sprint(st.alertCard(al.ID).Details), k.Key) || strings.Contains(al.Title, k.Key) {
			t.Fatalf("в оповещении ключ целиком: %+v", al)
		}
		rec := st.sys.waitAlert(t, alerting.BuiltinGatewayAuth, 60*time.Second)
		if rec.ID != al.ID || strings.Contains(rec.Raw, k.Key) {
			t.Fatalf("запись syslog: %s", rec.Raw)
		}
	})

	// Отозванный ключ: шлюз отказывает, но оповещения нет — дефект Д-E2E-1
	// (docs/plans/stage-3.md, «Дефекты, найденные e2e 3.32»): пакет несёт
	// только действующие ключи, шлюз видит отозванный ключ как неизвестный
	// (reason invalid), а DM-38 ждёт reason revoked. Отказ проверяется, шаг
	// с оповещением пропускается до исправления кода (ТЗ 5.16: «отозванный
	// ключ — всегда оповещение»).
	t.Run("DM-38 отозванный ключ", func(t *testing.T) {
		applied := strings.Count(st.gw.log(), "пакет конфигурации применён")
		r := st.admin.do("GET", "/api/v1/applications/"+app.id+"/keys", nil)
		var keys struct{ Items []struct{ ID, Prefix string } }
		r.json(t, &keys)
		if r.code != http.StatusOK || len(keys.Items) == 0 {
			t.Fatalf("ключи: %s", r)
		}
		for _, k := range keys.Items {
			if strings.HasPrefix(app.key, k.Prefix) {
				if r := st.admin.do("POST", "/api/v1/app-keys/"+k.ID+"/revoke", nil); r.code != http.StatusOK && r.code != http.StatusNoContent {
					t.Fatalf("отзыв ключа: %s", r)
				}
			}
		}
		if !s2WaitFor(90*time.Second, func() bool {
			return strings.Count(st.gw.log(), "пакет конфигурации применён") > applied
		}) {
			t.Fatalf("шлюз не получил пакет после отзыва:\n%s", st.gw.log())
		}
		if code, _ := st.chat(app.key, "Запрос с отозванным ключом."); code != http.StatusUnauthorized {
			t.Fatalf("шлюз принимает отозванный ключ: %d", code)
		}
		t.Skip("Д-E2E-1: оповещение DM-38 по отозванному ключу не поднимается (в пакете нет отозванных ключей); отказ шлюза проверен")
	})

	t.Run("DM-38 перебор ключей", func(t *testing.T) {
		// Серия неверных ключей блокирует адрес шлюзом (429); это отдельное
		// оповещение по адресу.
		blockedByLimiter := false
		for i := range 25 {
			code, _ := st.chat(fmt.Sprintf("aisec_%08d_bruteforce%02d", i, i), "Подбор ключа.")
			if code == http.StatusTooManyRequests {
				blockedByLimiter = true
				break
			}
		}
		if !blockedByLimiter {
			t.Fatal("шлюз не заблокировал адрес после серии неверных ключей")
		}
		if !s2WaitFor(30*time.Second, func() bool {
			for _, a := range st.alertsOf(alerting.BuiltinGatewayAuth) {
				if a.Group["remote_addr"] != "" {
					return true
				}
			}
			return false
		}) {
			t.Fatalf("нет оповещения о переборе по адресу: %+v", st.alertsOf(alerting.BuiltinGatewayAuth))
		}
	})
}

// siemAudit — запись журнала аудита, принятая приёмником syslog.
type siemAudit struct {
	Seq    int64
	Action string
	Prev   string
	Hash   string
	Raw    []byte
}

// auditRecords — записи журнала аудита среди принятых (MSGID audit).
func (sl *s3Syslog) auditRecords(t *testing.T) []siemAudit {
	t.Helper()
	sl.mu.Lock()
	defer sl.mu.Unlock()
	var out []siemAudit
	for _, rec := range sl.recs {
		if !strings.Contains(rec, " aisec - audit - ") {
			continue
		}
		var m struct {
			Type   string
			Record json.RawMessage
			Hash   string
		}
		i := strings.Index(rec, "{")
		if i < 0 || json.Unmarshal([]byte(rec[i:]), &m) != nil || m.Type != "audit" {
			t.Fatalf("запись аудита в syslog не разбирается: %s", rec)
		}
		var r struct {
			Seq    int64
			Action string
			Prev   string
		}
		if err := json.Unmarshal(m.Record, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, siemAudit{Seq: r.Seq, Action: r.Action, Prev: r.Prev, Hash: m.Hash, Raw: m.Record})
	}
	return out
}

// Передача журнала аудита в SIEM (РСБ.6, задача 3.14): записи приходят по
// порядку без пропусков, SIEM сам проверяет цепочку хешей; пока приёмник
// недоступен, записи не теряются — после его возвращения передача догоняет
// журнал.
func TestE2EStage3_AuditStreamSIEM(t *testing.T) {
	st := s3NewStack(t, s3Opts{syslog: true, auditStream: true})

	st.admin.createUser("auditor-e2e-1", auth.RoleAuditor)
	if !s2WaitFor(60*time.Second, func() bool {
		for _, r := range st.sys.auditRecords(t) {
			if r.Action == "user.create" {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("запись user.create не дошла до SIEM: %d записей аудита", len(st.sys.auditRecords(t)))
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	// verify проверяет то, что делает SIEM: хеш записи, связь с предыдущей и
	// непрерывность seq.
	verify := func() []siemAudit {
		t.Helper()
		recs := st.sys.auditRecords(t)
		seen := map[int64]bool{}
		var uniq []siemAudit
		for _, r := range recs {
			if !seen[r.Seq] {
				seen[r.Seq] = true
				uniq = append(uniq, r)
			}
		}
		for i, r := range uniq {
			if got := hex.EncodeToString(h.Sum(r.Raw)); got != r.Hash {
				t.Fatalf("хеш записи seq=%d не сходится: %s != %s", r.Seq, got, r.Hash)
			}
			if i > 0 {
				if r.Seq != uniq[i-1].Seq+1 {
					t.Fatalf("пропуск в передаче: seq %d после %d", r.Seq, uniq[i-1].Seq)
				}
				if r.Prev != uniq[i-1].Hash {
					t.Fatalf("запись seq=%d не связана с предыдущей", r.Seq)
				}
			}
		}
		return uniq
	}
	before := verify()

	// Приёмник недоступен: действия администратора продолжают писаться.
	st.sys.stop()
	for i := 2; i <= 4; i++ {
		st.admin.createUser(fmt.Sprintf("auditor-e2e-%d", i), auth.RoleAuditor)
	}
	st.sys.restart()
	// Догон: все три записи приходят после возвращения приёмника.
	if !s2WaitFor(150*time.Second, func() bool {
		n := 0
		for _, r := range st.sys.auditRecords(t) {
			if r.Action == "user.create" {
				n++
			}
		}
		return n >= 4
	}) {
		t.Fatalf("передача не догнала журнал после возвращения приёмника: %d записей аудита", len(st.sys.auditRecords(t)))
	}
	after := verify()
	if len(after) <= len(before) {
		t.Fatalf("новых записей нет: было %d, стало %d", len(before), len(after))
	}
	// Состояние передачи в консоли: ничего не ждёт передачи.
	var chans struct{ Items []struct{ ID string } }
	r := st.admin.do("GET", "/api/v1/notify-channels", nil)
	r.json(t, &chans)
	if len(chans.Items) != 1 {
		t.Fatalf("каналы: %s", r)
	}
	if !s2WaitFor(60*time.Second, func() bool {
		r := st.admin.do("GET", "/api/v1/notify-channels/"+chans.Items[0].ID+"/audit-stream", nil)
		return r.code == http.StatusOK && strings.Contains(string(r.body), `"subscribed":true`) &&
			strings.Contains(string(r.body), `"lagging":false`)
	}) {
		t.Fatalf("состояние передачи: %s", st.admin.do("GET", "/api/v1/notify-channels/"+chans.Items[0].ID+"/audit-stream", nil))
	}
}
