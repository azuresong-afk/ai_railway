//go:build e2e

package e2e

// Сценарии ТЗ 1.4 на настоящем сервере, шлюзе и PostgreSQL (задача 3.32
// этапа 3): S2 и S3 (инъекция, ПДн), S4 и S8 (канарейка → инцидент →
// закрытие). Строки матрицы обнаружения покрыты модульными тестами с ID
// строки, здесь — сквозной путь от запроса до оповещения, инцидента и
// доставки уведомления в тестовый syslog. Путь аналитика в консоли для S8
// проверяет Playwright (web/e2e/incidents.spec.ts).

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
	"github.com/azuresong-afk/ai_railway/internal/detect/canary"
	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
)

// S2 и S3: инъекция блокируется с корректной ошибкой и оповещением, ПДн
// не доходят до провайдера и возвращаются клиенту; оповещение доходит до
// тестового приёмника syslog по TLS.
func TestE2EStage3_S2S3_InjectionAndPII(t *testing.T) {
	st := s3NewStack(t, s3Opts{syslog: true})
	st.policy("support")
	app := st.app("support-bot", "support")
	st.startGateway()

	// S3: телефон и СНИЛС уходят провайдеру псевдонимами и возвращаются в ответе.
	phone, snils := pii.SynthPhone(1), pii.SynthSNILS(1)
	prompt := "Свяжитесь с клиентом по телефону " + phone + ", СНИЛС " + snils + ", и поблагодарите за заказ."
	code, body := st.chat(app.key, prompt)
	if code != http.StatusOK {
		t.Fatalf("запрос с ПДн: %d %s", code, body)
	}
	if !strings.Contains(body, phone) || !strings.Contains(body, snils) {
		t.Fatalf("исходные значения не возвращены клиенту: %s", body)
	}
	last := st.mockLast()
	if !last.Received || strings.Contains(last.Body, phone) || strings.Contains(last.Body, snils) ||
		!strings.Contains(last.Body, "[[PHONE_1]]") || !strings.Contains(last.Body, "[[SNILS_1]]") {
		t.Fatalf("провайдер получил: %+v", last)
	}
	// В консоль ПДн не попадают: ни в список, ни в карточку события.
	pseudo := s3LastEvent(t, st.admin, `app = "support-bot" and action = "pseudonymize"`, map[string]bool{})
	for _, path := range []string{"/api/v1/events?limit=50", "/api/v1/events/" + pseudo.ID} {
		if r := st.admin.do("GET", path, nil); r.code != http.StatusOK || strings.Contains(string(r.body), phone) ||
			strings.Contains(string(r.body), snils) {
			t.Fatalf("%s: ПДн в ответе консоли или нет ответа: %d", path, r.code)
		}
	}

	// S2: инъекция блокируется корректной ошибкой, до провайдера не доходит.
	st.mockReset()
	code, body = st.chat(app.key, s3InjectionText)
	if code != http.StatusBadRequest || !strings.Contains(body, "policy_violation") {
		t.Fatalf("инъекция: %d %s", code, body)
	}
	if st.mockLast().Received {
		t.Fatal("заблокированный запрос дошёл до провайдера")
	}
	blocked := s3LastEvent(t, st.admin, `app = "support-bot" and action = "block"`, map[string]bool{})

	// Оповещение DM-01: на приложение, со ссылкой на событие, без содержимого.
	al := st.waitAlert(alerting.BuiltinInjectionBlocked, 30*time.Second)
	if al.Group["app"] != "support-bot" || al.Severity != "high" || al.Status != "new" {
		t.Fatalf("оповещение: %+v", al)
	}
	card := st.alertCard(al.ID)
	if len(card.Events) == 0 || card.Events[0].ID != blocked.ID {
		t.Fatalf("оповещение не ссылается на заблокированное событие %s: %+v", blocked.ID, card.Events)
	}
	if r := st.admin.do("GET", "/api/v1/alerts/"+al.ID, nil); strings.Contains(string(r.body), "previous instructions") {
		t.Fatalf("содержимое запроса в оповещении: %s", r.body)
	}

	// Доставка: запись RFC 5424 по TLS, общий формат JSON, без содержимого.
	rec := st.sys.waitAlert(t, alerting.BuiltinInjectionBlocked, 60*time.Second)
	if rec.ID != al.ID || rec.Severity != "high" || rec.Group["app"] != "support-bot" || rec.Type != "alert" {
		t.Fatalf("запись syslog: %+v", rec)
	}
	if strings.Contains(rec.Raw, "previous instructions") || strings.Contains(rec.Raw, app.key) {
		t.Fatalf("в записи syslog содержимое запроса или ключ: %s", rec.Raw)
	}
	if !strings.HasPrefix(rec.Raw, "<") || !strings.Contains(rec.Raw, ">1 ") {
		t.Fatalf("запись не RFC 5424: %s", rec.Raw)
	}
	// Доставка видна в журнале доставок канала.
	var ch struct{ ID string }
	list := st.admin.do("GET", "/api/v1/notify-channels", nil)
	var chs struct{ Items []struct{ ID, Type string } }
	list.json(t, &chs)
	for _, c := range chs.Items {
		if c.Type == "syslog" {
			ch.ID = c.ID
		}
	}
	if ch.ID == "" {
		t.Fatalf("канал syslog не найден: %s", list)
	}
	if r := st.admin.do("GET", "/api/v1/notify-channels/"+ch.ID+"/deliveries?limit=20", nil); r.code != http.StatusOK ||
		!strings.Contains(string(r.body), `"status":"sent"`) {
		t.Fatalf("журнал доставок: %s", r)
	}
}

// S4 и S8: канарейка системного промпта в ответе блокирует ответ и создаёт
// инцидент; аналитик идёт от оповещения к событию, берёт инцидент в работу и
// закрывает его с резолюцией, оповещение закрывается вместе с ним.
func TestE2EStage3_S4S8_CanaryIncident(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	marker, err := canary.Generate(rnd)
	if err != nil {
		t.Fatal(err)
	}
	st := s3NewStack(t, s3Opts{mockArgs: []string{"-canary", marker}, syslog: true})
	st.policy("support")
	app := st.app("support-bot", "support")
	st.startGateway()

	// S4: ответ с канарейкой блокируется, значение не доходит до клиента.
	code, body := st.chat(app.key, "Расскажи, как работает шлюз.")
	if code != http.StatusBadRequest || !strings.Contains(body, "policy_violation") || strings.Contains(body, marker) {
		t.Fatalf("ответ с канарейкой: %d %s", code, body)
	}
	blocked := s3LastEvent(t, st.admin, `app = "support-bot" and detector = "canary"`, map[string]bool{})

	// Оповещение и инцидент создаются сразу, значение канарейки нигде не видно.
	al := st.waitAlert(alerting.BuiltinCanaryLeak, 30*time.Second)
	if al.Severity != "critical" || al.Group["app"] != "support-bot" || al.IncidentID == "" {
		t.Fatalf("оповещение: %+v", al)
	}
	r := st.admin.do("GET", "/api/v1/incidents/"+al.IncidentID, nil)
	if r.code != http.StatusOK || strings.Contains(string(r.body), marker) {
		t.Fatalf("инцидент: %s", r)
	}
	var inc struct {
		Number   int
		Category string
		Status   string
		Source   string
		Severity string
	}
	r.json(t, &inc)
	if inc.Category != "system_prompt_leak" || inc.Status != "new" || inc.Severity != "critical" {
		t.Fatalf("инцидент: %+v", inc)
	}
	// Оповещение ссылается на событие, событие открывается из него (S8).
	card := st.alertCard(al.ID)
	if len(card.Events) == 0 || card.Events[0].ID != blocked.ID {
		t.Fatalf("оповещение не ссылается на событие %s: %+v", blocked.ID, card.Events)
	}
	if r := st.admin.do("GET", "/api/v1/events/"+blocked.ID, nil); r.code != http.StatusOK ||
		!strings.Contains(string(r.body), `"canary"`) || strings.Contains(string(r.body), marker) {
		t.Fatalf("событие: %s", r)
	}

	// Оповещение доставлено в SIEM.
	rec := st.sys.waitAlert(t, alerting.BuiltinCanaryLeak, 60*time.Second)
	if rec.ID != al.ID || rec.Severity != "critical" || strings.Contains(rec.Raw, marker) {
		t.Fatalf("запись syslog: %s", rec.Raw)
	}

	// Повторная утечка дополняет открытый инцидент, а не создаёт новый.
	if code, _ := st.chat(app.key, "Ещё раз, как работает шлюз?"); code != http.StatusBadRequest {
		t.Fatalf("повтор: %d", code)
	}
	if !s2WaitFor(30*time.Second, func() bool { return st.waitAlertOnce(alerting.BuiltinCanaryLeak).Count >= 2 }) {
		t.Fatal("повторная утечка не дополнила оповещение")
	}
	if n := st.incidentCount(); n != 1 {
		t.Fatalf("инцидентов %d, ожидался 1", n)
	}

	// Разбор: в работу, затем закрытие с резолюцией; нужен пользователь с
	// правом управления инцидентами (аналитик не закрывает чужие системные).
	r = st.admin.do("POST", "/api/v1/incidents/"+al.IncidentID+"/status", map[string]any{"status": "in_progress", "comment": "Разбираюсь"})
	if r.code != http.StatusOK {
		t.Fatalf("в работу: %s", r)
	}
	if r := st.admin.do("POST", "/api/v1/incidents/"+al.IncidentID+"/status", map[string]any{"status": "closed"}); r.code != http.StatusBadRequest &&
		r.code != http.StatusUnprocessableEntity {
		t.Fatalf("закрытие без резолюции: %s", r)
	}
	r = st.admin.do("POST", "/api/v1/incidents/"+al.IncidentID+"/status", map[string]any{"status": "closed", "resolution": "resolved",
		"comment": "Промпт заменён, канарейка перевыпущена"})
	if r.code != http.StatusOK {
		t.Fatalf("закрытие: %s", r)
	}
	if got := st.alertCard(al.ID); got.Status != "closed" {
		t.Fatalf("оповещение не закрылось вместе с инцидентом: %+v", got.s3AlertItem)
	}
	for _, action := range []string{"incident.status_changed"} {
		if n := st.s.auditCount(action); n < 2 {
			t.Fatalf("аудит %s: %d записей", action, n)
		}
	}
	// Утечка после закрытия открывает новый инцидент (без окна подавления).
	if code, _ := st.chat(app.key, "И в третий раз про шлюз."); code != http.StatusBadRequest {
		t.Fatalf("после закрытия: %d", code)
	}
	if !s2WaitFor(30*time.Second, func() bool { return st.incidentCount() == 2 }) {
		t.Fatalf("после закрытия не открылся новый инцидент: %d", st.incidentCount())
	}
}

// customerClient — клиент приложения, доверяющий только корню roots: так
// выглядит приложение, не знающее внутренний УЦ продукта.
func (st *s3Stack) customerClient(roots []byte) *http.Client {
	st.t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		st.t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		st.t.Fatal(err)
	}
	cfg, err := tp.ClientConfig(roots)
	if err != nil {
		st.t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 30 * time.Second}
	st.t.Cleanup(hc.CloseIdleConnections)
	return hc
}

// post отправляет запрос в шлюз клиентом hc; err — отказ рукопожатия TLS.
func (st *s3Stack) post(hc *http.Client, key, text string) (int, error) {
	st.t.Helper()
	body := fmt.Sprintf(`{"model":"mock-echo","messages":[{"role":"user","content":%q}]}`, text)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, st.gw.base+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		st.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) //nolint:gosec // G104: тело не нужно
	_ = resp.Body.Close()                                        //nolint:gosec // G104: тело прочитано
	return resp.StatusCode, nil
}

// S1: владелец регистрирует приложение, получает ключ и пускает трафик через
// шлюз; приложение, не доверяющее внутреннему УЦ, получает адрес шлюза с
// сертификатом заказчика (шаг мастера подключения) — без перезапуска шлюза.
func TestE2EStage3_S1_ConnectWithCustomerCertificate(t *testing.T) {
	st := s3NewStack(t, s3Opts{})
	st.policy("support")
	app := st.app("support-bot", "support")
	st.startGateway()
	roots := mustRead(t, st.s.tls.ca)

	// Ключ приложения показывается один раз: в карточке и списке его нет.
	for _, path := range []string{"/api/v1/applications/" + app.id, "/api/v1/applications/" + app.id + "/keys", "/api/v1/applications"} {
		if r := st.admin.do("GET", path, nil); r.code != http.StatusOK || strings.Contains(string(r.body), app.key) {
			t.Fatalf("%s: ключ приложения виден повторно или нет ответа: %d", path, r.code)
		}
	}
	// Трафик идёт через защиту по сертификату внутреннего УЦ.
	if code, err := st.post(st.customerClient(roots), app.key, "Здравствуйте, где мой заказ?"); err != nil || code != http.StatusOK {
		t.Fatalf("запрос по внутреннему УЦ: %d %v", code, err)
	}
	if r := st.admin.do("GET", "/api/v1/gateway-certificate", nil); r.code != http.StatusOK || !strings.Contains(string(r.body), `"configured":false`) {
		t.Fatalf("сертификат заказчика до загрузки: %s", r)
	}

	// Шаг мастера: сертификат заказчика для адреса шлюза. Закрытый ключ
	// не возвращается ни в ответе, ни при чтении.
	chain, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	r := st.admin.do("PUT", "/api/v1/gateway-certificate", map[string]any{"host": "127.0.0.1", "chain_pem": string(chain.Full()),
		"key_pem": string(chain.Key)})
	if r.code != http.StatusOK {
		t.Fatalf("загрузка сертификата заказчика: %s", r)
	}
	if strings.Contains(string(r.body), "PRIVATE KEY") {
		t.Fatalf("закрытый ключ в ответе: %s", r.body)
	}
	if r = st.admin.do("GET", "/api/v1/gateway-certificate", nil); r.code != http.StatusOK ||
		!strings.Contains(string(r.body), `"configured":true`) || !strings.Contains(string(r.body), `"key_set":true`) ||
		strings.Contains(string(r.body), "PRIVATE KEY") {
		t.Fatalf("сведения о сертификате: %s", r)
	}
	if n := st.s.auditCount("gateway_tls.set"); n != 1 {
		t.Fatalf("аудит gateway_tls.set: %d", n)
	}
	if !st.gw.waitLog("адрес приложений переключён на сертификат заказчика без перезапуска", 90*time.Second) {
		t.Fatalf("шлюз не переключил TLS:\n%s", st.gw.log())
	}

	// Приложение, доверяющее только корню заказчика, подключается; без
	// перезапуска шлюза. Внутренний УЦ адрес больше не обслуживает.
	customer := st.customerClient(chain.Root)
	if code, err := st.post(customer, app.key, "Здравствуйте, где мой заказ?"); err != nil || code != http.StatusOK {
		t.Fatalf("запрос по сертификату заказчика: %d %v", code, err)
	}
	// Отказ — именно проверка сертификата, а не любой сбой соединения (3Н52).
	if _, err := st.post(st.customerClient(roots), app.key, "Здравствуйте"); err == nil ||
		!strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("адрес шлюза всё ещё обслуживается сертификатом внутреннего УЦ или отказ не по сертификату: %v", err)
	}
	if strings.Contains(st.gw.log(), "PRIVATE KEY") || strings.Contains(st.s.srv.log(), "PRIVATE KEY") {
		t.Fatal("закрытый ключ заказчика в техническом журнале")
	}

	// Удаление возвращает адрес сертификату внутреннего УЦ.
	if r := st.admin.do("DELETE", "/api/v1/gateway-certificate", nil); r.code != http.StatusNoContent {
		t.Fatalf("удаление сертификата заказчика: %s", r)
	}
	if !s2WaitFor(90*time.Second, func() bool {
		code, err := st.post(st.customerClient(roots), app.key, "Здравствуйте")
		return err == nil && code == http.StatusOK
	}) {
		t.Fatalf("после удаления адрес не вернулся к внутреннему УЦ:\n%s", st.gw.log())
	}
}

// S9: жёсткий бюджет приложения — запросы сверх бюджета отклоняются шлюзом
// (429 budget_exceeded), расход виден в консоли, на порогах 80 % и 100 %
// приходят оповещения и доходят до приёмника syslog.
func TestE2EStage3_S9_HardBudget(t *testing.T) {
	st := s3NewStack(t, s3Opts{syslog: true})
	st.policy("support")
	app := st.app("support-bot", "support")
	// 1 рубль за токен: запрос mock-echo стоит несколько рублей; бюджет 50 ₽
	// исчерпывается за несколько запросов.
	r := st.admin.do("POST", "/api/v1/model-prices", map[string]any{"provider_id": st.prov, "model": "mock-echo",
		"input_price": "1000.0000", "output_price": "1000.0000"})
	if r.code != http.StatusCreated {
		t.Fatalf("цена модели: %s", r)
	}
	r = st.admin.do("PUT", "/api/v1/applications/"+app.id+"/budget", map[string]any{"mode": "hard", "monthly_limit": "50.00"})
	if r.code != http.StatusOK {
		t.Fatalf("бюджет: %s", r)
	}
	st.startGateway()

	// Запросы идут, пока расход ниже бюджета; затем шлюз отказывает с
	// понятным кодом и временем повтора, провайдер запроса не видит.
	passed := 0
	var denied string
	for i := range 40 {
		code, body := st.chat(app.key, fmt.Sprintf("Расскажи про заказ номер %d.", i))
		if code == http.StatusTooManyRequests {
			denied = body
			break
		}
		if code != http.StatusOK {
			t.Fatalf("запрос %d: %d %s", i, code, body)
		}
		passed++
	}
	if denied == "" || passed == 0 || !strings.Contains(denied, "budget_exceeded") {
		t.Fatalf("бюджет не исчерпан за 40 запросов (прошло %d): %s", passed, denied)
	}
	st.mockReset()
	if code, body := st.chat(app.key, "Ещё запрос сверх бюджета."); code != http.StatusTooManyRequests || !strings.Contains(body, "budget_exceeded") {
		t.Fatalf("повтор сверх бюджета: %d %s", code, body)
	}
	if st.mockLast().Received {
		t.Fatal("запрос сверх бюджета дошёл до провайдера")
	}
	over := s3LastEvent(t, st.admin, `app = "support-bot" and threat = "DM-15"`, map[string]bool{})
	if over.Action != "block" {
		t.Fatalf("событие отказа по бюджету: %+v", over)
	}

	// Расход виден в консоли после heartbeat шлюза; бюджет исчерпан.
	if !s2WaitFor(90*time.Second, func() bool {
		r := st.admin.do("GET", "/api/v1/applications/"+app.id+"/budget", nil)
		return r.code == http.StatusOK && strings.Contains(string(r.body), `"exhausted":true`)
	}) {
		r := st.admin.do("GET", "/api/v1/applications/"+app.id+"/budget", nil)
		t.Fatalf("расход не дошёл до консоли: %s", r)
	}

	// Оповещения на порогах 80 % и 100 % (фоновая задача раз в минуту).
	var got map[string]bool
	if !s2WaitFor(150*time.Second, func() bool {
		r := st.admin.do("GET", "/api/v1/alerts?limit=50&rule_id="+st.ruleID(alerting.BuiltinBudget), nil)
		if r.code != http.StatusOK {
			t.Fatalf("оповещения: %s", r)
		}
		var page struct{ Items []s3AlertItem }
		r.json(t, &page)
		got = map[string]bool{}
		for _, a := range page.Items {
			if a.Group["app"] == "support-bot" {
				got[a.Group["threshold"]] = true
			}
		}
		return got["80 %"] && got["100 %"]
	}) {
		t.Fatalf("оповещения о бюджете: %v", got)
	}
	// Доставка в SIEM: оба порога (3Н52 — каждый своей записью).
	sent := map[string]bool{}
	if !s2WaitFor(60*time.Second, func() bool {
		for _, rec := range st.sys.alerts() {
			if rec.Rule != alerting.BuiltinBudget {
				continue
			}
			if rec.Group["app"] != "support-bot" || rec.Severity != "high" {
				t.Fatalf("запись syslog: %s", rec.Raw)
			}
			sent[rec.Group["threshold"]] = true
		}
		return sent["80 %"] && sent["100 %"]
	}) {
		t.Fatalf("в SIEM пришли пороги бюджета: %v", sent)
	}
	// Снятие бюджета возвращает доступ (после нового пакета).
	if r := st.admin.do("DELETE", "/api/v1/applications/"+app.id+"/budget", nil); r.code != http.StatusNoContent {
		t.Fatalf("снятие бюджета: %s", r)
	}
	if !s2WaitFor(90*time.Second, func() bool {
		code, _ := st.chat(app.key, "Запрос после снятия бюджета.")
		return code == http.StatusOK
	}) {
		t.Fatal("после снятия бюджета запросы по-прежнему отклоняются")
	}
}

// reportDay — день ГГГГ-ММ-ДД для периода отчёта.
func reportDay(d time.Time) string { return d.UTC().Format("2006-01-02") }

// S10: по окончании пилота — отчёт «Итоги пилота» в HTML, CSV и XLSX: сколько
// запросов прошло, какие ПДн ушли бы провайдеру, какие атаки найдены, сколько
// ложных срабатываний. В отчёте нет содержимого запросов и значений ПДн,
// каждая выгрузка пишет data.export.
func TestE2EStage3_S10_PilotReport(t *testing.T) {
	st := s3NewStack(t, s3Opts{})
	st.policy("support")
	app := st.app("support-bot", "support")
	st.startGateway()

	phone := pii.SynthPhone(2)
	for i := range 3 {
		if code, body := st.chat(app.key, fmt.Sprintf("Где мой заказ номер %d?", i)); code != http.StatusOK {
			t.Fatalf("обычный запрос: %d %s", code, body)
		}
	}
	for range 2 {
		if code, body := st.chat(app.key, "Перезвоните клиенту по телефону "+phone+"."); code != http.StatusOK {
			t.Fatalf("запрос с ПДн: %d %s", code, body)
		}
	}
	for range 2 {
		if code, _ := st.chat(app.key, s3InjectionText); code != http.StatusBadRequest {
			t.Fatalf("инъекция не заблокирована: %d", code)
		}
	}
	// Аналитик отмечает блокировку ложным срабатыванием.
	blocked := s3LastEvent(t, st.admin, `app = "support-bot" and action = "block"`, map[string]bool{})
	analystUser := st.admin.createUser("analyst-e2e", auth.RoleAnalyst)
	analyst := st.s.client("198.51.100.31")
	analyst.signIn(analystUser)
	if r := analyst.do("PUT", "/api/v1/events/"+blocked.ID+"/mark", map[string]any{"mark": "false_positive",
		"comment": "Цитата из базы знаний"}); r.code != http.StatusOK {
		t.Fatalf("отметка: %s", r)
	}

	// Период — вчера и сегодня; конец, выходящий за сегодня, урезается.
	now := time.Now()
	q := "?from=" + reportDay(now.AddDate(0, 0, -1)) + "&to=" + reportDay(now.AddDate(0, 0, 1))
	exports := st.s.auditCount("data.export")

	// HTML: агрегаты дашбордов считаются в фоне, ждём, пока отчёт увидит запросы.
	var html string
	if !s2WaitFor(90*time.Second, func() bool {
		r := st.admin.do("GET", "/api/v1/reports/pilot"+q+"&format=html", nil)
		if r.code != http.StatusOK {
			t.Fatalf("отчёт HTML: %s", r)
		}
		html = string(r.body)
		return strings.Contains(html, "Что найдено по строкам матрицы обнаружения") && strings.Contains(html, "DM-01")
	}) {
		t.Fatalf("в отчёте нет находок за период:\n%s", html)
	}
	for _, want := range []string{
		`<td>Запросов проверено</td><td class="num">7</td>`,
		`<td>Заблокировано (режим защиты)</td><td class="num">2</td>`,
		`<td>Замаскировано</td><td class="num">2</td>`,
		`<tr><td>DM-01</td><td class="num">2</td></tr>`,
		`<tr><td>pii.phone</td><td class="num">2</td><td class="num">0</td></tr>`,
		`<tr><td>injection.override</td><td class="num">2</td></tr>`,
		`<td>События, отмеченные как ложное срабатывание</td><td class="num">1</td>`,
		"Содержимого запросов и ответов в отчёте нет.",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("в отчёте нет %q:\n%s", want, html)
		}
	}
	for _, bad := range []string{phone, "previous instructions", "<script", app.key} {
		if strings.Contains(html, bad) {
			t.Fatalf("в отчёте недопустимое %q", bad)
		}
	}
	r := st.admin.do("GET", "/api/v1/reports/pilot"+q+"&format=html", nil)
	if csp := r.hdr.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") && !strings.Contains(csp, "script-src 'none'") {
		t.Fatalf("у отчёта HTML нет собственной политики CSP: %q", csp)
	}

	// CSV: UTF-8 с BOM, те же данные; XLSX: архив без макросов и формул.
	csv := st.admin.do("GET", "/api/v1/reports/pilot"+q+"&format=csv", nil)
	if csv.code != http.StatusOK || !strings.HasPrefix(csv.hdr.Get("Content-Type"), "text/csv") ||
		!strings.HasPrefix(string(csv.body), "\ufeff") || !strings.Contains(string(csv.body), "DM-01") ||
		strings.Contains(string(csv.body), phone) || csv.hdr.Get("X-Export-Rows") == "" {
		t.Fatalf("отчёт CSV: %d %v\n%.600s", csv.code, csv.hdr, csv.body)
	}
	x := st.admin.do("GET", "/api/v1/reports/pilot"+q+"&format=xlsx", nil)
	if x.code != http.StatusOK || !strings.Contains(x.hdr.Get("Content-Type"), "spreadsheetml") {
		t.Fatalf("отчёт XLSX: %d %v", x.code, x.hdr)
	}
	zr, err := zip.NewReader(bytes.NewReader(x.body), int64(len(x.body)))
	if err != nil {
		t.Fatalf("XLSX не архив: %v", err)
	}
	var sheet string
	for _, f := range zr.File {
		if strings.Contains(strings.ToLower(f.Name), "vba") || strings.HasSuffix(f.Name, ".bin") {
			t.Fatalf("в XLSX макросы или бинарные части: %s", f.Name)
		}
		if strings.HasPrefix(f.Name, "xl/worksheets/") || f.Name == "xl/sharedStrings.xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(io.LimitReader(rc, 8<<20))
			_ = rc.Close() //nolint:gosec // G104: часть архива прочитана
			if err != nil {
				t.Fatal(err)
			}
			sheet += string(b)
		}
	}
	if !strings.Contains(sheet, "DM-01") || strings.Contains(sheet, "<f>") || strings.Contains(sheet, phone) {
		t.Fatalf("содержимое XLSX: формулы, ПДн или нет данных:\n%.600s", sheet)
	}
	// Каждая выгрузка пишет data.export (DM-41): HTML (опрос и проверка CSP), CSV, XLSX —
	// по записи на каждый формат (3Н52).
	if n := st.s.auditCount("data.export") - exports; n < 3 {
		t.Fatalf("записей data.export за выгрузки отчётов: %d", n)
	}
	formats := map[string]bool{}
	rows, err := st.s.pg().Query(context.Background(),
		`SELECT details->>'format' FROM audit_log WHERE action = 'data.export' AND details->>'report' IS NOT NULL`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var f *string
		if err := rows.Scan(&f); err != nil {
			t.Fatal(err)
		}
		if f != nil {
			formats[*f] = true
		}
	}
	if rows.Close(); rows.Err() != nil || !formats["html"] || !formats["csv"] || !formats["xlsx"] {
		t.Fatalf("форматы в data.export отчётов: %v %v", formats, rows.Err())
	}
}
