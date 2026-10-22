package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/notify"
)

// Каналы уведомлений (задача 3.13 этапа 3) на хранилище Memory: права,
// секреты не возвращаются, ослабление с повторной проверкой, тестовая
// отправка с пределом частоты. Отправка — только на 127.0.0.1.

type notifyEnv struct {
	*authEnv
	store *notify.Memory
	caPEM string
}

func newNotifyEnv(t *testing.T) *notifyEnv {
	t.Helper()
	e := &notifyEnv{authEnv: &authEnv{mem: authtest.NewMemory(), log: &bytes.Buffer{}, clock: &testClock{t: time.Now()},
		secrets: map[string][]byte{}}, store: notify.NewMemory()}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, u := range []struct {
		id, login string
		role      auth.Role
	}{
		{tAdminID, "admin", auth.RoleSecurityAdmin}, {tSysAdminID, "sysadm", auth.RoleSystemAdmin},
		{tAuditorID, "auditor", auth.RoleAuditor}, {tAnalystID, "analyst", auth.RoleAnalyst},
	} {
		e.mem.AddUser(auth.User{ID: u.id, OrgID: audit.DefaultOrgID, Login: u.login, DisplayName: u.login, Role: u.role,
			Status: auth.StatusActive, PasswordHash: authtest.HashOf(tPhrase), PasswordChangedAt: now, CreatedAt: now, CreatedBy: "test"})
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	box, err := keyring.NewStaticKey(p, "01900000-0000-7000-8000-00000000d001", make([]byte, aisecCrypto.AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	tr, err := notify.NewTransport(p, "test", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := notify.New(notify.Options{Store: e.store, Box: box, Provider: p, Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := aisecCrypto.NewCA("AISec test CA", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.caPEM = string(ca.CertPEM())
	h, _, err := New(Options{Hasher: testHasher(t), Logger: slog.New(slog.NewTextHandler(e.log, nil)),
		Auth: testAuth(t, e.mem, auth.WithClock(e.clock.now)), Notify: svc,
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 100000, Window: time.Minute}}}})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	return e
}

func TestNotifyChannelsAPI(t *testing.T) {
	e := newNotifyEnv(t)
	admin := e.mustLogin(t, "admin")
	auditor := e.mustLogin(t, "auditor")
	analyst := e.mustLogin(t, "analyst")
	sys := e.mustLogin(t, "sysadm")
	ca, _ := json.Marshal(e.caPEM)
	hook := `{"name":"Mattermost SOC","type":"webhook","min_severity":"high","settings":{"format":"mattermost","ca_pem":` +
		string(ca) + `},"secrets":{"url":"https://127.0.0.1:1/hooks/synthetic-token","signing_key":"0123456789abcdef0123456789abcdef"}}`

	// Создание — только администратор безопасности.
	for _, s := range []session{auditor, analyst, sys} {
		mustProblem(t, e.call(s, "POST", "/api/v1/notify-channels", hook, true), 403, CodeForbidden)
	}
	mustProblem(t, e.call(analyst, "GET", "/api/v1/notify-channels", "", false), 403, CodeForbidden)
	w := e.call(admin, "POST", "/api/v1/notify-channels", hook, true)
	if w.Code != 201 || strings.Contains(w.Body.String(), "synthetic-token") || strings.Contains(w.Body.String(), "0123456789abcdef") {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	c := decode[NotifyChannelView](t, w.Body.Bytes())
	if c.Settings.URLOrigin != "https://127.0.0.1:1" || strings.Join(c.SecretsSet, ",") != "signing_key,url" || !c.Enabled {
		t.Fatalf("канал: %+v", c)
	}
	mustProblem(t, e.call(admin, "POST", "/api/v1/notify-channels", hook, true), 409, CodeConflict)
	w = e.call(admin, "POST", "/api/v1/notify-channels", strings.Replace(hook, "https://", "http://", 1), true)
	mustProblem(t, w, 400, CodeInvalidRequest)
	if !strings.Contains(w.Body.String(), `"field":"secrets.url"`) {
		t.Fatalf("поле ошибки: %s", w.Body)
	}

	// Чтение — аудитор и администратор безопасности, без секретов.
	w = e.call(auditor, "GET", "/api/v1/notify-channels", "", false)
	if w.Code != 200 || strings.Contains(w.Body.String(), "synthetic-token") {
		t.Fatalf("список: %d %s", w.Code, w.Body)
	}
	if got := decode[NotifyChannelList](t, w.Body.Bytes()); len(got.Items) != 1 {
		t.Fatalf("список: %+v", got)
	}
	url := "/api/v1/notify-channels/" + c.ID
	if w := e.call(auditor, "GET", url, "", false); w.Code != 200 {
		t.Fatalf("карточка: %d", w.Code)
	}
	mustProblem(t, e.call(auditor, "GET", "/api/v1/notify-channels/01900000-0000-7000-8000-0000000fffff", "", false), 404, CodeNotFound)

	// Изменение без секретов сохраняет их; отключение — ослабление.
	off := fmt.Sprintf(`{"name":"Mattermost SOC","enabled":false,"min_severity":"high","settings":{"format":"mattermost","ca_pem":%s},"version":%d`,
		ca, c.Version)
	mustProblem(t, e.call(auditor, "PUT", url, off+`}`, true), 403, CodeForbidden)
	w = e.call(admin, "PUT", url, off+`}`, true)
	mustProblem(t, w, 400, CodeInvalidRequest)
	if !strings.Contains(w.Body.String(), `"field":"password"`) {
		t.Fatalf("нет требования пароля: %s", w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", url, off+`,"password":"неверный"}`, true), 403, CodeReauthFailed)
	w = e.call(admin, "PUT", url, off+`,"password":"`+tPhrase+`"}`, true)
	got := decode[NotifyChannelView](t, w.Body.Bytes())
	if w.Code != 200 || got.Enabled || got.Version != 2 || strings.Join(got.SecretsSet, ",") != "signing_key,url" {
		t.Fatalf("отключение: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", url, off+`,"password":"`+tPhrase+`"}`, true), 409, CodeConflict)
	// Включение и понижение порога — не ослабление.
	on := strings.Replace(strings.Replace(off, `"enabled":false`, `"enabled":true`, 1), fmt.Sprintf(`"version":%d`, c.Version), `"version":2`, 1)
	if w := e.call(admin, "PUT", url, strings.Replace(on, `"high"`, `"low"`, 1)+`}`, true); w.Code != 200 {
		t.Fatalf("включение: %d %s", w.Code, w.Body)
	}
	var weak, changed int
	for _, a := range e.store.Audited() {
		if a.Action == "notify_channel.update" {
			changed++
			if a.Details.(map[string]any)["weakening"] == true {
				weak++
			}
		}
	}
	if changed != 2 || weak != 1 {
		t.Fatalf("аудит: изменений %d, ослаблений %d", changed, weak)
	}

	// Тестовая отправка: адрес недоступен — 200 с кодом ошибки; предел — 429.
	test := url + "/test"
	mustProblem(t, e.call(auditor, "POST", test, "", true), 403, CodeForbidden)
	for i := range notify.TestBurst {
		w := e.call(admin, "POST", test, "", true)
		d := decode[NotifyDeliveryView](t, w.Body.Bytes())
		if w.Code != 200 || d.Status != notify.StatusFailed || d.Error != notify.ErrCodeDial || d.Kind != notify.KindTest {
			t.Fatalf("тест %d: %d %s", i+1, w.Code, w.Body)
		}
	}
	mustProblem(t, e.call(admin, "POST", test, "", true), 429, CodeRateLimited)
	w = e.call(auditor, "GET", url+"/deliveries?limit=2", "", false)
	if d := decode[NotifyDeliveryList](t, w.Body.Bytes()); w.Code != 200 || len(d.Items) != 2 {
		t.Fatalf("журнал: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(auditor, "GET", url+"/deliveries?limit=500", "", false), 400, CodeInvalidRequest)
	mustProblem(t, e.call(analyst, "GET", url+"/deliveries", "", false), 403, CodeForbidden)
}

// Токену API права каналов не выдаются: notify_channels.manage — функция
// безопасности.
func TestNotifyChannelsManageNotTokenGrantable(t *testing.T) {
	if auth.TokenGrantable(auth.PermNotifyChannelsManage) || !auth.TokenGrantable(auth.PermNotifyChannelsRead) {
		t.Fatal("права токена на каналы")
	}
}
