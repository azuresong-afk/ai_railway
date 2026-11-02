package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/compliance"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// complianceTestFacts — установка, где настроена только часть мер.
type complianceTestFacts struct{}

func (complianceTestFacts) Snapshot(context.Context) (*compliance.Snapshot, error) {
	return &compliance.Snapshot{Now: shadowTestNow, Unavailable: map[string]bool{},
		Apps: []compliance.AppFact{{Slug: "bot", Env: "prod", PolicyMode: "enforce", InputRules: 1, Storage: "masked",
			Quotas: map[string]int{"requests_per_minute": 10}}},
		PrivilegedRoles: []compliance.RoleFact{{ID: "security_admin", MFA: true, Users: 1}},
		AuditChain:      &compliance.ChainFact{OK: true, CheckedAt: shadowTestNow.Add(-time.Hour)},
		Integrity:       &compliance.IntegrityFact{ServerOK: true, CheckedAt: shadowTestNow}}, nil
}

// signComplianceBase подписывает базу тестовым рабочим ключом репозитория.
func signComplianceBase(t *testing.T, yaml string) []byte {
	t.Helper()
	return signServiceDBKind(t, compliance.BaseKind, yaml)
}

// signServiceDBKind подписывает содержимое служебной базы вида kind тестовым
// рабочим ключом.
func signServiceDBKind(t *testing.T, kind, yaml string) []byte {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile("../../testdata/shadowai/" + name) //nolint:gosec // G304: фикстура теста из репозитория
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	_, seed, err := aisecCrypto.DecodeKeyPEM(read("subkey-test.signkey"), aisecCrypto.KeyKindVendorSubkey)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := p.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	out, err := aisecCrypto.SignServiceDB(sub, read("subkey-test.endorsement"), kind, []byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

const complianceTestBase = `format: aisec-compliance-base-v1
version: 100
date: "2026-10-28"
sources:
  - {id: src-a, title: Источник А}
requirements:
  - {id: test.manual, source: src-a, clause: п. 1, title: Организационная мера, summary: Пересказ, applies: [ispdn], manual: true}
  - {id: test.auto, source: src-a, clause: п. 2, title: Проверка, summary: Пересказ, applies: [gis], checks: [{name: content_storage}]}
`

// Соответствие (задача 4.24): чтение — compliance.read, отметки —
// compliance.mark (только администратор безопасности, только сессия),
// загрузка базы — compliance.base.load; каждое изменение пишет аудит.
func TestComplianceViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	admin := e.mustLogin(t, "admin")
	sys := e.mustLogin(t, "sysadm")
	auditor := e.mustLogin(t, "auditor")
	analyst := e.mustLogin(t, "analyst")
	owner := e.mustLogin(t, "owner")
	const markURL = "/api/v1/compliance/requirements/fstec-m.3.18.model-integrity/mark"
	const octet = "application/octet-stream"

	// Отказ в доступе на каждый эндпоинт.
	for _, s := range []session{analyst, owner} {
		for _, p := range []string{"/api/v1/compliance", "/api/v1/compliance/base", "/api/v1/compliance/requirements/f117.p60.access"} {
			mustProblem(t, e.call(s, "GET", p, "", false), 403, CodeForbidden)
		}
	}
	mustProblem(t, e.call(session{}, "GET", "/api/v1/compliance", "", false), 401, CodeUnauthorized)
	body := `{"status":"met","comment":"Регламент утверждён"}`
	for _, s := range []session{sys, auditor, analyst, owner} {
		mustProblem(t, e.call(s, "PUT", markURL, body, true), 403, CodeForbidden)
		mustProblem(t, e.call(s, "DELETE", markURL, "", true), 403, CodeForbidden)
	}
	for _, s := range []session{auditor, analyst, owner} {
		mustProblem(t, e.callFile(s, "PUT", "/api/v1/compliance/base", octet, []byte("x")), 403, CodeForbidden)
	}

	// Чтение: администратор безопасности, аудитор, администратор системы.
	for _, s := range []session{admin, auditor, sys} {
		w := e.call(s, "GET", "/api/v1/compliance", "", false)
		if w.Code != 200 {
			t.Fatalf("обзор: %d %s", w.Code, w.Body)
		}
		o := decode[compliance.Overview](t, w.Body.Bytes())
		if o.Base.Origin != "builtin" || len(o.Items) < 20 || o.Summary.Percent == nil || o.Summary.Drafts == 0 {
			t.Fatalf("обзор: %+v", o.Summary)
		}
		// Только настройки и ссылки: содержимого запросов в ответе нет.
		if strings.Contains(w.Body.String(), "prompt") && strings.Contains(w.Body.String(), "content\":") {
			t.Errorf("в обзоре похоже на содержимое: %s", w.Body)
		}
	}
	// Фильтры.
	w := e.call(auditor, "GET", "/api/v1/compliance?source=fz-152&applies=commercial", "", false)
	if o := decode[compliance.Overview](t, w.Body.Bytes()); w.Code != 200 || len(o.Items) != 2 {
		t.Fatalf("фильтр: %d %d", w.Code, len(o.Items))
	}
	for _, q := range []string{"?applies=moon", "?x=1", "?source=a&source=b", "?source=" + strings.Repeat("a", 33)} {
		mustProblem(t, e.call(auditor, "GET", "/api/v1/compliance"+q, "", false), 400, CodeInvalidRequest)
	}
	mustProblem(t, e.call(auditor, "GET", "/api/v1/compliance/requirements/nope", "", false), 404, CodeNotFound)
	mustProblem(t, e.call(auditor, "GET", "/api/v1/compliance/requirements/..%2F..", "", false), 404, CodeNotFound)

	// Ручная отметка: пункт, ждущий отметки.
	w = e.call(auditor, "GET", "/api/v1/compliance/requirements/fstec-m.3.18.model-integrity", "", false)
	if it := decode[compliance.Item](t, w.Body.Bytes()); w.Code != 200 || it.Status != compliance.StatusManual {
		t.Fatalf("пункт до отметки: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", markURL, `{"status":"met"}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "PUT", markURL, `{"status":"met","comment":"x","extra":1}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "PUT", markURL, `{"status":"met","comment":"x","review_by":"2020-01-01"}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/compliance/requirements/nope/mark", body, true), 404, CodeNotFound)
	// Статус пункта с проверками вычисляют проверки.
	const autoURL = "/api/v1/compliance/requirements/f117.p60.access/mark"
	mustProblem(t, e.call(admin, "PUT", autoURL, body, true), 422, CodeUnprocessable)
	// 4В36: «не применимо» у пункта с проверками — ослабление: срок
	// пересмотра обязателен, без пароля — 400 с полем password, с неверным —
	// отказ; с паролем — отметка с weakening в аудите.
	na := `{"status":"not_applicable","comment":"Доступ к ПДн закрыт договором","review_by":"2027-06-30"`
	mustProblem(t, e.call(admin, "PUT", autoURL, `{"status":"not_applicable","comment":"Доступ закрыт"}`, true), 400, CodeInvalidRequest)
	if w := e.call(admin, "PUT", autoURL, na+`}`, true); w.Code != 400 || !strings.Contains(w.Body.String(), `"field":"password"`) {
		t.Fatalf("без пароля: %d %s", w.Code, w.Body)
	}
	if w := e.call(admin, "PUT", autoURL, na+`,"password":"неверный пароль"}`, true); w.Code == 200 {
		t.Fatalf("неверный пароль: %d %s", w.Code, w.Body)
	}
	if w := e.call(admin, "PUT", autoURL, na+`,"password":"`+tPhrase+`"}`, true); w.Code != 200 {
		t.Fatalf("«не применимо» с паролем: %d %s", w.Code, w.Body)
	}
	if rec, _ := lastComplianceRecord(e, "compliance.mark_set"); rec.Details.(map[string]any)["weakening"] != true {
		t.Fatalf("аудит без weakening: %+v", rec.Details)
	}
	if w := e.call(admin, "DELETE", autoURL, "", true); w.Code != 200 {
		t.Fatalf("снятие: %d %s", w.Code, w.Body)
	}
	w = e.call(admin, "PUT", markURL, `{"status":"met","comment":"Регламент утверждён приказом № 5","document":"СТО-ИБ-12","review_by":"2027-06-30"}`, true)
	if it := decode[compliance.Item](t, w.Body.Bytes()); w.Code != 200 || it.Status != compliance.StatusMet || it.Mark == nil {
		t.Fatalf("отметка: %d %s", w.Code, w.Body)
	}
	var rec audit.Entry
	for _, r := range append(e.compl.Records(), e.dbs.Records()...) {
		if r.Action == "compliance.mark_set" {
			rec = r
		}
	}
	if rec.Action == "" || rec.Actor.Name != "admin" || rec.Object.ID != "fstec-m.3.18.model-integrity" {
		t.Fatalf("аудит отметки: %+v", rec)
	}
	if w = e.call(admin, "DELETE", markURL, "", true); w.Code != 200 {
		t.Fatalf("снятие: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "DELETE", markURL, "", true), 404, CodeNotFound)
	// Без CSRF-токена изменение не проходит.
	if w = e.call(admin, "PUT", markURL, body, false); w.Code != http.StatusForbidden {
		t.Fatalf("PUT без CSRF: %d", w.Code)
	}

	// База: чтение; загрузка — только подписанная, версия растёт.
	w = e.call(auditor, "GET", "/api/v1/compliance/base", "", false)
	if v := decode[compliance.BaseView](t, w.Body.Bytes()); w.Code != 200 || v.Active.Origin != "builtin" || v.Uploaded != nil {
		t.Fatalf("база: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/compliance/base", "application/json", []byte("{}")), 415, CodeUnsupportedMedia)
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/compliance/base", octet, []byte("мусор")), 422, CodeUnprocessable)
	signed := signComplianceBase(t, complianceTestBase)
	tampered := bytes.Replace(signed, []byte(`"payload":"`), []byte(`"payload":"AA`), 1)
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/compliance/base", octet, tampered), 422, CodeUnprocessable)
	if _, n := lastComplianceRecord(e, "service_db.rejected"); n != 2 {
		t.Fatalf("отказов в аудите %d", n)
	}
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/compliance/base", octet, bytes.Repeat([]byte("x"), complianceBaseMaxBody+1)), 413, CodePayloadTooLarge)
	w = e.callFile(sys, "PUT", "/api/v1/compliance/base", octet, signed)
	if v := decode[compliance.BaseView](t, w.Body.Bytes()); w.Code != 200 || v.Active.Version != 100 || v.Active.Origin != "uploaded" || v.Uploaded == nil || !v.Uploaded.Valid {
		t.Fatalf("загрузка: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/compliance/base", octet, signed), 409, CodeConflict)
	if o := decode[compliance.Overview](t, e.call(auditor, "GET", "/api/v1/compliance", "", false).Body.Bytes()); len(o.Items) != 2 || o.Base.Version != 100 {
		t.Fatalf("новая база не действует: %+v", o.Base)
	}
	// Раздел не подключён — 503.
	e2 := newAppsEnv(t, func(_ *appsEnv, o *Options) { o.Compliance = nil })
	mustProblem(t, e2.call(e2.mustLogin(t, "auditor"), "GET", "/api/v1/compliance", "", false), 503, CodeUnavailable)
}

func lastComplianceRecord(e *appsEnv, action string) (audit.Entry, int) {
	var last audit.Entry
	n := 0
	for _, r := range append(e.compl.Records(), e.dbs.Records()...) {
		if r.Action == action {
			last, n = r, n+1
		}
	}
	return last, n
}

// Расписание отчёта «Соответствие»: автору нужно compliance.read, получатели
// проверяются по тому же праву (3В31 ревью 3.r4, УПД.2).
func TestComplianceReportSchedule(t *testing.T) {
	e := newAppsEnv(t)
	admin := e.mustLogin(t, "admin")
	analyst := e.mustLogin(t, "analyst")
	mk := func(recipients ...string) string {
		b, _ := json.Marshal(recipients) //nolint:gosec // тест: маршалинг среза строк не падает
		return strings.Replace(strings.Replace(scheduleBody("Соответствие"), `"report":"summary"`, `"report":"compliance"`, 1),
			`"channel_id"`, `"recipient_user_ids":`+string(b)+`,"channel_id"`, 1)
	}
	// Аналитик не вправе создавать расписания; автор без compliance.read — 403.
	mustProblem(t, e.call(analyst, "POST", "/api/v1/report-schedules", mk(), true), 403, CodeForbidden)
	// Получатель без compliance.read (аналитик) не допускается, аудитор — да.
	mustProblem(t, e.call(admin, "POST", "/api/v1/report-schedules", mk(tAnalystID), true), 400, CodeInvalidRequest)
	w := e.call(admin, "POST", "/api/v1/report-schedules", mk(tAuditorID), true)
	if w.Code != http.StatusCreated {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	list, err := e.reports.Schedules(context.Background())
	if err != nil || len(list) != 1 || list[0].Report != "compliance" || !list[0].Scope.Compliance || list[0].Scope.Incidents {
		t.Fatalf("расписание: %+v %v", list, err)
	}
}
