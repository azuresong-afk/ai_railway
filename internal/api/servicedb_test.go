package api

import (
	"bytes"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/compliance"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
)

// Служебные базы через API (задача 5.15, ADR-0028): загрузка и откат — у
// модуля с его правом, состояние всех видов — system.read; каждый отказ и
// откат — запись аудита service_db.*.
func TestServiceDBsViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	analyst := e.mustLogin(t, "analyst")
	owner := e.mustLogin(t, "owner")
	auditor := e.mustLogin(t, "auditor")
	const octet = "application/octet-stream"

	// Отказ в доступе: откат без права модуля, состояние без system.read.
	mustProblem(t, e.call(analyst, "POST", "/api/v1/shadow-ai/catalog/rollback", "", true), 403, CodeForbidden)
	mustProblem(t, e.call(analyst, "POST", "/api/v1/compliance/base/rollback", "", true), 403, CodeForbidden)
	mustProblem(t, e.call(auditor, "POST", "/api/v1/compliance/base/rollback", "", true), 403, CodeForbidden)
	mustProblem(t, e.call(owner, "GET", "/api/v1/service-dbs", "", false), 403, CodeForbidden)

	// Состояние до загрузки: оба вида есть, версий нет.
	w := e.call(auditor, "GET", "/api/v1/service-dbs", "", false)
	list := decode[ServiceDBList](t, w.Body.Bytes())
	if w.Code != 200 || len(list.Items) != 2 || list.Items[0].Kind != shadowai.CatalogKind || list.Items[1].Kind != compliance.BaseKind ||
		list.Items[0].Active != servicedb.ActiveNone || list.Items[0].Current != nil {
		t.Fatalf("состояние: %d %s", w.Code, w.Body)
	}
	// Откат без предыдущей — 409 и запись аудита с отказом.
	mustProblem(t, e.call(sys, "POST", "/api/v1/shadow-ai/catalog/rollback", "", true), 409, CodeConflict)

	// Каталог: версия 1 из testdata, затем версия 2; откат возвращает 1.
	if w := e.callFile(sys, "PUT", "/api/v1/shadow-ai/catalog", octet, shadowFile(t, "catalog-test.aisecdb")); w.Code != 200 {
		t.Fatalf("каталог v1: %d %s", w.Code, w.Body)
	}
	v2 := signServiceDBKind(t, shadowai.CatalogKind, "format: aisec-shadow-ai-catalog-v1\nversion: 2\ndate: \"2026-10-28\"\nservices:\n"+
		"  - {id: chatgpt, name: ChatGPT, vendor: OpenAI, category: chat, suffixes: [chatgpt.com]}\n")
	w = e.callFile(sys, "PUT", "/api/v1/shadow-ai/catalog", octet, v2)
	if v := decode[shadowai.CatalogView](t, w.Body.Bytes()); w.Code != 200 || v.Version != 2 || v.Previous == nil || v.Previous.Version != 1 {
		t.Fatalf("каталог v2: %d %s", w.Code, w.Body)
	}
	w = e.call(sys, "POST", "/api/v1/shadow-ai/catalog/rollback", "", true)
	if v := decode[shadowai.CatalogView](t, w.Body.Bytes()); w.Code != 200 || v.Version != 1 || v.Previous != nil || len(v.Services) != 28 {
		t.Fatalf("откат каталога: %d %s", w.Code, w.Body)
	}
	// Откатанную версию можно загрузить снова.
	if w := e.callFile(sys, "PUT", "/api/v1/shadow-ai/catalog", octet, v2); w.Code != 200 {
		t.Fatalf("повторная загрузка v2: %d %s", w.Code, w.Body)
	}

	// База требований: версии 100 и 101, откат на 100.
	if w := e.callFile(sys, "PUT", "/api/v1/compliance/base", octet, signComplianceBase(t, complianceTestBase)); w.Code != 200 {
		t.Fatalf("база v100: %d %s", w.Code, w.Body)
	}
	b101 := bytes.Replace([]byte(complianceTestBase), []byte("version: 100"), []byte("version: 101"), 1)
	if w := e.callFile(sys, "PUT", "/api/v1/compliance/base", octet, signComplianceBase(t, string(b101))); w.Code != 200 {
		t.Fatalf("база v101: %d %s", w.Code, w.Body)
	}
	w = e.call(sys, "POST", "/api/v1/compliance/base/rollback", "", true)
	if v := decode[compliance.BaseView](t, w.Body.Bytes()); w.Code != 200 || v.Active.Version != 100 || v.Uploaded == nil ||
		v.Uploaded.Version != 100 || v.Previous != nil {
		t.Fatalf("откат базы: %d %s", w.Code, w.Body)
	}

	// Состояние после: каталог v2 с предыдущей v1, база v100 без предыдущей.
	list = decode[ServiceDBList](t, e.call(sys, "GET", "/api/v1/service-dbs", "", false).Body.Bytes())
	c, b := list.Items[0], list.Items[1]
	if c.Active != servicedb.ActiveCurrent || c.Current.Version != 2 || c.Previous == nil || c.Previous.Version != 1 || !c.Previous.Valid ||
		b.Current == nil || b.Current.Version != 100 || b.Current.Records != 2 || b.Previous != nil {
		t.Fatalf("состояние после: %+v", list)
	}

	// Аудит: загрузки, откаты (в том числе отказ без предыдущей) — с видом.
	got := map[string]int{}
	for _, r := range e.dbs.Records() {
		d, _ := r.Details.(map[string]any)
		if d["kind"] != shadowai.CatalogKind && d["kind"] != compliance.BaseKind {
			t.Fatalf("запись без вида: %+v", r)
		}
		got[r.Action+":"+string(r.Result)]++
	}
	for k, n := range map[string]int{
		servicedb.ActionLoaded + ":" + string(audit.ResultSuccess):     5,
		servicedb.ActionRolledBack + ":" + string(audit.ResultSuccess): 2,
		servicedb.ActionRolledBack + ":" + string(audit.ResultFailure): 1,
	} {
		if got[k] != n {
			t.Errorf("%s: %d, ждали %d (%v)", k, got[k], n, got)
		}
	}
}
