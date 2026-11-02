package api

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/inventory"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Отчёты сканера, запрет модели и база эталонов шаблонов чата через API
// (задачи 5.21 и 5.22 этапа 5, ADR-0029, дополнение 1): отказ в доступе у
// каждого эндпоинта, отчёт от токена с models.report, снятие запрета только
// в сессии консоли с повторной проверкой, загрузка и откат базы эталонов.

const invOtherHash = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"

func newScanEnv(t *testing.T) (*appsEnv, *inventory.Memory, *servicedb.Memory) {
	t.Helper()
	mem := inventory.NewMemory()
	dbs := servicedb.NewMemory()
	e := newAppsEnv(t, func(_ *appsEnv, o *Options) {
		p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := inventory.New(inventory.Options{Store: mem, Provider: p, ServiceDBs: dbs})
		if err != nil {
			t.Fatal(err)
		}
		o.Inventory = svc
	})
	return e, mem, dbs
}

func templatesFile(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/inventory/chat-templates-test.aisecdb")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func verifyBody(sha string) string {
	return fmt.Sprintf(`{"kind":"verify","host":"gpu-01","scanner_version":"1.5.0","files":[{"path":"model.safetensors","size":4096,"sha256":%q}]}`, sha)
}

func TestInventoryScanAccessDenied(t *testing.T) {
	e, _, _ := newScanEnv(t)
	sys := e.mustLogin(t, "sysadm")
	owner := e.mustLogin(t, "owner")
	auditor := e.mustLogin(t, "auditor")
	analyst := e.mustLogin(t, "analyst")
	const m = "/api/v1/inventory/models/01900000-0000-7000-8000-0000000000ff"
	type call struct {
		s            session
		method, path string
		body         string
	}
	var denied []call
	for _, s := range []session{owner, auditor, analyst} {
		denied = append(denied, call{s, "GET", m + "/reference", ""}, call{s, "POST", m + "/scan-reports", verifyBody(invHash)},
			call{s, "POST", m + "/unblock", `{"password":"x"}`}, call{s, "PUT", "/api/v1/inventory/chat-templates", ""},
			call{s, "POST", "/api/v1/inventory/chat-templates/rollback", ""})
	}
	// Владелец приложения не читает реестр; системный администратор не
	// снимает запрет (inventory.unblock — право безопасности).
	denied = append(denied, call{owner, "GET", m + "/scan-reports", ""}, call{owner, "GET", "/api/v1/inventory/chat-templates", ""},
		call{sys, "POST", m + "/unblock", `{"password":"x"}`})
	for _, c := range denied {
		mustProblem(t, e.call(c.s, c.method, c.path, c.body, true), http.StatusForbidden, CodeForbidden)
	}
	for _, s := range []session{auditor, analyst} {
		if w := e.call(s, "GET", "/api/v1/inventory/chat-templates", "", false); w.Code != http.StatusOK {
			t.Fatalf("чтение базы эталонов: %d %s", w.Code, w.Body)
		}
	}
	// Токен: отчёт и эталон — да, откат базы — только в сессии консоли.
	tok := session{bearer: e.issueToken(t, sys, auth.PermModelsReport, auth.PermModelsTemplatesLoad).Token}
	mustProblem(t, e.call(tok, "GET", m+"/reference", "", false), http.StatusNotFound, CodeNotFound)
	_, before := lastDenied(t, e.mem)
	mustProblem(t, e.call(tok, "POST", "/api/v1/inventory/chat-templates/rollback", "", false), http.StatusForbidden, CodeForbidden)
	rec, after := lastDenied(t, e.mem)
	if after != before+1 || rec.Actor.Type != audit.ActorAPIToken || rec.Details.(map[string]any)["reason"] != DenyReasonSessionOnly {
		t.Fatalf("отказ токену не записан: %+v", rec)
	}
	// Токен с models.report не читает отчёты (inventory.read).
	mustProblem(t, e.call(tok, "GET", m+"/scan-reports", "", false), http.StatusForbidden, CodeForbidden)
	// Без базы эталонов на сервере — 503.
	e2, _ := newInventoryEnv(t)
	mustProblem(t, e2.call(e2.mustLogin(t, "sysadm"), "GET", "/api/v1/inventory/chat-templates", "", false),
		http.StatusServiceUnavailable, CodeUnavailable)
}

func TestInventoryScanViaAPI(t *testing.T) {
	e, mem, _ := newScanEnv(t)
	sys := e.mustLogin(t, "sysadm")
	admin := e.mustLogin(t, "admin")
	w := e.call(sys, "POST", "/api/v1/inventory/models", `{"kind":"customer","name":"llama-ft","files":[`+
		fmt.Sprintf(`{"path":"model.safetensors","size":4096,"role":"weights","sha256":%q}`, invHash)+`]}`, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("модель: %d %s", w.Code, w.Body)
	}
	card := decode[InventoryModelCard](t, w.Body.Bytes())
	path := "/api/v1/inventory/models/" + card.ID
	tok := session{bearer: e.issueToken(t, sys, auth.PermModelsReport).Token}

	// Эталонные хеши — токену сканера.
	ref := decode[inventory.Reference](t, e.call(tok, "GET", path+"/reference", "", false).Body.Bytes())
	if len(ref.Files) != 1 || ref.Files[0].SHA256 != invHash || ref.Status != inventory.StatusActive {
		t.Fatalf("эталон: %+v", ref)
	}
	// Совпадение — 201, ok.
	w = e.call(tok, "POST", path+"/scan-reports", verifyBody(invHash), false)
	if res := decode[ScanReportResult](t, w.Body.Bytes()); w.Code != http.StatusCreated || res.Verdict != "ok" || res.ModelStatus != "active" {
		t.Fatalf("совпадение: %d %s", w.Code, w.Body)
	}
	// Подмена весов — запрет.
	w = e.call(tok, "POST", path+"/scan-reports", verifyBody(invOtherHash), false)
	res := decode[ScanReportResult](t, w.Body.Bytes())
	if w.Code != http.StatusCreated || res.Verdict != "block" || res.ModelStatus != "blocked" || !res.Blocked || res.MismatchTotal != 1 ||
		len(res.Mismatches) != 1 || res.Mismatches[0].Problem != inventory.MismatchChanged {
		t.Fatalf("подмена: %d %s", w.Code, w.Body)
	}
	if r := mem.Records[len(mem.Records)-1]; r.Action != inventory.ActionBlocked || r.Actor.Type != audit.ActorAPIToken {
		t.Fatalf("аудит запрета: %+v", r)
	}
	// Неверный отчёт — 400 с полем; лишнее поле — 400; не JSON — 415; сверх предела — 413.
	w = e.call(tok, "POST", path+"/scan-reports", strings.Replace(verifyBody(invHash), `"model.safetensors"`, `"../x"`, 1), false)
	mustProblem(t, w, http.StatusBadRequest, CodeInvalidRequest)
	if !strings.Contains(w.Body.String(), `"field":"files[0].path"`) {
		t.Fatalf("поле: %s", w.Body)
	}
	mustProblem(t, e.call(tok, "POST", path+"/scan-reports", `{"kind":"verify","weights":"AAAA"}`, false), http.StatusBadRequest, CodeInvalidRequest)
	if w := e.callFile(tok, "POST", path+"/scan-reports", "text/plain", []byte(verifyBody(invHash))); w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("тип: %d", w.Code)
	}
	big := `{"kind":"scan","host":"h","scanner_version":"1","files":[],"x":"` + strings.Repeat("a", inventory.MaxReportBody) + `"}`
	mustProblem(t, e.call(tok, "POST", path+"/scan-reports", big, false), http.StatusRequestEntityTooLarge, CodePayloadTooLarge)
	mustProblem(t, e.call(tok, "POST", "/api/v1/inventory/models/01900000-0000-7000-8000-0000000000ff/scan-reports", verifyBody(invHash), false),
		http.StatusNotFound, CodeNotFound)

	// Отчёты — новые первыми; удаление запрещённой модели — 409.
	list := decode[ScanReportList](t, e.call(sys, "GET", path+"/scan-reports", "", false).Body.Bytes())
	if len(list.Items) != 2 || list.Items[0].Verdict != "block" || list.Items[1].Verdict != "ok" {
		t.Fatalf("отчёты: %+v", list)
	}
	mustProblem(t, e.call(sys, "DELETE", path, "", true), http.StatusConflict, CodeConflict)

	// Снятие запрета: неверный пароль — отказ; верный — active, аудит с
	// пометкой ослабления (DM-40).
	mustProblem(t, e.call(admin, "POST", path+"/unblock", `{"password":"неверный"}`, true), http.StatusForbidden, CodeReauthFailed)
	if c := decode[InventoryModelCard](t, e.call(sys, "GET", path, "", false).Body.Bytes()); c.Status != inventory.StatusBlocked {
		t.Fatalf("после отказа: %s", c.Status)
	}
	w = e.call(admin, "POST", path+"/unblock", `{"password":"`+tPhrase+`"}`, true)
	if c := decode[InventoryModelCard](t, w.Body.Bytes()); w.Code != http.StatusOK || c.Status != inventory.StatusActive {
		t.Fatalf("снятие: %d %s", w.Code, w.Body)
	}
	r := mem.Records[len(mem.Records)-1]
	if d, _ := r.Details.(map[string]any); r.Action != inventory.ActionUnblocked || d["weakening"] != true || r.Actor.Name != "admin" {
		t.Fatalf("аудит снятия: %+v", r)
	}
	mustProblem(t, e.call(admin, "POST", path+"/unblock", `{"password":"`+tPhrase+`"}`, true), http.StatusConflict, CodeConflict)
}

func TestChatTemplatesViaAPI(t *testing.T) {
	e, _, dbs := newScanEnv(t)
	sys := e.mustLogin(t, "sysadm")
	const octet = "application/octet-stream"
	v := decode[ChatTemplatesView](t, e.call(sys, "GET", "/api/v1/inventory/chat-templates", "", false).Body.Bytes())
	if v.Active != servicedb.ActiveNone || v.Current != nil || len(v.Families) != 0 {
		t.Fatalf("до загрузки: %+v", v)
	}
	mustProblem(t, e.call(sys, "POST", "/api/v1/inventory/chat-templates/rollback", "", true), http.StatusConflict, CodeConflict)
	w := e.callFile(sys, "PUT", "/api/v1/inventory/chat-templates", octet, templatesFile(t))
	v = decode[ChatTemplatesView](t, w.Body.Bytes())
	if w.Code != http.StatusOK || v.Current == nil || v.Current.Version != 1 || len(v.Families) != 18 {
		t.Fatalf("загрузка: %d %s", w.Code, w.Body)
	}
	if f := v.Families[0]; f.ID == "" || len(f.Match) == 0 || len(f.Variants) == 0 {
		t.Fatalf("семейство: %+v", f)
	}
	// Текста шаблонов в ответе нет.
	if strings.Contains(w.Body.String(), "im_start") {
		t.Fatal("текст шаблона в ответе")
	}
	// Повтор той же версии и мусор — отказ с записью аудита.
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/inventory/chat-templates", octet, templatesFile(t)), http.StatusConflict, CodeConflict)
	mustProblem(t, e.callFile(sys, "PUT", "/api/v1/inventory/chat-templates", octet, []byte("\x00\x01")), http.StatusUnprocessableEntity, CodeUnprocessable)
	n := 0
	for _, r := range dbs.Records() {
		if r.Action == servicedb.ActionRejected {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("отказов в аудите: %d", n)
	}
}
