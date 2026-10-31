package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/cyclonedx"
	"github.com/azuresong-afk/ai_railway/internal/inventory"
)

// Реестр ИИ через API (задача 5.17, ADR-0029): отказ в доступе у каждого
// эндпоинта, ручная модель с файлами, изменение, удаление, пределы входа,
// сводка и использование по трафику; изменения пишутся в аудит.

const invHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func newInventoryEnv(t *testing.T) (*appsEnv, *inventory.Memory) {
	t.Helper()
	mem := inventory.NewMemory()
	mem.Providers = []inventory.Provider{{ID: "01900000-0000-7000-8000-0000000000e1", Slug: "gigachat", Name: "GigaChat", Type: "gigachat", External: true}}
	mem.Apps = []inventory.App{{ID: "01900000-0000-7000-8000-0000000000e2", Slug: "billing", Name: "Биллинг", Env: "prod", Provider: "gigachat",
		Models: []string{"GigaChat-Pro"}, Keys: []inventory.Key{{ID: "01900000-0000-7000-8000-0000000000e3", Name: "Основной", Prefix: "aisec_aaaaaaaa",
			State: inventory.KeyActive, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}}}}
	e := newAppsEnv(t, func(_ *appsEnv, o *Options) {
		p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := inventory.New(inventory.Options{Store: mem, Provider: p})
		if err != nil {
			t.Fatal(err)
		}
		o.Inventory = svc
	})
	return e, mem
}

func TestInventoryAccessDenied(t *testing.T) {
	e, _ := newInventoryEnv(t)
	owner := e.mustLogin(t, "owner")
	auditor := e.mustLogin(t, "auditor")
	analyst := e.mustLogin(t, "analyst")
	const id = "/api/v1/inventory/models/01900000-0000-7000-8000-0000000000ff"
	body := `{"kind":"customer","name":"m"}`
	// Владелец приложения не видит реестр; аудитор и аналитик только читают.
	for _, c := range []struct {
		s            session
		method, path string
		body         string
	}{
		{owner, "GET", "/api/v1/inventory", ""}, {owner, "GET", "/api/v1/inventory/models", ""}, {owner, "GET", id, ""},
		{owner, "GET", "/api/v1/inventory/usage", ""},
		{auditor, "POST", "/api/v1/inventory/models", body}, {auditor, "PATCH", id, `{}`}, {auditor, "DELETE", id, ""},
		{analyst, "POST", "/api/v1/inventory/models", body}, {analyst, "PATCH", id, `{}`}, {analyst, "DELETE", id, ""},
		// AI-BOM — только администраторам: аудитор и аналитик не выгружают (inventory.export не «.read»).
		{owner, "GET", "/api/v1/inventory/aibom", ""}, {auditor, "GET", "/api/v1/inventory/aibom", ""}, {analyst, "GET", "/api/v1/inventory/aibom", ""},
	} {
		mustProblem(t, e.call(c.s, c.method, c.path, c.body, true), http.StatusForbidden, CodeForbidden)
	}
	for _, s := range []session{auditor, analyst} {
		if w := e.call(s, "GET", "/api/v1/inventory", "", false); w.Code != http.StatusOK {
			t.Fatalf("чтение: %d %s", w.Code, w.Body)
		}
	}
	// Без подключённого реестра — 503.
	e2 := newAppsEnv(t)
	mustProblem(t, e2.call(e2.mustLogin(t, "sysadm"), "GET", "/api/v1/inventory", "", false), http.StatusServiceUnavailable, CodeUnavailable)
}

func TestInventoryViaAPI(t *testing.T) {
	e, mem := newInventoryEnv(t)
	sys := e.mustLogin(t, "sysadm")
	file := func(path string) string {
		return fmt.Sprintf(`{"path":%q,"size":4096,"role":"weights","sha256":%q}`, path, invHash)
	}
	w := e.call(sys, "POST", "/api/v1/inventory/models", `{"kind":"customer","name":"llama-ft","version":"1","owner":"Отдел ИИ","files":[`+
		file("model.safetensors")+`]}`, true)
	if w.Code != http.StatusCreated || !strings.HasPrefix(w.Header().Get("Location"), "/api/v1/inventory/models/") {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	card := decode[InventoryModelCard](t, w.Body.Bytes())
	if card.Origin != inventory.OriginManual || len(card.Files) != 1 || card.Files[0].SHA256 != invHash || card.Files[0].HashAlg != "SHA-256" {
		t.Fatalf("карточка: %+v", card)
	}
	if r := mem.Records[len(mem.Records)-1]; r.Action != "inventory.model_created" || r.Actor.Name != "sysadm" || strings.Contains(fmt.Sprint(r.Details), invHash) {
		t.Fatalf("аудит создания: %+v", r)
	}
	// Повтор пары «провайдер, имя» — 409; неизвестный провайдер — 400; неверный вход — 400 с полями.
	mustProblem(t, e.call(sys, "POST", "/api/v1/inventory/models", `{"kind":"customer","name":"llama-ft"}`, true), http.StatusConflict, CodeConflict)
	w = e.call(sys, "POST", "/api/v1/inventory/models", `{"kind":"provider","provider":"nope","name":"m"}`, true)
	mustProblem(t, w, http.StatusBadRequest, CodeInvalidRequest)
	if !strings.Contains(w.Body.String(), `"field":"provider"`) {
		t.Fatalf("поле провайдера: %s", w.Body)
	}
	w = e.call(sys, "POST", "/api/v1/inventory/models", `{"kind":"customer","name":"m","files":[`+file("../x")+`]}`, true)
	mustProblem(t, w, http.StatusBadRequest, CodeInvalidRequest)
	if !strings.Contains(w.Body.String(), `"field":"files[0].path"`) {
		t.Fatalf("поле пути: %s", w.Body)
	}
	mustProblem(t, e.call(sys, "POST", "/api/v1/inventory/models", `{"kind":"customer","name":"m","weights":"AAAA"}`, true),
		http.StatusBadRequest, CodeInvalidRequest)
	big := `{"kind":"customer","name":"m","description":"` + strings.Repeat("я", inventory.MaxBody/2) + `"}`
	mustProblem(t, e.call(sys, "POST", "/api/v1/inventory/models", big, true), http.StatusRequestEntityTooLarge, CodePayloadTooLarge)

	// Изменение и карточка; без отличий — без новой записи аудита.
	path := "/api/v1/inventory/models/" + card.ID
	w = e.call(sys, "PATCH", path, `{"title":"Кредиты","files":[`+file("model.gguf")+`,`+file("adapter/lora.safetensors")+`]}`, true)
	if c := decode[InventoryModelCard](t, w.Body.Bytes()); w.Code != http.StatusOK || c.Title != "Кредиты" || len(c.Files) != 2 || c.FileCount != 2 {
		t.Fatalf("изменение: %d %s", w.Code, w.Body)
	}
	n := len(mem.Records)
	if w := e.call(sys, "PATCH", path, `{"title":"Кредиты"}`, true); w.Code != http.StatusOK || len(mem.Records) != n {
		t.Fatalf("изменение без отличий: %d, записей %d → %d", w.Code, n, len(mem.Records))
	}
	// Карточка без файлов — с пустым массивом files (поле обязательно по схеме).
	w = e.call(sys, "POST", "/api/v1/inventory/models", `{"kind":"customer","name":"без-файлов"}`, true)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"files":[]`) {
		t.Fatalf("карточка без файлов: %d %s", w.Code, w.Body)
	}
	empty := decode[InventoryModelCard](t, w.Body.Bytes())
	if w := e.call(sys, "DELETE", "/api/v1/inventory/models/"+empty.ID, "", true); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d", w.Code)
	}
	mustProblem(t, e.call(sys, "PATCH", path, `{"kind":"provider"}`, true), http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(sys, "PATCH", path, `{"name":"другое"}`, true), http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(sys, "GET", "/api/v1/inventory/models/not-a-uuid", "", false), http.StatusNotFound, CodeNotFound)

	// Пополнение по трафику, сводка, список и использование.
	hour := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	mem.Seen = []inventory.Seen{{App: "billing", Provider: "gigachat", Model: "GigaChat-Pro", First: hour, Last: hour},
		{App: "support", Provider: "gigachat", Model: "GigaChat-Pro", First: hour, Last: hour}}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := inventory.New(inventory.Options{Store: mem, Provider: p})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := svc.Discover(t.Context()); err != nil || res.Models != 1 || res.Links != 2 {
		t.Fatalf("пополнение: %+v, %v", res, err)
	}
	ov := decode[InventoryOverview](t, e.call(sys, "GET", "/api/v1/inventory", "", false).Body.Bytes())
	if len(ov.Applications) != 1 || len(ov.Applications[0].Keys) != 1 || ov.Applications[0].Keys[0].Prefix != "aisec_aaaaaaaa" ||
		ov.Models != 2 || ov.Usage != 2 || ov.Limits.Models != inventory.MaxModels || ov.Sync.RunAt == nil {
		t.Fatalf("сводка: %+v", ov)
	}
	page := decode[PageResponse[InventoryModelView]](t, e.call(sys, "GET", "/api/v1/inventory/models?limit=1", "", false).Body.Bytes())
	if len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("первая страница: %+v", page)
	}
	page = decode[PageResponse[InventoryModelView]](t, e.call(sys, "GET", "/api/v1/inventory/models?limit=1&cursor="+page.NextCursor, "", false).Body.Bytes())
	if len(page.Items) != 1 || page.NextCursor != "" || page.Items[0].Origin != inventory.OriginTraffic {
		t.Fatalf("вторая страница: %+v", page)
	}
	mustProblem(t, e.call(sys, "GET", "/api/v1/inventory/models?kind=pickle", "", false), http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(sys, "GET", "/api/v1/inventory/models?kind=a&kind=b", "", false), http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(sys, "GET", "/api/v1/inventory/models?q="+strings.Repeat("a", 2000), "", false), http.StatusBadRequest, CodeInvalidRequest)
	us := decode[PageResponse[InventoryUsageView]](t, e.call(sys, "GET", "/api/v1/inventory/usage?limit=1", "", false).Body.Bytes())
	if len(us.Items) != 1 || us.NextCursor == "" {
		t.Fatalf("использование: %+v", us)
	}
	us = decode[PageResponse[InventoryUsageView]](t, e.call(sys, "GET", "/api/v1/inventory/usage?cursor="+us.NextCursor, "", false).Body.Bytes())
	if len(us.Items) != 1 || us.Items[0].Application != "support" {
		t.Fatalf("использование, вторая страница: %+v", us)
	}
	mustProblem(t, e.call(sys, "GET", "/api/v1/inventory/usage?cursor="+(Cursor{TimeMicro: 1, ID: "x"}).Encode(), "", false),
		http.StatusBadRequest, CodeInvalidRequest)

	// Удаление.
	if w := e.call(sys, "DELETE", path, "", true); w.Code != http.StatusNoContent {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sys, "DELETE", path, "", true), http.StatusNotFound, CodeNotFound)
	if r := mem.Records[len(mem.Records)-1]; r.Action != "inventory.model_deleted" {
		t.Fatalf("аудит удаления: %+v", r)
	}
}

// Выгрузка AI-BOM (задача 5.18): CycloneDX 1.6 по правилам схемы, запись
// data.export с видом aibom и числом компонентов (DM-41).
func TestInventoryAIBOMViaAPI(t *testing.T) {
	e, mem := newInventoryEnv(t)
	sys := e.mustLogin(t, "sysadm")
	w := e.call(sys, "POST", "/api/v1/inventory/models", `{"kind":"customer","provider":"gigachat","name":"llama-ft","owner":"Отдел ИИ","files":[`+
		fmt.Sprintf(`{"path":"model.safetensors","size":4096,"role":"weights","sha256":%q}`, invHash)+`]}`, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	n := len(mem.Records)
	w = e.call(sys, "GET", "/api/v1/inventory/aibom", "", false)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/vnd.cyclonedx+json") ||
		w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("выгрузка: %d %v %s", w.Code, w.Header(), w.Body)
	}
	bom, err := cyclonedx.Parse(w.Body.Bytes(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := cyclonedx.Validate(bom); err != nil {
		t.Fatalf("документ не по схеме: %v", err)
	}
	types := map[string]bool{}
	for _, c := range bom.Components {
		types[c.Type] = true
		for _, f := range c.Components {
			if f.Type == "file" && (len(f.Hashes) != 1 || f.Hashes[0].Content != invHash) {
				t.Errorf("файл модели без хеша: %+v", f)
			}
		}
	}
	if !types["machine-learning-model"] || !types["application"] || len(bom.Services) != 1 || bom.Services[0].TrustZone != "external" {
		t.Fatalf("состав: %v, сервисы %+v", types, bom.Services)
	}
	if strings.Contains(w.Body.String(), "aisec_aaaaaaaa") {
		t.Error("префикс ключа приложения в AI-BOM")
	}
	if len(mem.Records) != n+1 {
		t.Fatalf("записей аудита %d → %d", n, len(mem.Records))
	}
	rec := mem.Records[n]
	det, _ := rec.Details.(map[string]any)
	if rec.Action != "data.export" || det["kind"] != inventory.ExportKindAIBOM || det["components"] != 3 || rec.Actor.Name != "sysadm" {
		t.Errorf("запись data.export: %+v", rec)
	}
}
