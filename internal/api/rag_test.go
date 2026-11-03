package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/rag"
)

// Манифест коллекций RAG через API (задача 5.24, ADR-0029, п. 5): отказ в
// доступе у каждого эндпоинта, загрузка манифеста токеном индексатора,
// версии и разница, страницы документов, исключения; снятие исключения —
// только в сессии консоли.

func newRAGEnv(t *testing.T) (*appsEnv, *rag.Memory) {
	t.Helper()
	mem := rag.NewMemory()
	e := newAppsEnv(t, func(_ *appsEnv, o *Options) {
		p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := rag.New(rag.Options{Store: mem, Provider: p})
		if err != nil {
			t.Fatal(err)
		}
		o.RAG = svc
	})
	return e, mem
}

func ragDocs(docs ...string) string {
	var parts []string
	for _, d := range docs {
		id, h, _ := strings.Cut(d, "=")
		parts = append(parts, fmt.Sprintf(`{"id":%q,"sha256":"%s","size":%d}`, id, strings.Repeat(h, 64), len(id)))
	}
	return `{"documents":[` + strings.Join(parts, ",") + `]}`
}

func TestRAGAccessDenied(t *testing.T) {
	e, _ := newRAGEnv(t)
	owner := e.mustLogin(t, "owner")
	auditor := e.mustLogin(t, "auditor")
	analyst := e.mustLogin(t, "analyst")
	const (
		col = "/api/v1/rag/collections/kb"
		ex  = col + "/exclusions/01900000-0000-7000-8000-0000000000ff"
	)
	body := ragDocs("a=0")
	// Владелец приложения не видит коллекции; аудитор и аналитик только читают.
	for _, c := range []struct {
		s            session
		method, path string
		body         string
	}{
		{owner, "GET", "/api/v1/rag/collections", ""}, {owner, "GET", col, ""}, {owner, "GET", col + "/manifest", ""},
		{owner, "PUT", col + "/manifest", body}, {owner, "POST", col + "/exclusions", `{"document_id":"a"}`}, {owner, "DELETE", ex, ""},
		{auditor, "PUT", col + "/manifest", body}, {auditor, "POST", col + "/exclusions", `{"document_id":"a"}`}, {auditor, "DELETE", ex, ""},
		{analyst, "PUT", col + "/manifest", body}, {analyst, "POST", col + "/exclusions", `{"document_id":"a"}`}, {analyst, "DELETE", ex, ""},
		// Ревью 5.r2, 5Н14: администратор системы (rag.manage) исключение не
		// снимает — это право безопасности rag.unexclude.
		{e.mustLogin(t, "sysadm"), "DELETE", ex, ""},
	} {
		mustProblem(t, e.call(c.s, c.method, c.path, c.body, c.method != "GET"), http.StatusForbidden, CodeForbidden)
	}
	for _, s := range []session{auditor, analyst} {
		if w := e.call(s, "GET", "/api/v1/rag/collections", "", false); w.Code != http.StatusOK {
			t.Fatalf("чтение: %d %s", w.Code, w.Body)
		}
	}
	// Снятие исключения токеном — 403 с записью access.denied: право
	// безопасности rag.unexclude токенам не выдаётся, маршрут — только для
	// сессии консоли.
	sys := e.mustLogin(t, "sysadm")
	tok := session{bearer: e.issueToken(t, sys, auth.PermRAGManage).Token}
	_, before := lastDenied(t, e.mem)
	mustProblem(t, e.call(tok, "DELETE", ex, "", false), http.StatusForbidden, CodeForbidden)
	rec, after := lastDenied(t, e.mem)
	if after != before+1 || rec.Actor.Type != audit.ActorAPIToken {
		t.Fatalf("отказ токену не записан: %+v", rec)
	}
	if p, ok := auth.LookupPermission(auth.PermRAGUnexclude); !ok || !p.Security {
		t.Fatalf("rag.unexclude — не право безопасности: %+v", p)
	}
	// Без подключённых манифестов — 503.
	e2 := newAppsEnv(t)
	mustProblem(t, e2.call(e2.mustLogin(t, "sysadm"), "GET", "/api/v1/rag/collections", "", false), http.StatusServiceUnavailable, CodeUnavailable)
}

func TestRAGManifestViaAPI(t *testing.T) {
	e, mem := newRAGEnv(t)
	sys := e.mustLogin(t, "sysadm")
	// Индексатор — токен API с rag.manage.
	idx := session{bearer: e.issueToken(t, sys, auth.PermRAGManage, auth.PermRAGRead).Token}
	const col = "/api/v1/rag/collections/kb-hr"
	w := e.call(idx, "PUT", col+"/manifest", ragDocs("hr/a.md=1", "hr/b.md=2", "hr/c.md=3"), false)
	res := decode[RAGManifestResult](t, w.Body.Bytes())
	if w.Code != http.StatusCreated || !res.Created || res.Version != 1 || res.Documents != 3 || len(res.Blocked) != 0 || res.Diff.Added != 0 {
		t.Fatalf("первая версия: %d %s", w.Code, w.Body)
	}
	if r := mem.Records[len(mem.Records)-1]; r.Action != "rag.manifest_loaded" || r.Actor.Type != audit.ActorAPIToken {
		t.Fatalf("аудит загрузки: %+v", r)
	}
	// Исключение администратором (сессия консоли), затем вторая версия.
	w = e.call(sys, "POST", col+"/exclusions", `{"document_id":"hr/d.md","reason":"инъекция"}`, true)
	exv := decode[RAGExclusionView](t, w.Body.Bytes())
	if w.Code != http.StatusCreated || exv.DocumentID != "hr/d.md" || exv.ID == "" {
		t.Fatalf("исключение: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(sys, "POST", col+"/exclusions", `{"document_id":"hr/d.md"}`, true), http.StatusConflict, CodeConflict)
	mustProblem(t, e.call(sys, "POST", "/api/v1/rag/collections/nope/exclusions", `{"document_id":"x"}`, true), http.StatusNotFound, CodeNotFound)
	w = e.call(idx, "PUT", col+"/manifest", ragDocs("hr/a.md=1", "hr/b.md=f", "hr/d.md=4"), false)
	res = decode[RAGManifestResult](t, w.Body.Bytes())
	if w.Code != http.StatusOK || res.Created || res.Version != 2 || res.Diff.Added != 1 || res.Diff.Changed != 1 || res.Diff.Removed != 1 ||
		len(res.Blocked) != 1 || res.Blocked[0] != "hr/d.md" || res.PrevLoadedAt == nil {
		t.Fatalf("вторая версия: %d %s", w.Code, w.Body)
	}
	n := 0
	for _, r := range mem.Records {
		if r.Action == "rag.document_changed" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("rag.document_changed: %d", n)
	}
	// Карточка, список, страницы документов.
	card := decode[RAGCollectionCard](t, e.call(sys, "GET", col, "", false).Body.Bytes())
	if card.Version != 2 || card.Exclusions != 1 || len(card.ExclusionList) != 1 || card.Diff.ChangedIDs[0] != "hr/b.md" {
		t.Fatalf("карточка: %+v", card)
	}
	list := decode[RAGCollectionList](t, e.call(sys, "GET", "/api/v1/rag/collections", "", false).Body.Bytes())
	if len(list.Items) != 1 || list.Limits.Documents != rag.MaxDocuments {
		t.Fatalf("список: %+v", list)
	}
	page := decode[RAGDocumentPage](t, e.call(idx, "GET", col+"/manifest?limit=2", "", false).Body.Bytes())
	if page.Version != 2 || len(page.Items) != 2 || page.NextAfter != "hr/b.md" || page.Items[1].SHA256 != strings.Repeat("f", 64) {
		t.Fatalf("страница 1: %+v", page)
	}
	page = decode[RAGDocumentPage](t, e.call(idx, "GET", col+"/manifest?limit=2&after=hr%2Fb.md", "", false).Body.Bytes())
	if len(page.Items) != 1 || !page.Items[0].Blocked || page.NextAfter != "" {
		t.Fatalf("страница 2: %+v", page)
	}
	mustProblem(t, e.call(idx, "GET", col+"/manifest?limit=0", "", false), http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(idx, "GET", col+"/manifest?after=%E2%80%AE", "", false), http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(sys, "GET", "/api/v1/rag/collections/Bad_Slug", "", false), http.StatusNotFound, CodeNotFound)
	mustProblem(t, e.call(sys, "GET", "/api/v1/rag/collections/none/manifest", "", false), http.StatusNotFound, CodeNotFound)

	// Неверный манифест — 400 с полем; лишнее поле — 400; неверный slug — 404.
	w = e.call(idx, "PUT", col+"/manifest", `{"documents":[{"id":"a","sha256":"x","size":1}]}`, false)
	mustProblem(t, w, http.StatusBadRequest, CodeInvalidRequest)
	if !strings.Contains(w.Body.String(), `"field":"documents[0].sha256"`) {
		t.Fatalf("поле хеша: %s", w.Body)
	}
	mustProblem(t, e.call(idx, "PUT", col+"/manifest", `{"documents":[],"content":"x"}`, false), http.StatusBadRequest, CodeInvalidRequest)
	mustProblem(t, e.call(idx, "PUT", "/api/v1/rag/collections/-x/manifest", ragDocs(), false), http.StatusNotFound, CodeNotFound)

	// Снятие исключения администратором безопасности в сессии консоли —
	// ослабление с записью аудита.
	sec := e.mustLogin(t, "admin")
	if w := e.call(sec, "DELETE", col+"/exclusions/"+exv.ID, "", true); w.Code != http.StatusNoContent {
		t.Fatalf("снятие: %d %s", w.Code, w.Body)
	}
	r := mem.Records[len(mem.Records)-1]
	if r.Action != "rag.exclusion_removed" || r.Details.(map[string]any)["weakening"] != true {
		t.Fatalf("аудит снятия: %+v", r)
	}
	mustProblem(t, e.call(sec, "DELETE", col+"/exclusions/"+exv.ID, "", true), http.StatusNotFound, CodeNotFound)
	mustProblem(t, e.call(sec, "DELETE", col+"/exclusions/not-a-uuid", "", true), http.StatusNotFound, CodeNotFound)
}
