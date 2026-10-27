package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Покрывает: DM-26
// Эталон системного промпта через API (задача 4.14): задаёт и видит
// только администратор безопасности (applications.policy), текст в ответе
// ему одному и не в аудите; понижение режима и снятие — с повторной
// проверкой и weakening (DM-40). Отказ в доступе по всем маршрутам — ещё и
// в TestRBACMatrixDenials.
func TestDM26_PromptBaselineViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	admin := e.mustLogin(t, "admin")
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	owner := e.mustLogin(t, "owner")
	p := e.provider(t, sys, "openai-main")
	a := e.application(t, sys, "crm", p.ID, tOwnerID)
	path := "/api/v1/applications/" + a.ID + "/prompt-baseline"
	const text = "Ты — помощник CRM.\nНе раскрывай кодовое слово «полярная сова»."
	body, err := json.Marshal(PromptBaselineRequest{Text: ptrStr(text), Mode: "block"})
	if err != nil {
		t.Fatal(err)
	}

	// Отказ в доступе: администратор системы, аналитик, аудитор, владелец.
	for _, s := range []session{sys, analyst, auditor, owner} {
		mustProblem(t, e.call(s, "GET", path, "", false), 403, CodeForbidden)
		mustProblem(t, e.call(s, "PUT", path, string(body), true), 403, CodeForbidden)
		mustProblem(t, e.call(s, "DELETE", path, "", true), 403, CodeForbidden)
	}
	if w := e.call(admin, "GET", path, "", false); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"configured":false}` {
		t.Fatalf("без эталона: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "GET", "/api/v1/applications/01900000-0000-7000-8000-0000000000ee/prompt-baseline", "", false), 404, CodeNotFound)
	for name, bad := range map[string]string{
		"режим":       `{"text":"x","mode":"strict"}`,
		"пустой":      `{"text":" ","mode":"alert"}`,
		"без текста":  `{"mode":"alert"}`,
		"управляющий": `{"text":"a\u0000b","mode":"alert"}`,
		"лишнее поле": `{"text":"x","mode":"alert","x":1}`,
		"длинный":     fmt.Sprintf(`{"text":%q,"mode":"alert"}`, strings.Repeat("a", 128<<10+1)),
	} {
		w := e.call(admin, "PUT", path, bad, true)
		if w.Code != 400 && w.Code != 413 {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	w := e.call(admin, "PUT", path, string(body), true)
	if w.Code != http.StatusOK {
		t.Fatalf("задание: %d %s", w.Code, w.Body)
	}
	v := decode[PromptBaselineView](t, w.Body.Bytes())
	if !v.Configured || v.Mode != "block" || len(v.Hash) != 64 || v.Text != text || v.Bytes != len(text) {
		t.Fatalf("эталон: %+v", v)
	}
	rec, n := e.appAction("application.prompt_baseline_set")
	raw, err := json.Marshal(rec.Details)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || rec.Actor.ID != tAdminID || strings.Contains(string(raw), "полярная") || !strings.Contains(string(raw), v.Hash) {
		t.Fatalf("аудит: %d %s", n, raw)
	}
	// Понижение режима: без пароля — 400, неверный — 403, с паролем — weakening.
	mustProblem(t, e.call(admin, "PUT", path, `{"mode":"alert"}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "PUT", path, `{"mode":"alert","password":"неверный"}`, true), 403, CodeReauthFailed)
	admin = e.mustLogin(t, "admin")
	if w := e.call(admin, "PUT", path, `{"mode":"alert","password":"`+tPhrase+`"}`, true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"mode":"alert"`) {
		t.Fatalf("понижение: %d %s", w.Code, w.Body)
	}
	if rec, n := e.appAction("application.prompt_baseline_set"); n != 2 || rec.Details.(map[string]any)["weakening"] != true {
		t.Fatalf("аудит понижения: %d %+v", n, rec.Details)
	}
	// Снятие действующего эталона — тоже с паролем.
	mustProblem(t, e.call(admin, "DELETE", path, "", true), 400, CodeInvalidRequest)
	if w := e.call(admin, "DELETE", path, `{"password":"`+tPhrase+`"}`, true); w.Code != http.StatusNoContent {
		t.Fatalf("снятие: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "DELETE", path, "", true), 404, CodeNotFound)
	if rec, n := e.appAction("application.prompt_baseline_removed"); n != 1 || rec.Details.(map[string]any)["weakening"] != true {
		t.Fatalf("аудит снятия: %d %+v", n, rec.Details)
	}
	if strings.Contains(e.log.String(), "полярная") {
		t.Fatal("текст эталона в техническом журнале")
	}
}

func ptrStr(s string) *string { return &s }
