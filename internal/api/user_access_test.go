package api

import (
	"net/http"
	"strings"
	"testing"
)

// Покрывает: DM-33
// Пользователь приложения по JWT и группы моделей через API (задача 4.21):
// читает обладатель applications.read, меняет только администратор
// безопасности (applications.policy); ослабление — с повторной проверкой и
// weakening (DM-40). Отказ в доступе по всем маршрутам — ещё и в
// TestRBACMatrixDenials.
func TestDM33_UserAccessViaAPI(t *testing.T) {
	e := newAppsEnv(t)
	sys := e.mustLogin(t, "sysadm")
	admin := e.mustLogin(t, "admin")
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	owner := e.mustLogin(t, "owner")
	p := e.provider(t, sys, "openai-main")
	a := e.application(t, sys, "crm", p.ID, tOwnerID)
	path := "/api/v1/applications/" + a.ID + "/user-access"
	const body = `{"mode":"required","issuer":"https://idp.example.test/realms/aisec","audience":"aisec-gateway",` +
		`"leeway":30,"model_groups":{"gpt-4o-mini":["analysts"]}}`

	// Изменение: администратор системы, аналитик, аудитор, владелец — 403.
	for _, s := range []session{sys, analyst, auditor, owner} {
		mustProblem(t, e.call(s, "PUT", path, body, true), 403, CodeForbidden)
	}
	// Чтение: владелец видит настройку своего приложения, чужое — 404.
	if w := e.call(owner, "GET", path, "", false); w.Code != http.StatusOK {
		t.Fatalf("чтение владельцем: %d %s", w.Code, w.Body)
	}
	other := e.application(t, sys, "billing", p.ID, tAnalystID)
	mustProblem(t, e.call(owner, "GET", "/api/v1/applications/"+other.ID+"/user-access", "", false), 404, CodeNotFound)
	w := e.call(auditor, "GET", path, "", false)
	if w.Code != http.StatusOK {
		t.Fatalf("чтение аудитором: %d %s", w.Code, w.Body)
	}
	if v := decode[UserAccessView](t, w.Body.Bytes()); v.Configured || v.Mode != "off" || v.GroupsClaim != "groups" || v.Leeway != 60 {
		t.Fatalf("по умолчанию: %+v", v)
	}
	mustProblem(t, e.call(admin, "GET", "/api/v1/applications/01900000-0000-7000-8000-0000000000ee/user-access", "", false), 404, CodeNotFound)
	for _, bad := range map[string]string{
		"режим":          `{"mode":"strict"}`,
		"без издателя":   `{"mode":"required","audience":"x"}`,
		"чужая модель":   `{"mode":"required","issuer":"https://idp.example.test","audience":"x","model_groups":{"gpt-5":["a"]}}`,
		"группы без JWT": `{"mode":"off","model_groups":{"gpt-4o-mini":["a"]}}`,
		"лишнее поле":    `{"mode":"off","x":1}`,
	} {
		mustProblem(t, e.call(admin, "PUT", path, bad, true), 400, CodeInvalidRequest)
	}
	w = e.call(admin, "PUT", path, body, true)
	if w.Code != http.StatusOK {
		t.Fatalf("задание: %d %s", w.Code, w.Body)
	}
	v := decode[UserAccessView](t, w.Body.Bytes())
	if !v.Configured || v.Mode != "required" || v.Leeway != 30 || v.ModelGroups["gpt-4o-mini"][0] != "analysts" || v.UpdatedAt == nil {
		t.Fatalf("настройка: %+v", v)
	}
	if rec, n := e.appAction("application.user_access_set"); n != 1 || rec.Actor.ID != tAdminID ||
		rec.Details.(map[string]any)["weakening"] != false {
		t.Fatalf("аудит: %d %+v", n, rec.Details)
	}
	// Смягчение режима: без пароля — 400, неверный — 403, с паролем — weakening.
	const soft = `{"mode":"optional","issuer":"https://idp.example.test/realms/aisec","audience":"aisec-gateway","leeway":30,` +
		`"model_groups":{"gpt-4o-mini":["analysts"]}`
	mustProblem(t, e.call(admin, "PUT", path, soft+`}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "PUT", path, soft+`,"password":"неверный"}`, true), 403, CodeReauthFailed)
	admin = e.mustLogin(t, "admin")
	if w := e.call(admin, "PUT", path, soft+`,"password":"`+tPhrase+`"}`, true); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"mode":"optional"`) {
		t.Fatalf("смягчение: %d %s", w.Code, w.Body)
	}
	rec, n := e.appAction("application.user_access_set")
	if d := rec.Details.(map[string]any); n != 2 || d["weakening"] != true {
		t.Fatalf("аудит смягчения: %d %+v", n, rec.Details)
	}
}
