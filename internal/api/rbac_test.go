package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
)

// Синтетические учётные записи матрицы «роль × эндпоинт».
const (
	tTargetID     = "01900000-0000-7000-8000-00000000f001"
	tTargetRole   = "target_role"
	tEmptyRole    = "empty_role"
	tUserIDPrefix = "01900000-0000-7000-8000-0000000010"
)

// rbacEnv — сервер на хранилище в памяти с пользователем каждой роли.
type rbacEnv struct {
	*authEnv
	rt    *Router
	roles []auth.RoleDef
}

func newRBACEnv(t *testing.T) *rbacEnv {
	t.Helper()
	e := &rbacEnv{authEnv: &authEnv{mem: authtest.NewMemory(), log: &bytes.Buffer{}, clock: &testClock{t: time.Now()}, secrets: map[string][]byte{}}}
	now := time.Now().UTC().Truncate(time.Microsecond)
	ctx := context.Background()
	rec := audit.Entry{Actor: audit.Actor{Type: audit.ActorCLI, ID: "test"}, Action: "role.create", Result: audit.ResultSuccess}
	for _, id := range []auth.Role{tEmptyRole, tTargetRole} {
		if err := e.mem.CreateRole(ctx, audit.DefaultOrgID, "", auth.RoleDef{ID: id, DisplayName: string(id), Grants: auth.Grants{},
			CreatedAt: now, UpdatedAt: now, CreatedBy: "test"}, func(auth.Actor) (audit.Entry, error) { return rec, nil }); err != nil {
			t.Fatal(err)
		}
	}
	e.roles = append(auth.BuiltinRoles(), auth.RoleDef{ID: tEmptyRole, Grants: auth.Grants{}})
	add := func(id, login string, role auth.Role) {
		e.mem.AddUser(auth.User{ID: id, OrgID: audit.DefaultOrgID, Login: login, DisplayName: login, Role: role,
			Status: auth.StatusActive, PasswordHash: authtest.HashOf(tPhrase), PasswordChangedAt: now, CreatedAt: now, CreatedBy: "test"})
	}
	for i, r := range e.roles {
		add(tUserIDPrefix+string(rune('a'+i))+"0", "u_"+string(r.ID), r.ID)
	}
	// Цель действий над учётной записью — без прав: её может трогать любой,
	// у кого есть разрешение маршрута (разделение обязанностей не мешает).
	add(tTargetID, "target", auth.RoleAppOwner)
	h, rt, err := New(Options{Hasher: testHasher(t), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Auth: testAuth(t, e.mem, auth.WithClock(e.clock.now)),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 100000, Window: time.Minute}}}})
	if err != nil {
		t.Fatal(err)
	}
	e.h, e.rt = h, rt
	return e
}

// target — путь запроса из шаблона: {id} указывает на цель своего типа.
func target(path string) string {
	if strings.HasPrefix(path, "/api/v1/roles/") {
		return strings.ReplaceAll(path, "{id}", tTargetRole)
	}
	return strings.ReplaceAll(path, "{id}", tTargetID)
}

func lastDenied(t *testing.T, m *authtest.Memory) (audit.Entry, int) {
	t.Helper()
	recs := m.Records()
	n := 0
	var last audit.Entry
	for _, r := range recs {
		if r.Action == "access.denied" {
			n++
			last = r
		}
	}
	return last, n
}

// УПД.3, критерий приёмки этапа 2: каждая пара «роль × эндпоинт» проверена.
// Где у роли нет разрешения — 403 и запись access.denied; где есть — ни
// 401, ни 403. Разрешения берутся из x-permission в api/openapi.yaml; тест
// падает, если у маршрута нет строки в спецификации или разрешения в ней.
func TestRBACMatrixDenials(t *testing.T) {
	s := loadSpec(t)
	e := newRBACEnv(t)
	pairs, denials := 0, 0
	for _, r := range e.rt.Routes() {
		if r.Public {
			continue
		}
		op, ok := s.Paths[r.Path][strings.ToLower(r.Method)]
		if !ok || op.Permission == "" {
			t.Errorf("%s %s: нет строки матрицы (x-permission в openapi.yaml)", r.Method, r.Path)
			continue
		}
		if op.Permission != r.Permission {
			t.Errorf("%s %s: x-permission %q, у маршрута %q", r.Method, r.Path, op.Permission, r.Permission)
			continue
		}
		for _, role := range e.roles {
			pairs++
			sess := e.mustLogin(t, "u_"+string(role.ID))
			_, before := lastDenied(t, e.mem)
			w := e.call(sess, r.Method, target(r.Path), "", true)
			// Права полностью вошедшего пользователя: роль, self и session.
			g := auth.SessionGrants(auth.Caller{Session: auth.Session{State: auth.SessionActive}}, role.Grants)
			deny := !g.Full(r.Permission)
			if r.Scoped {
				deny = !g.Allows(r.Permission)
			}
			if !deny {
				if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
					t.Errorf("%s %s, роль %s: ожидался доступ, ответ %d %s", r.Method, r.Path, role.ID, w.Code, w.Body)
				}
				continue
			}
			denials++
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s, роль %s: ожидался отказ 403, ответ %d", r.Method, r.Path, role.ID, w.Code)
				continue
			}
			rec, after := lastDenied(t, e.mem)
			d, _ := rec.Details.(map[string]any)
			if after != before+1 || d["permission"] != r.Permission || d["path"] != r.Path || rec.Actor.Name != "u_"+string(role.ID) {
				t.Errorf("%s %s, роль %s: отказ не записан в аудит: %+v", r.Method, r.Path, role.ID, rec)
			}
		}
	}
	if pairs == 0 || denials == 0 {
		t.Fatalf("пар %d, отказов %d", pairs, denials)
	}
}

// УПД.6, DM-39 (неудачные попытки доступа к управлению): отказ в доступе
// пишется в журнал аудита — кто, откуда, к чему и какое право требовалось.
// Покрывает: DM-39
func TestDM39_AccessDeniedAudited(t *testing.T) {
	e := newAuthEnv(t)
	s := e.mustLogin(t, "analyst")
	w := e.call(s, "PUT", "/api/v1/auth/policy", `{}`, true)
	mustProblem(t, w, 403, CodeForbidden)
	rec, n := lastDenied(t, e.mem)
	d, _ := rec.Details.(map[string]any)
	if n != 1 || rec.Actor.ID != tAnalystID || rec.Result != audit.ResultDenied || rec.SourceIP.String() != "192.0.2.1" ||
		d["method"] != "PUT" || d["path"] != "/api/v1/auth/policy" || d["permission"] != auth.PermAuthPolicyManage ||
		d["reason"] != DenyReasonPermission {
		t.Fatalf("запись аудита: %+v", rec)
	}
	// Разрешение есть, но нет CSRF-токена — причина check.
	admin := e.mustLogin(t, "admin")
	mustProblem(t, e.call(admin, "PUT", "/api/v1/auth/policy", `{}`, false), 403, CodeForbidden)
	rec, n = lastDenied(t, e.mem)
	if d, _ := rec.Details.(map[string]any); n != 2 || d["reason"] != DenyReasonCheck {
		t.Fatalf("отказ по CSRF: %d %+v", n, rec)
	}
	// Без аутентификации — 401 без записи в аудит (поток ограничен ЗИ.6).
	mustProblem(t, do(e.h, "GET", "/api/v1/users", ""), 401, CodeUnauthorized)
	if _, n := lastDenied(t, e.mem); n != 2 {
		t.Fatalf("отказ без аутентификации записан в аудит: %d", n)
	}
}

func decode[T any](t *testing.T, body []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return v
}

func TestRolesAPI(t *testing.T) {
	e := newAuthEnv(t)
	admin := e.mustLogin(t, "admin")

	w := e.call(admin, "GET", "/api/v1/permissions", "", false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"name":"roles.manage"`) {
		t.Fatalf("каталог: %d %s", w.Code, w.Body)
	}
	body := `{"id":"soc_lead","display_name":"Руководитель SOC","permissions":[{"permission":"users.read"},{"permission":"sessions.read","scope":"all"}]}`
	w = e.call(admin, "POST", "/api/v1/roles", body, true)
	if w.Code != 201 || w.Header().Get("Location") != "/api/v1/roles/soc_lead" {
		t.Fatalf("создание: %d %s", w.Code, w.Body)
	}
	created := decode[RoleView](t, w.Body.Bytes())
	if created.Builtin || created.MFARequired || len(created.Permissions) != 2 {
		t.Fatalf("роль: %+v", created)
	}
	mustProblem(t, e.call(admin, "POST", "/api/v1/roles", body, true), 409, CodeConflict)
	mustProblem(t, e.call(admin, "POST", "/api/v1/roles", `{"id":"Bad","display_name":"x","permissions":[]}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "POST", "/api/v1/roles", `{"id":"ok_id","display_name":"x","permissions":[],"extra":1}`, true), 400, CodeInvalidRequest)

	list := decode[RoleList](t, e.call(admin, "GET", "/api/v1/roles", "", false).Body.Bytes())
	if len(list.Items) != 6 || list.Items[0].ID != "security_admin" || list.Items[5].ID != "soc_lead" || list.Items[0].Users != 1 {
		t.Fatalf("список: %+v", list)
	}
	mustProblem(t, e.call(admin, "GET", "/api/v1/roles/nope_role", "", false), 404, CodeNotFound)
	mustProblem(t, e.call(admin, "GET", "/api/v1/roles/..", "", false), 404, CodeNotFound)

	// applications.read — чтобы роль покрывала права владельца приложения (задача 2.11).
	w = e.call(admin, "PUT", "/api/v1/roles/soc_lead", `{"display_name":"SOC","permissions":[{"permission":"users.manage"},{"permission":"applications.read"}]}`, true)
	if w.Code != 200 || !decode[RoleView](t, w.Body.Bytes()).MFARequired {
		t.Fatalf("изменение: %d %s", w.Code, w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", "/api/v1/roles/soc_lead", `{"id":"other","display_name":"SOC","permissions":[]}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/roles/auditor", `{"display_name":"A","permissions":[]}`, true), 422, CodeUnprocessable)
	mustProblem(t, e.call(admin, "DELETE", "/api/v1/roles/security_admin", "", true), 422, CodeUnprocessable)

	// Назначение роли: сессии пользователя завершаются, своя роль не меняется.
	an := e.mustLogin(t, "analyst")
	w = e.call(admin, "PUT", "/api/v1/users/"+tAnalystID+"/role", `{"role":"soc_lead"}`, true)
	if w.Code != 200 {
		t.Fatalf("назначение: %d %s", w.Code, w.Body)
	}
	if got := decode[AssignedRole](t, w.Body.Bytes()); got.User.Role != "soc_lead" || got.RevokedSessions != 1 {
		t.Fatalf("назначение: %+v", got)
	}
	mustProblem(t, e.call(an, "GET", "/api/v1/me", "", false), 401, CodeUnauthorized)
	// Та же роль — 409 (Н13 ревью 2.r2).
	mustProblem(t, e.call(admin, "PUT", "/api/v1/users/"+tAnalystID+"/role", `{"role":"soc_lead"}`, true), 409, CodeConflict)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/users/"+tAdminID+"/role", `{"role":"auditor"}`, true), 422, CodeUnprocessable)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/users/"+tAnalystID+"/role", `{"role":"no_role"}`, true), 400, CodeInvalidRequest)
	mustProblem(t, e.call(admin, "PUT", "/api/v1/users/not-a-uuid/role", `{"role":"auditor"}`, true), 404, CodeNotFound)
	mustProblem(t, e.call(admin, "DELETE", "/api/v1/roles/soc_lead", "", true), 409, CodeConflict)

	// Пользователь со своей ролью не выдаёт права сверх своих (УПД.2).
	soc := e.mustLogin(t, "analyst")
	mustProblem(t, e.call(soc, "POST", "/api/v1/users", `{"login":"boss","display_name":"Босс","role":"security_admin"}`, true), 403, CodeForbidden)
	if w := e.call(soc, "POST", "/api/v1/users", `{"login":"own1","display_name":"Владелец","role":"app_owner"}`, true); w.Code != 201 {
		t.Fatalf("создание учётной записи слабее себя: %d %s", w.Code, w.Body)
	}

	if w := e.call(admin, "PUT", "/api/v1/users/"+tAnalystID+"/role", `{"role":"analyst"}`, true); w.Code != 200 {
		t.Fatalf("возврат роли: %d", w.Code)
	}
	if w := e.call(admin, "DELETE", "/api/v1/roles/soc_lead", "", true); w.Code != 204 {
		t.Fatalf("удаление: %d %s", w.Code, w.Body)
	}
	for _, a := range []string{"role.create", "role.update", "user.role_changed", "role.delete"} {
		if !strings.Contains(strings.Join(e.mem.Actions(), " "), a) {
			t.Errorf("нет записи %s в аудите", a)
		}
	}
}

func TestMePermissions(t *testing.T) {
	e := newAuthEnv(t)
	for login, want := range map[string]string{
		"analyst": `"permissions":["applications.read","events.export","events.read","policies.read","policies.test","providers.read","self","session","system.read"]`,
		// Без events.content.read: содержимое событий — только у администратора безопасности (ТЗ 1.3).
		"auditor": `"permissions":["api_tokens.read","applications.read","audit.read","audit.verify","auth_policy.read","events.read","policies.read","providers.read","roles.read","self","session","sessions.read","system.read","users.read"]`,
	} {
		s := e.mustLogin(t, login)
		if w := e.call(s, "GET", "/api/v1/me", "", false); !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %s", login, w.Body)
		}
	}
}

// УПД.8: разрешение только на свои объекты пускает лишь к маршрутам, которые
// сами отбирают объекты (Scoped); без признака нужен доступ ко всем.
func TestScopedRoutes(t *testing.T) {
	const perm = "things.read"
	ok := func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		WriteJSON(w, 200, map[string]string{"scope": p.Grants.Scope(perm).String()})
	}
	authz := scopeAuthz{perm: perm, scope: auth.ScopeOwn}
	h, _ := newHandler(t, Options{Authorizer: authz, Extra: []Route{
		{Method: "GET", Path: "/api/v1/things", Permission: perm, Scoped: true, Handler: ok},
		{Method: "GET", Path: "/api/v1/all-things", Permission: perm, Handler: ok},
	}})
	if w := do(h, "GET", "/api/v1/things", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"own"`) {
		t.Fatalf("свои объекты: %d %s", w.Code, w.Body)
	}
	var reasons []string
	h, _ = newHandler(t, Options{Authorizer: authz, OnDenied: func(_ *http.Request, d Denial) { reasons = append(reasons, d.Reason) },
		Extra: []Route{{Method: "GET", Path: "/api/v1/all-things", Permission: perm, Handler: ok}}})
	mustProblem(t, do(h, "GET", "/api/v1/all-things", ""), 403, CodeForbidden)
	if len(reasons) != 1 || reasons[0] != DenyReasonScope {
		t.Fatalf("причина отказа: %v", reasons)
	}
	h, _ = newHandler(t, Options{Authorizer: scopeAuthz{perm: perm, scope: auth.ScopeAll}, Extra: []Route{
		{Method: "GET", Path: "/api/v1/all-things", Permission: perm, Handler: ok},
	}})
	if w := do(h, "GET", "/api/v1/all-things", ""); w.Code != 200 {
		t.Fatalf("все объекты: %d", w.Code)
	}
	r := &Router{mux: http.NewServeMux()}
	if err := r.Add(Route{Method: "GET", Path: "/x", Public: true, Scoped: true, Handler: ok}); err == nil {
		t.Fatal("Scoped у открытого маршрута принят")
	}
}

// Сбой проверки прав — 503 без записи об отказе.
func TestAuthorizerUnavailable(t *testing.T) {
	denied := 0
	h, _ := newHandler(t, Options{Authorizer: unavailableAuthz{}, OnDenied: func(*http.Request, Denial) { denied++ }})
	mustProblem(t, do(h, "GET", "/api/v1/system/info", ""), 503, CodeUnavailable)
	if denied != 0 {
		t.Fatal("сбой записан как отказ")
	}
}

type unavailableAuthz struct{}

func (unavailableAuthz) Authorize(*http.Request, string) (Principal, Decision) {
	return Principal{}, Unavailable
}

// scopeAuthz пропускает субъекта с разрешением perm в области scope.
type scopeAuthz struct {
	perm  string
	scope auth.Scope
}

func (a scopeAuthz) Authorize(_ *http.Request, perm string) (Principal, Decision) {
	p := Principal{ID: "u1", Grants: auth.Grants{a.perm: a.scope}}
	if p.Grants.Allows(perm) {
		return p, Allow
	}
	return p, Forbidden
}
