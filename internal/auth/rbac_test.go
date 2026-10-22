package auth_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
)

// Синтетические учётные записи для проверок ролей.
const (
	helperID = "01900000-0000-7000-8000-00000000d001"
	ownerID  = "01900000-0000-7000-8000-00000000e001"
	admin2ID = "01900000-0000-7000-8000-00000000a002"
)

// allowed — есть ли у сессии c право perm с учётом её роли и состояния.
func allowed(t *testing.T, e *env, c auth.Caller, perm string) bool {
	t.Helper()
	g, err := e.svc.CallerGrants(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return g.Allows(perm)
}

func grants(perms ...string) []auth.GrantInput {
	out := make([]auth.GrantInput, len(perms))
	for i, p := range perms {
		out[i] = auth.GrantInput{Permission: p}
	}
	return out
}

// createRole создаёт свою роль от имени администратора.
func (e *env) createRole(t *testing.T, id string, perms ...string) auth.RoleDef {
	t.Helper()
	r, err := e.svc.CreateRole(context.Background(), e.adminCaller(t), auth.RoleInput{ID: id, DisplayName: "Роль " + id, Permissions: grants(perms...)})
	if err != nil {
		t.Fatalf("роль %s: %v", id, err)
	}
	return r
}

func deniedRecords(m *authtest.Memory, action string) int {
	n := 0
	for _, r := range m.Records() {
		if r.Action == action && r.Result == audit.ResultDenied {
			n++
		}
	}
	return n
}

// УПД.2: аудитор только читает; администратор системы не получает
// разрешений управления безопасностью; администратор безопасности — все.
func TestBuiltinRoleInvariants(t *testing.T) {
	roles := map[auth.Role]auth.RoleDef{}
	for _, r := range auth.BuiltinRoles() {
		if !r.ID.Valid() || !r.Builtin || r.DisplayName == "" {
			t.Errorf("роль %+v", r)
		}
		roles[r.ID] = r
	}
	if len(roles) != 5 {
		t.Fatalf("предустановленных ролей %d", len(roles))
	}
	for _, p := range auth.Permissions() {
		if !roles[auth.RoleSecurityAdmin].Grants.Full(p.Name) {
			t.Errorf("у администратора безопасности нет %s", p.Name)
		}
		if p.Security && roles[auth.RoleSystemAdmin].Grants.Allows(p.Name) {
			t.Errorf("у администратора системы есть %s (УПД.2)", p.Name)
		}
		// Исключение — проверка цепочки аудита: ничего не меняет (задача 2.4a).
		if !p.ReadOnly() && !slices.Contains(auth.AuditorExtra(), p.Name) && roles[auth.RoleAuditor].Grants.Allows(p.Name) {
			t.Errorf("у аудитора есть %s (УПД.2)", p.Name)
		}
		// Чтение с признаком безопасности (содержимое событий, УПД.7) —
		// только у администратора безопасности (ТЗ 1.3).
		if p.Security && roles[auth.RoleAuditor].Grants.Allows(p.Name) {
			t.Errorf("у аудитора есть %s (ТЗ 1.3)", p.Name)
		}
	}
	// УПД.8: владелец приложения видит только свои объекты.
	for p, s := range roles[auth.RoleAppOwner].Grants {
		if s != auth.ScopeOwn {
			t.Errorf("у владельца приложения есть право %s сверх своих объектов", p)
		}
	}
	if !roles[auth.RoleSecurityAdmin].MFARequired || !roles[auth.RoleSystemAdmin].MFARequired {
		t.Error("административные роли без обязательного второго фактора")
	}
	// Копии независимы: изменение не затрагивает каталог.
	roles[auth.RoleAnalyst].Grants[auth.PermUsersManage] = auth.ScopeAll
	if r, _ := auth.LookupBuiltinRole(auth.RoleAnalyst); r.Grants.Allows(auth.PermUsersManage) {
		t.Fatal("права предустановленной роли изменились через копию")
	}
}

func TestGrants(t *testing.T) {
	g := auth.Grants{"users.read": auth.ScopeAll, "apps.read": auth.ScopeOwn}
	if g.Allows(auth.PermSelf) || !g.Allows("apps.read") || g.Full("apps.read") || g.Allows("users.manage") {
		t.Fatal("Allows/Full")
	}
	if !g.Covers(auth.Grants{"apps.read": auth.ScopeOwn}) || g.Covers(auth.Grants{"apps.read": auth.ScopeAll}) ||
		g.Covers(auth.Grants{"users.manage": auth.ScopeAll}) || !g.Covers(auth.Grants{"x.read": auth.ScopeNone}) {
		t.Fatal("Covers")
	}
	if got := g.Names(); !slices.Equal(got, []string{"apps.read", "users.read"}) {
		t.Fatalf("Names: %v", got)
	}
	for _, s := range []auth.Scope{auth.ScopeOwn, auth.ScopeAll} {
		if p, ok := auth.ParseScope(s.String()); !ok || p != s {
			t.Fatalf("область %v", s)
		}
	}
	if _, ok := auth.ParseScope("none"); ok {
		t.Fatal("область none принята")
	}
}

func TestRoleIDValid(t *testing.T) {
	for _, ok := range []string{"soc_lead", "abc", "a12", "security_admin", "a23456789012345678901234567890123456789012345678"} {
		if !auth.Role(ok).Valid() {
			t.Errorf("%q отклонён", ok)
		}
	}
	for _, bad := range []string{"", "ab", "1abc", "_abc", "Abc", "ab-c", "аbc", "ab c",
		"a234567890123456789012345678901234567890123456789"} {
		if auth.Role(bad).Valid() {
			t.Errorf("%q принят", bad)
		}
	}
}

func TestCreateRoleValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	var ie *auth.InputError
	for _, in := range []auth.RoleInput{
		{ID: "x", DisplayName: "Роль"},
		{ID: "Bad_ID", DisplayName: "Роль"},
		{ID: "ok_role", DisplayName: ""},
		{ID: "ok_role", DisplayName: "Роль\u202e"},
		{ID: "ok_role", DisplayName: "Роль", Description: string(make([]byte, 501))},
		{ID: "ok_role", DisplayName: "Роль", Permissions: grants("nope.read")},
		{ID: "ok_role", DisplayName: "Роль", Permissions: grants(auth.PermSelf)},
		{ID: "ok_role", DisplayName: "Роль", Permissions: grants(auth.PermUsersRead, auth.PermUsersRead)},
		{ID: "ok_role", DisplayName: "Роль", Permissions: []auth.GrantInput{{Permission: auth.PermUsersRead, Scope: "own"}}},
		{ID: "ok_role", DisplayName: "Роль", Permissions: []auth.GrantInput{{Permission: auth.PermUsersRead, Scope: "some"}}},
	} {
		if _, err := e.svc.CreateRole(ctx, admin, in); !errors.As(err, &ie) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	if _, err := e.svc.CreateRole(ctx, admin, auth.RoleInput{ID: "auditor", DisplayName: "Дубль"}); !errors.Is(err, auth.ErrRoleTaken) {
		t.Fatalf("ID предустановленной роли: %v", err)
	}
	r, err := e.svc.CreateRole(ctx, admin, auth.RoleInput{ID: "helpdesk", DisplayName: " Служба поддержки ",
		Description: "Сброс паролей", Permissions: grants(auth.PermUsersRead, auth.PermUsersManage)})
	if err != nil {
		t.Fatal(err)
	}
	if r.DisplayName != "Служба поддержки" || !r.MFARequired || !r.Grants.Full(auth.PermUsersManage) || r.Builtin {
		t.Fatalf("роль: %+v", r)
	}
	if _, err := e.svc.CreateRole(ctx, admin, auth.RoleInput{ID: "helpdesk", DisplayName: "Дубль"}); !errors.Is(err, auth.ErrRoleTaken) {
		t.Fatalf("повтор ID: %v", err)
	}
	rec := lastRecord(t, e.mem, "role.create")
	if rec.Object != (audit.Object{Type: "role", ID: "helpdesk"}) || rec.Result != audit.ResultSuccess {
		t.Fatalf("аудит: %+v", rec)
	}
	ro, err := e.svc.CreateRole(ctx, admin, auth.RoleInput{ID: "reader", DisplayName: "Чтение", Permissions: grants(auth.PermUsersRead)})
	if err != nil || ro.MFARequired {
		t.Fatalf("роль только на чтение: %+v, %v", ro, err)
	}
}

// УПД.2: пользователь со своей ролью не выдаёт и не получает прав, которых
// у него нет, и не управляет учётными записями сильнее себя.
func TestNoPrivilegeEscalation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// applications.read и dashboards.read покрывают права владельца приложения (задачи 2.11, 3.19).
	e.createRole(t, "helpdesk", auth.PermUsersRead, auth.PermUsersManage, auth.PermSessionsManage, auth.PermRolesManage, auth.PermApplicationsRead,
		auth.PermDashboardsRead)
	e.mem.AddUser(e.user(helperID, "helper", "helpdesk"))
	e.mem.AddUser(e.user(ownerID, "owner", auth.RoleAppOwner))
	helper := e.mfa.complete(t, e.mustLogin(t, "helper", phrase))

	if _, err := e.svc.CreateRole(ctx, helper, auth.RoleInput{ID: "wider", DisplayName: "Шире",
		Permissions: grants(auth.PermUsersRead, auth.PermAuthPolicyManage)}); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("роль с чужим разрешением: %v", err)
	}
	if _, _, err := e.svc.CreateUser(ctx, helper, auth.NewUser{Login: "boss", DisplayName: "Босс", Role: auth.RoleSecurityAdmin}); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("создание администратора: %v", err)
	}
	// У аналитика есть system.read, которого нет у helpdesk.
	if _, _, err := e.svc.CreateUser(ctx, helper, auth.NewUser{Login: "an", DisplayName: "Аналитик", Role: auth.RoleAnalyst}); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("создание аналитика: %v", err)
	}
	if _, err := e.svc.ResetPassword(ctx, helper, adminID); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("сброс пароля администратора: %v", err)
	}
	if err := e.svc.SetStatus(ctx, helper, adminID, auth.StatusDeactivated); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("деактивация администратора: %v", err)
	}
	if _, err := e.svc.RevokeSessions(ctx, helper, adminID, true); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("завершение сессий администратора: %v", err)
	}
	if err := e.svc.ResetMFA(ctx, helper, adminID); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("сброс второго фактора администратора: %v", err)
	}
	if _, err := e.svc.AssignRole(ctx, helper, ownerID, auth.RoleSecurityAdmin); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("назначение роли администратора: %v", err)
	}
	if _, err := e.svc.AssignRole(ctx, helper, adminID, auth.RoleAppOwner); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("понижение администратора: %v", err)
	}
	for action, n := range map[string]int{"role.create": 1, "user.create": 2, "user.password_reset": 1,
		"user.deactivate": 1, "auth.sessions_revoked": 1, "auth.mfa_reset": 1, "user.role_changed": 2} {
		if got := deniedRecords(e.mem, action); got != n {
			t.Errorf("%s: отказов в аудите %d, ожидалось %d", action, got, n)
		}
	}
	// Учётная запись не сильнее своей — можно.
	if _, _, err := e.svc.CreateUser(ctx, helper, auth.NewUser{Login: "own2", DisplayName: "Владелец", Role: auth.RoleAppOwner}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ResetPassword(ctx, helper, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AssignRole(ctx, helper, ownerID, "helpdesk"); err != nil {
		t.Fatal(err)
	}
}

func TestAssignRole(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	a := e.mustLogin(t, "ivanov", phrase)
	if !allowed(t, e, a.Caller, auth.PermSystemRead) || allowed(t, e, a.Caller, auth.PermUsersRead) {
		t.Fatal("права аналитика")
	}
	if _, err := e.svc.AssignRole(ctx, admin, adminID, auth.RoleAuditor); !errors.Is(err, auth.ErrSelf) {
		t.Fatalf("смена своей роли: %v", err)
	}
	if _, err := e.svc.AssignRole(ctx, admin, userID, "no_such"); !errors.Is(err, auth.ErrRoleNotFound) {
		t.Fatalf("неизвестная роль: %v", err)
	}
	if _, err := e.svc.AssignRole(ctx, admin, "01900000-0000-7000-8000-0000000000ff", auth.RoleAuditor); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("неизвестный пользователь: %v", err)
	}
	n, err := e.svc.AssignRole(ctx, admin, userID, auth.RoleAuditor)
	if err != nil || n != 1 {
		t.Fatalf("назначение: %d, %v", n, err)
	}
	if _, err := e.caller(t, a.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("сессия пользователя после смены роли не завершена")
	}
	rec := lastRecord(t, e.mem, "user.role_changed")
	d, _ := rec.Details.(map[string]any)
	if rec.Object.ID != userID || d["before"] != "analyst" || d["after"] != "auditor" || d["revoked_sessions"] != 1 {
		t.Fatalf("аудит: %+v", rec)
	}
	b := e.mustLogin(t, "ivanov", phrase)
	if !allowed(t, e, b.Caller, auth.PermUsersRead) || allowed(t, e, b.Caller, auth.PermUsersManage) {
		t.Fatal("права после смены роли")
	}
	// Повторное назначение той же роли ничего не меняет и отвечает отказом,
	// а не успехом без записи в аудите (Н13 ревью 2.r2).
	before := len(e.mem.Records())
	if n, err := e.svc.AssignRole(ctx, admin, userID, auth.RoleAuditor); !errors.Is(err, auth.ErrRoleUnchanged) || n != 0 || len(e.mem.Records()) != before {
		t.Fatalf("та же роль: %d, %v", n, err)
	}
}

// Последнего активного администратора безопасности нельзя понизить даже
// пользователю со своей ролью, равной ему по правам.
func TestAssignRoleKeepsLastAdmin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	all := []string{}
	for _, p := range auth.Permissions() {
		all = append(all, p.Name)
	}
	e.createRole(t, "deputy", all...)
	e.mem.AddUser(e.user(helperID, "deputy", "deputy"))
	deputy := e.mfa.complete(t, e.mustLogin(t, "deputy", phrase))
	if _, err := e.svc.AssignRole(ctx, deputy, adminID, auth.RoleAnalyst); !errors.Is(err, auth.ErrLastAdmin) {
		t.Fatalf("последний администратор: %v", err)
	}
	e.mem.AddUser(e.user(admin2ID, "admin2", auth.RoleSecurityAdmin))
	if _, err := e.svc.AssignRole(ctx, deputy, adminID, auth.RoleAnalyst); err != nil {
		t.Fatal(err)
	}
}

// Права действующего перечитываются в транзакции изменения: сессия,
// открытая до понижения роли или деактивации, не управляет ролями по
// старым правам (УПД.2).
func TestStaleActorGrants(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	e.createRole(t, "helpdesk", auth.PermUsersRead, auth.PermRolesRead, auth.PermRolesManage)
	e.createRole(t, "reader", auth.PermUsersRead)
	e.createRole(t, "extra", auth.PermRolesRead)
	e.mem.AddUser(e.user(helperID, "helper", "helpdesk"))
	e.mem.AddUser(e.user(ownerID, "owner", auth.RoleAppOwner))
	helper := e.mfa.complete(t, e.mustLogin(t, "helper", phrase))
	if _, err := e.svc.AssignRole(ctx, admin, helperID, "reader"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateRole(ctx, helper, auth.RoleInput{ID: "stale", DisplayName: "x",
		Permissions: grants(auth.PermRolesRead)}); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("создание по старым правам: %v", err)
	}
	if _, err := e.svc.UpdateRole(ctx, helper, "reader", auth.RoleInput{DisplayName: "x"}); !errors.Is(err, auth.ErrOwnRole) {
		t.Fatalf("изменение роли, назначенной во время сессии: %v", err)
	}
	if err := e.svc.DeleteRole(ctx, helper, "extra"); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("удаление по старым правам: %v", err)
	}
	if _, err := e.svc.AssignRole(ctx, helper, ownerID, "extra"); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("назначение по старым правам: %v", err)
	}
	for _, a := range []string{"role.create", "role.update", "role.delete", "user.role_changed"} {
		if deniedRecords(e.mem, a) != 1 {
			t.Errorf("%s: нет отказа в аудите", a)
		}
	}

	// Деактивированный администратор безопасности — без прав.
	e.mem.AddUser(e.user(admin2ID, "admin2", auth.RoleSecurityAdmin))
	admin2 := e.mfa.complete(t, e.mustLogin(t, "admin2", phrase))
	if err := e.svc.SetStatus(ctx, admin, admin2ID, auth.StatusDeactivated); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateRole(ctx, admin2, auth.RoleInput{ID: "late", DisplayName: "x"}); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("создание деактивированным: %v", err)
	}
	if _, err := e.svc.AssignRole(ctx, admin2, ownerID, auth.RoleAuditor); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("назначение деактивированным: %v", err)
	}
}

// Сброс пароля сверяет роль цели под блокировкой строки: если роль
// сменили после проверки прав, сброс не выполняется (УПД.2).
func TestResetPasswordRoleChanged(t *testing.T) {
	e := newEnv(t)
	err := e.mem.SetPassword(context.Background(), auth.PasswordChange{UserID: userID, NewHash: authtest.HashOf("x"),
		ExpectRole: auth.RoleAuditor, Now: e.clock.now()}, audit.Entry{})
	if !errors.Is(err, auth.ErrRoleChanged) {
		t.Fatalf("роль сменилась: %v", err)
	}
	if e.userByID(t, userID).PasswordHash != authtest.HashOf(phrase) {
		t.Fatal("пароль изменён")
	}
}

// Предел числа своих ролей.
func TestTooManyRoles(t *testing.T) {
	e := newEnv(t)
	for i := range auth.MaxCustomRoles {
		e.createRole(t, fmt.Sprintf("role_%03d", i))
	}
	if _, err := e.svc.CreateRole(context.Background(), e.adminCaller(t), auth.RoleInput{ID: "one_more", DisplayName: "x"}); !errors.Is(err, auth.ErrTooManyRoles) {
		t.Fatalf("сверх предела: %v", err)
	}
}

func TestUpdateRole(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	e.createRole(t, "reader", auth.PermUsersRead)
	e.mem.AddUser(e.user(helperID, "reader", "reader"))
	r := e.mustLogin(t, "reader", phrase)
	if !allowed(t, e, r.Caller, auth.PermUsersRead) || allowed(t, e, r.Caller, auth.PermSessionsRead) {
		t.Fatal("права до изменения")
	}
	upd, err := e.svc.UpdateRole(ctx, admin, "reader", auth.RoleInput{DisplayName: "Чтение", Description: "Учётные записи и сессии",
		Permissions: grants(auth.PermUsersRead, auth.PermSessionsRead)})
	if err != nil {
		t.Fatal(err)
	}
	if upd.DisplayName != "Чтение" || upd.CreatedBy != adminID || !upd.Grants.Full(auth.PermSessionsRead) {
		t.Fatalf("роль: %+v", upd)
	}
	// Права действуют сразу, без нового входа.
	if !allowed(t, e, r.Caller, auth.PermSessionsRead) {
		t.Fatal("изменение роли не действует на сессию")
	}
	rec := lastRecord(t, e.mem, "role.update")
	d, _ := rec.Details.(map[string]any)
	if d["before"] == nil || d["after"] == nil {
		t.Fatalf("аудит без значений до и после: %+v", rec)
	}
	if _, err := e.svc.UpdateRole(ctx, admin, auth.RoleAuditor, auth.RoleInput{DisplayName: "Аудитор"}); !errors.Is(err, auth.ErrRoleBuiltin) {
		t.Fatalf("предустановленная роль: %v", err)
	}
	if _, err := e.svc.UpdateRole(ctx, admin, "missing", auth.RoleInput{DisplayName: "Нет"}); !errors.Is(err, auth.ErrRoleNotFound) {
		t.Fatalf("нет роли: %v", err)
	}
	// Своя роль не меняется, даже если права позволяют.
	e.createRole(t, "managers", auth.PermRolesManage, auth.PermUsersRead, auth.PermSessionsRead)
	e.mem.AddUser(e.user(ownerID, "manager", "managers"))
	m := e.mfa.complete(t, e.mustLogin(t, "manager", phrase))
	if _, err := e.svc.UpdateRole(ctx, m, "managers", auth.RoleInput{DisplayName: "Мы"}); !errors.Is(err, auth.ErrOwnRole) {
		t.Fatalf("своя роль: %v", err)
	}
	if _, err := e.svc.UpdateRole(ctx, m, "reader", auth.RoleInput{DisplayName: "Шире",
		Permissions: grants(auth.PermUsersRead, auth.PermUsersManage)}); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("выдача недостающего права: %v", err)
	}
	if deniedRecords(e.mem, "role.update") != 2 {
		t.Fatalf("отказы не в аудите: %v", e.mem.Actions())
	}
	// Роль сильнее своей нельзя ослабить или удалить.
	e.createRole(t, "strong", auth.PermAuthPolicyManage)
	if _, err := e.svc.UpdateRole(ctx, m, "strong", auth.RoleInput{DisplayName: "Слабее"}); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("изменение роли сильнее своей: %v", err)
	}
	if err := e.svc.DeleteRole(ctx, m, "strong"); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("удаление роли сильнее своей: %v", err)
	}
}

func TestDeleteRole(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	e.createRole(t, "temp_role", auth.PermUsersRead)
	e.mem.AddUser(e.user(helperID, "temp", "temp_role"))
	if err := e.svc.DeleteRole(ctx, admin, "temp_role"); !errors.Is(err, auth.ErrRoleInUse) {
		t.Fatalf("роль с пользователем: %v", err)
	}
	if _, err := e.svc.AssignRole(ctx, admin, helperID, auth.RoleAnalyst); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteRole(ctx, admin, "temp_role"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteRole(ctx, admin, "temp_role"); !errors.Is(err, auth.ErrRoleNotFound) {
		t.Fatalf("повторное удаление: %v", err)
	}
	if err := e.svc.DeleteRole(ctx, admin, auth.RoleAnalyst); !errors.Is(err, auth.ErrRoleBuiltin) {
		t.Fatalf("предустановленная роль: %v", err)
	}
	if rec := lastRecord(t, e.mem, "role.delete"); rec.Object.ID != "temp_role" || rec.Result != audit.ResultSuccess {
		t.Fatalf("аудит: %+v", rec)
	}
}

func TestRolesList(t *testing.T) {
	e := newEnv(t)
	e.createRole(t, "zeta", auth.PermUsersRead)
	e.createRole(t, "alpha")
	roles, err := e.svc.Roles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	auth.SortRoles(roles)
	var ids []string
	users := map[auth.Role]int{}
	for _, r := range roles {
		ids = append(ids, string(r.ID))
		users[r.ID] = r.Users
	}
	want := []string{"security_admin", "system_admin", "analyst", "auditor", "app_owner", "alpha", "zeta"}
	if !slices.Equal(ids, want) {
		t.Fatalf("порядок %v", ids)
	}
	if users[auth.RoleSecurityAdmin] != 1 || users[auth.RoleAnalyst] != 1 || users["zeta"] != 0 {
		t.Fatalf("число пользователей %v", users)
	}
}

func TestRoleRequiresMFA(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.createRole(t, "writer", auth.PermUsersManage)
	e.createRole(t, "reader", auth.PermUsersRead)
	for role, want := range map[auth.Role]bool{auth.RoleSecurityAdmin: true, auth.RoleSystemAdmin: true,
		auth.RoleAnalyst: false, auth.RoleAuditor: false, "writer": true, "reader": false, "unknown_role": true} {
		got, err := e.svc.RoleRequiresMFA(ctx, role)
		if err != nil || got != want {
			t.Errorf("%s: %v, %v", role, got, err)
		}
	}
}

// Без хранилища ролей своя роль не даёт прав: доступ закрыт по умолчанию.
func TestCustomRoleWithoutStore(t *testing.T) {
	mem := authtest.NewMemory()
	svc, err := auth.NewService(context.Background(), mem, mem, provider(t), auth.WithPasswordHasher(&authtest.Hasher{}))
	if err != nil {
		t.Fatal(err)
	}
	g, err := svc.Grants(context.Background(), "custom_role")
	if err != nil || len(g) != 0 {
		t.Fatalf("%v, %v", g, err)
	}
	if _, err := svc.CreateRole(context.Background(), auth.Caller{}, auth.RoleInput{ID: "custom_role", DisplayName: "Р"}); err == nil {
		t.Fatal("роль создана без хранилища")
	}
	g, err = svc.Grants(context.Background(), auth.RoleAuditor)
	if err != nil || !g.Full(auth.PermUsersRead) {
		t.Fatalf("предустановленная роль без хранилища: %v, %v", g, err)
	}
}

func TestAccessDeniedAudit(t *testing.T) {
	e := newEnv(t)
	a := e.mfa.complete(t, e.mustLogin(t, "ivanov", phrase))
	if err := e.svc.AccessDenied(context.Background(), a, "GET", "/api/v1/users", auth.PermUsersRead, "permission"); err != nil {
		t.Fatal(err)
	}
	rec := lastRecord(t, e.mem, "access.denied")
	d, _ := rec.Details.(map[string]any)
	if rec.Actor.ID != userID || rec.Result != audit.ResultDenied || d["permission"] != auth.PermUsersRead || d["path"] != "/api/v1/users" ||
		d["reason"] != "permission" {
		t.Fatalf("аудит: %+v", rec)
	}
}

// В6 ревью 2.r2: роль получила права, при которых второй фактор обязателен,
// — открытые сессии без фактора завершаются; сессия, прошедшая фактор,
// продолжает работу.
func TestRoleGainsMFARequirement(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.adminCaller(t)
	e.createRole(t, "reader", auth.PermUsersRead)
	e.mem.AddUser(e.user(helperID, "reader", "reader"))
	plain := e.mustLogin(t, "reader", phrase)
	if plain.Caller.Session.State != auth.SessionActive || plain.Caller.Session.MFAVerified {
		t.Fatalf("вход без фактора: %+v", plain.Caller.Session)
	}
	// Второй пользователь роли подключил фактор в своей сессии.
	const other = "01900000-0000-7000-8000-00000000b003"
	e.mem.AddUser(e.user(other, "reader2", "reader"))
	withMFA := e.mustLogin(t, "reader2", phrase)
	e.mfa.enroll(t, withMFA.Caller)
	if _, err := e.svc.ConfirmMFA(ctx, withMFA.Caller, e.mfa.code(t, other)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateRole(ctx, admin, "reader", auth.RoleInput{DisplayName: "Управление",
		Permissions: grants(auth.PermUsersRead, auth.PermUsersManage)}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.caller(t, plain.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия без фактора после расширения роли: %v", err)
	}
	if rec := lastRecord(t, e.mem, "auth.session_expired"); rec.Details.(map[string]any)["reason"] != auth.RevokeMFARequired {
		t.Fatalf("причина: %v", rec.Details)
	}
	if c := e.mustCaller(t, withMFA.Token); !allowed(t, e, c, auth.PermUsersManage) {
		t.Fatal("сессия с фактором потеряла права")
	}
	if r := e.mustLogin(t, "reader", phrase); r.Caller.Session.State != auth.SessionMFASetup {
		t.Fatalf("новый вход: %s", r.Caller.Session.State)
	}
}

// В6: включение mfa_required_all завершает полные сессии без фактора;
// сессия, прошедшая фактор при входе, продолжает работу.
func TestMFARequiredAllExpiresPlainSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.mfa.completeLogin(t, e.mustLogin(t, "admin", phrase))
	if !admin.Caller.Session.MFAVerified {
		t.Fatal("сессия после второго фактора без признака")
	}
	plain := e.mustLogin(t, "ivanov", phrase)
	e.mustCaller(t, plain.Token)
	p := auth.DefaultPolicy()
	p.MFARequiredAll = true
	if err := e.svc.SetPolicy(ctx, admin.Caller, p, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.caller(t, plain.Token); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия без фактора: %v", err)
	}
	e.mustCaller(t, admin.Token)
}
