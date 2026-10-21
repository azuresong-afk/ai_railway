package auth_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
)

// Тесты ролей на живой БД (AISEC_TEST_DATABASE_URL); без переменной
// пропускаются. Строки матрицы обнаружения покрыты тестами без БД.

func TestPGRolesFlow(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	e.addUser(t, userID, "ivanov", auth.RoleAnalyst)
	res, err := e.login(t, "admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	admin := e.mfa.complete(t, res)
	if _, err := e.svc.CreateRole(ctx, admin, auth.RoleInput{ID: "soc_lead", DisplayName: "Руководитель SOC",
		Permissions: grants(auth.PermUsersRead, auth.PermSessionsRead)}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateRole(ctx, admin, auth.RoleInput{ID: "soc_lead", DisplayName: "Дубль"}); !errors.Is(err, auth.ErrRoleTaken) {
		t.Fatalf("повтор ID: %v", err)
	}
	upd, err := e.svc.UpdateRole(ctx, admin, "soc_lead", auth.RoleInput{DisplayName: "SOC", Description: "Разбор",
		Permissions: grants(auth.PermUsersRead, auth.PermUsersManage)})
	if err != nil || !upd.MFARequired {
		t.Fatalf("изменение: %+v, %v", upd, err)
	}
	r, err := e.svc.RoleDef(ctx, "soc_lead")
	if err != nil || r.DisplayName != "SOC" || r.Description != "Разбор" || !r.Grants.Full(auth.PermUsersManage) ||
		r.Grants.Allows(auth.PermSessionsRead) || !r.MFARequired || r.CreatedBy != adminID {
		t.Fatalf("роль из БД: %+v, %v", r, err)
	}
	ivanov, err := e.login(t, "ivanov", phrase)
	if err != nil {
		t.Fatal(err)
	}
	n, err := e.svc.AssignRole(ctx, admin, userID, "soc_lead")
	if err != nil || n != 1 {
		t.Fatalf("назначение: %d, %v", n, err)
	}
	if _, err := e.svc.Authenticate(ctx, ivanov.Token, testIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("сессия после смены роли не завершена")
	}
	if u, err := e.svc.User(ctx, userID); err != nil || u.Role != "soc_lead" {
		t.Fatalf("роль пользователя: %+v, %v", u, err)
	}
	if _, err := e.svc.AssignRole(ctx, admin, userID, "missing_role"); !errors.Is(err, auth.ErrRoleNotFound) {
		t.Fatalf("неизвестная роль: %v", err)
	}
	if err := e.svc.DeleteRole(ctx, admin, "soc_lead"); !errors.Is(err, auth.ErrRoleInUse) {
		t.Fatalf("удаление роли с пользователем: %v", err)
	}
	roles, err := e.svc.Roles(ctx)
	if err != nil || len(roles) != 6 {
		t.Fatalf("список: %d, %v", len(roles), err)
	}
	for _, x := range roles {
		if x.ID == "soc_lead" && x.Users != 1 {
			t.Fatalf("пользователей у роли: %d", x.Users)
		}
	}
	if _, err := e.svc.AssignRole(ctx, admin, userID, auth.RoleAnalyst); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteRole(ctx, admin, "soc_lead"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RoleDef(ctx, "soc_lead"); !errors.Is(err, auth.ErrRoleNotFound) {
		t.Fatalf("после удаления: %v", err)
	}
	for action, want := range map[string]int{"role.create": 1, "role.update": 1, "user.role_changed": 2, "role.delete": 1} {
		if got := auditCount(t, e, action); got != want {
			t.Errorf("%s: %d записей, ожидалось %d", action, got, want)
		}
	}
	if _, err := e.svc.UpdateRole(ctx, admin, auth.RoleAuditor, auth.RoleInput{DisplayName: "А"}); !errors.Is(err, auth.ErrRoleBuiltin) {
		t.Fatalf("предустановленная роль: %v", err)
	}
}

// Защита ролей на уровне СУБД: предустановленные роли неизменны даже для
// владельца таблицы, у роли приложения нет лишних прав, users.role ссылается
// только на существующие роли.
func TestPGRoleGuards(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	res, err := e.login(t, "admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateRole(ctx, e.mfa.complete(t, res), auth.RoleInput{ID: "custom_one", DisplayName: "Своя"}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"UPDATE roles SET display_name = 'x' WHERE id = 'auditor'",
		"DELETE FROM roles WHERE id = 'analyst'",
		"INSERT INTO role_permissions (org_id, role_id, permission, scope) SELECT org_id, 'auditor', 'users.manage', 'all' FROM roles WHERE id = 'auditor'",
		"UPDATE roles SET builtin = true WHERE id = 'custom_one'",
	} {
		if _, err := e.owner.Exec(ctx, q); sqlState(err) != "42501" {
			t.Errorf("владелец: %s: %v", q, err)
		}
		if _, err := e.app.Exec(ctx, q); sqlState(err) != "42501" {
			t.Errorf("aisec_app: %s: %v", q, err)
		}
	}
	for _, q := range []string{
		"UPDATE roles SET id = 'other_id' WHERE id = 'custom_one'",
		"INSERT INTO roles (org_id, id, display_name, builtin, mfa_required, created_at, created_by, updated_at) SELECT org_id, 'fake_builtin', 'x', true, false, now(), 'x', now() FROM roles WHERE id = 'custom_one'",
		"UPDATE role_permissions SET scope = 'all'",
		"UPDATE users SET org_id = org_id",
	} {
		if _, err := e.app.Exec(ctx, q); sqlState(err) != "42501" {
			t.Errorf("aisec_app: %s: %v", q, err)
		}
	}
	if _, err := e.owner.Exec(ctx, `INSERT INTO roles (org_id, id, display_name, mfa_required, created_at, created_by, updated_at)
		SELECT org_id, 'auditor', 'x', false, now(), 'x', now() FROM roles WHERE id = 'custom_one'`); sqlState(err) != "23514" {
		t.Errorf("своя роль с ID предустановленной: %v", err)
	}
	if _, err := e.app.Exec(ctx, "UPDATE users SET role = 'no_such_role'"); sqlState(err) != "23503" {
		t.Errorf("роль вне таблицы ролей: %v", err)
	}
	if _, err := e.app.Exec(ctx, "INSERT INTO role_permissions (org_id, role_id, permission, scope) SELECT org_id, id, 'Bad Perm', 'all' FROM roles WHERE id = 'custom_one'"); sqlState(err) != "23514" {
		t.Errorf("недопустимое имя разрешения: %v", err)
	}
	var n int
	if err := e.owner.QueryRow(ctx, "SELECT count(*) FROM roles WHERE builtin").Scan(&n); err != nil || n != 5 {
		t.Fatalf("предустановленных ролей в БД %d, %v", n, err)
	}
}

// Встречные понижения двух последних администраторов безопасности: одно
// проходит, система не остаётся без администратора.
func TestPGAssignRoleLastAdminConcurrent(t *testing.T) {
	e := setupPG(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	e.addUser(t, admin2ID, "admin2", auth.RoleSecurityAdmin)
	r1, err := e.login(t, "admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := e.login(t, "admin2", phrase)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, pair := range []struct {
		by     auth.Caller
		target string
	}{{e.mfa.complete(t, r1), admin2ID}, {e.mfa.complete(t, r2), adminID}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = e.svc.AssignRole(pgCtx(t), pair.by, pair.target, auth.RoleAuditor)
		}()
	}
	wg.Wait()
	var admins int
	if err := e.owner.QueryRow(pgCtx(t), "SELECT count(*) FROM users WHERE role = 'security_admin' AND status = 'active'").Scan(&admins); err != nil {
		t.Fatal(err)
	}
	if admins != 1 || (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("администраторов %d, ошибки %v", admins, errs)
	}
}

// Права действующего перечитываются в транзакции: после понижения роли
// открытая сессия не создаёт роли и не назначает их; сброс пароля сверяет
// роль цели под блокировкой строки.
func TestPGStaleActorAndRoleChanged(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	e.addUser(t, admin2ID, "admin2", auth.RoleSecurityAdmin)
	e.addUser(t, userID, "ivanov", auth.RoleAnalyst)
	r1, err := e.login(t, "admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := e.login(t, "admin2", phrase)
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := e.mfa.complete(t, r1), e.mfa.complete(t, r2)
	if _, err := e.svc.AssignRole(ctx, c1, admin2ID, auth.RoleAuditor); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateRole(ctx, c2, auth.RoleInput{ID: "stale_one", DisplayName: "x"}); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("создание по старым правам: %v", err)
	}
	if _, err := e.svc.AssignRole(ctx, c2, userID, auth.RoleAuditor); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("назначение по старым правам: %v", err)
	}
	err = e.store.SetPassword(ctx, auth.PasswordChange{UserID: userID, NewHash: authtest.HashOf("x"),
		ExpectRole: auth.RoleSecurityAdmin, Now: e.clock.now()}, audit.Entry{})
	if !errors.Is(err, auth.ErrRoleChanged) {
		t.Fatalf("роль цели сменилась: %v", err)
	}
}
