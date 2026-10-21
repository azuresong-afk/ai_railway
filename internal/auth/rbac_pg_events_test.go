package auth_test

import (
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Своя роль с разрешением из трёх частей (events.content.read, задача 2.16)
// сохраняется в role_permissions и требует второй фактор: это чтение данных
// безопасности (УПД.7).
func TestPGRoleWithContentRead(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	res, err := e.login(t, "admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	admin := e.mfa.complete(t, res)
	r, err := e.svc.CreateRole(ctx, admin, auth.RoleInput{ID: "incident_reader", DisplayName: "Разбор инцидентов",
		Permissions: grants(auth.PermEventsRead, auth.PermEventsContentRead)})
	if err != nil || !r.MFARequired {
		t.Fatalf("создание: %+v, %v", r, err)
	}
	got, err := e.svc.RoleDef(ctx, "incident_reader")
	if err != nil || !got.Grants.Full(auth.PermEventsContentRead) || !got.MFARequired {
		t.Fatalf("роль из БД: %+v, %v", got, err)
	}
}
