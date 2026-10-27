package apps_test

import (
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/apps"
)

// Пользователь по JWT на живой БД (задача 4.21, миграция 0057): запись и
// чтение с группами, счётчик изменений конфигурации, права роли
// приложения и ограничения таблицы.
func TestPGUserAccessStorage(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	_, a := e.fixture(t)
	revision := func() int64 {
		var r int64
		if err := e.owner.QueryRow(ctx, `SELECT coalesce(max(revision), 0) FROM config_revisions`).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if u, err := e.svc.UserAccess(ctx, a.ID); err != nil || u.Configured || u.Mode != apps.UserTokenOff {
		t.Fatalf("без записи: %+v %v", u, err)
	}
	rev0 := revision()
	in := apps.UserAccessInput{Mode: apps.UserTokenRequired, Issuer: "https://idp.example.test/realms/aisec", Audience: "aisec-gateway",
		ModelGroups: map[string][]string{a.Models[0]: {"Аналитики ИБ", "admins"}}}
	if _, err := e.svc.SetUserAccess(ctx, e.by, a.ID, in); err != nil {
		t.Fatal(err)
	}
	if revision() <= rev0 {
		t.Fatal("счётчик изменений конфигурации не вырос")
	}
	u, err := e.svc.UserAccess(ctx, a.ID)
	if err != nil || !u.Configured || u.Mode != apps.UserTokenRequired || len(u.ModelGroups[a.Models[0]]) != 2 || u.Leeway != 60 {
		t.Fatalf("после записи: %+v %v", u, err)
	}
	// Повтор без изменений — без новой версии конфигурации.
	rev1 := revision()
	if _, err := e.svc.SetUserAccess(ctx, e.by, a.ID, in); err != nil || revision() != rev1 {
		t.Fatalf("повтор: %v, счётчик %d → %d", err, rev1, revision())
	}
	if list, err := e.svc.UserAccessList(ctx); err != nil || len(list) != 1 || list[0].AppID != a.ID {
		t.Fatalf("список: %+v %v", list, err)
	}
	// Роль приложения не удаляет запись и не меняет приложение строки;
	// режим без издателя отклоняет сама таблица.
	if _, err := e.app.Exec(ctx, `DELETE FROM app_user_access`); sqlState(err) != "42501" {
		t.Fatalf("удаление ролью приложения: %v", err)
	}
	if _, err := e.app.Exec(ctx, `UPDATE app_user_access SET app_id = app_id`); sqlState(err) != "42501" {
		t.Fatalf("смена приложения: %v", err)
	}
	if _, err := e.app.Exec(ctx, `UPDATE app_user_access SET issuer = ''`); sqlState(err) != "23514" {
		t.Fatalf("required без издателя: %v", err)
	}
}
