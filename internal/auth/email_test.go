package auth_test

import (
	"fmt"

	"context"
	"errors"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

func TestNormalizeEmail(t *testing.T) {
	long := strings.Repeat("a", 243) + "@example.ru" // 254 байта
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"", "", true},
		{"   ", "", true},
		{"ivanov@example.ru", "ivanov@example.ru", true},
		{"  ivanov@example.ru ", "ivanov@example.ru", true},
		{"a.b+tag@sub.example.ru", "a.b+tag@sub.example.ru", true},
		{long, long, true},
		{long + "x", "", false},
		{"ivanov", "", false},
		{"a@b@example.ru", "", false},
		{"Иванов <ivanov@example.ru>", "", false},
		{"<ivanov@example.ru>", "", false},
		{"iva nov@example.ru", "", false},
		{"ivanov@example.ru\r\nBcc: x@example.ru", "", false},
		{"ivanov@example.ru\x00", "", false},
		{"ivanov@exa mple.ru", "", false},
		{"ivanov@example.ru, petrov@example.ru", "", false},
		{"@example.ru", "", false},
		{"ivanov@", "", false},
		{"\xff@example.ru", "", false},
	} {
		got, ok := auth.NormalizeEmail(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%q: %q %v, ждали %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func FuzzNormalizeEmail(f *testing.F) {
	for _, s := range []string{"", "a@b.ru", "a@b@c", "x\r\ny@z.ru", "Имя <a@b.ru>", "\xff", strings.Repeat("a", 300)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, ok := auth.NormalizeEmail(s)
		if !ok {
			return
		}
		if len(got) > auth.MaxEmailLen || strings.ContainsAny(got, " \t\r\n\x00<>,;\"") {
			t.Fatalf("принят %q → %q", s, got)
		}
		again, ok2 := auth.NormalizeEmail(got)
		if !ok2 || again != got {
			t.Fatalf("нормализация не идемпотентна: %q → %q → %q", s, got, again)
		}
	})
}

// Задача 4.6: администратор задаёт и убирает e-mail чужой записи, пользователь —
// свой; в журнале аудита адреса нет.
func TestSetEmail(t *testing.T) {
	e := newEnv(t)
	admin := e.adminCaller(t)
	ctx := context.Background()
	if err := e.svc.SetEmail(ctx, admin, userID, " ivanov@example.ru "); err != nil {
		t.Fatal(err)
	}
	if u, err := e.svc.User(ctx, userID); err != nil || u.Email != "ivanov@example.ru" {
		t.Fatalf("после задания: %+v %v", u, err)
	}
	rec := lastRecord(t, e.mem, "user.email_set")
	if rec.Actor.ID != adminID || rec.Object.ID != userID || strings.Contains(auditText(rec), "example.ru") {
		t.Fatalf("аудит: %+v", rec)
	}
	d, _ := rec.Details.(map[string]any)
	if d["self"] != false || d["cleared"] != false || d["changed"] != true {
		t.Fatalf("подробности: %v", d)
	}
	// Пользователь убирает свой адрес.
	self := admin
	self.User = e.user(userID, "ivanov", auth.RoleAnalyst)
	if err := e.svc.SetOwnEmail(ctx, self, ""); err != nil {
		t.Fatal(err)
	}
	if u, _ := e.svc.User(ctx, userID); u.Email != "" { //nolint:gosec // тест: ошибка чтения проверяется по полю адреса
		t.Fatalf("адрес не убран: %q", u.Email)
	}
	d, _ = lastRecord(t, e.mem, "user.email_set").Details.(map[string]any)
	if d["self"] != true || d["cleared"] != true {
		t.Fatalf("подробности: %v", d)
	}
	// Неверный формат и неизвестная запись.
	var ie *auth.InputError
	if err := e.svc.SetEmail(ctx, admin, userID, "не адрес"); !errors.As(err, &ie) || ie.Field != "email" {
		t.Fatalf("неверный адрес: %v", err)
	}
	if err := e.svc.SetOwnEmail(ctx, self, "a@b@c"); !errors.As(err, &ie) {
		t.Fatalf("неверный адрес в профиле: %v", err)
	}
	if err := e.svc.SetEmail(ctx, admin, "01900000-0000-7000-8000-0000000000ff", "a@example.ru"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("несуществующая запись: %v", err)
	}
}

// Нельзя менять адрес более сильной записи (УПД.2): подмена адреса позволила
// бы получать чужие отчёты.
func TestSetEmailEscalation(t *testing.T) {
	e := newEnv(t)
	analyst := e.adminCaller(t)
	analyst.User = e.user(userID, "ivanov", auth.RoleAnalyst)
	if err := e.svc.SetEmail(context.Background(), analyst, adminID, "evil@example.ru"); !errors.Is(err, auth.ErrEscalation) {
		t.Fatalf("аналитик сменил адрес администратора безопасности: %v", err)
	}
	if u, _ := e.svc.User(context.Background(), adminID); u.Email != "" { //nolint:gosec // тест: ошибка чтения проверяется по полю адреса
		t.Fatalf("адрес изменён: %q", u.Email)
	}
}

// auditText — запись аудита одной строкой для поиска значений.
func auditText(r audit.Entry) string { return fmt.Sprintf("%+v", r) }
