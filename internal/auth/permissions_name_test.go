package auth

import "testing"

// Имя разрешения — 2–3 части (events.content.read из ТЗ 5.5); то же
// ограничение — в role_permissions (миграция 0011).
func TestValidPermissionName(t *testing.T) {
	for _, s := range []string{"users.read", "events.content.read", "a_b.c_d", "x1.y2.z3", "events.retention.manage"} {
		if !validPermissionName(s) {
			t.Errorf("%q отклонено", s)
		}
	}
	for _, s := range []string{"", "users", "a.b.c.d", ".read", "users.", "users..read", "1x.read", "x.1read",
		"Users.read", "users.read-all", "users.re ad", "u.ü", "x." + string(make([]byte, 70))} {
		if validPermissionName(s) {
			t.Errorf("%q принято", s)
		}
	}
}

func FuzzValidPermissionName(f *testing.F) {
	f.Add("events.content.read")
	f.Add("a..b")
	f.Fuzz(func(t *testing.T, s string) {
		if !validPermissionName(s) {
			return
		}
		if len(s) > 64 {
			t.Fatalf("длинное имя принято: %q", s)
		}
		for i := 0; i < len(s); i++ {
			if c := s[i]; !permissionNameByte(c) && c != '.' {
				t.Fatalf("символ %q принят", c)
			}
		}
	})
}
