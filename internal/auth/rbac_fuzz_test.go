package auth

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// roleIDPattern — тот же шаблон, что CHECK в миграции 0009_rbac.
var roleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,47}$`)

// Разбор своей роли из запроса: без паники; принятая роль содержит только
// разрешения каталога с допустимой областью, а ID — только по шаблону БД.
func FuzzParseRole(f *testing.F) {
	f.Add("helpdesk", "Служба", "", "users.read", "", "users.manage", "all")
	f.Add("x", "\u202e", "описание", "nope.read", "own", "self", "")
	f.Add("ab_1", " ", "\x00", "users.read", "users.read", "roles.manage", "none")
	f.Fuzz(func(t *testing.T, id, name, desc, p1, s1, p2, s2 string) {
		if Role(id).Valid() != roleIDPattern.MatchString(id) {
			t.Fatalf("Role.Valid(%q) расходится с CHECK миграции", id)
		}
		r, err := parseRole(RoleInput{ID: id, DisplayName: name, Description: desc,
			Permissions: []GrantInput{{Permission: p1, Scope: s1}, {Permission: p2, Scope: s2}}})
		if err != nil {
			return
		}
		if !utf8.ValidString(r.DisplayName) || r.DisplayName == "" || utf8.RuneCountInString(r.Description) > MaxRoleDescriptionLen {
			t.Fatalf("принято недопустимое имя или описание: %+v", r)
		}
		for p, s := range r.Grants {
			perm, ok := LookupPermission(p)
			if !ok || s == ScopeNone || (s == ScopeOwn && !perm.Ownable) {
				t.Fatalf("принято разрешение %q с областью %v", p, s)
			}
			if !perm.ReadOnly() && !r.MFARequired {
				t.Fatalf("роль с %q без обязательного второго фактора", p)
			}
		}
	})
}

// apiTokenPattern — тот же шаблон префикса, что CHECK в миграции 0012_api_tokens.
var apiTokenPattern = regexp.MustCompile(`^aisec_pat_[a-z0-9]{8}$`)

// Разбор предъявленного токена API: без паники; принятый токен — каноничная
// запись ровно 32 байт секрета, префикс проходит CHECK миграции и не
// принимается вместо ключа приложения.
func FuzzParseAPIToken(f *testing.F) {
	f.Add("aisec_pat_abcd1234_" + strings.Repeat("A", 43))
	f.Add("aisec_pat_abcd1234_" + strings.Repeat("A", 42) + "B")
	f.Add("aisec_abcd1234_" + strings.Repeat("A", 43))
	f.Add("Bearer aisec_pat_abcd1234_")
	f.Fuzz(func(t *testing.T, s string) {
		prefix, err := ParseAPIToken(s)
		if err != nil {
			if prefix != "" {
				t.Fatalf("префикс при ошибке: %q", prefix)
			}
			return
		}
		if !apiTokenPattern.MatchString(prefix) || !strings.HasPrefix(s, prefix+"_") {
			t.Fatalf("префикс %q из %q", prefix, s)
		}
		b, err := base64.RawURLEncoding.Strict().DecodeString(s[len(prefix)+1:])
		if err != nil || len(b) != tokenBytes || base64.RawURLEncoding.EncodeToString(b) != s[len(prefix)+1:] {
			t.Fatalf("принят неканоничный секрет: %q", s)
		}
		if _, err := ParseAppKey(s); err == nil {
			t.Fatalf("строка принята и как токен, и как ключ приложения: %q", s)
		}
	})
}
