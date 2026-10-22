package auth

import "testing"

// В22 ревью 2.r4: роль и токен из резервной копии проверяются правилами API.
func TestCheckStoredRole(t *testing.T) {
	ok := []GrantInput{{Permission: PermUsersRead}, {Permission: PermAuditVerify, Scope: "all"}}
	if err := CheckStoredRole("Дежурный", "", true, ok); err != nil {
		t.Fatal(err)
	}
	if err := CheckStoredRole("Читатель", "", false, []GrantInput{{Permission: PermUsersRead}}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		mfa   bool
		perms []GrantInput
	}{
		"неизвестное разрешение":         {true, []GrantInput{{Permission: "pii.renamed"}}},
		"неизвестная область":            {true, []GrantInput{{Permission: PermUsersRead, Scope: "some"}}},
		"own у неделимого":               {true, []GrantInput{{Permission: PermUsersRead, Scope: "own"}}},
		"повтор":                         {true, []GrantInput{{Permission: PermUsersRead}, {Permission: PermUsersRead}}},
		"право на изменение без фактора": {false, []GrantInput{{Permission: PermUsersManage}}},
	} {
		if err := CheckStoredRole("Роль", "", c.mfa, c.perms); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if err := CheckStoredRole("", "", true, ok); err == nil {
		t.Error("пустое название принято")
	}
}

func TestCheckStoredTokenGrants(t *testing.T) {
	if err := CheckStoredTokenGrants([]string{"users.read:all", "audit.verify:all"}); err != nil {
		t.Fatal(err)
	}
	for _, perms := range [][]string{
		nil,
		{"users.manage:all"},      // функция безопасности (решение 2.10)
		{"api_tokens.manage:own"}, // токен не выпускает токены
		{"users.read"},            // без области
		{"users.read:own"},        // own только у Ownable
		{"pii.renamed:all"},
		{"users.read:all", "users.read:all"},
	} {
		if err := CheckStoredTokenGrants(perms); err == nil {
			t.Errorf("%v: принято", perms)
		}
	}
}
