package auth

import "strings"

// Проверки объектов, которые попадают в БД не через API, а из резервной
// копии (В22 ревью 2.r4): те же правила, что при создании через API.
// Копия от другого выпуска не должна внести роль или токен, которые API
// не создал бы.

// CheckStoredRole проверяет свою роль: название, описание, разрешения по
// каталогу, область own — только у Ownable; признак второго фактора не
// слабее того, что вывел бы API.
func CheckStoredRole(displayName, description string, mfaRequired bool, perms []GrantInput) error {
	def, err := parseRole(RoleInput{DisplayName: displayName, Description: description, MFARequired: mfaRequired,
		Permissions: perms})
	if err != nil {
		return err
	}
	if def.MFARequired && !mfaRequired {
		return &InputError{"mfa_required", "Роль с правом на изменение требует второй фактор."}
	}
	return nil
}

// CheckStoredTokenGrants проверяет область токена API в виде столбца
// permissions («разрешение:область») по правилам выпуска: только
// TokenGrantable (решение по задаче 2.10), область own — только у Ownable.
func CheckStoredTokenGrants(perms []string) error {
	in := make([]GrantInput, 0, len(perms))
	for _, e := range perms {
		perm, scope, ok := strings.Cut(e, ":")
		if !ok {
			return &InputError{"permissions", patPermsRule + "запись «разрешение:область»."}
		}
		in = append(in, GrantInput{Permission: perm, Scope: scope})
	}
	_, err := parseAPITokenGrants(in)
	return err
}
