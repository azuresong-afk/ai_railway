package bad

import goldap "github.com/go-ldap/ldap/v3" // want:depguard

// UseLDAP — библиотека LDAP вне internal/auth/ldap запрещена.
func UseLDAP(l *goldap.Conn) error { return l.Bind("cn=svc", "pw") }
