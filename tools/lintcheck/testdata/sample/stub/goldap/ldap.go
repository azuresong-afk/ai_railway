// Пакет ldap — заглушка github.com/go-ldap/ldap/v3 для образца lintcheck:
// только имена, на которые действуют запреты.
package ldap

import "log"

// Conn — соединение.
type Conn struct{ Debug bool }

// Bind — simple bind.
func (l *Conn) Bind(dn, pw string) error { return nil }

// NTLMBind — bind NTLM.
func (l *Conn) NTLMBind(domain, user, pw string) error { return nil }

// MD5Bind — bind DIGEST-MD5.
func (l *Conn) MD5Bind(host, user, pw string) error { return nil }

// UnauthenticatedBind — bind без пароля.
func (l *Conn) UnauthenticatedBind(user string) error { return nil }

// DialURL — соединение по адресу.
func DialURL(addr string) (*Conn, error) { return &Conn{}, nil }

// Logger — журнал отладки.
func Logger(l *log.Logger) {}
