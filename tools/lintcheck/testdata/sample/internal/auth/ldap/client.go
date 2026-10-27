// Пакет ldap образца: здесь библиотека LDAP разрешена, но не NTLM,
// DIGEST-MD5, анонимный bind, свои соединения библиотеки и отладка.
package ldap

import (
	ber "github.com/go-asn1-ber/asn1-ber" // clean:depguard
	goldap "github.com/go-ldap/ldap/v3"   // clean:depguard
)

// Use вызывает разрешённое и запрещённое.
func Use(l *goldap.Conn) {
	ber.MaxPacketLengthBytes = 1
	_ = l.Bind("cn=svc", "pw")        // clean:forbidigo
	_ = l.NTLMBind("d", "u", "p")     // want:forbidigo
	_ = l.MD5Bind("h", "u", "p")      // want:forbidigo
	_ = l.UnauthenticatedBind("u")    // want:forbidigo
	_, _ = goldap.DialURL("ldap://h") // want:forbidigo
	goldap.Logger(nil)                // want:forbidigo
	l.Debug = true                    // want:forbidigo
}
