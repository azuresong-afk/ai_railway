module example.com/lintsample

go 1.27.0

require (
	github.com/Azure/go-ntlmssp v0.0.0
	github.com/go-asn1-ber/asn1-ber v0.0.0
	github.com/go-ldap/ldap/v3 v3.0.0
	github.com/google/uuid v0.0.0
	github.com/yalue/onnxruntime_go v0.0.0
	golang.org/x/crypto v0.0.0
)

// Заглушка вместо настоящего модуля: образец собирается без сети.
replace golang.org/x/crypto => ./stub/xcrypto

replace github.com/go-ldap/ldap/v3 => ./stub/goldap

replace github.com/go-asn1-ber/asn1-ber => ./stub/asn1ber

replace github.com/google/uuid => ./stub/uuid

replace github.com/Azure/go-ntlmssp => ./stub/ntlmssp

replace github.com/yalue/onnxruntime_go => ./stub/onnxruntime
