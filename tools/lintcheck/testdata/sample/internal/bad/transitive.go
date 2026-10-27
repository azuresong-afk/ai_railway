package bad

import (
	"github.com/Azure/go-ntlmssp" // want:depguard
	"github.com/google/uuid"      // want:depguard
)

// UseTransitive — модули, попавшие в vendor только транзитивно, коду продукта запрещены.
func UseTransitive() string {
	_, _ = ntlmssp.NewNegotiateMessage("", "")
	return uuid.New()
}
