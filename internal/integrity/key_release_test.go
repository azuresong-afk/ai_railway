//go:build aisec_release

package integrity

import (
	"bytes"
	"testing"
)

// Н35 ревью 2.r4: в поставочную сборку встроен не тестовый ключ.
func TestReleaseKeyIsNotTestKey(t *testing.T) {
	if embeddedTestKey {
		t.Fatal("поставочная сборка помечена как тестовая")
	}
	if bytes.Equal(bytes.TrimSpace(embeddedKeyPEM), bytes.TrimSpace(testKeyPEM)) {
		t.Fatal("keys/manifest.pub совпадает с manifest-test.pub")
	}
	if _, _, err := EmbeddedVerifier(provider(t)); err != nil {
		t.Fatal(err)
	}
}
