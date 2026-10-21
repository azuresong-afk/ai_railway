package authtest

import (
	"context"
	"errors"
	"strings"
	"sync"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Hasher — быстрая замена Argon2id для тестов: «хеш» — пароль с префиксом.
// Считает вызовы Verify и запоминает проверенные хеши, чтобы
// тест мог убедиться, что пароль проверялся и при неизвестном логине.
type Hasher struct {
	mu       sync.Mutex
	verified []string
	// Stale — хеши с этим префиксом Verify отмечает как устаревшие (needsRehash).
	Stale string
	// OnVerify — если задан, вызывается после каждой проверки: тест меняет
	// состояние хранилища, пока «идёт» хеширование.
	OnVerify func()
}

const fakePrefix = "$fake$"

var _ aisecCrypto.PasswordHasher = (*Hasher)(nil)

// Name — имя алгоритма.
func (*Hasher) Name() string { return "fake" }

// Hash возвращает «хеш» пароля.
func (*Hasher) Hash(_ context.Context, password []byte) (string, error) {
	return fakePrefix + string(password), nil
}

// Verify сравнивает пароль с «хешем».
func (h *Hasher) Verify(_ context.Context, password []byte, encoded string) (bool, bool, error) {
	h.mu.Lock()
	h.verified = append(h.verified, encoded)
	hook := h.OnVerify
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
	rest, ok := strings.CutPrefix(encoded, fakePrefix)
	if !ok {
		return false, false, errors.New("authtest: неизвестный формат хеша")
	}
	match := aisecCrypto.Equal([]byte(rest), password)
	return match, match && h.Stale != "" && strings.HasPrefix(encoded, h.Stale), nil
}

// Verified — хеши, с которыми вызывался Verify, по порядку.
func (h *Hasher) Verified() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.verified...)
}

// HashOf — «хеш» пароля без учёта вызова (подготовка теста).
func HashOf(password string) string { return fakePrefix + password }
