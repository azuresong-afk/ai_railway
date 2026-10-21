package integrity

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// signContext разделяет подписи: ключ манифеста подписывает только
// манифесты, и подпись манифеста нельзя выдать за контрольную точку аудита
// или пакет политик (у них свои контексты).
const signContext = "aisec-integrity-manifest-v1\n"

// maxSignatureFile — предел файла подписи: base64 64 байт и перевод строки.
const maxSignatureFile = 1 << 10

func signedMessage(data []byte) []byte {
	return append([]byte(signContext), data...)
}

// Sign подписывает байты манифеста и возвращает содержимое файла подписи:
// base64 подписи и перевод строки.
func Sign(s aisecCrypto.Signer, manifest []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("подпись манифеста: нет ключа")
	}
	sig, err := s.Sign(signedMessage(manifest))
	if err != nil {
		return nil, fmt.Errorf("подпись манифеста: %w", err)
	}
	out := base64.StdEncoding.AppendEncode(nil, sig)
	return append(out, '\n'), nil
}

// ErrBadSignature — подпись манифеста неверна или файл подписи испорчен.
var ErrBadSignature = errors.New("подпись манифеста неверна")

// VerifySignature проверяет подпись байтов манифеста до их разбора. Файл
// подписи — недоверенный вход (FuzzVerifySignature).
func VerifySignature(v aisecCrypto.Verifier, manifest, sigFile []byte) error {
	if v == nil {
		return errors.New("проверка манифеста: нет ключа проверки")
	}
	if len(sigFile) > maxSignatureFile {
		return ErrBadSignature
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSuffix(sigFile, []byte("\n"))))
	// Длину подписи проверяет Verifier профиля.
	if err != nil || len(sig) == 0 {
		return ErrBadSignature
	}
	if !v.Verify(signedMessage(manifest), sig) {
		return ErrBadSignature
	}
	return nil
}
