package bundle

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// SealInput — данные для подписи пакета одному шлюзу.
type SealInput struct {
	Version  int64
	IssuedAt time.Time
	// GatewayID — CN сертификата шлюза, который запросил пакет.
	GatewayID string
	// Content — байты содержимого (Content.Marshal), уже проверенные сборщиком.
	Content []byte
	// Secrets — учётные данные провайдеров; шифруются для RecipientKey.
	Secrets Secrets
	// RecipientKey — открытый ключ шлюза из запроса (заголовок AISec-Bundle-Key).
	RecipientKey []byte
}

// Sealer подписывает пакеты ключом сервера (bundle-signing.key, ADR-0007).
type Sealer struct {
	provider aisecCrypto.Provider
	hasher   aisecCrypto.Hasher
	signer   aisecCrypto.Signer
	keyID    string
}

// NewSealer создаёт подписывающего пакеты.
func NewSealer(p aisecCrypto.Provider, signer aisecCrypto.Signer) (*Sealer, error) {
	if p == nil || signer == nil {
		return nil, errors.New("пакет: не заданы криптопрофиль или ключ подписи")
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	return &Sealer{provider: p, hasher: h, signer: signer, keyID: KeyID(h, signer.PublicKey())}, nil
}

// KeyID — идентификатор ключа подписи.
func (s *Sealer) KeyID() string { return s.keyID }

// ContentHash — хеш содержимого (hex) и имя алгоритма.
func (s *Sealer) ContentHash(content []byte) (string, string) {
	return hex.EncodeToString(s.hasher.Sum(content)), s.hasher.Name()
}

// Seal собирает и подписывает пакет. Учётные данные шифруются для ключа
// шлюза; открытым текстом они не попадают в результат.
func (s *Sealer) Seal(in SealInput) ([]byte, error) {
	if in.Version < 1 || in.GatewayID == "" || len(in.Content) == 0 {
		return nil, errors.New("пакет: нет версии, шлюза или содержимого")
	}
	hash, alg := s.ContentHash(in.Content)
	h := Header{Format: Format, Version: in.Version, IssuedAt: in.IssuedAt.UTC(), GatewayID: in.GatewayID,
		ContentHash: hash, HashAlg: alg}
	header, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	plain, err := marshalSecrets(in.Secrets)
	if err != nil {
		return nil, err
	}
	sealed, err := s.provider.SealTo(in.RecipientKey, secretsInfo(h), plain)
	clear(plain)
	if err != nil {
		return nil, fmt.Errorf("пакет: шифрование секретов: %w", err)
	}
	sig, err := s.signer.Sign(signedMessage(header, in.Content, sealed))
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(envelope{Format: Format, KeyID: s.keyID, Header: encodeB64(header),
		Content: encodeB64(in.Content), Secrets: encodeB64(sealed), Signature: encodeB64(sig)})
	if err != nil {
		return nil, err
	}
	if len(out) > MaxSize {
		return nil, reject(ReasonTooLarge, "пакет больше %d байт", MaxSize)
	}
	return out, nil
}

// marshalSecrets кодирует секреты в порядке ID провайдера.
func marshalSecrets(s Secrets) ([]byte, error) {
	type item struct {
		Provider   string `json:"provider"`
		Credential string `json:"credential"`
	}
	ids := make([]string, 0, len(s))
	for id := range s {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	items := make([]item, 0, len(ids))
	for _, id := range ids {
		items = append(items, item{Provider: id, Credential: s[id]})
	}
	return json.Marshal(items)
}
