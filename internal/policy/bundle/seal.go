package bundle

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync/atomic"
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
	// TLSKey — закрытый ключ сертификата заказчика в PEM (раздел
	// gateway_tls, задача 3.27); шифруется вместе с учётными данными.
	TLSKey KeyPEM
	// MCPSecrets — учётные данные MCP-серверов по slug (раздел
	// mcp_servers, задача 4.8); шифруются вместе с остальными.
	MCPSecrets Secrets
}

// Sealer подписывает пакеты ключом сервера (bundle-signing.key, ADR-0007).
type Sealer struct {
	provider aisecCrypto.Provider
	hasher   aisecCrypto.Hasher
	signer   aisecCrypto.Signer
	keyID    string
	// trust — заявления о доверии для конверта; nil — ротаций не было.
	trust atomic.Pointer[sealTrust]
}

// sealTrust — последние заявления цепочки в base64 и номер последнего.
type sealTrust struct {
	seq   int64
	items []string
}

// SetTrust задаёт заявления о доверии, которые уходят шлюзам в каждом
// пакете: последние MaxTrustInBundle из цепочки.
func (s *Sealer) SetTrust(c *TrustChain) {
	if c == nil || c.Seq() == 0 {
		s.trust.Store(nil)
		return
	}
	t := &sealTrust{seq: c.Seq()}
	for _, raw := range c.Raw(c.Seq() - MaxTrustInBundle + 1) {
		t.items = append(t.items, encodeB64(raw))
	}
	s.trust.Store(t)
}

// TrustSeq — номер последнего заявления о доверии; 0 — ротаций не было.
func (s *Sealer) TrustSeq() int64 {
	if t := s.trust.Load(); t != nil {
		return t.seq
	}
	return 0
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
	plain, err := marshalSecrets(in.Secrets, in.MCPSecrets, in.TLSKey)
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
	env := envelope{Format: Format, KeyID: s.keyID, Header: encodeB64(header),
		Content: encodeB64(in.Content), Secrets: encodeB64(sealed), Signature: encodeB64(sig)}
	if t := s.trust.Load(); t != nil {
		env.Trust = t.items
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxSize {
		return nil, reject(ReasonTooLarge, "пакет больше %d байт", MaxSize)
	}
	return out, nil
}

// secretItem — элемент секретов: учётные данные провайдера, учётные
// данные MCP-сервера (MCP) или ключ сертификата заказчика.
type secretItem struct {
	Provider   string `json:"provider,omitempty"`
	MCP        string `json:"mcp,omitempty"`
	Credential string `json:"credential,omitempty"`
	TLSKey     string `json:"tls_key,omitempty"`
}

// marshalSecrets кодирует секреты в порядке ID провайдера, затем учётные
// данные MCP-серверов в порядке slug; ключ сертификата заказчика —
// последним элементом. Без ключа и MCP-серверов формат прежний: шлюзы
// прежних версий принимают такой пакет.
func marshalSecrets(s, mcp Secrets, tlsKey KeyPEM) ([]byte, error) {
	type item = secretItem
	items := make([]item, 0, len(s)+len(mcp)+1)
	for _, id := range slices.Sorted(maps.Keys(s)) {
		items = append(items, item{Provider: id, Credential: s[id]})
	}
	for _, id := range slices.Sorted(maps.Keys(mcp)) {
		items = append(items, item{MCP: id, Credential: mcp[id]})
	}
	if len(tlsKey) > 0 {
		items = append(items, item{TLSKey: string(tlsKey)})
	}
	return json.Marshal(items)
}
