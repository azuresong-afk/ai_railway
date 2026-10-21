package bundle

import (
	"encoding/hex"
	"errors"
	"fmt"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Opener проверяет и разбирает пакеты на шлюзе.
type Opener struct {
	hasher aisecCrypto.Hasher
	// verifiers — ключи проверки по KeyID: до двух на время ротации.
	verifiers map[string]aisecCrypto.Verifier
	recipient aisecCrypto.Recipient
	gatewayID string
}

// MaxVerifiers — ключей проверки одновременно: действующий и новый на
// время ротации ключа подписи.
const MaxVerifiers = 2

// NewOpener — проверка пакетов шлюза gatewayID (CN его сертификата) ключами
// verifiers; recipient расшифровывает секреты.
func NewOpener(p aisecCrypto.Provider, verifiers []aisecCrypto.Verifier, recipient aisecCrypto.Recipient, gatewayID string) (*Opener, error) {
	if p == nil || recipient == nil || gatewayID == "" {
		return nil, errors.New("пакет: не заданы криптопрофиль, ключ шлюза или ID шлюза")
	}
	if len(verifiers) == 0 || len(verifiers) > MaxVerifiers {
		return nil, fmt.Errorf("пакет: нужно от 1 до %d ключей проверки подписи", MaxVerifiers)
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	o := &Opener{hasher: h, verifiers: map[string]aisecCrypto.Verifier{}, recipient: recipient, gatewayID: gatewayID}
	for _, v := range verifiers {
		id := KeyID(h, v.PublicKey())
		if _, dup := o.verifiers[id]; dup {
			return nil, errors.New("пакет: один и тот же ключ проверки указан дважды")
		}
		o.verifiers[id] = v
	}
	return o, nil
}

// Bundle — проверенный пакет.
type Bundle struct {
	Header  Header
	KeyID   string
	Content *Content
	// Secrets — расшифрованные учётные данные; вызывающий затирает их
	// после создания провайдеров (Secrets.Clear).
	Secrets Secrets
	// Raw — пакет как получен: его шлюз сохраняет на диск.
	Raw []byte
}

// ETag — ETag версии пакета.
func (b *Bundle) ETag() string { return ETag(b.Header.Version) }

// Open проверяет пакет в порядке: размер, строгий разбор конверта, ключ,
// подпись, заголовок (формат, шлюз, версия не меньше minVersion), хеш, и
// только затем строгий разбор содержимого и расшифрование секретов. Любой
// отказ — RejectError с причиной.
func (o *Opener) Open(data []byte, minVersion int64) (*Bundle, error) {
	if len(data) > MaxSize {
		return nil, reject(ReasonTooLarge, "пакет больше %d байт", MaxSize)
	}
	var env envelope
	if err := decodeStrict(data, &env); err != nil {
		return nil, reject(ReasonFormat, "конверт: %v", err)
	}
	if env.Format != Format {
		return nil, reject(ReasonFormat, "неизвестный формат")
	}
	v, ok := o.verifiers[env.KeyID]
	if !ok {
		return nil, reject(ReasonSignature, "пакет подписан неизвестным ключом")
	}
	header, err := decodeB64(env.Header, maxHeader)
	if err != nil {
		return nil, reject(ReasonFormat, "заголовок: %v", err)
	}
	content, err := decodeB64(env.Content, MaxSize)
	if err != nil {
		return nil, reject(ReasonFormat, "содержимое: %v", err)
	}
	sealed, err := decodeB64(env.Secrets, MaxSize)
	if err != nil {
		return nil, reject(ReasonFormat, "секреты: %v", err)
	}
	sig, err := decodeB64(env.Signature, aisecCrypto.SignatureSize)
	if err != nil {
		return nil, reject(ReasonFormat, "подпись: %v", err)
	}
	if !v.Verify(signedMessage(header, content, sealed), sig) {
		return nil, reject(ReasonSignature, "подпись не сходится")
	}
	// Подпись верна: дальше разбираются данные сервера, но строго.
	var h Header
	if err := decodeStrict(header, &h); err != nil {
		return nil, reject(ReasonFormat, "заголовок: %v", err)
	}
	switch {
	case h.Format != Format || h.Version < 1:
		return nil, reject(ReasonFormat, "заголовок: формат или версия")
	case h.GatewayID != o.gatewayID:
		return nil, reject(ReasonGatewayMismatch, "пакет собран для другого шлюза")
	case h.Version < minVersion:
		return nil, reject(ReasonRollback, "версия %d меньше применённой %d", h.Version, minVersion)
	case h.HashAlg != o.hasher.Name() || h.ContentHash != hex.EncodeToString(o.hasher.Sum(content)):
		return nil, reject(ReasonFormat, "хеш содержимого не совпадает с заголовком")
	}
	c, err := ParseContent(content)
	if err != nil {
		return nil, reject(ReasonInvalidContent, "%v", err)
	}
	plain, err := o.recipient.Open(sealed, secretsInfo(h))
	if err != nil {
		return nil, reject(ReasonDecrypt, "секреты не расшифрованы ключом этого шлюза")
	}
	secrets, err := parseSecrets(plain, c)
	clear(plain)
	if err != nil {
		return nil, reject(ReasonInvalidContent, "секреты: %v", err)
	}
	return &Bundle{Header: h, KeyID: env.KeyID, Content: c, Secrets: secrets, Raw: data}, nil
}

// parseSecrets — секреты только для провайдеров из содержимого, видимый
// ASCII (уходят в заголовок Authorization), не длиннее MaxCredential.
func parseSecrets(plain []byte, c *Content) (Secrets, error) {
	var items []struct {
		Provider   string `json:"provider"`
		Credential string `json:"credential"`
	}
	if err := decodeStrict(plain, &items); err != nil {
		return nil, errors.New("неверный формат")
	}
	known := map[string]bool{}
	for _, p := range c.Providers {
		known[p.ID] = true
	}
	out := Secrets{}
	for _, it := range items {
		if !known[it.Provider] {
			return nil, errors.New("секрет для провайдера, которого нет в пакете")
		}
		if _, dup := out[it.Provider]; dup {
			return nil, errors.New("секрет провайдера указан дважды")
		}
		if err := checkCredential(it.Credential); err != nil {
			return nil, err
		}
		out[it.Provider] = it.Credential
	}
	return out, nil
}

// checkCredential — те же правила, что при сохранении в сервере (2.11).
func checkCredential(s string) error {
	if s == "" || len(s) > MaxCredential {
		return fmt.Errorf("учётные данные — от 1 байта до %d байт", MaxCredential)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return errors.New("учётные данные — только видимые символы ASCII")
		}
	}
	return nil
}
