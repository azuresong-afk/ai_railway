package bundle

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Opener проверяет и разбирает пакеты на шлюзе.
type Opener struct {
	hasher aisecCrypto.Hasher
	// verifiers — ключи проверки по KeyID: до двух на время ротации.
	verifiers map[string]aisecCrypto.Verifier
	recipient aisecCrypto.Recipient
	gatewayID string
	// trust — цепочка заявлений о доверии от тех же ключей (ADR-0018,
	// п. 4.4); nil — пакеты проверяются только ключами verifiers.
	trust *TrustChain
	clock func() time.Time
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
	o := &Opener{hasher: h, verifiers: map[string]aisecCrypto.Verifier{}, recipient: recipient, gatewayID: gatewayID,
		clock: time.Now}
	for _, v := range verifiers {
		id := KeyID(h, v.PublicKey())
		if _, dup := o.verifiers[id]; dup {
			return nil, errors.New("пакет: один и тот же ключ проверки указан дважды")
		}
		o.verifiers[id] = v
	}
	return o, nil
}

// SetTrust подключает цепочку заявлений о доверии, построенную от тех же
// ключей-якорей; clock — часы шлюза для сроков перекрытия (nil — time.Now).
func (o *Opener) SetTrust(c *TrustChain, clock func() time.Time) {
	o.trust = c
	if clock != nil {
		o.clock = clock
	}
}

// TrustSeq — номер последнего принятого заявления о доверии.
func (o *Opener) TrustSeq() int64 {
	if o.trust == nil {
		return 0
	}
	return o.trust.Seq()
}

// TrustRaw — все принятые заявления по порядку: их шлюз сохраняет в
// trust.json.
func (o *Opener) TrustRaw() [][]byte {
	if o.trust == nil {
		return nil
	}
	return o.trust.Raw(1)
}

// TrustRoots — корни УЦ с неистёкшим перекрытием: по ним шлюз проверяет
// перевыпущенный сертификат (ADR-0018, п. 6.3).
func (o *Opener) TrustRoots() [][]byte {
	if o.trust == nil {
		return nil
	}
	return o.trust.ValidRoots(o.clock())
}

// KeyIDs — идентификаторы ключей проверки по возрастанию: шлюз сообщает
// их в heartbeat для сверки с ключом подписи сервера (В19 ревью 2.r4).
func (o *Opener) KeyIDs() []string {
	out := make([]string, 0, len(o.verifiers))
	for id := range o.verifiers {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// Bundle — проверенный пакет.
type Bundle struct {
	Header  Header
	KeyID   string
	Content *Content
	// Secrets — расшифрованные учётные данные; вызывающий затирает их
	// после создания провайдеров (Secrets.Clear).
	Secrets Secrets
	// TLSKey — закрытый ключ сертификата заказчика (раздел gateway_tls) в
	// PEM; nil — раздела нет. Вызывающий затирает его после применения.
	TLSKey KeyPEM
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
	verifiers := o.verifiers
	if o.trust != nil {
		// Заявления принимаются до проверки подписи пакета: ими приходит
		// новый ключ. Подменённое заявление — отказ всего пакета.
		if len(env.Trust) > MaxTrustInBundle {
			return nil, reject(ReasonFormat, "больше %d заявлений о доверии", MaxTrustInBundle)
		}
		for _, item := range env.Trust {
			raw, err := decodeB64(item, MaxTrustStatement)
			if err != nil {
				return nil, reject(ReasonFormat, "заявление о доверии: %v", err)
			}
			if _, err := o.trust.Append(raw); err != nil {
				return nil, reject(ReasonSignature, "%v", err)
			}
		}
		verifiers = o.trust.Verifiers(o.clock())
	} else if len(env.Trust) > 0 {
		return nil, reject(ReasonFormat, "заявления о доверии не ожидаются")
	}
	v, ok := verifiers[env.KeyID]
	if !ok {
		return nil, reject(ReasonSignature, "пакет подписан неизвестным ключом или ключом с истёкшим перекрытием")
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
	secrets, tlsKey, err := parseSecrets(plain, c)
	clear(plain)
	if err != nil {
		return nil, reject(ReasonInvalidContent, "секреты: %v", err)
	}
	return &Bundle{Header: h, KeyID: env.KeyID, Content: c, Secrets: secrets, TLSKey: tlsKey, Raw: data}, nil
}

// parseSecrets — секреты только для провайдеров из содержимого, видимый
// ASCII (уходят в заголовок Authorization), не длиннее MaxCredential, и
// ключ сертификата заказчика — ровно тогда, когда в содержимом есть
// раздел gateway_tls.
func parseSecrets(plain []byte, c *Content) (Secrets, KeyPEM, error) {
	var items []secretItem
	if err := decodeStrict(plain, &items); err != nil {
		return nil, nil, errors.New("неверный формат")
	}
	known := map[string]bool{}
	for _, p := range c.Providers {
		known[p.ID] = true
	}
	out := Secrets{}
	var tlsKey KeyPEM
	for _, it := range items {
		if it.TLSKey != "" {
			switch {
			case it.Provider != "" || it.Credential != "":
				return nil, nil, errors.New("ключ сертификата вместе с учётными данными провайдера")
			case tlsKey != nil:
				return nil, nil, errors.New("ключ сертификата заказчика указан дважды")
			case c.GatewayTLS == nil:
				return nil, nil, errors.New("ключ сертификата без раздела gateway_tls")
			}
			if err := checkTLSKey(it.TLSKey); err != nil {
				return nil, nil, err
			}
			tlsKey = KeyPEM(it.TLSKey)
			continue
		}
		if !known[it.Provider] {
			return nil, nil, errors.New("секрет для провайдера, которого нет в пакете")
		}
		if _, dup := out[it.Provider]; dup {
			return nil, nil, errors.New("секрет провайдера указан дважды")
		}
		if err := checkCredential(it.Credential); err != nil {
			return nil, nil, err
		}
		out[it.Provider] = it.Credential
	}
	if c.GatewayTLS != nil && tlsKey == nil {
		return nil, nil, errors.New("раздел gateway_tls без ключа сертификата")
	}
	return out, tlsKey, nil
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
