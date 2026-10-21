// Пакет bundletest — подписанные пакеты конфигурации для тестов шлюза и
// сервера: ключ подписи, ключ шлюза и пример содержимого. Только для
// *_test.go (depguard test-doubles).
package bundletest

import (
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// GatewayID — ID шлюза в примерах (CN сертификата).
const GatewayID = "0192a000-0000-7000-8000-000000000001"

// Credential — синтетические учётные данные провайдера «llm».
const Credential = "sk-synthetic-test-credential-0001"

// Key — ключ приложения «crm» (SHA-256 из KeyHash): синтетический.
const (
	Key       = "aisec_abcd1234_c3ludGhldGljLWtleS1mb3ItdGVzdHMtb25seS0wMDA"
	KeyPrefix = "aisec_abcd1234"
)

// Fixture — ключи подписи и шлюза для одного теста.
type Fixture struct {
	Provider  aisecCrypto.Provider
	Signer    aisecCrypto.Signer
	Recipient aisecCrypto.Recipient
	Sealer    *bundle.Sealer
}

// New создаёт ключи профиля standard.
func New(t testing.TB) *Fixture {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := bundle.NewSealer(p, s)
	if err != nil {
		t.Fatal(err)
	}
	return &Fixture{Provider: p, Signer: s, Recipient: r, Sealer: sealer}
}

// Verifier — ключ проверки подписи фикстуры.
func (f *Fixture) Verifier(t testing.TB) aisecCrypto.Verifier {
	t.Helper()
	v, err := f.Provider.NewVerifier(f.Signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Opener — проверка пакетов для GatewayID.
func (f *Fixture) Opener(t testing.TB) *bundle.Opener {
	t.Helper()
	o, err := bundle.NewOpener(f.Provider, []aisecCrypto.Verifier{f.Verifier(t)}, f.Recipient, GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// KeyHash — SHA-256 ключа Key в hex.
func (f *Fixture) KeyHash(t testing.TB) string {
	t.Helper()
	h, err := f.Provider.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return auth.HashAppKey(h, Key)
}

// CAPEM — заглушка корневых сертификатов: содержимое пакета проверяет
// только наличие, разбор — шлюз при создании провайдера.
const CAPEM = "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"

// Content — пример содержимого: провайдер llm, политика corp (копия
// «Базовой защиты» с правилом на словарь lists.codename) и приложение crm
// со словарём codename и ключом Key.
func (f *Fixture) Content(t testing.TB) *bundle.Content {
	t.Helper()
	spec, ok := policy.Template(policy.TemplateBase)
	if !ok {
		t.Fatal("нет шаблона base")
	}
	spec.ID, spec.Name = "corp", "Корпоративная"
	spec.Rules = append(spec.Rules, policy.RuleSpec{ID: "codename", Detector: "lists", Categories: []string{"lists.codename"},
		Action: policy.Block, Severity: policy.High})
	y, err := policy.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return &bundle.Content{
		Providers: []bundle.Provider{{ID: "llm", Type: "openai", BaseURL: "https://llm.example/v1", CAPEM: CAPEM, External: true}},
		Policies:  []bundle.Policy{{ID: "corp", Version: 3, YAML: string(y)}},
		Applications: []bundle.Application{{
			ID: "crm", Env: "prod", Provider: "llm", Models: []string{"gpt-4o"}, Policy: "corp", PolicyMode: "enforce",
			FailMode: "fail_closed", Storage: "masked", UserFrom: "none",
			Lists: []bundle.List{{ID: "projects", Category: "codename", Words: []string{"проект зенит"}}},
			Keys:  []bundle.Key{{Prefix: KeyPrefix, SHA256: f.KeyHash(t), ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)}},
		}},
	}
}

// Seal подписывает содержимое c версией version для GatewayID.
func (f *Fixture) Seal(t testing.TB, c *bundle.Content, version int64) []byte {
	t.Helper()
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.Sealer.Seal(bundle.SealInput{Version: version, IssuedAt: time.Now(), GatewayID: GatewayID,
		Content: b, Secrets: bundle.Secrets{"llm": Credential}, RecipientKey: f.Recipient.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
