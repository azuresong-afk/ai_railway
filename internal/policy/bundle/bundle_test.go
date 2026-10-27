package bundle_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
)

func TestSealOpenRoundTrip(t *testing.T) {
	f := bundletest.New(t)
	c := f.Content(t)
	raw := f.Seal(t, c, 42)
	if bytes.Contains(raw, []byte(bundletest.Credential)) {
		t.Fatal("учётные данные в пакете открытым текстом")
	}
	b, err := f.Opener(t).Open(raw, 42)
	if err != nil {
		t.Fatal(err)
	}
	if b.Header.Version != 42 || b.Header.GatewayID != bundletest.GatewayID || b.ETag() != `"42"` || b.KeyID != f.Sealer.KeyID() {
		t.Fatalf("заголовок: %+v, %s", b.Header, b.KeyID)
	}
	if b.Secrets["llm"] != bundletest.Credential || len(b.Secrets) != 1 {
		t.Fatal("секреты не расшифрованы")
	}
	if len(b.Content.Applications) != 1 || b.Content.Applications[0].Lists[0].Category != "codename" {
		t.Fatalf("содержимое: %+v", b.Content)
	}
	if !bytes.Equal(b.Raw, raw) {
		t.Fatal("Raw — не исходные байты")
	}
	specs, err := b.Content.Specs()
	if err != nil || len(specs) != 1 || specs[0].ID != "corp" {
		t.Fatalf("Specs: %v", err)
	}
	recs, err := b.Content.KeyRecords()
	if err != nil || len(recs) != 1 || recs[0].Prefix != bundletest.KeyPrefix || recs[0].Expires.IsZero() {
		t.Fatalf("KeyRecords: %+v, %v", recs, err)
	}
	if apps := b.Content.GatewayApplications(); apps[0].PolicyMode != "enforce" || len(apps[0].Lists) != 1 {
		t.Fatalf("GatewayApplications: %+v", apps)
	}
	if ps := b.Content.GatewayProviders(); !ps[0].IsExternal() || ps[0].BaseURL != "https://llm.example/v1" {
		t.Fatalf("GatewayProviders: %+v", ps)
	}
	// Секреты не выводятся ни в fmt, ни в формате %#v.
	out := fmt.Sprintf("%v %+v %#v %s", b.Secrets, b.Secrets, b.Secrets, b.Secrets)
	if strings.Contains(out, "sk-") {
		t.Fatalf("секрет в выводе: %s", out)
	}
}

// mutate переписывает часть конверта.
func mutate(t *testing.T, raw []byte, fn func(m map[string]string)) []byte {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func flipB64(t *testing.T, s string, at int) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	b[at%len(b)] ^= 1
	return base64.StdEncoding.EncodeToString(b)
}

// TestDM42_BundleSignatureRejected — подмена пакета конфигурации (DM-42,
// ОЦЛ.3): любой изменённый байт заголовка, содержимого, секретов или подписи,
// чужой или неизвестный ключ — отказ с причиной signature до разбора
// содержимого.
func TestDM42_BundleSignatureRejected(t *testing.T) {
	f := bundletest.New(t)
	raw := f.Seal(t, f.Content(t), 7)
	o := f.Opener(t)
	cases := map[string][]byte{
		"заголовок":        mutate(t, raw, func(m map[string]string) { m["header"] = flipB64(t, m["header"], 20) }),
		"содержимое":       mutate(t, raw, func(m map[string]string) { m["content"] = flipB64(t, m["content"], 100) }),
		"секреты":          mutate(t, raw, func(m map[string]string) { m["secrets"] = flipB64(t, m["secrets"], 40) }),
		"подпись":          mutate(t, raw, func(m map[string]string) { m["signature"] = flipB64(t, m["signature"], 3) }),
		"неизвестный ключ": mutate(t, raw, func(m map[string]string) { m["key_id"] = "0000000000000000" }),
		// Части переставлены: длины в подписи не дают сдвинуть границу.
		"перестановка частей": mutate(t, raw, func(m map[string]string) { m["content"], m["secrets"] = m["secrets"], m["content"] }),
	}
	// Подменённое содержимое, подписанное чужим ключом с тем же key_id.
	evil := bundletest.New(t)
	forged := evil.Seal(t, f.Content(t), 8)
	cases["чужой ключ"] = mutate(t, forged, func(m map[string]string) { m["key_id"] = f.Sealer.KeyID() })
	for name, data := range cases {
		_, err := o.Open(data, 0)
		var re *bundle.RejectError
		if !errors.As(err, &re) || re.Reason != bundle.ReasonSignature {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Исходный пакет по-прежнему принимается.
	if _, err := o.Open(raw, 7); err != nil {
		t.Fatal(err)
	}
}

func TestBundleRollbackRejected(t *testing.T) {
	f := bundletest.New(t)
	o := f.Opener(t)
	old := f.Seal(t, f.Content(t), 10)
	if _, err := o.Open(old, 11); bundle.Reason(err) != bundle.ReasonRollback {
		t.Fatalf("откат на 10 после 11: %v", err)
	}
	if _, err := o.Open(old, 10); err != nil {
		t.Fatalf("та же версия: %v", err)
	}
}

func TestBundleOtherGatewayRejected(t *testing.T) {
	f := bundletest.New(t)
	raw := f.Seal(t, f.Content(t), 1)
	other, err := bundle.NewOpener(f.Provider, []aisecCrypto.Verifier{f.Verifier(t)}, f.Recipient, "другой-шлюз")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(raw, 0); bundle.Reason(err) != bundle.ReasonGatewayMismatch {
		t.Fatalf("чужой шлюз: %v", err)
	}
	// Тот же шлюз, но другой ключ шифрования (ключ пересоздан): секреты не
	// расшифровываются.
	r2, err := f.Provider.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	o2, err := bundle.NewOpener(f.Provider, []aisecCrypto.Verifier{f.Verifier(t)}, r2, bundletest.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o2.Open(raw, 0); bundle.Reason(err) != bundle.ReasonDecrypt {
		t.Fatalf("другой ключ шлюза: %v", err)
	}
}

// TestBundleKeyRotation — на время ротации шлюз принимает пакеты, подписанные
// любым из двух ключей.
func TestBundleKeyRotation(t *testing.T) {
	f := bundletest.New(t)
	next := bundletest.New(t)
	next.Recipient = f.Recipient
	o, err := bundle.NewOpener(f.Provider, []aisecCrypto.Verifier{f.Verifier(t), next.Verifier(t)}, f.Recipient, bundletest.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Open(f.Seal(t, f.Content(t), 1), 0); err != nil {
		t.Fatalf("старый ключ: %v", err)
	}
	if _, err := o.Open(next.Seal(t, f.Content(t), 2), 0); err != nil {
		t.Fatalf("новый ключ: %v", err)
	}
	if _, err := bundle.NewOpener(f.Provider, []aisecCrypto.Verifier{f.Verifier(t), f.Verifier(t)}, f.Recipient, bundletest.GatewayID); err == nil {
		t.Fatal("один ключ дважды принят")
	}
	three := []aisecCrypto.Verifier{f.Verifier(t), next.Verifier(t), bundletest.New(t).Verifier(t)}
	if _, err := bundle.NewOpener(f.Provider, three, f.Recipient, bundletest.GatewayID); err == nil {
		t.Fatal("три ключа приняты")
	}
}

func TestBundleFormatRejected(t *testing.T) {
	f := bundletest.New(t)
	raw := f.Seal(t, f.Content(t), 1)
	o := f.Opener(t)
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env["extra"] = "x"
	extra, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		data   []byte
		reason string
	}{
		"пусто":            {nil, bundle.ReasonFormat},
		"не JSON":          {[]byte("{"), bundle.ReasonFormat},
		"неизвестное поле": {extra, bundle.ReasonFormat},
		"данные после":     {append(bytes.Clone(raw), []byte(" {}")...), bundle.ReasonFormat},
		"формат":           {mutate(t, raw, func(m map[string]string) { m["format"] = "v2" }), bundle.ReasonFormat},
		"не base64":        {mutate(t, raw, func(m map[string]string) { m["header"] = "!!" }), bundle.ReasonFormat},
		"большой":          {make([]byte, bundle.MaxSize+1), bundle.ReasonTooLarge},
	} {
		if _, err := o.Open(c.data, 0); bundle.Reason(err) != c.reason {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// sealRaw подписывает произвольные байты содержимого: проверка содержимого
// после подписи (ключ сервера скомпрометирован не был, но сервер ошибся).
func sealRaw(t *testing.T, f *bundletest.Fixture, content []byte, secrets bundle.Secrets) []byte {
	t.Helper()
	out, err := f.Sealer.Seal(bundle.SealInput{Version: 1, IssuedAt: time.Now(), GatewayID: bundletest.GatewayID,
		Content: content, Secrets: secrets, RecipientKey: f.Recipient.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBundleContentRejected(t *testing.T) {
	f := bundletest.New(t)
	o := f.Opener(t)
	good := f.Content(t)
	enc := func(c *bundle.Content) []byte {
		b, err := c.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	clone := func(fn func(c *bundle.Content)) []byte {
		var c bundle.Content
		if err := json.Unmarshal(enc(good), &c); err != nil {
			t.Fatal(err)
		}
		fn(&c)
		return enc(&c)
	}
	cases := map[string][]byte{
		"неизвестное поле": []byte(`{"providers":[],"applications":[],"policies":[],"x":1}`),
		"нет провайдера":   clone(func(c *bundle.Content) { c.Applications[0].Provider = "nope" }),
		"нет политики":     clone(func(c *bundle.Content) { c.Applications[0].Policy = "nope" }),
		"нет policy_mode":  clone(func(c *bundle.Content) { c.Applications[0].PolicyMode = "" }),
		"http провайдер":   clone(func(c *bundle.Content) { c.Providers[0].BaseURL = "http://llm.example" }),
		"нет ca_pem":       clone(func(c *bundle.Content) { c.Providers[0].CAPEM = "" }),
		"повтор префикса": clone(func(c *bundle.Content) {
			c.Applications[0].Keys = append(c.Applications[0].Keys, c.Applications[0].Keys[0])
		}),
		"плохой sha256":     clone(func(c *bundle.Content) { c.Applications[0].Keys[0].SHA256 = "zz" }),
		"нет срока ключа":   clone(func(c *bundle.Content) { c.Applications[0].Keys[0].ExpiresAt = time.Time{} }),
		"ненормальная сеть": clone(func(c *bundle.Content) { c.Applications[0].Keys[0].AllowedCIDRs = []string{"10.0.0.1/8"} }),
		"политика-шаблон":   clone(func(c *bundle.Content) { c.Policies[0].ID = "base" }),
		"YAML с чужим id": clone(func(c *bundle.Content) {
			c.Policies[0].YAML = strings.Replace(c.Policies[0].YAML, "id: corp", "id: other", 1)
		}),
		"неверный YAML":      clone(func(c *bundle.Content) { c.Policies[0].YAML = "rules: [" }),
		"отрицательный тайм": clone(func(c *bundle.Content) { c.Providers[0].ConnectTimeout = -1 }),
		"неверный словарь":   clone(func(c *bundle.Content) { c.Applications[0].Lists[0].Category = "Плохо" }),
		"много отозванных": clone(func(c *bundle.Content) {
			k := c.Applications[0].Keys[0]
			for i := range bundle.MaxRevokedKeysPerApp + 1 {
				k.Prefix, k.Revoked = fmt.Sprintf("aisec_r%07d", i), true
				c.Applications[0].Keys = append(c.Applications[0].Keys, k)
			}
		}),
	}
	for name, content := range cases {
		if _, err := o.Open(sealRaw(t, f, content, bundle.Secrets{}), 0); bundle.Reason(err) != bundle.ReasonInvalidContent {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, s := range map[string]bundle.Secrets{
		"секрет чужого провайдера": {"other": "x"},
		"перевод строки в секрете": {"llm": "a\nb"},
		"пустой секрет":            {"llm": ""},
	} {
		if _, err := o.Open(sealRaw(t, f, enc(good), s), 0); bundle.Reason(err) != bundle.ReasonInvalidContent {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestDM38_RevokedKeyFromBundle — отозванный ключ из пакета: шлюз отвечает
// причиной revoked (по ней DM-38 поднимает оповещение), а не invalid;
// чужой секрет с тем же префиксом — invalid, отзыв по префиксу не узнать
// (Д-E2E-1). Покрывает: DM-38.
func TestDM38_RevokedKeyFromBundle(t *testing.T) {
	f := bundletest.New(t)
	c := f.Content(t)
	c.Applications[0].Keys[0].Revoked = true
	b, err := f.Opener(t).Open(f.Seal(t, c, 1), 0)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := b.Content.KeyRecords()
	if err != nil || len(recs) != 1 || !recs[0].Revoked {
		t.Fatalf("KeyRecords: %+v, %v", recs, err)
	}
	h, err := f.Provider.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.NewAuthenticator(h, recs)
	if err != nil {
		t.Fatal(err)
	}
	remote := netip.MustParseAddr("192.0.2.10")
	if id, fail := a.Authenticate(bundletest.Key, remote, time.Now()); id != nil || fail.Reason != auth.ReasonRevoked || fail.AppID != "crm" {
		t.Fatalf("отозванный ключ: %+v %+v", id, fail)
	}
	forged := bundletest.KeyPrefix + "_" + strings.Repeat("A", 43)
	if id, fail := a.Authenticate(forged, remote, time.Now()); id != nil || fail.Reason != auth.ReasonInvalid {
		t.Fatalf("чужой секрет: %+v %+v", id, fail)
	}
	// Без отозванных ключей байты содержимого прежние: поля revoked нет.
	raw, err := f.Content(t).Marshal()
	if err != nil || bytes.Contains(raw, []byte(`"revoked"`)) {
		t.Fatalf("revoked в пакете без отзыва: %s, %v", raw, err)
	}
}

func TestSealerRejects(t *testing.T) {
	f := bundletest.New(t)
	if _, err := f.Sealer.Seal(bundle.SealInput{Version: 0, GatewayID: "g", Content: []byte("{}"), RecipientKey: f.Recipient.PublicKey()}); err == nil {
		t.Error("версия 0 принята")
	}
	if _, err := f.Sealer.Seal(bundle.SealInput{Version: 1, GatewayID: "g", Content: []byte("{}"), RecipientKey: []byte("short")}); err == nil {
		t.Error("неверный ключ шлюза принят")
	}
}

// FuzzOpenBundle — пакет от сервера или с диска шлюза — недоверенный вход.
// Open не паникует; принимается только исходный пакет.
func FuzzOpenBundle(f *testing.F) {
	fx := bundletest.New(f)
	o := fx.Opener(f)
	raw := fx.Seal(f, fx.Content(f), 5)
	f.Add(raw)
	f.Add([]byte("{}"))
	f.Add([]byte(`{"format":"aisec-config-bundle/1","key_id":"","header":"","content":"","secrets":"","signature":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := o.Open(data, 0)
		if err == nil && !bytes.Equal(data, raw) {
			// Допустимы только иные записи того же конверта (пробелы, порядок полей).
			if b.Header.Version != 5 {
				t.Fatalf("принят чужой пакет версии %d", b.Header.Version)
			}
		}
		if err != nil {
			if r := bundle.Reason(err); !strings.Contains(strings.Join(bundle.Reasons, ","), r) {
				t.Fatalf("неизвестная причина %q", r)
			}
		}
	})
}

// FuzzParseContent — разбор содержимого не паникует на произвольных данных.
func FuzzParseContent(f *testing.F) {
	fx := bundletest.New(f)
	good, err := fx.Content(f).Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"providers":null}`))
	// Раздел budgets (задача 3.18).
	withBudgets := fx.Content(f)
	withBudgets.Budgets = &bundle.Budgets{Timezone: "Europe/Moscow",
		Prices: []bundle.ModelPrice{{Provider: "llm", Model: "gpt-4o", Input: 1, Output: 2}}, Hard: []bundle.HardBudget{{App: "crm", Limit: 3}}}
	wb, err := withBudgets.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wb)
	// Разделы агентов (задача 4.8).
	wa, err := withAgents(f, fx).Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wa)
	f.Add([]byte(`{"providers":[],"applications":[],"policies":[],"budgets":{"timezone":"Local","prices":null,"hard":[{"app":"x","limit":-1}]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := bundle.ParseContent(data)
		if err == nil {
			if _, err := c.Specs(); err != nil {
				t.Fatalf("проверенное содержимое: политики не разобраны: %v", err)
			}
			if _, err := c.KeyRecords(); err != nil {
				t.Fatalf("проверенное содержимое: ключи не разобраны: %v", err)
			}
		}
	})
}

// Раздел tools версии политики идёт в пакете внутри YAML (ADR-0023,
// раздел 2): шлюз получает правила вызовов и ограничения аргументов,
// а схема с незнакомым ключевым словом или нелинейным выражением
// отклоняет весь пакет. Покрывает: DM-20, DM-21.
func TestBundlePolicyToolsSection(t *testing.T) {
	f := bundletest.New(t)
	o := f.Opener(t)
	withTools := func(args string) []byte {
		c := f.Content(t)
		c.Policies[0].YAML += `tools:
  unapproved: block
  default: block
  approval_timeout: 10m
  limits: {agent_per_minute: 120, session_calls: 500, repeat: 5, repeat_window: 10m}
  rules:
    - id: read
      tool: files/read_*
      action: allow
      severity: medium
      args: ` + args + `
`
		b, err := c.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := withTools(`{type: object, properties: {path: {type: string, x-aisec-path-prefix: [/data/]}}}`)
	b, err := o.Open(sealRaw(t, f, good, bundle.Secrets{"llm": bundletest.Credential}), 0)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := b.Content.Specs()
	if err != nil {
		t.Fatal(err)
	}
	if specs[0].Tools == nil || len(specs[0].Tools.Rules) != 1 || specs[0].Tools.Rules[0].Args == nil {
		t.Fatalf("раздел tools потерян: %+v", specs[0].Tools)
	}
	for name, args := range map[string]string{
		"незнакомое слово": `{type: object, $ref: "#/x"}`,
		"обратная ссылка":  `{type: string, pattern: "(a)\\1"}`,
		"префикс у числа":  `{type: integer, x-aisec-path-prefix: [/data/]}`,
	} {
		if _, err := o.Open(sealRaw(t, f, withTools(args), bundle.Secrets{"llm": bundletest.Credential}), 0); bundle.Reason(err) != bundle.ReasonInvalidContent {
			t.Errorf("%s: %v", name, err)
		}
	}
}
