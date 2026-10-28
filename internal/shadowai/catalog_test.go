package shadowai

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

const (
	testCatalogSource = "catalog/catalog.yaml"
	testCatalogSigned = "../../testdata/shadowai/catalog-test.aisecdb"
	testSubkey        = "../../testdata/shadowai/subkey-test.signkey"
	testEndorsement   = "../../testdata/shadowai/subkey-test.endorsement"
	testVendorKey     = "../../testdata/integrity/manifest-test.signkey"
)

// testNow — внутри срока тестового заверения (01.10.2026 — 30.09.2031).
var testNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: фикстура теста из репозитория
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func provider(t testing.TB) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func sourceCatalog(t testing.TB) *Catalog {
	t.Helper()
	c, err := ParseCatalog(readFile(t, testCatalogSource))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// DM-37: имя узла из журнала прокси сопоставляется с сервисом каталога —
// точное имя, затем самый длинный суффикс по меткам; общие домены
// компаний и адреса IP не сопоставляются.
// Покрывает: DM-37
func TestDM37_CatalogMatch(t *testing.T) {
	c := sourceCatalog(t)
	for raw, want := range map[string]string{
		"chatgpt.com":                       "chatgpt",
		"CHAT.OpenAI.com.":                  "chatgpt",
		"chat.openai.com:443":               "chatgpt",
		"api.openai.com":                    "openai-api",
		"platform.openai.com":               "openai-api",
		"cdn.oaistatic.com":                 "chatgpt",
		"my-res.openai.azure.com":           "azure-openai",
		"claude.ai":                         "claude",
		"api.anthropic.com":                 "anthropic-api",
		"gemini.google.com":                 "gemini",
		"generativelanguage.googleapis.com": "google-ai-api",
		"giga.chat":                         "gigachat",
		"gigachat.devices.sberbank.ru":      "gigachat",
		"llm.api.cloud.yandex.net":          "yandexgpt-alice",
		"alice.yandex.ru":                   "yandexgpt-alice",
		"chat.deepseek.com":                 "deepseek",
		"www.perplexity.ai":                 "perplexity",
		"api.x.ai":                          "grok",
		"huggingface.co":                    "huggingface",
		"copilot.microsoft.com":             "microsoft-copilot",
		"api.githubcopilot.com":             "github-copilot",
		"chat.qwen.ai":                      "qwen",
		"fusionbrain.ai":                    "kandinsky",
		"":                                  "", "google.com": "", "www.google.com": "", "yandex.ru": "", "mail.yandex.ru": "", "sber.ru": "",
		"microsoft.com": "", "openai.com.evil.example.com": "", "notchatgpt.com": "", "chatgpt.com.example.ru": "",
		"203.0.113.10": "", "[2001:db8::1]:443": "", "2001:db8::1": "", "чат.рф": "", "xn--80aswg.xn--p1ai": "",
	} {
		host, ok := NormalizeHost(raw)
		got := ""
		if ok {
			if s, found := c.Match(host); found {
				got = s.ID
			}
		}
		if got != want {
			t.Errorf("%q: сервис %q, ожидался %q", raw, got, want)
		}
	}
}

func TestCatalogSource(t *testing.T) {
	c := sourceCatalog(t)
	if c.Version != 1 || c.Date != "2026-10-28" || len(c.Services) < 25 {
		t.Fatalf("каталог: версия %d, дата %s, сервисов %d", c.Version, c.Date, len(c.Services))
	}
	// Начальное наполнение по ADR-0027, п. 4: сервисы, которыми пользуются в России.
	for _, id := range []string{"chatgpt", "claude", "gemini", "microsoft-copilot", "deepseek", "perplexity", "mistral", "qwen",
		"gigachat", "yandexgpt-alice", "kandinsky"} {
		if _, ok := c.ByID(id); !ok {
			t.Errorf("нет сервиса %s", id)
		}
	}
}

func TestParseCatalogRejects(t *testing.T) {
	base := "format: aisec-shadow-ai-catalog-v1\nversion: 2\ndate: \"2026-10-28\"\nservices:\n"
	svc := "  - {id: a, name: A, vendor: V, category: chat, domains: [a.example.com]}\n"
	if _, err := ParseCatalog([]byte(base + svc)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"пусто":            "",
		"не YAML":          "\x00\x01",
		"формат":           strings.Replace(base, "v1", "v2", 1) + svc,
		"версия 0":         strings.Replace(base, "version: 2", "version: 0", 1) + svc,
		"версия строкой":   strings.Replace(base, "version: 2", "version: two", 1) + svc,
		"дата":             strings.Replace(base, "2026-10-28", "28.10.2026", 1) + svc,
		"нет сервисов":     base,
		"неизвестное поле": base + "  - {id: a, name: A, vendor: V, category: chat, domains: [a.example.com], regex: '.*'}\n",
		"категория":        base + "  - {id: a, name: A, vendor: V, category: games, domains: [a.example.com]}\n",
		"id":               base + "  - {id: A_1, name: A, vendor: V, category: chat, domains: [a.example.com]}\n",
		"повтор id":        base + svc + "  - {id: a, name: B, vendor: V, category: chat, domains: [b.example.com]}\n",
		"повтор имени":     base + svc + "  - {id: b, name: B, vendor: V, category: chat, suffixes: [a.example.com]}\n",
		"одна метка":       base + "  - {id: a, name: A, vendor: V, category: chat, suffixes: [com]}\n",
		"звёздочка":        base + "  - {id: a, name: A, vendor: V, category: chat, suffixes: ['*.example.com']}\n",
		"верхний регистр":  base + "  - {id: a, name: A, vendor: V, category: chat, domains: [A.example.com]}\n",
		"адрес IPv4":       base + "  - {id: a, name: A, vendor: V, category: chat, domains: [192.0.2.1]}\n",
		"без имён":         base + "  - {id: a, name: A, vendor: V, category: chat}\n",
		"управляющий":      base + "  - {id: a, name: \"A\\x07\", vendor: V, category: chat, domains: [a.example.com]}\n",
		"два документа":    base + svc + "---\nformat: x\n",
		"сверх размера":    base + svc + "#" + strings.Repeat("x", maxCatalogSize),
	} {
		if _, err := ParseCatalog([]byte(doc)); err == nil {
			t.Errorf("%s: каталог принят", name)
		}
	}
}

// Подписанный тестовый каталог репозитория совпадает с исходником: правка
// catalog.yaml без пересоздания файла видна в тесте.
func TestTestCatalogMatchesSource(t *testing.T) {
	p := provider(t)
	sc, err := VerifyCatalogFile(p, readFile(t, testCatalogSigned), testNow)
	if err != nil {
		t.Fatal(err)
	}
	db, err := aisecCrypto.InspectServiceDB(readFile(t, testCatalogSigned))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(db.Payload, readFile(t, testCatalogSource)) {
		t.Fatal("testdata/shadowai/catalog-test.aisecdb устарел: пересоздайте его по README")
	}
	if sc.Endorsement.Serial != 1 || sc.Catalog.Version != 1 || sc.Fingerprint == "" {
		t.Fatalf("каталог: %+v", sc.Endorsement)
	}
}

// signer — тестовый ключ производителя или рабочий ключ из репозитория.
func signer(t testing.TB, path, kind string) aisecCrypto.Signer {
	t.Helper()
	p := provider(t)
	_, seed, err := aisecCrypto.DecodeKeyPEM(readFile(t, path), kind)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signCatalog подписывает YAML тестовым рабочим ключом с заверением
// endorsement (nil — заверение репозитория).
func signCatalog(t testing.TB, yaml string, endorsement []byte) []byte {
	t.Helper()
	if endorsement == nil {
		endorsement = readFile(t, testEndorsement)
	}
	out, err := aisecCrypto.SignServiceDB(signer(t, testSubkey, aisecCrypto.KeyKindVendorSubkey), endorsement, CatalogKind, []byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// endorseTest — заверение тестового рабочего ключа с другими полями.
func endorseTest(t testing.TB, purpose string, serial uint64, from, until time.Time) []byte {
	t.Helper()
	sub := signer(t, testSubkey, aisecCrypto.KeyKindVendorSubkey)
	out, err := aisecCrypto.SignEndorsement(signer(t, testVendorKey, aisecCrypto.KeyKindManifestSigning), aisecCrypto.Endorsement{
		Purpose: purpose, Profile: aisecCrypto.ProfileStandard, Serial: serial, PublicKey: sub.PublicKey(), NotBefore: from, NotAfter: until})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func catalogYAML(version int, date string) string {
	return "format: aisec-shadow-ai-catalog-v1\nversion: " + strconv.Itoa(version) + "\ndate: \"" + date + "\"\nservices:\n" +
		"  - {id: chatgpt, name: ChatGPT, vendor: OpenAI, category: chat, suffixes: [chatgpt.com]}\n" +
		"  - {id: claude, name: Claude, vendor: Anthropic, category: chat, suffixes: [claude.ai]}\n"
}

// swapEndorsement заменяет заверение в файле базы: подпись содержимого тем
// же рабочим ключом остаётся верной.
func swapEndorsement(t testing.TB, db, endorsement []byte) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(db, &m); err != nil {
		t.Fatal(err)
	}
	m["endorsement"] = bytes.TrimSpace(endorsement)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyCatalogRejects(t *testing.T) {
	p := provider(t)
	vendor, _, err := integrity.EmbeddedVerifier(p)
	if err != nil {
		t.Fatal(err)
	}
	from, until := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)
	good := signCatalog(t, catalogYAML(2, "2026-10-28"), nil)
	if _, err := VerifyCatalog(p, vendor, good, testNow); err != nil {
		t.Fatal(err)
	}
	foreign, err := p.NewSigner(bytes.Repeat([]byte{5}, aisecCrypto.SigningSeedSize))
	if err != nil {
		t.Fatal(err)
	}
	foreignV, err := p.NewVerifier(foreign.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	revokedSerials := revokedServiceDBSerials
	t.Cleanup(func() { revokedServiceDBSerials = revokedSerials })
	for name, tc := range map[string]struct {
		vendor aisecCrypto.Verifier
		data   []byte
		at     time.Time
		reason string
	}{
		"чужой ключ производителя": {foreignV, good, testNow, "signature"},
		"заверение лицензий":       {vendor, swapEndorsement(t, good, endorseTest(t, aisecCrypto.PurposeLicense, 2, from, until)), testNow, "purpose"},
		"истёкшее заверение":       {vendor, good, time.Date(2031, 10, 1, 0, 0, 0, 0, time.UTC), "expired"},
		"дата вне заверения":       {vendor, signCatalog(t, catalogYAML(2, "2027-12-01"), endorseTest(t, aisecCrypto.PurposeServiceDB, 3, from, until)), time.Time{}, "date"},
		"отозванное":               {vendor, signCatalog(t, catalogYAML(2, "2026-10-28"), endorseTest(t, aisecCrypto.PurposeServiceDB, 99, from, until)), testNow, "revoked"},
		"мусор":                    {vendor, []byte("\x00\x01binary"), testNow, "format"},
		"неверный каталог":         {vendor, signCatalog(t, "format: x\n", nil), testNow, "format"},
	} {
		t.Run(name, func(t *testing.T) {
			revokedServiceDBSerials = []uint64{99}
			_, err := VerifyCatalog(p, tc.vendor, tc.data, tc.at)
			if err == nil || RejectReason(err) != tc.reason {
				t.Fatalf("ожидалась причина %s, получено %v (%s)", tc.reason, err, RejectReason(err))
			}
		})
	}
	if RejectReason(ErrStaleCatalog) != "stale_version" || !errors.Is(&CatalogError{Err: ErrStaleCatalog}, ErrStaleCatalog) {
		t.Fatal("причина stale_version")
	}
}

// FuzzParseCatalog: недоверенное содержимое каталога не роняет разбор, а
// принятый каталог сопоставляет только свои имена.
func FuzzParseCatalog(f *testing.F) {
	f.Add(readFile(f, testCatalogSource))
	f.Add([]byte(catalogYAML(1, "2026-10-28")))
	f.Add([]byte("format: aisec-shadow-ai-catalog-v1\nversion: 1\nservices: &a [*a]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseCatalog(data)
		if err != nil {
			return
		}
		for _, s := range c.Services {
			for _, d := range append(append([]string{}, s.Domains...), s.Suffixes...) {
				if got, ok := c.Match(d); !ok || got.ID != s.ID {
					t.Fatalf("%s: сопоставлено с %q", d, got.ID)
				}
			}
		}
	})
}
