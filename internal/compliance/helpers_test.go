package compliance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

const (
	testSubkey      = "../../testdata/shadowai/subkey-test.signkey"
	testEndorsement = "../../testdata/shadowai/subkey-test.endorsement"
	testVendorKey   = "../../testdata/integrity/manifest-test.signkey"
)

// testNow — внутри срока тестового заверения (01.10.2026 — 30.09.2031).
var testNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

var testBy = By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000a1", Name: "secadm"}}

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

func signer(t testing.TB, path, kind string) aisecCrypto.Signer {
	t.Helper()
	_, seed, err := aisecCrypto.DecodeKeyPEM(readFile(t, path), kind)
	if err != nil {
		t.Fatal(err)
	}
	s, err := provider(t).NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signBase подписывает YAML тестовым рабочим ключом (kind — вид базы).
func signBase(t testing.TB, kind, yaml string, endorsement []byte) []byte {
	t.Helper()
	if endorsement == nil {
		endorsement = readFile(t, testEndorsement)
	}
	out, err := aisecCrypto.SignServiceDB(signer(t, testSubkey, aisecCrypto.KeyKindVendorSubkey), endorsement, kind, []byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

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

// miniBase — небольшая база версии version для тестов службы.
func miniBase(version int, date string) string {
	return "format: aisec-compliance-base-v1\nversion: " + itoa(version) + "\ndate: \"" + date + "\"\n" +
		"sources:\n  - {id: src-a, title: Источник А}\n" +
		"requirements:\n" +
		"  - {id: auto.one, source: src-a, clause: п. 1, title: Автоматический, summary: Пересказ, applies: [gis], checks: [{name: content_storage}]}\n" +
		"  - {id: manual.one, source: src-a, clause: п. 2, title: Ручной, summary: Пересказ, applies: [gis, ispdn], manual: true}\n" +
		"  - {id: draft.one, source: src-a, clause: проект, title: Проект, summary: Пересказ, applies: [gis], draft: true, manual: true}\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// fakeFacts отдаёт заданный снимок.
type fakeFacts struct{ snap *Snapshot }

func (f *fakeFacts) Snapshot(context.Context) (*Snapshot, error) {
	s := *f.snap
	return &s, nil
}

// goodSnapshot — установка, где всё настроено.
func goodSnapshot() *Snapshot {
	return &Snapshot{Now: testNow, Unavailable: map[string]bool{},
		Apps: []AppFact{{Slug: "bot", Env: "prod", PolicyMode: "enforce", InputRules: 2, OutputRules: 1, PIIRules: 1, ExternalProvider: true,
			ToolsBlockUnapproved: true, Storage: "masked", Models: 2, Quotas: map[string]int{"requests_per_minute": 60, "max_input_bytes": 1000}}},
		PrivilegedRoles:   []RoleFact{{ID: "security_admin", MFA: true, Users: 1}, {ID: "system_admin", MFA: true, Users: 1}},
		AuditChain:        &ChainFact{OK: true, CheckedAt: testNow.Add(-time.Hour)},
		Integrity:         &IntegrityFact{ServerOK: true, CheckedAt: testNow, Gateways: 1, GatewaysOK: 1},
		AlertRulesEnabled: 10, ChannelsEnabled: 1}
}

func newTestService(t testing.TB, st Store, snap *Snapshot) *Service {
	t.Helper()
	base, err := ParseBase([]byte(miniBase(1, "2026-10-28")))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Store: st, ServiceDBs: st.(*Memory).ServiceDBs(), Provider: provider(t), Facts: &fakeFacts{snap: snap}, Embedded: base,
		Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func lastRecord(m *Memory, action string) (audit.Entry, int) {
	var last audit.Entry
	n := 0
	for _, r := range append(m.Records(), m.ServiceDBs().Records()...) {
		if r.Action == action {
			last, n = r, n+1
		}
	}
	return last, n
}

func hasPrefix(s, p string) bool { return strings.HasPrefix(s, p) }

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
