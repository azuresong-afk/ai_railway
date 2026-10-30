package servicedb

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

const (
	testSubkey      = "../../testdata/shadowai/subkey-test.signkey"
	testEndorsement = "../../testdata/shadowai/subkey-test.endorsement"
	testVendorKey   = "../../testdata/integrity/manifest-test.signkey"
	testVendorPub   = "../integrity/keys/manifest-test.pub"
	testKindName    = "test_db"
)

// testNow — внутри срока тестового заверения (01.10.2026 — 30.09.2031).
var testNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

var testBy = By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000a1", Name: "sysadm"}}

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

// testVendor — тестовый ключ производителя из файла, а не встроенный: тест
// идёт и в release-test, где встроена имитация ключа производителя.
func testVendor(t testing.TB) aisecCrypto.Verifier {
	t.Helper()
	_, pub, err := aisecCrypto.DecodeKeyPEM(readFile(t, testVendorPub), aisecCrypto.KeyKindManifestSigningPublic)
	if err != nil {
		t.Fatal(err)
	}
	v, err := provider(t).NewVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// testDB — содержимое тестового вида: строгий JSON.
type testDB struct {
	Version uint64 `json:"version"`
	Date    string `json:"date"`
	Records int    `json:"records"`
}

// testKind — вид для тестов общего слоя.
func testKind() Kind {
	return Kind{Name: testKindName, Title: "Тестовая база", Parse: func(b []byte) (Content, error) {
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		var v testDB
		if err := d.Decode(&v); err != nil {
			return Content{}, err
		}
		day, err := time.Parse(time.DateOnly, v.Date)
		if err != nil {
			return Content{}, err
		}
		if v.Version == 0 {
			return Content{}, errors.New("нет версии")
		}
		return Content{Value: &v, Version: v.Version, Date: day, Records: v.Records}, nil
	}}
}

func payload(version int, date string) string {
	return `{"version":` + strconv.Itoa(version) + `,"date":"` + date + `","records":3}`
}

// sign подписывает содержимое тестовым рабочим ключом (endorsement nil —
// тестовое заверение № 1).
func sign(t testing.TB, kind, body string, endorsement []byte) []byte {
	t.Helper()
	if endorsement == nil {
		endorsement = readFile(t, testEndorsement)
	}
	out, err := aisecCrypto.SignServiceDB(signer(t, testSubkey, aisecCrypto.KeyKindVendorSubkey), endorsement, kind, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func endorse(t testing.TB, purpose string, serial uint64, from, until time.Time) []byte {
	t.Helper()
	sub := signer(t, testSubkey, aisecCrypto.KeyKindVendorSubkey)
	out, err := aisecCrypto.SignEndorsement(signer(t, testVendorKey, aisecCrypto.KeyKindManifestSigning), aisecCrypto.Endorsement{
		Purpose: purpose, Profile: aisecCrypto.ProfileStandard, Serial: serial, PublicKey: sub.PublicKey(), NotBefore: from, NotAfter: until})
	if err != nil {
		t.Fatal(err)
	}
	return out
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

// corrupt портит подпись файла: разбор проходит, проверка — нет.
func corrupt(file []byte) []byte {
	return bytes.Replace(file, []byte(`"signature":"`), []byte(`"signature":"AAAA`), 1)
}

func newManager(t testing.TB, st Store, minVersion uint64) *Manager {
	t.Helper()
	m, err := NewManager(Options{Store: st, Provider: provider(t), Kind: testKind(), Clock: func() time.Time { return testNow },
		MinVersion: minVersion, Vendor: testVendor(t), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// count — записи аудита с кодом и итогом.
func count(m *Memory, action string, result audit.Result) (audit.Entry, int) {
	var last audit.Entry
	n := 0
	for _, r := range m.Records() {
		if r.Action == action && r.Result == result {
			last, n = r, n+1
		}
	}
	return last, n
}
