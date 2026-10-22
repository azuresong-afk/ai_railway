package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
)

// FuzzParseTrust — trust.json из каталога состояния (3Н4 ревью 3.r1):
// недоверенный вход разбирается без паники; принятое — не больше
// MaxTrustStored заявлений и сохраняется в ту же форму.
func FuzzParseTrust(f *testing.F) {
	f.Add([]byte(`{"format":"aisec-gateway-trust/1","statements":["AQI="]}`))
	f.Add([]byte(`{"format":"aisec-gateway-trust/1","statements":[]}`))
	f.Add([]byte(`{"format":"aisec-gateway-trust/1","statements":["!"]}`))
	f.Add([]byte(`{"format":"other","statements":[]} {}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		raws, err := parseTrust(data)
		if err != nil {
			return
		}
		if len(raws) > MaxTrustStored {
			t.Fatalf("принято %d заявлений", len(raws))
		}
		doc := trustDoc{Format: trustFormat, Statements: []string{}}
		for _, r := range raws {
			doc.Statements = append(doc.Statements, base64.StdEncoding.EncodeToString(r))
		}
		again, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		back, err := parseTrust(again)
		if err != nil || len(back) != len(raws) {
			t.Fatalf("повторный разбор: %d, %v", len(back), err)
		}
		for i := range raws {
			if !bytes.Equal(back[i], raws[i]) {
				t.Fatalf("заявление %d изменилось", i)
			}
		}
	})
}

// FuzzParseClientPair — client.pem из каталога состояния (3Н4 ревью 3.r1):
// без паники; принято — ровно один сертификат и один ключ в PEM.
func FuzzParseClientPair(f *testing.F) {
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{4, 5, 6}})
	f.Add(append(append([]byte{}, cert...), key...))
	f.Add(append(append(append([]byte{}, cert...), cert...), key...))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		c, k, err := parseClientPair(data)
		if err != nil {
			if c != nil || k != nil {
				t.Fatal("при ошибке возвращены данные")
			}
			return
		}
		for _, part := range []struct {
			b    []byte
			kind string
		}{{c, "CERTIFICATE"}, {k, "PRIVATE KEY"}} {
			block, rest := pem.Decode(part.b)
			if block == nil || block.Type != part.kind || len(bytes.TrimSpace(rest)) != 0 {
				t.Fatalf("принят не один блок %s", part.kind)
			}
		}
	})
}
