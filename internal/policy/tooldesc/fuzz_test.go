package tooldesc

import (
	"bytes"
	"encoding/json"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// FuzzDescriptorHash — разбор описания инструмента (вход от шлюза и
// вышестоящего MCP-сервера): без паники; принятое описание даёт
// каноническую форму, которую стандартный разборщик читает как JSON, а
// повторный разбор не меняет ни её, ни хеш.
func FuzzDescriptorHash(f *testing.F) {
	for _, s := range []string{readDesc, `{"name":"a","icons":[],"_meta":{}}`, `{"name":"a","name":"b"}`, "{\"name\":\"\xff\"}",
		`{"name":"a","x":[1e400]}`, `{"name":"a","d":"\ud800"}`, `{"name":"a"} x`, `{"name":"a","s":"\u0000\u001f "}`} {
		f.Add([]byte(s))
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		f.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Parse(data)
		if err != nil {
			return
		}
		if !json.Valid(d.Canonical) {
			t.Fatalf("каноническая форма — не JSON: %q", d.Canonical)
		}
		again, err := Parse(d.Canonical)
		if err != nil || !bytes.Equal(again.Canonical, d.Canonical) || again.Name != d.Name {
			t.Fatalf("повторный разбор: %v", err)
		}
		if !bytes.Equal(Hash(h, d), Hash(h, again)) {
			t.Fatal("хеш изменился")
		}
	})
}
