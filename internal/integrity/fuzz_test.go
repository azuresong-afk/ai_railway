package integrity

import (
	"io"
	"log/slog"
	"testing"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// FuzzParseManifest — разбор манифеста (недоверенный файл): без паники, а
// принятый манифест кодируется обратно и разбирается в то же самое.
func FuzzParseManifest(f *testing.F) {
	good, err := Marshal(validManifest())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"format":"aisec-manifest-v1","files":[{"path":"bin/../x"}]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil {
			return
		}
		out, err := Marshal(m)
		if err != nil {
			t.Fatalf("принятый манифест не кодируется: %v", err)
		}
		m2, err := Parse(out)
		if err != nil || len(m2.Files) != len(m.Files) || m2.Version != m.Version {
			t.Fatalf("повторный разбор: %v", err)
		}
	})
}

// FuzzVerifySignature — разбор файла подписи: без паники, и случайный файл
// не проходит проверку.
func FuzzVerifySignature(f *testing.F) {
	p := provider(f)
	s, err := p.GenerateSigner()
	if err != nil {
		f.Fatal(err)
	}
	v, err := p.NewVerifier(s.PublicKey())
	if err != nil {
		f.Fatal(err)
	}
	manifest := []byte(`{"format":"aisec-manifest-v1"}`)
	good, err := Sign(s, manifest)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte("AAAA\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, sig []byte) {
		err := VerifySignature(v, manifest, sig)
		if err == nil && string(sig) != string(good) && string(sig) != string(good[:len(good)-1]) {
			t.Fatalf("принята чужая подпись %q", sig)
		}
	})
}
