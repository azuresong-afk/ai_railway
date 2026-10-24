package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Разборщики входных файлов не должны падать на произвольном содержимом.
func FuzzReadKeys(f *testing.F) {
	f.Add("a=1\n# c\n\nb = 2")
	f.Add("=\n==")
	f.Fuzz(func(t *testing.T, s string) {
		p := filepath.Join(t.TempDir(), "k")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Skip()
		}
		_, _, _ = readKeys(p) //nolint:gosec // G104: проверяется только отсутствие паники
	})
}

func FuzzReadCorpusFile(f *testing.F) {
	f.Add(`{"id":"a","text":"t","expect":["x"]}`)
	f.Add("{\n\n[]")
	f.Fuzz(func(t *testing.T, s string) {
		p := filepath.Join(t.TempDir(), "c.jsonl")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Skip()
		}
		_, _ = readCorpusFile(p) //nolint:gosec // G104: проверяется только отсутствие паники
	})
}

// Без -allow-remote принимается только https и только localhost или loopback-литерал.
func FuzzCheckGateway(f *testing.F) {
	f.Add("https://127.0.0.1:8443")
	f.Add("https://gw.example.ru")
	f.Add("https://[::1]:1/%zz")
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := checkGateway(raw, false)
		if err != nil {
			return
		}
		h := u.Hostname()
		ip := net.ParseIP(h)
		if u.Scheme != "https" || u.User != nil || (h != "localhost" && (ip == nil || !ip.IsLoopback())) {
			t.Fatalf("принят адрес вне loopback: %q", raw)
		}
	})
}
