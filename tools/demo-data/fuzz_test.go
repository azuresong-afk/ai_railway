package main

import (
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
