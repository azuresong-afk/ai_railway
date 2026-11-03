package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/crypto/cryptotest"
)

const corpusDir = "../../../testdata/corpus/judge"

// Покрывает: DM-19 (LLM)
func TestRunStandWritesReport(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sub", "judge.md")
	var stdout bytes.Buffer
	if err := run([]string{"-stand", "-corpus", corpusDir, "-out", out}, &stdout); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out) //nolint:gosec // G304: путь во временном каталоге теста
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"# Замер judge.llm против lists", "стенд-оценщик", "no-refund-promises"} {
		if !strings.Contains(string(b), s) {
			t.Errorf("в отчёте нет %q", s)
		}
	}
	if !strings.Contains(stdout.String(), "judge-quality: примеров") || !strings.Contains(stdout.String(), "не проверено 0") {
		t.Errorf("вывод: %q", stdout.String())
	}
}

func TestFlagErrors(t *testing.T) {
	cases := map[string][]string{
		"нет режима":            {},
		"оба режима":            {"-stand", "-base-url", "https://10.0.0.1/v1", "-model", "m"},
		"адрес без модели":      {"-base-url", "https://10.0.0.1/v1"},
		"порог":                 {"-stand", "-threshold", "1.5"},
		"срок":                  {"-stand", "-timeout", "1ms"},
		"лишний аргумент":       {"-stand", "x"},
		"неизвестный флаг":      {"-stand", "-x"},
		"http вместо https":     {"-base-url", "http://10.0.0.1/v1", "-model", "m", "-corpus", corpusDir, "-out", filepath.Join(os.TempDir(), "never.md")},
		"нет корпуса":           {"-stand", "-corpus", "/nonexistent"},
		"неизвестный профиль":   {"-stand", "-corpus", corpusDir, "-profile", "x"},
		"нет файла ключа":       {"-base-url", "https://10.0.0.1/v1", "-model", "m", "-key-file", "/nonexistent", "-corpus", corpusDir},
		"нет файла сертификата": {"-base-url", "https://10.0.0.1/v1", "-model", "m", "-ca", "/nonexistent", "-corpus", corpusDir},
	}
	for name, args := range cases {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

// Адрес вне частной сети (здесь — loopback) оценщику не подходит: соединения
// нет, все оценки «не проверено» (unavailable), текст корпуса никуда не уходит.
// Покрывает: DM-19 (LLM)
func TestRealModeRefusesNonPrivateAddress(t *testing.T) {
	chain, err := cryptotest.NewChain(cryptotest.ChainOptions{Hosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, chain.Root, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "judge.md")
	var stdout bytes.Buffer
	if err := run([]string{"-base-url", "https://127.0.0.1:9/v1", "-model", "m", "-ca", ca, "-corpus", corpusDir, "-out", out, "-timeout", "2s"}, &stdout); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out) //nolint:gosec // G304: путь во временном каталоге теста
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "unavailable") || strings.Contains(stdout.String(), "не проверено 0") {
		t.Errorf("ожидали unavailable для всех оценок, вывод %q", stdout.String())
	}
}
