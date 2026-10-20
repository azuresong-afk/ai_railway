package pseudonym

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/corpus"
	"github.com/azuresong-afk/ai_railway/internal/mockllm"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Эксперимент ADR-0005 (решение Р9): формат псевдонима на корпусах
// детекторов и mock-llm. Реальной модели в среде разработки нет, поэтому
// переписывание псевдонима моделью моделируется искажениями, которые
// известны по поведению моделей (экранирование markdown, регистр, пробелы,
// потерянные скобки, перевод). На пилоте эксперимент повторяется на
// реальных моделях. Итоги печатает go test -run Experiment -v.

const corpusRoot = "../../testdata/corpus"

// loadCorpora — все примеры всех корпусов детекторов.
func loadCorpora(t *testing.T) map[string][]corpus.Sample {
	t.Helper()
	dirs, err := os.ReadDir(corpusRoot)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]corpus.Sample{}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		ss, err := corpus.Load(filepath.Join(corpusRoot, d.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[d.Name()] = ss
	}
	if len(out) == 0 {
		t.Fatal("корпуса не найдены")
	}
	return out
}

// TestExperimentCollisions — как часто формат-кандидат встречается в
// обычных текстах (атаки и чистые примеры RU/EN всех корпусов). Совпадение
// — риск принять текст пользователя или модели за псевдоним.
func TestExperimentCollisions(t *testing.T) {
	candidates := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"[[ТИП_N]]", regexp.MustCompile(`\[\[[A-Za-z][A-Za-z0-9]*_[1-9][0-9]*\]\]`)},
		{"{{ТИП_N}} (шаблоны Jinja, Handlebars)", regexp.MustCompile(`\{\{[^{}]{1,40}\}\}`)},
		{"<ТИП_N> (теги HTML и служебные токены)", regexp.MustCompile(`<[|/]?[A-Za-z][A-Za-z0-9_|]*>`)},
		{"ТИП_N без скобок", regexp.MustCompile(`\b[A-Z][A-Z0-9]*_[0-9]+\b`)},
		{"__ТИП_N__ (жирный markdown)", regexp.MustCompile(`__[A-Za-z0-9]+__`)},
	}
	samples := 0
	hits := make([]int, len(candidates))
	tolerant := 0
	for _, ss := range loadCorpora(t) {
		for _, s := range ss {
			samples++
			for i, c := range candidates {
				if c.re.MatchString(s.Text) {
					hits[i]++
				}
			}
			for i := 0; i < len(s.Text); i++ {
				if _, r := parseToken(s.Text, i, true, true); r == scanMatch {
					tolerant++
					t.Logf("грамматика подстановки приняла текст примера %s", s.ID)
					break
				}
			}
		}
	}
	t.Logf("примеров во всех корпусах: %d", samples)
	for i, c := range candidates {
		t.Logf("%-45s примеров с совпадением: %d", c.name, hits[i])
	}
	t.Logf("грамматика обратной подстановки (с искажениями): %d", tolerant)
	if hits[0] != 0 || tolerant != 0 {
		t.Fatal("формат [[ТИП_N]] встречается в обычных текстах: пересмотреть ADR-0005")
	}
}

// distortion — как модель переписала псевдоним; recoverable — ожидается ли
// восстановление.
type distortion struct {
	name        string
	apply       func(typ, n string) string
	recoverable bool
}

var distortions = []distortion{
	{"без изменений", func(t, n string) string { return "[[" + t + "_" + n + "]]" }, true},
	{"экранирование markdown", func(t, n string) string { return `\[\[` + t + `\_` + n + `\]\]` }, true},
	{"нижний регистр", func(t, n string) string { return "[[" + strings.ToLower(t) + "_" + n + "]]" }, true},
	{"пробелы у скобок", func(t, n string) string { return "[[ " + t + "_" + n + " ]]" }, true},
	{"одна пара скобок", func(t, n string) string { return "[" + t + "_" + n + "]" }, true},
	{"потеряна закрывающая скобка", func(t, n string) string { return "[[" + t + "_" + n + "]" }, true},
	{"дефис или пробел вместо «_»", func(t, n string) string { return "[[" + t + "-" + n + "]]" }, true},
	{"перевод типа на русский", func(t, n string) string { return "[[ЗНАЧЕНИЕ_" + n + "]]" }, false},
	{"скобки потеряны", func(t, n string) string { return t + "_" + n }, false},
	{"угловые скобки", func(t, n string) string { return "<" + t + "_" + n + ">" }, false},
}

var canonicalRe = regexp.MustCompile(`\[\[([A-Z][A-Z0-9]*)_([1-9][0-9]*)\]\]`)

// echo отправляет текст в mock-llm (сценарий echo) и возвращает ответ.
func echo(t *testing.T, srv *httptest.Server, text string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model":    "mock-echo",
		"messages": []map[string]string{{"role": "user", "content": text}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("mock-llm: %d %v", resp.StatusCode, err)
	}
	r, err := chat.ParseResponse(raw)
	if err != nil || r.Choices[0].Message.Content == nil {
		t.Fatalf("ответ mock-llm: %v", err)
	}
	return *r.Choices[0].Message.Content
}

// pseudonymized — пример корпуса pii.ru после псевдонимизации всех находок.
type pseudonymized struct {
	id, text, protected string
	values              []string
	vault               *Vault
}

// piiSamples — положительные примеры корпуса pii.ru (вход), псевдонимизированные.
func piiSamples(t *testing.T) []pseudonymized {
	t.Helper()
	ss, err := corpus.Load(filepath.Join(corpusRoot, "pii.ru"))
	if err != nil {
		t.Fatal(err)
	}
	var out []pseudonymized
	for _, s := range ss {
		if len(s.Expect) == 0 || s.Direction != detect.Input {
			continue
		}
		spans := detectSpans(t, s.Text, policy.Pseudonymize)
		if len(spans) == 0 {
			continue
		}
		v := NewVault(Limits{})
		if err := v.Reserve(s.Text); err != nil {
			t.Fatal(err)
		}
		p := pseudonymized{id: s.ID, text: s.Text, vault: v, protected: protect(t, v, s.Text, spans...)}
		for _, sp := range spans {
			p.values = append(p.values, s.Text[sp.Start:sp.End])
		}
		out = append(out, p)
	}
	if len(out) < 20 {
		t.Fatalf("мало примеров с ПДн: %d", len(out))
	}
	return out
}

// TestDM31_ExperimentMockLLM — ПДн корпуса проходят через mock-llm только
// псевдонимами и восстанавливаются в ответе; искажения моделью из списка
// recoverable восстанавливаются, прочие оставляют значение замаскированным.
func TestDM31_ExperimentMockLLM(t *testing.T) {
	srv := httptest.NewServer(mockllm.New(slog.New(slog.DiscardHandler)).Handler())
	defer srv.Close()
	samples := piiSamples(t)
	ok := make([]int, len(distortions))
	for _, p := range samples {
		for _, val := range p.values {
			if strings.Contains(p.protected, val) {
				t.Errorf("%s: значение ушло в запрос к модели", p.id)
			}
		}
		answer := echo(t, srv, p.protected)
		if answer != p.protected {
			t.Fatalf("%s: mock-llm изменил текст", p.id)
		}
		for i, d := range distortions {
			distorted := canonicalRe.ReplaceAllStringFunc(answer, func(tok string) string {
				m := canonicalRe.FindStringSubmatch(tok)
				return d.apply(m[1], m[2])
			})
			got := p.vault.Restore(distorted)
			if got == p.text {
				ok[i]++
			}
			if !d.recoverable {
				for _, val := range p.values {
					if strings.Contains(got, val) && !strings.Contains(distorted, val) {
						t.Errorf("%s, %s: восстановлено искажение, которое не должно приниматься", p.id, d.name)
					}
				}
			}
		}
	}
	t.Logf("примеров pii.ru с ПДн: %d", len(samples))
	for i, d := range distortions {
		t.Logf("%-30s восстановлено %d из %d", d.name, ok[i], len(samples))
		if d.recoverable && ok[i] != len(samples) {
			t.Errorf("%s: восстановлено %d из %d", d.name, ok[i], len(samples))
		}
		if !d.recoverable && ok[i] != 0 {
			t.Errorf("%s: восстановлено %d, ожидалось 0", d.name, ok[i])
		}
	}
}
