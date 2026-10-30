package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/ml"
	"github.com/azuresong-afk/ai_railway/internal/ml/mltest"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// nerInfo — модель pii.ner тестового aisec-ml: метки BIO, оба направления.
var nerInfo = ml.ModelInfo{ID: "pii-ner-ru", Version: "1.0",
	Labels:     []string{"o", "b-per", "i-per", "b-org", "i-org", "b-loc", "i-loc", "b-addr", "i-addr"},
	Directions: []string{"input", "output"}}

// startNERML — aisec-ml с тестовой моделью pii.ner: слово → сущность.
func startNERML(t *testing.T, words map[string]string) string {
	t.Helper()
	sock := filepath.Join(mlSocketDir(t), "s")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sock, 0o660); err != nil { //nolint:gosec // G302: тест задаёт права сокета намеренно
		t.Fatal(err)
	}
	srv, err := ml.NewServer(ml.ServerConfig{Models: []ml.Model{mltest.NewModel(nerInfo, words, nil)}, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	return sock
}

func TestExpandWords(t *testing.T) {
	text := "Звонил Иванову Петру, ул. Ёлочная-7"
	at := func(w string) (int, int) { i := strings.Index(text, w); return i, i + len(w) }
	for _, tc := range []struct{ part, want string }{
		{"Иванов", "Иванову"}, // конец внутри слова
		{"анову", "Иванову"},  // начало внутри слова
		{"Иванову Петру", "Иванову Петру"},
		{"ову Пет", "Иванову Петру"},
		{"ул.", "ул."},        // точка — не буква: дальше не идёт
		{"лочная", "Ёлочная"}, // дефис — граница слова
		{", ", ", "},          // фрагмент без букв не меняется
	} {
		s, e := at(tc.part)
		s, e = expandWords(text, s, e)
		if text[s:e] != tc.want {
			t.Errorf("%q → %q, ожидалось %q", tc.part, text[s:e], tc.want)
		}
	}
	// Расширение ограничено: слово длиннее предела не раскрывается целиком.
	long := strings.Repeat("я", 200)
	s, e := expandWords(long, 200, 202)
	if 200-s > maxWordExpand || e-202 > maxWordExpand || s == 200 || e == 202 {
		t.Fatalf("длинное слово: [%d, %d)", s, e)
	}
}

// FuzzExpandWords — расширение до слов на произвольном тексте: результат
// содержит исходный фрагмент, на границах символов, не дальше
// maxWordExpand в каждую сторону, добавлены только символы слова.
//
// Покрывает: DM-31 (NER), DM-09 (NER)
func FuzzExpandWords(f *testing.F) {
	f.Add("Иванову Петру", 2, 6)
	f.Add("a\xffb", 0, 1)
	f.Add("ёж", 0, 2)
	f.Fuzz(func(t *testing.T, text string, start, end int) {
		if len(text) > 4096 || start < 0 || end > len(text) || start >= end ||
			!detect.OnRuneBoundary(text, start) || !detect.OnRuneBoundary(text, end) {
			return
		}
		s, e := expandWords(text, start, end)
		if s > start || e < end || start-s > maxWordExpand || e-end > maxWordExpand {
			t.Fatalf("[%d, %d) → [%d, %d)", start, end, s, e)
		}
		if !detect.OnRuneBoundary(text, s) || !detect.OnRuneBoundary(text, e) {
			t.Fatalf("[%d, %d) режет символ", s, e)
		}
		if utf8.ValidString(text) {
			for _, r := range text[s:start] + text[end:e] {
				if !wordRune(r) {
					t.Fatalf("расширение захватило не букву %q", r)
				}
			}
		}
	})
}

// nerSetup — реестр приложения с pii.ner через aisec-ml и политика:
// псевдонимизация имён, адресов и организаций в запросе, маскирование в
// ответе.
func nerSetup(t *testing.T, sock string) func(*App) {
	return nerPolicySetup(t, sock, policy.Enforce, policy.Pseudonymize, policy.Redact)
}

// nerPolicySetup — то же с заданными режимом и действиями.
func nerPolicySetup(t *testing.T, sock string, mode policy.Mode, inAct, outAct policy.Action) func(*App) {
	return func(a *App) {
		reg, err := appDetectors(config.Application{}, newMLClient(t, sock, nil))
		if err != nil {
			t.Fatal(err)
		}
		in, out := []detect.Direction{detect.Input}, []detect.Direction{detect.Output}
		p, err := policy.Compile(&policy.Spec{ID: "t", Name: "t", Version: 1, Mode: mode, Rules: []policy.RuleSpec{
			{ID: "ner-in", Detector: builtin.PIINERID, Directions: in, Action: inAct, Severity: policy.Medium},
			{ID: "ner-out", Detector: builtin.PIINERID, Directions: out, Action: outAct, Severity: policy.Medium},
		}}, reg)
		if err != nil {
			t.Fatal(err)
		}
		a.Detectors, a.Policy = reg, p
	}
}

// Имя, найденное pii.ner в запросе, уходит провайдеру псевдонимом целиком
// (модель отметила только часть слова), приложение получает имя обратно;
// организация — свой тип псевдонима; город (loc) не маскируется.
//
// Покрывает: DM-31 (NER)
func TestDM31_NERNameMaskedBeforeProvider(t *testing.T) {
	sock := startNERML(t, map[string]string{"Иванов": "per", "Ромашка": "org", "Твери": "loc"})
	up, rec := newUpstream(t, echoHandler(t))
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { o.setup, log = nerSetup(t, sock), o.events })
	resp := postChat(t, g, userBody(t, "Передай Иванову из ООО «Ромашка» в Твери"), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	_, _, body, _ := rec.get()
	if strings.Contains(body, "Иванов") || strings.Contains(body, "ову") || strings.Contains(body, "Ромашка") ||
		!strings.Contains(body, "Передай [[PERSON_1]] из ООО «[[ORGANIZATION_1]]» в Твери") {
		t.Fatalf("провайдер получил: %s", body)
	}
	if got := responseContent(t, resp); got != "Передай Иванову из ООО «Ромашка» в Твери" {
		t.Fatalf("обратная подстановка: %q", got)
	}
	e := lastEvent(t, log, resp)
	if e.Decision.MLUnavailable || !slices.Contains(e.Threats, "DM-31") {
		t.Fatalf("событие: %+v %v", e.Decision, e.Threats)
	}
	for _, f := range e.Findings {
		if f.Detector == builtin.PIINERID && f.Category == builtin.CatPerson && (f.Rule != "pii-ner-ru-1.0" || f.Threat != "DM-31") {
			t.Fatalf("находка: %+v", f)
		}
	}
}

// Имя в ответе модели маскируется до приложения (DM-09).
//
// Покрывает: DM-09 (NER)
func TestDM09_NERNameRedactedInResponse(t *testing.T) {
	sock := startNERML(t, map[string]string{"Сидоренко": "per"})
	up, _ := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		replyJSON(t, w, "Договор подписал Сидоренко Ф. Ф.")
	})
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { o.setup, log = nerSetup(t, sock), o.events })
	resp := postChat(t, g, userBody(t, "Кто подписал договор?"), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if got := responseContent(t, resp); got != "Договор подписал [[PERSON]] Ф. Ф." {
		t.Fatalf("ответ: %q", got)
	}
	if e := lastEvent(t, log, resp); !slices.Contains(e.Threats, "DM-09") {
		t.Fatalf("строки матрицы: %v", e.Threats)
	}
}

// Режим хранения masked: имя, найденное pii.ner, не попадает в содержимое
// события, даже если правило только записывает находку (шаблоны —
// «Мониторинг» до Р4), а провайдеру уходит как есть.
//
// Покрывает: DM-31 (NER)
func TestNERMaskedInEventContent(t *testing.T) {
	sock := startNERML(t, map[string]string{"Иванов": "per"})
	up, rec := newUpstream(t, echoHandler(t))
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { a.Storage = "masked" }
		o.setup, log = nerPolicySetup(t, sock, policy.Enforce, policy.Log, policy.Log), o.events
	})
	resp := postChat(t, g, userBody(t, "Передай Иванову отчёт"), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if _, _, body, _ := rec.get(); !strings.Contains(body, "Передай Иванову отчёт") {
		t.Fatalf("провайдер получил: %s", body)
	}
	e := lastEvent(t, log, resp)
	if e.Content == nil || strings.Contains(e.Content.Request, "Иванов") || !strings.Contains(e.Content.Request, "[pii.person]") {
		t.Fatalf("содержимое события: %+v", e.Content)
	}
}

// Текст длиннее MLMaxChunks частей: имена проверенной части возвращаются
// (их маскируют), и сбой — неполная проверка (ml_unavailable), а не
// «проверено целиком»: остаток текста не замаскирован.
//
// Покрывает: DM-31 (NER)
func TestNERPartialKeepsFindings(t *testing.T) {
	c := newMLClient(t, startNERML(t, map[string]string{"Иванов": "per"}), func(cfg *MLClientConfig) { cfg.Timeout = 5 * time.Second })
	var spec builtin.MLSpec
	for _, s := range builtin.MLSpecs() {
		if s.ID == builtin.PIINERID {
			spec = s
		}
	}
	d, err := NewMLDetector(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := detect.NewRegistry(d)
	if err != nil {
		t.Fatal(err)
	}
	huge := "Иванову " + strings.Repeat("a", ml.MaxText*MLMaxChunks) + " Иванову"
	fs, rerrs, err := reg.Run(context.Background(), []string{builtin.PIINERID}, detect.Text{Text: huge, Direction: detect.Input}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || huge[fs[0].Start:fs[0].End] != "Иванову" {
		t.Fatalf("находки: %+v", fs)
	}
	if len(rerrs) != 1 || !errors.Is(rerrs[0].Err, ErrMLUnavailable) || !errors.Is(rerrs[0].Err, detect.ErrPartial) {
		t.Fatalf("сбои: %v", rerrs)
	}
	// Короткий текст проверен целиком — без сбоя.
	if fs, rerrs, err = reg.Run(context.Background(), []string{builtin.PIINERID}, detect.Text{Text: "Иванову", Direction: detect.Input}, 5*time.Second); err != nil || len(fs) != 1 || len(rerrs) != 0 {
		t.Fatalf("%+v %v %v", fs, rerrs, err)
	}
}
