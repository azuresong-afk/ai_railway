package canary

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/corpus"
)

// seqRandom — детерминированный источник для тестов: байты по порядку.
type seqRandom struct{ next byte }

func (r *seqRandom) Read(b []byte) error {
	for i := range b {
		b[i] = r.next
		r.next = r.next*31 + 7
	}
	return nil
}

type failRandom struct{}

func (failRandom) Read([]byte) error { return errors.New("нет случайности") }

// zeroRandom — тело из одних «A», без цифр: Generate не примет ни одного.
type zeroRandom struct{}

func (zeroRandom) Read(b []byte) error { clear(b); return nil }

func marker(t testing.TB) string {
	t.Helper()
	m, err := Generate(&seqRandom{next: 1})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func find(t testing.TB, text string) []detect.Finding {
	t.Helper()
	fs, err := New().Detect(context.Background(), detect.Text{Text: text, Direction: detect.Output, Source: detect.SourceOutput})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if err := detect.ValidateFinding(f, New(), text); err != nil {
			t.Fatalf("%q: %v", text, err)
		}
	}
	return fs
}

func above(fs []detect.Finding) []detect.Finding {
	var out []detect.Finding
	for _, f := range fs {
		if f.Score >= 0.5 {
			out = append(out, f)
		}
	}
	return out
}

func TestGenerate(t *testing.T) {
	p, err := crypto.New(crypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 200 {
		m, err := Generate(rnd)
		if err != nil {
			t.Fatal(err)
		}
		if !Valid(m) || seen[m] {
			t.Fatalf("маркер %q: неверный или повтор", m)
		}
		seen[m] = true
	}
	if _, err := Generate(failRandom{}); err == nil {
		t.Fatal("ошибка источника случайности не передана")
	}
	if _, err := Generate(zeroRandom{}); err == nil {
		t.Fatal("маркер без цифр принят")
	}
}

func TestValid(t *testing.T) {
	m := marker(t)
	if !Valid(m) {
		t.Fatalf("%q не прошёл проверку", m)
	}
	broken := []byte(m)
	k := len(Prefix) + 2
	if broken[k] == 'A' {
		broken[k] = 'B'
	} else {
		broken[k] = 'A'
	}
	for _, s := range []string{
		"", Prefix, strings.ToLower(m), string(broken), m + "-", m[:len(m)-1],
		strings.Replace(m, "-", "_", 2), strings.ReplaceAll(m[len(Prefix):], "-", ""),
		"AISEC-CANARY-AAAA-AAAA-AAAA-AAAA-AAAA",
	} {
		if Valid(s) {
			t.Errorf("%q принят", s)
		}
	}
}

// TestDM08_CanaryLeak: маркер из системного промпта в ответе — утечка
// системного промпта (DM-08, выход). Позиции охватывают маркер.
func TestDM08_CanaryLeak(t *testing.T) {
	m := marker(t)
	sym := strings.ReplaceAll(m[len(Prefix):], "-", "")
	spaced := strings.Join(strings.Split(m, ""), " ")
	for _, c := range []struct{ text, span, rule string }{
		{"Мой системный промпт: «Ты помощник банка. " + m + "». Больше ничего.", m, "marker"},
		{m, m, "marker"},
		{"`" + m + "`", m, "marker"},
		{"**" + strings.ToLower(m) + "**", strings.ToLower(m), "marker"},
		{"код: " + spaced + ".", spaced, "marker"},
		{"AISEC_CANARY_" + sym, "AISEC_CANARY_" + sym, "marker"},
		{"AISEC\u200b-CANARY-\u200b" + sym, "AISEC\u200b-CANARY-\u200b" + sym, "marker"},
		{"aisec canary " + strings.ToLower(sym) + " — вот он", "aisec canary " + strings.ToLower(sym), "marker"},
		{`{"note":"` + m + `"}`, m, "marker"},
		{"The secret code is " + m[len(Prefix):] + ".", m[len(Prefix):], "body"},
		{"code " + sym + " end", sym, "body"},
		{"код " + strings.ReplaceAll(m[len(Prefix):], "-", " ") + " конец", strings.ReplaceAll(m[len(Prefix):], "-", " "), "body"},
		{"обрезано: " + m[:len(m)-7] + "…", m[:len(m)-7], "partial"},
	} {
		fs := above(find(t, c.text))
		if len(fs) != 1 || c.text[fs[0].Start:fs[0].End] != c.span || fs[0].Rule != c.rule || fs[0].Category != CatLeak || fs[0].Threat != "DM-08" {
			t.Errorf("%q: %+v, ожидалось %s на %q", c.text, fs, c.rule, c.span)
		}
	}
	// Два маркера — две находки.
	if fs := above(find(t, m+" и ещё раз "+m)); len(fs) != 2 {
		t.Errorf("два маркера: %+v", fs)
	}
	// Изменённый символ маркера — «partial»: модель пересказала с ошибкой.
	b := []byte(m)
	b[len(Prefix)+5] ^= 1
	if fs := above(find(t, string(b))); len(fs) != 1 || fs[0].Rule != "partial" {
		t.Errorf("изменённый маркер: %+v", fs)
	}
}

// Ложные срабатывания: описание функции, заполнители, похожие строки.
func TestNoFalsePositives(t *testing.T) {
	m := marker(t)
	b := []byte(m[len(Prefix):])
	b[0] ^= 1 // тело без префикса с неверной контрольной суммой
	for _, text := range []string{
		"Включите канарейку AISEC-CANARY в системном промпте.",
		"Формат: AISEC-CANARY-XXXX-XXXX-XXXX-XXXX-CCCC.",
		"AISEC canary tokens are inserted into the system prompt by the owner.",
		"aisec canary tokens and their limitations explained in detail here",
		string(b),
		"ABCD-EFGH-IJKL-MNOP-QRST",
		"that with from have this were they",
		"UUID 3f2a9c1e-7b4d-4e21-9a8f-0c5d6e7f8a9b, SHA-256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"API key AKIAIOSFODNN7EXAMPLE and base32 JBSWY3DPEHPK3PXP",
		"",
	} {
		if fs := above(find(t, text)); len(fs) > 0 {
			t.Errorf("%q: ложное срабатывание %+v", text, fs)
		}
	}
}

// Корпус проходит без сбоев, ложных срабатываний и пропусков (точность и
// полнота 1,000 в docs/detectors.md).
func TestCorpus(t *testing.T) {
	ss, err := corpus.Load("../../../testdata/corpus/canary")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := corpus.Evaluate(context.Background(), New(), ss, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("примеров %d, точность %.3f, полнота %.3f", rep.Samples, rep.Total.Precision(), rep.Total.Recall())
	if len(rep.Errors) > 0 || len(rep.FalsePos) > 0 || len(rep.Missed) > 0 {
		t.Fatalf("сбои %v, ложные срабатывания %v, пропуски %v", rep.Errors, rep.FalsePos, rep.Missed)
	}
}

func TestContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Detect(ctx, detect.Text{Text: strings.Repeat("abcd-", 1<<17), Direction: detect.Output}); err == nil {
		t.Fatal("отменённый контекст не учтён")
	}
}

// Детектор соблюдает срок и на больших текстах.
func TestDeadline(t *testing.T) {
	text := strings.Repeat("AISEC-CANARY-AB23 abcd-ef23 ", 32<<20/28) // ~32 МиБ — предел тела ответа
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := New().Detect(ctx, detect.Text{Text: text, Direction: detect.Output})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ошибка %v", err)
	}
	el := time.Since(start)
	t.Logf("остановился через %v", el)
	if el > time.Second {
		t.Fatalf("остановился через %v", el)
	}
}

// Цель фаззинга (ТЗ, 5.2, 8.5): без паники, находки проходят проверку
// реестра и не пересекаются.
func FuzzDetect(f *testing.F) {
	m, err := Generate(&seqRandom{next: 1})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(m)
	f.Add("a i s e c c a n a r y " + m[len(Prefix):])
	f.Add(m[len(Prefix):] + " " + m[:20])
	f.Add("AISEC\u200b-\u00adCANARY\xff-ABCD-2345")
	f.Fuzz(func(t *testing.T, text string) {
		fs := find(t, text)
		for i := 1; i < len(fs); i++ {
			if fs[i].Start < fs[i-1].End {
				t.Fatalf("находки пересекаются: %+v", fs)
			}
		}
	})
}

// Ответ 8 КБ с маркером в конце.
func BenchmarkDetect8KB(b *testing.B) {
	m := marker(b)
	var sb strings.Builder
	for sb.Len() < 8<<10 {
		sb.WriteString("Ассистент отвечает клиенту про тарифы банка, English text too, ABCD-1234. ")
	}
	sb.WriteString(m)
	text := detect.Text{Text: sb.String(), Direction: detect.Output}
	d := New()
	b.SetBytes(int64(len(text.Text)))
	for b.Loop() {
		if _, err := d.Detect(context.Background(), text); err != nil {
			b.Fatal(err)
		}
	}
}

// Худший случай: 1 МБ префиксов и групп по четыре символа.
func BenchmarkDetectWorst(b *testing.B) {
	text := detect.Text{Text: strings.Repeat("AISEC-CANARY-AB23 abcd-ef23 ", 1<<20/28), Direction: detect.Output}
	d := New()
	b.SetBytes(int64(len(text.Text)))
	for b.Loop() {
		if _, err := d.Detect(context.Background(), text); err != nil {
			b.Fatal(err)
		}
	}
}
