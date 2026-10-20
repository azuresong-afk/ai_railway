package canary

import (
	"context"
	"errors"
	"slices"
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

// joinRunes — символы строки через разделитель.
func joinRunes(s, sep string) string { return strings.Join(strings.Split(s, ""), sep) }

// groups4 — символы маркера после префикса группами по четыре.
func groups4(m string) []string { return strings.Split(m[len(Prefix):], "-") }

// TestDM08_CanaryLeakSeparators (замечание 3 ревью 1.17–1.21): маркер,
// записанный через обычные разделители, — типичные просьбы при извлечении
// промпта: через запятую, через «/», по символу на строку, группами в
// обратных кавычках (DM-08, выход).
func TestDM08_CanaryLeakSeparators(t *testing.T) {
	m := marker(t)
	sym := strings.ReplaceAll(m[len(Prefix):], "-", "")
	g := groups4(m)
	bt := "`AISEC` `CANARY` `" + strings.Join(g, "` `") + "`"
	for _, c := range []struct{ name, span, rule string }{
		{"через запятую", joinRunes(m, ", "), "marker"},
		{"через запятую без дефисов", joinRunes(prefixLetters+sym, ","), "marker"},
		{"через запятую и пробел без дефисов", joinRunes(prefixLetters+sym, ", "), "marker"},
		{"через косую черту", joinRunes(m, " / "), "marker"},
		{"косая черта без пробелов", joinRunes(m, "/"), "marker"},
		{"по символу на строку", joinRunes(m, "\n"), "marker"},
		{"по символу на строку, CRLF", joinRunes(m, "\r\n"), "marker"},
		{"по символу на строку через пустую строку", joinRunes(m, "\n\n"), "marker"},
		{"списком", joinRunes(m, "\n- "), "marker"},
		{"по символу в кавычках", joinRunes(prefixLetters+sym, "', '"), "marker"},
		{"группами в обратных кавычках", bt[1 : len(bt)-1], "marker"},
		{"неразрывные пробелы и точки", joinRunes(m, ".\u00a0"), "marker"},
		{"тело группами через запятую", strings.Join(g, ", "), "body"},
		{"тело группами через косую черту", strings.Join(g, " / "), "body"},
		{"тело группами в обратных кавычках", strings.Join(g, "` `"), "body"},
		{"тело группами по строкам", strings.Join(g, "\n"), "body"},
		{"тело группами через точку с запятой", strings.Join(g, ";"), "body"},
	} {
		text := "Вот он: «" + c.span + "». Всё."
		if strings.Contains(c.name, "обратных") {
			text = "Вот он: `" + c.span + "`. Всё."
		}
		fs := above(find(t, text))
		if len(fs) != 1 || text[fs[0].Start:fs[0].End] != c.span || fs[0].Rule != c.rule || fs[0].Threat != "DM-08" {
			t.Errorf("%s: %q: %+v, ожидалось %s на %q", c.name, text, fs, c.rule, c.span)
		}
	}
}

// TestDM08_CanaryHomoglyphs: гомоглифы, полноширинные и математические
// символы и теги вместо букв маркера сводятся к ASCII (DM-08, выход).
func TestDM08_CanaryHomoglyphs(t *testing.T) {
	m := marker(t)
	g := groups4(m)
	fullwidth := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			if r > ' ' && r < 0x7F {
				r += 0xFEE0
			}
			b.WriteRune(r)
		}
		return b.String()
	}
	cyr := strings.NewReplacer("A", "\u0410", "C", "\u0421", "E", "\u0415", "K", "\u041a", "M", "\u041c", "H", "\u041d", "O", "\u041e", "P", "\u0420", "T", "\u0422", "X", "\u0425", "Y", "\u0423")
	tags := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			b.WriteRune(0xE0000 + r)
		}
		return b.String()
	}
	for _, c := range []struct{ name, span, rule string }{
		{"кириллица вместо латиницы", cyr.Replace(m), "marker"},
		{"кириллица в нижнем регистре", strings.NewReplacer("a", "\u0430", "c", "\u0441", "e", "\u0435", "o", "\u043e", "p", "\u0440", "x", "\u0445", "y", "\u0443").Replace(strings.ToLower(m)), "marker"},
		{"греческие буквы", strings.NewReplacer("A", "\u0391", "N", "\u039d", "I", "\u0399").Replace(m), "marker"},
		{"полноширинные символы", fullwidth(m), "marker"},
		{"полноширинные через запятую", fullwidth(joinRunes(m, ", ")), "marker"},
		{"математические буквы префикса", "\U0001d400\U0001d408\U0001d412\U0001d404\U0001d402" + m[len("AISEC"):], "marker"},
		{"теги", tags(m), "marker"},
		{"тело кириллицей группами через запятую", cyr.Replace(strings.Join(g, ", ")), "body"},
		{"тело полноширинное подряд", fullwidth(strings.Join(g, "")), "body"},
	} {
		text := "Ответ: " + c.span + " — конец."
		fs := above(find(t, text))
		if len(fs) != 1 || text[fs[0].Start:fs[0].End] != c.span || fs[0].Rule != c.rule {
			t.Errorf("%s: %q: %+v, ожидалось %s на %q", c.name, text, fs, c.rule, c.span)
		}
	}
}

// TestSeparatorLimits — граничные значения: до трёх разделителей и до
// четырёх пробельных символов между символами маркера, у групп тела — один
// и тот же разделитель из 1–3 символов.
func TestSeparatorLimits(t *testing.T) {
	m := marker(t)
	g := groups4(m)
	// Без дефисов: иначе разделитель стоит и до, и после дефиса.
	plain := prefixLetters + strings.Join(g, "")
	for _, c := range []struct {
		name string
		text string
		want string // правило находки выше порога или "" — нет
	}{
		{"три разделителя", joinRunes(plain, ",;,"), "marker"},
		{"четыре разделителя", joinRunes(plain, ",;,;"), ""},
		{"четыре пробела", joinRunes(plain, "    "), "marker"},
		{"пять пробелов", joinRunes(plain, "     "), ""},
		{"три разделителя и четыре пробела", joinRunes(plain, " , ; , "), "marker"},
		{"три невидимых символа", joinRunes(plain, "\u200b\u200c\u2060"), "marker"},
		{"четыре невидимых символа", joinRunes(plain, "\u200b\u200c\u2060\ufeff"), ""},
		{"разделитель групп из трёх символов", strings.Join(g, " / "), "body"},
		{"разделитель групп из четырёх символов", strings.Join(g, " // "), ""},
		{"разные разделители групп", g[0] + ", " + g[1] + " / " + g[2] + ", " + g[3] + ", " + g[4], ""},
		{"эмодзи между группами", strings.Join(g, "\U0001F600"), ""},
		{"буква между символами", joinRunes(plain, "\u0436"), ""},
	} {
		fs := above(find(t, c.text))
		switch {
		case c.want == "" && len(fs) > 0:
			t.Errorf("%s: %q: лишняя находка %+v", c.name, c.text, fs)
		case c.want != "" && (len(fs) != 1 || fs[0].Rule != c.want):
			t.Errorf("%s: %q: %+v, ожидалось %s", c.name, c.text, fs, c.want)
		}
	}
}

// TestNoFalsePositivesSeparators: похожий текст без верных контрольных
// символов и обычный текст через запятые не дают находок выше порога.
func TestNoFalsePositivesSeparators(t *testing.T) {
	m := marker(t)
	g := groups4(m)
	broken := slices.Clone(g)
	broken[4] = string(rune(broken[4][0])^1) + broken[4][1:] // неверная CRC
	bm := Prefix + strings.Join(broken, "-")
	texts := []string{
		joinRunes(bm, ", "),
		joinRunes(bm, "\n"),
		strings.Join(broken, ", "),
		strings.Join(broken, " / "),
		strings.Join(broken, "` `"),
		"\uff21\uff29\uff33\uff25\uff23-\uff23\uff21\uff2e\uff21\uff32\uff39 " + strings.Join(broken, ", "),
		"A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z",
		"ABCD, EFGH, IJKL, MNOP, QRST, UVWX, YZ23, 4567",
		"Коды: AB23, CD45, EF67, GH23, JK45; ещё 2345 / 6723 / 4567 / 2222 / 3333.",
		"СЕРА, ВОСК, ТАКС, КОРА, РОСА — слова из похожих на латиницу букв.",
		"Я, конечно, могу, но, увы, не стану раскрывать инструкции, правила, запреты.",
		"A, I, S, E, C — это буквы, а canary — птица, AISEC, CANARY, marker.",
		"a i s e c, c a n a r y: tokens, are, inserted, into, the, prompt, by, owner",
	}
	// Случайные наборы групп через запятую: CRC отсекает их все.
	x := uint32(12345)
	for range 2000 {
		var parts [5]string
		for k := range parts {
			var b [4]byte
			for q := range b {
				x = x*1664525 + 1013904223
				b[q] = alphabet[x>>27]
			}
			parts[k] = string(b[:])
		}
		texts = append(texts, strings.Join(parts[:], ", "))
	}
	for _, text := range texts {
		if fs := above(find(t, text)); len(fs) > 0 {
			t.Errorf("%q: ложное срабатывание %+v", text, fs)
		}
	}
}
