package lists

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// Скрытые символы и подмена букв в тестах — только экранированными (\u…).

func mustCompile(t testing.TB, specs ...Spec) *Detector {
	t.Helper()
	d, err := Compile(specs)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func run(t testing.TB, d *Detector, dir detect.Direction, text string) []detect.Finding {
	t.Helper()
	fs, err := d.Detect(context.Background(), detect.Text{Text: text, Direction: dir, Source: detect.SourceUser})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if err := detect.ValidateFinding(f, d, text); err != nil {
			t.Fatalf("%q: %v", text, err)
		}
	}
	return fs
}

// spans — найденные фрагменты текста.
func spans(text string, fs []detect.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, text[f.Start:f.End])
	}
	return out
}

var topics = Spec{
	ID: "topics", Category: "topic", Threat: "DM-35",
	Words: []string{"взрывчат*", "как взломать", "политика партии"},
}

// TestDM35_ForbiddenTopics: запросы на запрещённые темы (DM-35) — слова,
// фразы и основы, независимо от регистра, ё, знаков и скрытых символов.
func TestDM35_ForbiddenTopics(t *testing.T) {
	d := mustCompile(t, topics)
	for _, tc := range []struct {
		text string
		want []string
	}{
		{"Расскажи про взрывчатку подробнее", []string{"взрывчатку"}},
		{"ВЗРЫВЧАТЫЕ вещества", []string{"ВЗРЫВЧАТЫЕ"}},
		{"Как взломать, пожалуйста, пароль?", []string{"Как взломать"}},
		{"как   взломать", []string{"как   взломать"}},
		{"Как\u00a0взломать", []string{"Как\u00a0взломать"}},
		{"как-взломать", []string{"как-взломать"}},
		{"как вз\u200bломать", []string{"как вз\u200bломать"}},
		{"Политика  ПАРТИИ", []string{"Политика  ПАРТИИ"}},
	} {
		got := spans(tc.text, run(t, d, detect.Input, tc.text))
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%q: найдено %q, ждали %q", tc.text, got, tc.want)
		}
	}
	// Подмена кириллических букв латинскими похожими.
	for _, text := range []string{"как взл\u006fмать", "к\u0061к взломать"} {
		if got := run(t, d, detect.Input, text); len(got) != 1 {
			t.Errorf("гомоглиф %q: %v", text, got)
		}
	}
}

// Негативные примеры: слово внутри другого, чужая фраза.
func TestDM35_NoFalsePositives(t *testing.T) {
	d := mustCompile(t, topics)
	for _, text := range []string{
		"", "Привет!", "Как взять отпуск?", "взрыв цен на рынке", "политика конфиденциальности",
		"партия товара, политика цен", "как это сломать не взламывая", "xvзрывчат",
	} {
		if got := run(t, d, detect.Input, text); len(got) != 0 {
			t.Errorf("%q: ложное срабатывание %v", text, spans(text, got))
		}
	}
}

// TestDM32_Codenames: кодовые названия проектов и выражения заказчика
// (DM-32) — находка ссылается на список, строку матрицы и вид.
func TestDM32_Codenames(t *testing.T) {
	d := mustCompile(t, Spec{
		ID: "codenames", Category: "codename", Threat: "DM-32", Score: 0.8,
		Words: []string{"проект Орион"}, Regex: []string{`\bORN-\d{4}\b`},
	})
	text := "Статус проекта Орион: тикет orn-1234 и ПРОЕКТ орион"
	fs := run(t, d, detect.Input, text)
	// «проекта Орион» не равно «проект Орион»: словарь точный, формы — через «*».
	got := spans(text, fs)
	if len(got) != 2 || got[0] != "orn-1234" || got[1] != "ПРОЕКТ орион" {
		t.Fatalf("найдено %q", got)
	}
	for _, f := range fs {
		if f.Category != "lists.codename" || f.Threat != "DM-32" || f.Score != 0.8 || !strings.HasPrefix(f.Rule, "list.codenames.") {
			t.Errorf("находка %+v", f)
		}
	}
}

// Слова словаря с основой находят формы слов.
func TestDM18_StopWords(t *testing.T) {
	d := mustCompile(t, Spec{ID: "stop", Category: "stopword", Threat: "DM-18", Words: []string{"проект орион*", "idiot"}})
	text := "проект Орионом занимается Idiot"
	if got := spans(text, run(t, d, detect.Input, text)); len(got) != 2 || got[0] != "проект Орионом" {
		t.Fatalf("найдено %q", got)
	}
}

// Направление списка: список «output» не срабатывает на запросе и наоборот.
func TestDirection(t *testing.T) {
	d := mustCompile(t,
		Spec{ID: "in", Direction: "input", Words: []string{"секрет один"}},
		Spec{ID: "out", Direction: "output", Words: []string{"секрет два"}, Regex: []string{`ZZ\d`}},
		Spec{ID: "both", Words: []string{"секрет три"}},
	)
	text := "секрет один секрет два секрет три ZZ1"
	rules := func(dir detect.Direction) string {
		var rs []string
		for _, f := range run(t, d, dir, text) {
			rs = append(rs, f.Rule)
		}
		return strings.Join(rs, ",")
	}
	if got := rules(detect.Input); got != "list.in.word,list.both.word" {
		t.Errorf("вход: %s", got)
	}
	if got := rules(detect.Output); got != "list.out.word,list.both.word,list.out.re" {
		t.Errorf("выход: %s", got)
	}
}

// Регистр в выражениях: по умолчанию без учёта, case_sensitive — с учётом.
func TestRegexCase(t *testing.T) {
	ci := mustCompile(t, Spec{ID: "a", Regex: []string{`проект-\d+`}})
	cs := mustCompile(t, Spec{ID: "a", Regex: []string{`проект-\d+`}, CaseSensitive: true})
	if len(run(t, ci, detect.Input, "ПРОЕКТ-42")) != 1 || len(run(t, cs, detect.Input, "ПРОЕКТ-42")) != 0 {
		t.Error("учёт регистра")
	}
}

// Р5: правила заказчика ограничены, ошибки возвращаются списком.
func TestCustomerRuleLimits(t *testing.T) {
	long := strings.Repeat("a", MaxWordBytes+1)
	manyWords := make([]string, MaxWordsPerList+1)
	for i := range manyWords {
		manyWords[i] = fmt.Sprintf("слово%d", i)
	}
	manyRegex := make([]string, MaxRegexTotal+1)
	for i := range manyRegex {
		manyRegex[i] = fmt.Sprintf("x%d", i)
	}
	manyLists := make([]Spec, MaxLists+1)
	for i := range manyLists {
		manyLists[i] = Spec{ID: fmt.Sprintf("l%d", i), Words: []string{"слово"}}
	}
	for name, specs := range map[string][]Spec{
		"пустой список":           {{ID: "a"}},
		"плохой id":               {{ID: "A_b", Words: []string{"слово"}}},
		"id длиннее 32":           {{ID: strings.Repeat("a", 33), Words: []string{"слово"}}},
		"дубль id":                {{ID: "a", Words: []string{"слово"}}, {ID: "a", Words: []string{"слово"}}},
		"плохая категория":        {{ID: "a", Category: "Topic", Words: []string{"слово"}}},
		"плохая строка матрицы":   {{ID: "a", Threat: "DM-01", Words: []string{"слово"}}},
		"оценка 2":                {{ID: "a", Score: 2, Words: []string{"слово"}}},
		"оценка 0,05":             {{ID: "a", Score: 0.05, Words: []string{"слово"}}},
		"плохое направление":      {{ID: "a", Direction: "x", Words: []string{"слово"}}},
		"длинное слово":           {{ID: "a", Words: []string{long}}},
		"одна буква":              {{ID: "a", Words: []string{"я"}}},
		"слово из знаков":         {{ID: "a", Words: []string{"!!!"}}},
		"звёздочка внутри":        {{ID: "a", Words: []string{"вз*ыв"}}},
		"короткая основа":         {{ID: "a", Words: []string{"вз*"}}},
		"длинная основа":          {{ID: "a", Words: []string{strings.Repeat("а", MaxStemRunes+1) + "*"}}},
		"много слов во фразе":     {{ID: "a", Words: []string{"а б в г д е ж з и"}}},
		"невалидный UTF-8":        {{ID: "a", Words: []string{"\xff\xfe"}}},
		"слов в списке":           {{ID: "a", Words: manyWords}},
		"выражений всего":         {{ID: "a", Regex: manyRegex}},
		"списков":                 manyLists,
		"длинное выражение":       {{ID: "a", Regex: []string{strings.Repeat("a", MaxRegexBytes+1)}}},
		"не RE2: обратная ссылка": {{ID: "a", Regex: []string{`(a)\1`}}},
		"не RE2: просмотр вперёд": {{ID: "a", Regex: []string{`a(?=b)`}}},
		"синтаксис":               {{ID: "a", Regex: []string{`(`}}},
		"пустое совпадение":       {{ID: "a", Regex: []string{`a*`}}},
		"раздутая программа":      {{ID: "a", Regex: []string{`((((a{1000}){1000}){1000}){1000})`}}},
		"пустое выражение":        {{ID: "a", Regex: []string{""}}},
	} {
		if _, err := Compile(specs); err == nil {
			t.Errorf("%s: правила приняты", name)
		}
	}
	// Все ошибки сразу.
	err := Validate([]Spec{{ID: "A"}, {ID: "b", Regex: []string{"("}}})
	if err == nil || strings.Count(err.Error(), "lists[") < 2 {
		t.Errorf("ошибки списком: %v", err)
	}
	// Предельные значения принимаются.
	if _, err := Compile([]Spec{{ID: strings.Repeat("a", 32), Words: []string{strings.Repeat("а", MaxWordBytes/2)}, Regex: []string{strings.Repeat("a", MaxRegexBytes)}}}); err != nil {
		t.Errorf("граничные значения: %v", err)
	}
}

// Р5: выражение, катастрофическое для перебора, работает за линейное время.
func TestRegexLinearTime(t *testing.T) {
	d := mustCompile(t, Spec{ID: "a", Regex: []string{`(a+)+$`, `(x|xx)*y`}})
	text := strings.Repeat("a", 1<<20) + "b"
	start := time.Now()
	run(t, d, detect.Input, text)
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("%v на 1 МиБ", el)
	}
}

// Предел находок.
func TestFindingsCap(t *testing.T) {
	d := mustCompile(t, Spec{ID: "a", Words: []string{"хх"}, Regex: []string{`yy`}})
	text := strings.Repeat("хх yy ", 5000)
	if n := len(run(t, d, detect.Input, text)); n != MaxFindings {
		t.Fatalf("находок %d, ждали %d", n, MaxFindings)
	}
}

// Фраза на границе частей текста находится, и ровно один раз.
func TestPartBoundary(t *testing.T) {
	d := mustCompile(t, Spec{ID: "a", Words: []string{"секретный проект орион"}})
	for off := partBytes - 40; off < partBytes+40; off++ {
		text := strings.Repeat("a", off) + " секретный проект Орион " + strings.Repeat("б", 3*partBytes)
		if n := len(run(t, d, detect.Input, text)); n != 1 {
			t.Fatalf("смещение %d: находок %d", off, n)
		}
	}
}

// TestDM35_PartBoundaryGap (замечание 5 ревью 1.17–1.21): слово, разорванное
// тысячами невидимых символов, и фраза с тысячами пробелов на стыке частей
// по 64 КиБ находятся так же, как в коротком тексте, и ровно один раз
// (DM-35).
func TestDM35_PartBoundaryGap(t *testing.T) {
	d := mustCompile(t, topics)
	for _, c := range []struct{ name, frag string }{
		{"невидимые внутри слова", "взрыв" + strings.Repeat("\u200b", 3000) + "чатка"},
		{"пробелы внутри фразы", "как" + strings.Repeat(" ", 3000) + "взломать"},
		{"пробелов больше части", "как" + strings.Repeat(" ", partBytes+5000) + "взломать"},
		{"переводы строк внутри фразы", "политика" + strings.Repeat("\n", 5000) + "партии"},
	} {
		// Короткий текст — одна находка.
		if fs := run(t, d, detect.Input, "x "+c.frag+" y"); len(fs) != 1 {
			t.Fatalf("%s, короткий текст: %+v", c.name, fs)
		}
		// Фрагмент начинается за off байт до стыка частей (partBytes).
		for _, off := range []int{1, 5, 100, 1000, len(c.frag) / 2, len(c.frag) - 10} {
			filler := strings.Repeat("word ", max(partBytes-off, 0)/5) // много токенов до стыка
			text := filler + c.frag + " " + strings.Repeat("б", 2*partBytes)
			fs := run(t, d, detect.Input, text)
			if len(fs) != 1 || text[fs[0].Start:fs[0].End] != c.frag {
				t.Fatalf("%s, за %d байт до стыка: находок %d", c.name, off, len(fs))
			}
		}
	}
}

// Перекрытие частей в словах не делает работу квадратичной: части почти
// без слов (по десять токенов на 64 КиБ) проходят за линейное время.
func TestPartsLinearTime(t *testing.T) {
	d := mustCompile(t, topics)
	block := "а б в г д е ж з и к " + strings.Repeat(" ", partBytes-20)
	text := strings.Repeat(block, 64) // 4 МиБ
	start := time.Now()
	run(t, d, detect.Input, text)
	sparse := time.Since(start)
	dense := strings.Repeat("слово ", len(text)/12)
	start = time.Now()
	run(t, d, detect.Input, dense)
	el := time.Since(start)
	t.Logf("редкие слова %v, плотный текст %v", sparse, el)
	if sparse > 5*time.Second {
		t.Fatalf("%v на 4 МиБ", sparse)
	}
}

// TestDM35_CombiningMarks (замечание 6 ревью 1.17–1.21): комбинируемые знаки
// не обходят словарь — ударения и прочие знаки над буквами пропускаются,
// разложенные «й» (и + U+0306) и «ё» (е + U+0308) равны составным (DM-35).
func TestDM35_CombiningMarks(t *testing.T) {
	d := mustCompile(t, topics, Spec{ID: "marks", Words: []string{"секретный узел", "тве\u0308рдый актив", "йод*"}})
	for _, tc := range []struct {
		text string
		want []string
	}{
		{"как сделать взры\u0301вчатку", []string{"взры\u0301вчатку"}},
		{"ка\u0301к взлома\u0301ть", []string{"ка\u0301к взлома\u0301ть"}},
		{"в\u0300\u0301\u0302\u0303зрывчатка", []string{"в\u0300\u0301\u0302\u0303зрывчатка"}},
		{"секретны\u0438\u0306 узел", []string{"секретны\u0438\u0306 узел"}},
		{"СЕКРЕТНЫ\u0418\u0306 УЗЕЛ", []string{"СЕКРЕТНЫ\u0418\u0306 УЗЕЛ"}},
		{"твёрдый актив", []string{"твёрдый актив"}},
		{"тве\u0308рдый актив", []string{"тве\u0308рдый актив"}},
		{"твердый актив", []string{"твердый актив"}},
		{"и\u0306одистый", []string{"и\u0306одистый"}},
		{"взрывча\u0301тка\u0301", []string{"взрывча\u0301тка\u0301"}},
		// «и» без бревиса — другое слово.
		{"секретныи узел", nil},
		{"иод", nil},
		{"взрыв\u0301 ча\u0301т", nil},
	} {
		fs := run(t, d, detect.Input, tc.text)
		if got := spans(tc.text, fs); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%q: найдено %q, ожидалось %q", tc.text, got, tc.want)
		}
		for _, f := range fs {
			if f.Threat != "DM-35" {
				t.Errorf("%q: строка матрицы %s", tc.text, f.Threat)
			}
		}
	}
}

// Встроенный список грифов.
func TestDefaultMarks(t *testing.T) {
	d := New()
	text := "Документ СТРОГО конфиденциально, для служебного пользования"
	fs := run(t, d, detect.Input, text)
	if len(fs) != 2 || fs[0].Threat != "DM-32" || fs[0].Category != "lists.marker" {
		t.Fatalf("находки %+v", fs)
	}
	if len(run(t, d, detect.Output, text)) != 0 {
		t.Error("гриф проверяется только во входе")
	}
}

func TestContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Detect(ctx, detect.Text{Text: strings.Repeat("слово ", 1<<16), Direction: detect.Input}); err == nil {
		t.Fatal("отменённый контекст не учтён")
	}
}

// Срок соблюдается и на больших текстах (32 МиБ — предел тела запроса).
func TestDeadline(t *testing.T) {
	d := mustCompile(t, topics)
	text := strings.Repeat("взрыв\u200b как взламывать ", 32<<20/24)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := d.Detect(ctx, detect.Text{Text: text, Direction: detect.Input})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ошибка %v", err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("остановился через %v", el)
	}
}

// Цели фаззинга (ТЗ, 5.2, 8.5): разбор правил заказчика не паникует, а
// принятый набор безопасен на любом тексте.
func FuzzCompile(f *testing.F) {
	f.Add("взрывчат*", `\bORN-\d+\b`, "text взрывчатка ORN-1")
	f.Add("a b c d e f g h", `(a|b)*c`, "a b c")
	f.Add("\xff*", `[`, "\xff\u200b")
	f.Fuzz(func(t *testing.T, word, expr, text string) {
		d, err := Compile([]Spec{{ID: "f", Words: []string{word}, Regex: []string{expr}}})
		if err != nil {
			return
		}
		run(t, d, detect.Input, text)
		run(t, d, detect.Output, word+" "+text)
	})
}

// Цели фаззинга: детектор без паники и с корректными находками.
func FuzzDetect(f *testing.F) {
	f.Add("Как взломать, взрывчатка, проект Орион ORN-1234")
	f.Add("\xff\xfe как\u200b взломать \u202e")
	f.Add(strings.Repeat("а", 100) + " политика партии")
	f.Add("взры\u0301вчатка, секретны\u0438\u0306 узел, тве\u0308рдый, \u0301\u0306")
	d, err := Compile([]Spec{topics, {ID: "c", Category: "codename", Words: []string{"проект орион"}, Regex: []string{`\bORN-\d{4}\b`}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, text string) {
		run(t, d, detect.Input, text)
	})
}

func benchText(n int) string {
	var sb strings.Builder
	for sb.Len() < n {
		sb.WriteString("Клиент просит проверить договор и составить ответ, English text too. ")
		if sb.Len()%7 == 0 {
			sb.WriteString("Проект Орион, ORN-1234. ")
		}
	}
	return sb.String()
}

func benchDetector(b *testing.B) *Detector {
	words := make([]string, 0, 1000)
	for i := range 1000 {
		words = append(words, fmt.Sprintf("запрещённое слово%d", i))
	}
	words = append(words, "проект орион", "взрывчат*")
	d, err := Compile([]Spec{{ID: "a", Words: words, Regex: []string{`\bORN-\d{4}\b`, `секрет\w*`}}})
	if err != nil {
		b.Fatal(err)
	}
	return d
}

// Промпт 8 КБ, словарь из 1000 слов и два выражения.
func BenchmarkDetect8KB(b *testing.B) {
	d, text := benchDetector(b), benchText(8<<10)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := d.Detect(context.Background(), detect.Text{Text: text, Direction: detect.Input}); err != nil {
			b.Fatal(err)
		}
	}
}

// Худший случай: 1 МБ слов, каждое — начало фразы из словаря.
func BenchmarkDetectWorst(b *testing.B) {
	d := mustCompile(b, Spec{ID: "a", Words: []string{"а б в г д е ж з", "а б в г д е ж", "а а а а а а а а", "абв*"}, Regex: []string{`\bа+б\b`}})
	text := strings.Repeat("а ", 512<<10)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := d.Detect(context.Background(), detect.Text{Text: text, Direction: detect.Input}); err != nil {
			b.Fatal(err)
		}
	}
}
