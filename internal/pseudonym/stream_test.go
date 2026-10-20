package pseudonym

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// streamVault — словарь с телефонами [[PHONE_1]], [[PHONE_2]] и паролем с
// кавычкой [[PASSWORD_1]]; одинаков при каждом вызове.
func streamVault(t testing.TB) *Vault {
	t.Helper()
	v := NewVault(Limits{})
	text := pii.SynthPhone(1) + " " + pii.SynthPhone(2) + ` п"ароль`
	spans := []Span{
		{0, len(pii.SynthPhone(1)), pii.CatPhone, policy.Pseudonymize},
		{len(pii.SynthPhone(1)) + 1, len(pii.SynthPhone(1)) + 1 + len(pii.SynthPhone(2)), pii.CatPhone, policy.Pseudonymize},
		{len(text) - len(`п"ароль`), len(text), "secret.password", policy.Pseudonymize},
	}
	if _, err := v.Protect(text, spans); err != nil {
		t.Fatal(err)
	}
	return v
}

// streamAll — склейка Write по частям и Flush; проверяет предел задержки.
func streamAll(t testing.TB, s *Stream, parts []string) string {
	t.Helper()
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(s.Write(p))
		if s.Pending() > MaxPending {
			t.Fatalf("задержано %d байт, предел %d", s.Pending(), MaxPending)
		}
	}
	b.WriteString(s.Flush())
	if s.Pending() != 0 {
		t.Fatal("после Flush остался хвост")
	}
	return b.String()
}

var streamTexts = []string{
	"Ваш телефон [[PHONE_1]], второй — [[PHONE_2]].",
	`Экранировано: \[\[PHONE\_2\]\] и [ phone-1 ] и [[PHONE_1]`,
	"Конец на скобке [[PHONE_1]",
	"Обрыв [[PHONE_1",
	"Ссылка https://evil.example/?q=[[PHONE_1]] и потом [[PHONE_2]]",
	"Неизвестный [[PHONE_7]] и [[INN_1]] и [[ТЕЛЕФОН_1]] и [[PASSWORD_1]]",
	"[[[[PHONE_1]]]] \\\\[[PHONE_2]] [x] [[ [[PHONE_1]]",
	"Юникод: «[[PHONE_1]]» — ёж 🦔 [[PHONE_2]]",
	// Правило мест смотрит байты после псевдонима: решение не должно
	// зависеть от того, где разрезан текст после него.
	"Поддомен [[PHONE_1]].evil.example, конец [[PHONE_2]]. Далее [[PHONE_1]].",
	"IDN [[PHONE_1]].пример.рф, «[[PHONE_2]].» и [[PHONE_1]].ё",
	"Порт [[PHONE_1]]:80, вопрос [[PHONE_2]]? и [PHONE_1]@x [[PHONE_2]]\\.x",
}

// TestStreamSplitEverywhere — результат не зависит от разбиения: на две
// части в каждой позиции и по одному байту.
func TestStreamSplitEverywhere(t *testing.T) {
	jsonTexts := []string{
		`{"a":"[[PASSWORD_1]]","b":"тел [[PHONE_1]]","u":"https:\/\/x\/[[PHONE_2]]"}`,
		`{"q":"\"[[PASSWORD_1]]\\","r":[[PHONE_1]]}`,
		`{"a":"[[PHONE_1]].x","b":"[[PHONE_2]]\u002e","c":"[[PHONE_1]]. ок","d":"пример.рф","e":"[[PHONE_2]]"}`,
	}
	check := func(t *testing.T, text string, json bool) {
		restore, stream := streamVault(t), streamVault(t)
		newStream, want := stream.NewStream, ""
		if json {
			newStream, want = stream.NewJSONStream, restore.RestoreJSON(text)
		} else {
			want = restore.Restore(text)
		}
		for cut := 0; cut <= len(text); cut++ {
			if got := streamAll(t, newStream(), []string{text[:cut], text[cut:]}); got != want {
				t.Fatalf("разрез %d: %q, ожидалось %q", cut, got, want)
			}
		}
		var bytes []string
		for i := range len(text) {
			bytes = append(bytes, text[i:i+1])
		}
		if got := streamAll(t, newStream(), bytes); got != want {
			t.Fatalf("по байту: %q, ожидалось %q", got, want)
		}
	}
	for _, text := range streamTexts {
		check(t, text, false)
	}
	for _, text := range jsonTexts {
		check(t, text, true)
	}
}

// TestStreamHoldsOnlyCandidate — задерживается только возможный псевдоним,
// остальное отдаётся сразу.
func TestStreamHoldsOnlyCandidate(t *testing.T) {
	v := streamVault(t)
	s := v.NewStream()
	if got := s.Write("Телефон: [[PHO"); got != "Телефон: " || s.Pending() != len("[[PHO") {
		t.Fatalf("Write: %q, задержано %d", got, s.Pending())
	}
	if got := s.Write("NE_1]"); got != "" {
		t.Fatalf("до второй скобки ничего не отдаётся: %q", got)
	}
	if got := s.Write("] готово"); got != pii.SynthPhone(1)+" готово" {
		t.Fatalf("Write: %q", got)
	}
	// Возможный псевдоним с переведённым типом ждёт решения (метрика).
	if got := s.Write("[[ВОТ"); got != "" || s.Pending() != len("[[ВОТ") {
		t.Fatalf("Write: %q, задержано %d", got, s.Pending())
	}
	if got := s.Write(" и всё "); got != "[[ВОТ и всё " || s.Pending() != 0 {
		t.Fatalf("не псевдоним задержан: %q", got)
	}
	// Длинная строка скобок и букв не копится: буфер ограничен.
	long := "[[" + strings.Repeat("A", 4*MaxPending)
	if got := s.Write(long); got != long {
		t.Fatalf("длинный кандидат задержан: %d из %d", len(got), len(long))
	}
	if got := s.Write("[[PHONE_1]"); got != "" {
		t.Fatalf("псевдоним с одной скобкой в конце части ждёт следующую: %q", got)
	}
	if got := s.Flush(); got != pii.SynthPhone(1) {
		t.Fatalf("Flush: %q", got)
	}
}

// FuzzStream — потоковая подстановка при любом тексте и разбиении: без
// паники, задержано не больше MaxPending, склейка равна Restore (RestoreJSON)
// всего текста, счётчики совпадают; из частей с верным UTF-8 — верный UTF-8.
func FuzzStream(f *testing.F) {
	for _, s := range streamTexts {
		f.Add(s, []byte{3, 7, 1, 30}, false)
	}
	f.Add(`{"a":"[[PASSWORD_1]]","u":"https:\/\/x\/[[PHONE_2]]"}`, []byte{9, 2, 11}, true)
	f.Add(`\[\[PHONE\_1\]\]`, []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, false)
	f.Add("[[PHONE_1]].пример [[PHONE_2]].", []byte{11, 1, 1, 1, 12}, false)
	f.Add(`{"h":"пример.рф","a":"[[PHONE_1]].x","b":"[[PHONE_2]]\u002e"}`, []byte{7, 4, 20, 1, 1}, true)
	f.Fuzz(func(t *testing.T, text string, cuts []byte, json bool) {
		if len(text) > 8192 || len(cuts) > 256 {
			return
		}
		var parts []string
		rest := text
		for _, c := range cuts {
			n := min(int(c), len(rest))
			parts = append(parts, rest[:n])
			rest = rest[n:]
		}
		parts = append(parts, rest)
		restore, stream := streamVault(t), streamVault(t)
		var want string
		var s *Stream
		if json {
			want, s = restore.RestoreJSON(text), stream.NewJSONStream()
		} else {
			want, s = restore.Restore(text), stream.NewStream()
		}
		validParts := true
		for _, p := range parts {
			validParts = validParts && utf8.ValidString(p)
		}
		var b strings.Builder
		for _, p := range parts {
			out := s.Write(p)
			if validParts && !utf8.ValidString(out) {
				t.Fatalf("из верного UTF-8 получен неверный: %q", out)
			}
			b.WriteString(out)
			if s.Pending() > MaxPending {
				t.Fatalf("задержано %d байт", s.Pending())
			}
		}
		b.WriteString(s.Flush())
		if got := b.String(); got != want {
			t.Fatalf("поток %q, целиком %q", got, want)
		}
		if restore.Stats() != stream.Stats() {
			t.Fatalf("счётчики: %+v и %+v", restore.Stats(), stream.Stats())
		}
	})
}
