package auth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func testRandom(t testing.TB) aisecCrypto.Random {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func testHasher(t testing.TB) aisecCrypto.Hasher {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCheckPassword(t *testing.T) {
	p := DefaultPolicy()
	ok := []string{
		"Синтетический-Пароль-42",
		"abcdefgH1234",     // ровно 12, три класса
		"пароль ПАРОЛЬ 12", // кириллица и пробел
		strings.Repeat("Aa1", 85),
	}
	for _, pw := range ok {
		if err := p.CheckPassword(pw, "ivanov"); err != nil {
			t.Errorf("%q: %v", pw, err)
		}
	}
	bad := []string{
		"",
		"Abcdefgh123",      // 11 символов
		"abcdefghijklmnop", // один класс
		"abcdefgh12345",    // два класса
		"Abcdefgh123\x00",  // управляющий символ
		"Abcdefgh123\n4",   // перевод строки
		"Abc-IVANOV-1234",  // содержит логин
		string([]byte{0xff, 'A', 'a', '1'}) + "bcdefghijk", // не UTF-8
		strings.Repeat("Aa1", 86),                          // длиннее 256 символов
		strings.Repeat("Я", 520) + "a1",                    // больше 1024 байт
	}
	for _, pw := range bad {
		var pe *PasswordError
		if err := p.CheckPassword(pw, "ivanov"); !errors.As(err, &pe) {
			t.Errorf("%q принят: %v", pw, err)
		}
	}
	// Короткий логин не проверяется на вхождение: «ab» есть почти в любом пароле.
	if err := p.CheckPassword("abcdefgH1234", "ab"); err != nil {
		t.Fatal(err)
	}
	one := p
	one.PasswordMinClasses = 1
	if err := one.CheckPassword("abcdefghijklmnop", "x"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyValidate(t *testing.T) {
	if err := DefaultPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
	mods := []func(*Policy){
		func(p *Policy) { p.PasswordMinLength = 7 },
		func(p *Policy) { p.PasswordMinLength = 65 },
		func(p *Policy) { p.PasswordMinClasses = 0 },
		func(p *Policy) { p.PasswordMinClasses = 5 },
		func(p *Policy) { p.PasswordHistory = -1 },
		func(p *Policy) { p.PasswordHistory = 25 },
		func(p *Policy) { p.PasswordMaxAgeDays = 366 },
		func(p *Policy) { p.PasswordWarnDays = 90 },
		func(p *Policy) { p.LockoutThreshold = 2 },
		func(p *Policy) { p.LockoutThreshold = 21 },
		func(p *Policy) { p.LockoutMinutes = -1 },
		func(p *Policy) { p.LockoutMinutes = 1441 },
		func(p *Policy) { p.SessionIdleMinutes = 0 },
		func(p *Policy) { p.SessionIdleMinutes = 241 },
		func(p *Policy) { p.SessionMaxPerUser = 0 },
		func(p *Policy) { p.SessionMaxPerUser = 21 },
		func(p *Policy) { p.TempPasswordHours = 0 },
		func(p *Policy) { p.TempPasswordHours = 169 },
	}
	for i, m := range mods {
		p := DefaultPolicy()
		m(&p)
		if p.Validate() == nil {
			t.Errorf("изменение %d принято: %+v", i, p)
		}
	}
	// Бессрочный пароль: предупреждение не сравнивается со сроком.
	p := DefaultPolicy()
	p.PasswordMaxAgeDays, p.PasswordWarnDays = 0, 30
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateTempPassword(t *testing.T) {
	r := testRandom(t)
	for _, minLen := range []int{8, 12, 20, 64} {
		p := DefaultPolicy()
		p.PasswordMinLength, p.PasswordMinClasses = minLen, 4
		seen := map[string]bool{}
		for range 200 {
			pw, err := GenerateTempPassword(r, p)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.CheckPassword(pw, "ivanov"); err != nil {
				t.Fatalf("%q: %v", pw, err)
			}
			if len(pw) != max(minLen, tempMinLen) || seen[pw] {
				t.Fatalf("длина %d или повтор: %q", len(pw), pw)
			}
			seen[pw] = true
		}
	}
}

func TestUniform(t *testing.T) {
	r := testRandom(t)
	counts := make([]int, 7)
	for range 7000 {
		i, err := uniform(r, 7)
		if err != nil {
			t.Fatal(err)
		}
		counts[i]++
	}
	for i, c := range counts {
		if c < 800 || c > 1200 {
			t.Fatalf("значение %d выпало %d раз из 7000", i, c)
		}
	}
}

func TestNormalizeLogin(t *testing.T) {
	ok := map[string]string{"Ivanov": "ivanov", "a": "a", "a.b-c_d": "a.b-c_d", "0x": "0x", strings.Repeat("a", 64): strings.Repeat("a", 64)}
	for in, want := range ok {
		if got, valid := NormalizeLogin(in); !valid || got != want {
			t.Errorf("%q → %q, %v", in, got, valid)
		}
	}
	for _, in := range []string{"", ".a", "-a", "_a", "a b", "иванов", "a@b", strings.Repeat("a", 65), "a\x00", "İvanov", "\u212a"} {
		if _, valid := NormalizeLogin(in); valid {
			t.Errorf("%q принят", in)
		}
	}
}

func TestCleanDisplayName(t *testing.T) {
	if got, ok := CleanDisplayName("  Петрова Анна  "); !ok || got != "Петрова Анна" {
		t.Fatalf("%q %v", got, ok)
	}
	// Управляющие, направление текста, нулевая ширина, разделители строк и абзацев.
	for _, in := range []string{"", "   ", "a\tb", "a\u0085b", string([]byte{0xff}), strings.Repeat("я", 201),
		"Анна\u202eанмиA", "a\u200bb", "a\u200fb", "a\u2066b", "a\u2028b", "a\u2029b", "a\ufeffb", "a\u00adb"} {
		if _, ok := CleanDisplayName(in); ok {
			t.Errorf("%q принят", in)
		}
	}
}

func TestCleanUserAgent(t *testing.T) {
	if got := cleanUserAgent("Mozilla/5.0\r\n\x00ä" + strings.Repeat("x", 300)); len(got) != MaxUserAgentLen || strings.ContainsAny(got, "\r\n\x00") {
		t.Fatalf("%q", got)
	}
}

func TestTokens(t *testing.T) {
	r, h := testRandom(t), testHasher(t)
	tok, hash, err := newToken(r, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != TokenLen {
		t.Fatalf("длина %d", len(tok))
	}
	got, err := hashToken(h, tok)
	if err != nil || !aisecCrypto.Equal(got, hash) {
		t.Fatalf("хеш не совпал: %v", err)
	}
	zero := strings.Repeat("A", TokenLen) // 32 нулевых байта — корректный токен
	if _, err := parseToken(zero); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"", tok[:42], tok + "A", tok[:42] + "=", tok[:42] + "\n", strings.Repeat("+", TokenLen),
		zero[:42] + "B", // лишние биты в последнем символе: неканоническая запись
		zero[:20] + "\r" + zero[21:],
	} {
		if _, err := parseToken(bad); err == nil {
			t.Errorf("%q принят", bad)
		}
	}
}

func FuzzParseToken(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB")
	f.Add("")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nA")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := parseToken(s)
		if err != nil {
			return
		}
		// Принятый токен однозначен: ровно 32 байта и обратное кодирование совпадает.
		if len(b) != tokenBytes || base64.RawURLEncoding.EncodeToString(b) != s {
			t.Fatalf("принят неканонический токен %q", s)
		}
	})
}

func FuzzNormalizeLogin(f *testing.F) {
	for _, s := range []string{"Ivanov", "a.b", "-a", "иванов", "", "A\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		l, ok := NormalizeLogin(s)
		if !ok {
			return
		}
		again, ok2 := NormalizeLogin(l)
		if !ok2 || again != l || len(l) > MaxLoginLen || l != strings.ToLower(l) {
			t.Fatalf("%q → %q: нормализация не идемпотентна или выходит за пределы", s, l)
		}
	})
}

func FuzzCheckPassword(f *testing.F) {
	for _, s := range []string{"Синтетический-Пароль-42", "short", "abcdefgH1234", "\x00\x01", strings.Repeat("Aa1", 90)} {
		f.Add(s, "ivanov")
	}
	p := DefaultPolicy()
	f.Fuzz(func(t *testing.T, pw, login string) {
		if p.CheckPassword(pw, login) != nil {
			return
		}
		n := utf8.RuneCountInString(pw)
		if !utf8.ValidString(pw) || n < p.PasswordMinLength || n > MaxPasswordRunes || len(pw) > aisecCrypto.MaxPasswordLen {
			t.Fatalf("принят пароль вне границ: %q", pw)
		}
	})
}

func FuzzCleanDisplayName(f *testing.F) {
	for _, s := range []string{"Петрова Анна", "  a  ", "a\u202eb", "a\u200bb", "\x00", strings.Repeat("я", 201)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := CleanDisplayName(s)
		if !ok {
			return
		}
		again, ok2 := CleanDisplayName(n)
		if !ok2 || again != n || !utf8.ValidString(n) || n == "" || utf8.RuneCountInString(n) > MaxDisplayNameLen {
			t.Fatalf("%q → %q: имя не идемпотентно или выходит за пределы", s, n)
		}
		for _, r := range n {
			if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
				t.Fatalf("%q: пропущен символ %U", n, r)
			}
		}
	})
}

func FuzzCleanUserAgent(f *testing.F) {
	for _, s := range []string{"Mozilla/5.0", "a\r\nb", "ä", strings.Repeat("x", 300)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ua := cleanUserAgent(s)
		if len(ua) > MaxUserAgentLen || cleanUserAgent(ua) != ua {
			t.Fatalf("%q → %q: длина или повторная очистка", s, ua)
		}
		for i := 0; i < len(ua); i++ {
			if c := ua[i]; c < 0x20 || c >= 0x7f {
				t.Fatalf("%q: непечатный байт %#x", ua, c)
			}
		}
	})
}
