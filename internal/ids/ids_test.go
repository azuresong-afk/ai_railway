package ids

import (
	"errors"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func gen(t *testing.T) *Generator {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	return NewGenerator(r)
}

func TestNewFormat(t *testing.T) {
	g := gen(t)
	fixed := time.Date(2026, 10, 5, 12, 0, 0, 123_000_000, time.UTC)
	g.now = func() time.Time { return fixed }
	u, err := g.New()
	if err != nil {
		t.Fatal(err)
	}
	s := u.String()
	if len(s) != 36 || s[14] != '7' || !strings.ContainsRune("89ab", rune(s[19])) || s != strings.ToLower(s) {
		t.Fatalf("неверная запись UUIDv7: %s", s)
	}
	if !u.Time().Equal(fixed) {
		t.Fatalf("время %v, ожидалось %v", u.Time(), fixed)
	}
	back, err := Parse(s)
	if err != nil || back != u {
		t.Fatalf("Parse(String()) = %v, %v", back, err)
	}
	if up, err := Parse(strings.ToUpper(s)); err != nil || up != u {
		t.Fatal("прописные цифры должны разбираться")
	}
}

func TestOrderingAndUniqueness(t *testing.T) {
	g := gen(t)
	base := time.Now()
	seen := map[UUID]bool{}
	var prev string
	for i := range 10_000 {
		g.now = func() time.Time { return base.Add(time.Duration(i) * time.Millisecond) }
		u, err := g.New()
		if err != nil {
			t.Fatal(err)
		}
		if seen[u] {
			t.Fatal("повтор идентификатора")
		}
		seen[u] = true
		if s := u.String(); s <= prev {
			t.Fatalf("идентификаторы не упорядочены по времени: %s после %s", s, prev)
		} else {
			prev = s
		}
	}
}

type failRandom struct{}

func (failRandom) Read([]byte) error { return errors.New("нет случайности") }

func TestRandomFailure(t *testing.T) {
	if _, err := NewGenerator(failRandom{}).New(); err == nil {
		t.Fatal("ошибка источника случайности должна возвращаться")
	}
}

func TestTimeOutOfRange(t *testing.T) {
	g := gen(t)
	g.now = func() time.Time { return time.UnixMilli(-1) }
	if _, err := g.New(); err == nil {
		t.Fatal("время до 1970 года должно отвергаться")
	}
}

func TestParseRejects(t *testing.T) {
	for _, s := range []string{
		"",
		"0192f1a0-7b3c-7d4e-8f00-00000000000",    // короче
		"0192f1a0-7b3c-4d4e-8f00-000000000000",   // версия 4
		"0192f1a0-7b3c-7d4e-cf00-000000000000",   // вариант 110
		"0192f1a07b3c-7d4e-8f00-0000000000000",   // дефисы не на месте
		"0192f1a0-7b3c-7d4e-8f00-00000000000g",   // не шестнадцатеричная цифра
		"{0192f1a0-7b3c-7d4e-8f00-000000000000}", // фигурные скобки
	} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q): ожидалась ошибка", s)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("0192f1a0-7b3c-7d4e-8f00-000000000000")
	f.Add("not-a-uuid")
	f.Fuzz(func(t *testing.T, s string) {
		u, err := Parse(s)
		if err != nil {
			return
		}
		if !strings.EqualFold(u.String(), s) {
			t.Fatalf("Parse(%q).String() = %q", s, u.String())
		}
	})
}
