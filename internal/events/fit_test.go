package events

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// В10 ревью 2.r3a: «<» без HTML-экранирования занимает 1 байт, и 2 × 64 КиБ
// таких символов помещаются в предел шифротекста целиком.
func TestMarshalContentNoHTMLEscape(t *testing.T) {
	c := Content{Request: strings.Repeat("<", MaxContentBytes), Response: strings.Repeat("&>", MaxContentBytes/2)}
	b, err := MarshalContent(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 2*MaxContentBytes+64 {
		t.Fatalf("длина %d: HTML экранирован", len(b))
	}
	var back Content
	if err := json.Unmarshal(b, &back); err != nil || back != c {
		t.Fatalf("обратное чтение: %v", err)
	}
	// Прежняя запись с экранированием читается так же.
	old, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(old, &back); err != nil || back != c {
		t.Fatalf("прежняя запись: %v", err)
	}
	if fit, cut := FitContent(c, MaxSealedPlain); cut || fit != c {
		t.Fatal("«<» обрезано, хотя помещается")
	}
}

func TestFitContent(t *testing.T) {
	ctl := strings.Repeat("\x01", MaxContentBytes)
	cases := map[string]struct {
		in       Content
		cut      bool
		reqWhole bool // запрос сохранён целиком
	}{
		"короткое":                 {Content{Request: "привет", Response: "ответ"}, false, true},
		"управляющие в обоих":      {Content{Request: ctl, Response: ctl}, true, false},
		"управляющие в ответе":     {Content{Request: "короткий запрос", Response: ctl + ctl + ctl}, true, true},
		"только запрос":            {Content{Request: ctl + ctl + ctl + ctl + ctl}, true, false},
		"кириллица и управляющие":  {Content{Request: strings.Repeat("я\x02", MaxContentBytes/3), Response: ctl}, true, false},
		"4-байтные и управляющие":  {Content{Request: strings.Repeat("😀\x03", MaxContentBytes/5), Response: ctl}, true, false},
		"переводы строк и кавычки": {Content{Request: strings.Repeat("\"\n\\", MaxContentBytes/3), Response: ctl}, true, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, cut := FitContent(c.in, MaxSealedPlain)
			if cut != c.cut {
				t.Fatalf("обрезка %v, ожидалась %v", cut, c.cut)
			}
			checkFit(t, c.in, got, MaxSealedPlain)
			if c.reqWhole && got.Request != c.in.Request {
				t.Fatal("короткий запрос обрезан")
			}
			if cut && len(got.Request)+len(got.Response) < MaxSealedPlain/7 {
				t.Fatalf("обрезано слишком много: %d + %d байт", len(got.Request), len(got.Response))
			}
		})
	}
}

// checkFit — общие свойства результата FitContent.
func checkFit(t *testing.T, in, got Content, limit int) {
	t.Helper()
	b, err := MarshalContent(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > limit {
		t.Fatalf("открытый текст %d байт больше предела %d", len(b), limit)
	}
	for _, p := range [][2]string{{in.Request, got.Request}, {in.Response, got.Response}} {
		orig, fit := p[0], p[1]
		if !utf8.ValidString(fit) && utf8.ValidString(orig) {
			t.Fatal("обрезка посреди символа")
		}
		if fit != orig && (!strings.HasSuffix(fit, truncMark) || !strings.HasPrefix(orig, strings.TrimSuffix(fit, truncMark))) {
			t.Fatalf("обрезанный текст — не начало исходного с «…»: %q", fit)
		}
	}
}

func FuzzFitContent(f *testing.F) {
	f.Add("привет", "<>&", 200)
	f.Add(strings.Repeat("\x01", 300), "ответ", 120)
	f.Add("😀😀😀", strings.Repeat("\"", 100), 40)
	f.Add("", "", 30)
	f.Fuzz(func(t *testing.T, req, resp string, limit int) {
		// Предел — не меньше ключей JSON и двух отметок обрезки.
		if limit < 40 || limit > 1<<20 {
			return
		}
		in := Content{Request: req, Response: resp}
		got, _ := FitContent(in, limit)
		checkFit(t, in, got, limit)
	})
}
