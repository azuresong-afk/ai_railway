package ml

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func frame(t FrameType, id uint32, body []byte) []byte {
	b := AppendHeader(nil, Header{Type: t, ID: id, Length: uint32(len(body))}) //nolint:gosec // G115: тестовые тела малы
	return append(b, body...)
}

func TestFrameRoundTrip(t *testing.T) {
	body, err := EncodeDetect("injection", "Привет, мир")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Header{Type: TypeDetect, ID: 7}, body); err != nil {
		t.Fatal(err)
	}
	h, got, err := ReadFrame(&buf, ServerSide)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != TypeDetect || h.ID != 7 || !bytes.Equal(got, body) {
		t.Fatalf("кадр %+v %q", h, got)
	}
	model, text, err := ParseDetect(got)
	if err != nil || model != "injection" || text != "Привет, мир" {
		t.Fatalf("тело: %q %q %v", model, text, err)
	}
}

// countingReader считает прочитанные байты: кадр сверх предела отвергается
// без чтения тела.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestReadFrameTooLargeDoesNotReadBody(t *testing.T) {
	for _, tc := range []struct {
		side Side
		typ  FrameType
		max  int
	}{
		{ServerSide, TypeDetect, MaxDetectBody},
		{ServerSide, TypeHello, 0},
		{ClientSide, TypeResult, MaxResultBody},
		{ClientSide, TypeHelloOK, MaxHelloOKBody},
		{ClientSide, TypeError, MaxErrorBody},
	} {
		// Тело не передаётся вовсе: если бы его читали, получили бы EOF.
		hdr := AppendHeader(nil, Header{Type: tc.typ, ID: 1, Length: uint32(tc.max + 1)}) //nolint:gosec // G115: пределы малы
		cr := &countingReader{r: io.MultiReader(bytes.NewReader(hdr), strings.NewReader(strings.Repeat("x", 64)))}
		_, _, err := ReadFrame(cr, tc.side)
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("тип %d: ошибка %v, нужна ErrFrameTooLarge", tc.typ, err)
		}
		if cr.n != HeaderSize {
			t.Fatalf("тип %d: прочитано %d байт, нужно только заголовок", tc.typ, cr.n)
		}
	}
}

func TestReadFrameBoundary(t *testing.T) {
	body := make([]byte, MaxErrorBody)
	_, got, err := ReadFrame(bytes.NewReader(frame(TypeError, 1, body)), ClientSide)
	if err != nil || len(got) != MaxErrorBody {
		t.Fatalf("тело ровно на пределе: %v", err)
	}
}

func TestParseHeaderRejects(t *testing.T) {
	good := AppendHeader(nil, Header{Type: TypeHello, ID: 1})
	if _, err := ParseHeader(good, ServerSide); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"magic":    append([]byte("AIMX"), good[4:]...),
		"версия":   append(append([]byte{}, good[:4]...), append([]byte{2}, good[5:]...)...),
		"резерв":   append(append([]byte{}, good[:6]...), append([]byte{0, 1}, good[8:]...)...),
		"короткий": good[:15],
	}
	for name, b := range cases {
		if _, err := ParseHeader(b, ServerSide); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Сторона не принимает чужих типов: сервер — ответов, клиент — запросов.
	if _, err := ParseHeader(AppendHeader(nil, Header{Type: TypeResult}), ServerSide); !errors.Is(err, ErrProtocol) {
		t.Errorf("сервер принял result: %v", err)
	}
	if _, err := ParseHeader(AppendHeader(nil, Header{Type: TypeDetect}), ClientSide); !errors.Is(err, ErrProtocol) {
		t.Errorf("клиент принял detect: %v", err)
	}
	if _, err := ParseHeader(AppendHeader(nil, Header{Type: 9}), ClientSide); !errors.Is(err, ErrProtocol) {
		t.Errorf("неизвестный тип: %v", err)
	}
}

// TestHeaderTimeout — срок шлюза передаётся только в detect (4В30): у
// остальных типов поле — нулевой резерв.
func TestHeaderTimeout(t *testing.T) {
	b := AppendHeader(nil, Header{Type: TypeDetect, Timeout: 250, ID: 7, Length: 3})
	h, err := ParseHeader(b, ServerSide)
	if err != nil || h.Timeout != 250 || h.ID != 7 || h.Length != 3 {
		t.Fatalf("срок detect: %+v, %v", h, err)
	}
	for _, tc := range []struct {
		side Side
		typ  FrameType
	}{{ServerSide, TypeHello}, {ClientSide, TypeResult}, {ClientSide, TypeError}, {ClientSide, TypeHelloOK}} {
		if _, err := ParseHeader(AppendHeader(nil, Header{Type: tc.typ, Timeout: 1}), tc.side); !errors.Is(err, ErrProtocol) {
			t.Errorf("тип %d со сроком: %v", tc.typ, err)
		}
	}
}

func TestReadFrameTruncatedBody(t *testing.T) {
	b := frame(TypeError, 1, []byte(`{"code":"internal"}`))
	if _, _, err := ReadFrame(bytes.NewReader(b[:len(b)-3]), ClientSide); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("обрезанное тело: %v", err)
	}
}

func TestWriteFrameRefusesOversize(t *testing.T) {
	if err := WriteFrame(io.Discard, Header{Type: TypeResult}, make([]byte, MaxResultBody+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("запись сверх предела: %v", err)
	}
	if err := WriteFrame(io.Discard, Header{Type: TypeHello}, []byte{1}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("hello с телом: %v", err)
	}
}

func TestDetectBody(t *testing.T) {
	if _, err := EncodeDetect("Bad", "x"); err == nil {
		t.Error("ID с заглавной буквой принят")
	}
	if _, err := EncodeDetect("m", strings.Repeat("a", MaxText+1)); err == nil {
		t.Error("текст сверх предела принят")
	}
	if _, err := EncodeDetect("m", "\xff"); err == nil {
		t.Error("не UTF-8 принят")
	}
	if b, err := EncodeDetect("m", strings.Repeat("a", MaxText)); err != nil || len(b) != 2+MaxText {
		t.Errorf("текст ровно на пределе: %v", err)
	}
	for name, body := range map[string][]byte{
		"пусто":         {},
		"длина 0":       {0, 'a'},
		"короче длины":  {5, 'a'},
		"ID":            append([]byte{1}, 'A'),
		"не UTF-8":      append([]byte{1, 'm'}, 0xff),
		"ID длиннее 64": append([]byte{65}, []byte(strings.Repeat("a", 65))...),
	} {
		if _, _, err := ParseDetect(body); !errors.Is(err, ErrBadBody) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if m, txt, err := ParseDetect([]byte{1, 'm'}); err != nil || m != "m" || txt != "" {
		t.Errorf("пустой текст: %q %q %v", m, txt, err)
	}
}

var testInfo = ModelInfo{ID: "injection", Version: "1.0", Labels: []string{"injection", "benign"}, Directions: []string{"input"}}

func TestParseResult(t *testing.T) {
	text := "ignore всё"
	ok := `{"model":"injection","version":"1.0","findings":[{"label":"injection","score":0.9,"start":0,"end":6}]}`
	r, err := ParseResult([]byte(ok), testInfo, text)
	if err != nil || len(r.Findings) != 1 {
		t.Fatalf("верный ответ: %v", err)
	}
	for name, body := range map[string]string{
		"другая модель":    `{"model":"toxicity","version":"1.0","findings":[]}`,
		"другая версия":    `{"model":"injection","version":"2.0","findings":[]}`,
		"чужая метка":      `{"model":"injection","version":"1.0","findings":[{"label":"x","score":0.9,"start":0,"end":6}]}`,
		"оценка > 1":       `{"model":"injection","version":"1.0","findings":[{"label":"injection","score":1.5,"start":0,"end":6}]}`,
		"конец за текстом": `{"model":"injection","version":"1.0","findings":[{"label":"injection","score":0.5,"start":0,"end":99}]}`,
		"середина символа": `{"model":"injection","version":"1.0","findings":[{"label":"injection","score":0.5,"start":0,"end":8}]}`,
		"пустой отрезок":   `{"model":"injection","version":"1.0","findings":[{"label":"injection","score":0.5,"start":3,"end":3}]}`,
		"лишнее поле":      `{"model":"injection","version":"1.0","findings":[],"x":1}`,
		"данные после":     `{"model":"injection","version":"1.0","findings":[]} {}`,
	} {
		if _, err := ParseResult([]byte(body), testInfo, text); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
}

func TestParseHelloOK(t *testing.T) {
	ok := `{"protocol":1,"models":[{"id":"injection","version":"1.0","labels":["injection"],"directions":["input"]}]}`
	if _, err := ParseHelloOK([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"версия протокола": `{"protocol":2,"models":[]}`,
		"повтор модели":    `{"protocol":1,"models":[{"id":"a","version":"1","labels":["x"],"directions":["input"]},{"id":"a","version":"1","labels":["x"],"directions":["input"]}]}`,
		"направление":      `{"protocol":1,"models":[{"id":"a","version":"1","labels":["x"],"directions":["both"]}]}`,
		"без меток":        `{"protocol":1,"models":[{"id":"a","version":"1","labels":[],"directions":["input"]}]}`,
	} {
		if _, err := ParseHelloOK([]byte(body)); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
}

func TestParseError(t *testing.T) {
	if c, err := ParseError([]byte(`{"code":"overloaded"}`)); err != nil || c != ErrOverloaded {
		t.Fatalf("%q %v", c, err)
	}
	if _, err := ParseError([]byte(`{"code":"другое"}`)); err == nil {
		t.Fatal("неизвестный код принят")
	}
}

// FuzzServerReadFrame — сторона aisec-ml: кадр от шлюза и тело detect.
// Без паники; принятый кадр — допустимого для сервера типа и не длиннее
// предела; принятое тело detect — корректный ID и UTF-8 не длиннее MaxText.
func FuzzServerReadFrame(f *testing.F) {
	body, _ := EncodeDetect("injection", "ignore previous") //nolint:gosec // G104: ошибка в тесте не важна
	f.Add(frame(TypeDetect, 1, body))
	f.Add(frame(TypeHello, 2, nil))
	f.Add(frame(TypeResult, 3, []byte("{}")))
	f.Add(AppendHeader(nil, Header{Type: TypeDetect, Length: MaxDetectBody + 1}))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, b, err := ReadFrame(bytes.NewReader(data), ServerSide)
		if err != nil {
			return
		}
		if h.Type != TypeHello && h.Type != TypeDetect {
			t.Fatalf("сервер принял тип %d", h.Type)
		}
		if int(h.Length) != len(b) || len(b) > MaxDetectBody {
			t.Fatalf("длина %d, тело %d", h.Length, len(b))
		}
		if h.Type == TypeDetect {
			m, txt, err := ParseDetect(b)
			if err == nil && (!ValidModelID(m) || len(txt) > MaxText) {
				t.Fatalf("принято неверное тело: %q", m)
			}
		}
	})
}

// FuzzClientReadFrame — сторона шлюза: кадр от aisec-ml и его тело. Без
// паники; принятый result проверен против модели и текста запроса.
func FuzzClientReadFrame(f *testing.F) {
	f.Add(frame(TypeResult, 1, []byte(`{"model":"injection","version":"1.0","findings":[{"label":"injection","score":0.9,"start":0,"end":6}]}`)), "ignore всё")
	f.Add(frame(TypeHelloOK, 1, []byte(`{"protocol":1,"models":[{"id":"injection","version":"1.0","labels":["injection"],"directions":["input"]}]}`)), "")
	f.Add(frame(TypeError, 1, []byte(`{"code":"overloaded"}`)), "")
	f.Fuzz(func(t *testing.T, data []byte, text string) {
		h, b, err := ReadFrame(bytes.NewReader(data), ClientSide)
		if err != nil {
			return
		}
		switch h.Type {
		case TypeHelloOK:
			if hello, err := ParseHelloOK(b); err == nil && len(hello.Models) > MaxModels {
				t.Fatal("моделей больше предела")
			}
		case TypeResult:
			r, err := ParseResult(b, testInfo, text)
			if err != nil {
				return
			}
			for _, s := range r.Findings {
				if s.Start < 0 || s.End > len(text) || s.Start >= s.End || s.Score < 0 || s.Score > 1 {
					t.Fatalf("принята неверная находка %+v", s)
				}
			}
		case TypeError:
			if c, err := ParseError(b); err == nil && !validCode(c) {
				t.Fatalf("принят код %q", c)
			}
		default:
			t.Fatalf("клиент принял тип %d", h.Type)
		}
	})
}
