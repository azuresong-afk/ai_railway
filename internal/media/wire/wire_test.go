package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func frame(t FrameType, id uint32, body []byte) []byte {
	b := AppendHeader(nil, Header{Type: t, ID: id, Length: uint32(len(body))}) //nolint:gosec // G115: тела тестов малы
	return append(b, body...)
}

func TestHeaderRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Header{Type: TypeAnalyze, Timeout: 1500, ID: 7}, []byte("png")); err != nil {
		t.Fatal(err)
	}
	h, body, err := ReadFrame(&buf, ServerSide)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != TypeAnalyze || h.Timeout != 1500 || h.ID != 7 || string(body) != "png" {
		t.Fatalf("кадр %+v %q", h, body)
	}
}

func TestParseHeaderRejects(t *testing.T) {
	good := AppendHeader(nil, Header{Type: TypeAnalyze, Length: 10})
	cases := map[string]struct {
		b    []byte
		side Side
		want error
	}{
		"короткий": {good[:15], ServerSide, ErrProtocol},
		"magic":    {append([]byte("AIML"), good[4:]...), ServerSide, ErrProtocol},
		"версия":   {append(append([]byte{}, good[:4]...), append([]byte{2}, good[5:]...)...), ServerSide, ErrProtocol},
		"тип ответа на сервере":     {AppendHeader(nil, Header{Type: TypeResult}), ServerSide, ErrProtocol},
		"тип запроса у клиента":     {good, ClientSide, ErrProtocol},
		"неизвестный тип":           {AppendHeader(nil, Header{Type: 9}), ServerSide, ErrProtocol},
		"срок не у analyze":         {AppendHeader(nil, Header{Type: TypeHello, Timeout: 1}), ServerSide, ErrProtocol},
		"тело у hello":              {AppendHeader(nil, Header{Type: TypeHello, Length: 1}), ServerSide, ErrFrameTooLarge},
		"изображение сверх предела": {AppendHeader(nil, Header{Type: TypeAnalyze, Length: MaxContent + 1}), ServerSide, ErrFrameTooLarge},
		"result сверх предела":      {AppendHeader(nil, Header{Type: TypeResult, Length: MaxResultBody + 1}), ClientSide, ErrFrameTooLarge},
		"error сверх предела":       {AppendHeader(nil, Header{Type: TypeError, Length: MaxErrorBody + 1}), ClientSide, ErrFrameTooLarge},
	}
	for name, c := range cases {
		if _, err := ParseHeader(c.b, c.side); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, ожидалось %v", name, err, c.want)
		}
	}
	if _, err := ParseHeader(AppendHeader(nil, Header{Type: TypeAnalyze, Length: MaxContent}), ServerSide); err != nil {
		t.Errorf("граница MaxContent: %v", err)
	}
}

// Кадр сверх предела: тело не читается — из потока взяты только 16 байт.
func TestReadFrameTooLargeDoesNotReadBody(t *testing.T) {
	data := append(AppendHeader(nil, Header{Type: TypeAnalyze, Length: MaxContent + 1}), make([]byte, 100)...)
	r := bytes.NewReader(data)
	if _, _, err := ReadFrame(r, ServerSide); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
	if r.Len() != 100 {
		t.Fatalf("прочитано тела: %d", 100-r.Len())
	}
}

func TestReadFrameTruncatedBody(t *testing.T) {
	data := frame(TypeAnalyze, 1, []byte("abcdef"))
	if _, _, err := ReadFrame(bytes.NewReader(data[:len(data)-2]), ServerSide); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}

func TestWriteFrameRejects(t *testing.T) {
	if err := WriteFrame(io.Discard, Header{Type: TypeError}, make([]byte, MaxErrorBody+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
	if err := WriteFrame(io.Discard, Header{Type: TypeResult, Timeout: 5}, nil); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
	if err := WriteFrame(io.Discard, Header{Type: 9}, nil); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatal(err)
	}
}

func TestParseResult(t *testing.T) {
	good := []string{
		`{"status":"ok","format":"png","width":10,"height":20,"frames":1,"checks":["decode"]}`,
		`{"status":"ok","format":"gif","width":1,"height":1,"frames":3,"checks":["decode"],"cached":true}`,
		`{"status":"unsupported","format":"webp","width":5,"height":5,"frames":1,"checks":[]}`,
		`{"status":"unsupported","checks":[]}`,
		`{"status":"rejected","reason":"too_many_pixels","format":"png","width":100000,"height":100000,"frames":1,"checks":[]}`,
		`{"status":"rejected","reason":"malformed","checks":[]}`,
	}
	for _, b := range good {
		if _, err := ParseResult([]byte(b)); err != nil {
			t.Errorf("%s: %v", b, err)
		}
	}
	bad := []string{
		`{"status":"ok","format":"png","width":10,"height":20,"frames":1,"checks":[]}`,
		`{"status":"ok","format":"png","width":0,"height":20,"frames":1,"checks":["decode"]}`,
		`{"status":"ok","format":"svg","width":1,"height":1,"frames":1,"checks":["decode"]}`,
		`{"status":"ok","format":"png","width":1,"height":1,"frames":1,"checks":["decode","decode"]}`,
		`{"status":"ok","format":"png","width":1,"height":1,"frames":1,"checks":["decode"],"reason":"malformed"}`,
		`{"status":"rejected","checks":[]}`,
		`{"status":"rejected","reason":"other","checks":[]}`,
		`{"status":"rejected","reason":"malformed","checks":["decode"]}`,
		`{"status":"unsupported"}`,
		`{"status":"fine","checks":[]}`,
		`{"status":"ok","format":"png","width":-1,"height":1,"frames":1,"checks":["decode"]}`,
		`{"status":"unsupported","checks":[],"text":"секрет"}`,
		`{"status":"unsupported","checks":[]} {}`,
		`[]`,
	}
	for _, b := range bad {
		if _, err := ParseResult([]byte(b)); err == nil {
			t.Errorf("принято: %s", b)
		}
	}
}

func TestParseHelloOKAndError(t *testing.T) {
	if _, err := ParseHelloOK([]byte(`{"protocol":1,"formats":["png","jpeg","gif"],"checks":["decode"],"max_bytes":10485760,"max_pixels":25000000}`)); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{
		`{"protocol":2,"formats":[],"checks":[],"max_bytes":1,"max_pixels":1}`,
		`{"protocol":1,"formats":["png","png"],"checks":[],"max_bytes":1,"max_pixels":1}`,
		`{"protocol":1,"formats":[],"checks":[],"max_bytes":33554433,"max_pixels":1}`,
		`{"protocol":1,"formats":[],"checks":[],"max_bytes":1,"max_pixels":0}`,
		`{"protocol":1,"checks":[],"max_bytes":1,"max_pixels":1}`,
	} {
		if _, err := ParseHelloOK([]byte(b)); err == nil {
			t.Errorf("принято: %s", b)
		}
	}
	if c, err := ParseError([]byte(`{"code":"overloaded"}`)); err != nil || c != ErrOverloaded {
		t.Fatal(c, err)
	}
	if _, err := ParseError([]byte(`{"code":"busy"}`)); err == nil {
		t.Fatal("принят неизвестный код")
	}
}

// FuzzServerReadFrame — сторона aisec-media: кадр от шлюза. Без паники;
// принятый кадр — допустимого для сервера типа и не длиннее предела.
func FuzzServerReadFrame(f *testing.F) {
	f.Add(frame(TypeAnalyze, 1, []byte("\x89PNG\r\n\x1a\n")))
	f.Add(frame(TypeHello, 2, nil))
	f.Add(frame(TypeResult, 3, []byte("{}")))
	f.Add(AppendHeader(nil, Header{Type: TypeAnalyze, Length: MaxContent + 1}))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, b, err := ReadFrame(bytes.NewReader(data), ServerSide)
		if err != nil {
			return
		}
		if h.Type != TypeHello && h.Type != TypeAnalyze {
			t.Fatalf("сервер принял тип %d", h.Type)
		}
		if int(h.Length) != len(b) || len(b) > MaxContent || (h.Type == TypeHello && len(b) != 0) {
			t.Fatalf("длина %d, тело %d", h.Length, len(b))
		}
		if h.Timeout != 0 && h.Type != TypeAnalyze {
			t.Fatal("срок у кадра не analyze")
		}
	})
}

// FuzzClientReadFrame — сторона шлюза: кадр от aisec-media и его тело. Без
// паники; принятые hello_ok, result и error прошли проверку.
func FuzzClientReadFrame(f *testing.F) {
	f.Add(frame(TypeResult, 1, []byte(`{"status":"ok","format":"png","width":10,"height":20,"frames":1,"checks":["decode"]}`)))
	f.Add(frame(TypeHelloOK, 1, []byte(`{"protocol":1,"formats":["png"],"checks":["decode"],"max_bytes":1,"max_pixels":1}`)))
	f.Add(frame(TypeError, 1, []byte(`{"code":"timeout"}`)))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, b, err := ReadFrame(bytes.NewReader(data), ClientSide)
		if err != nil {
			return
		}
		switch h.Type {
		case TypeHelloOK:
			if hello, err := ParseHelloOK(b); err == nil && (hello.MaxBytes > MaxContent || hello.MaxPixels > MaxPixelsLimit) {
				t.Fatal("принят предел сверх протокола")
			}
		case TypeResult:
			if r, err := ParseResult(b); err == nil {
				if r.Validate() != nil || (r.Status == StatusOK && (r.Width <= 0 || r.Height <= 0)) {
					t.Fatalf("принят неверный итог %+v", r)
				}
			}
		case TypeError:
			_, _ = ParseError(b) //nolint:gosec // G104: проверяется отсутствие паники
		default:
			t.Fatalf("клиент принял тип %d", h.Type)
		}
	})
}
