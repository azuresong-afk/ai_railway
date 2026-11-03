package wire

import (
	"bytes"
	"errors"
	"io"
	"strings"
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
		"sanitized на сервере":      {AppendHeader(nil, Header{Type: TypeSanitized}), ServerSide, ErrProtocol},
		"sanitize у клиента":        {AppendHeader(nil, Header{Type: TypeSanitize}), ClientSide, ErrProtocol},
		"срок у sanitized":          {AppendHeader(nil, Header{Type: TypeSanitized, Timeout: 1}), ClientSide, ErrProtocol},
		"sanitize сверх предела":    {AppendHeader(nil, Header{Type: TypeSanitize, Length: MaxContent + 1}), ServerSide, ErrFrameTooLarge},
		"sanitized сверх предела":   {AppendHeader(nil, Header{Type: TypeSanitized, Length: MaxSanitizedBody + 1}), ClientSide, ErrFrameTooLarge},
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
	f.Add(frame(TypeSanitize, 4, []byte("\xff\xd8\xff")))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, b, err := ReadFrame(bytes.NewReader(data), ServerSide)
		if err != nil {
			return
		}
		if h.Type != TypeHello && h.Type != TypeAnalyze && h.Type != TypeSanitize {
			t.Fatalf("сервер принял тип %d", h.Type)
		}
		if int(h.Length) != len(b) || len(b) > MaxContent || (h.Type == TypeHello && len(b) != 0) {
			t.Fatalf("длина %d, тело %d", h.Length, len(b))
		}
		if h.Timeout != 0 && h.Type != TypeAnalyze && h.Type != TypeSanitize {
			t.Fatal("срок у кадра не analyze и не sanitize")
		}
	})
}

// FuzzClientReadFrame — сторона шлюза: кадр от aisec-media и его тело. Без
// паники; принятые hello_ok, result и error прошли проверку.
func FuzzClientReadFrame(f *testing.F) {
	f.Add(frame(TypeResult, 1, []byte(`{"status":"ok","format":"png","width":10,"height":20,"frames":1,"checks":["decode"]}`)))
	f.Add(frame(TypeHelloOK, 1, []byte(`{"protocol":1,"formats":["png"],"checks":["decode"],"max_bytes":1,"max_pixels":1}`)))
	f.Add(frame(TypeError, 1, []byte(`{"code":"timeout"}`)))
	f.Add(frame(TypeError, 1, []byte(`{"code":"rejected"}`)))
	f.Add(frame(TypeSanitized, 1, []byte("\x89PNG\r\n\x1a\n")))
	f.Add(frame(TypeHelloOK, 1, []byte(`{"protocol":1,"formats":["png"],"checks":["decode"],"max_bytes":1,"max_pixels":1,"sanitize":true}`)))
	f.Add(frame(TypeResult, 1, []byte(`{"status":"ok","format":"png","width":10,"height":20,"frames":1,"checks":["decode","metadata","qr"],`+
		`"texts":[{"text":"meta","source":"metadata"},{"text":"qr","source":"qr","box":{"x":1,"y":2,"w":3,"h":4}}]}`)))
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
		case TypeSanitized:
			if f, err := SanitizedFormat(b); err == nil && f != FormatPNG && f != FormatJPEG {
				t.Fatalf("очищенное изображение формата %s", f)
			}
		default:
			t.Fatalf("клиент принял тип %d", h.Type)
		}
	})
}

func TestResultTexts(t *testing.T) {
	ok := func() Result {
		return Result{Status: StatusOK, Format: FormatPNG, Width: 100, Height: 50, Frames: 1,
			Checks: []Check{CheckDecode, CheckMetadata, CheckQR},
			Texts:  []Text{{Text: "описание", Source: SourceMetadata}, {Text: "код", Source: SourceQR, Box: &Box{X: 90, Y: 40, W: 10, H: 10}}}}
	}
	if r := ok(); r.Validate() != nil {
		t.Fatal("верный итог отвергнут")
	}
	body, err := MarshalBody(ok())
	if err != nil {
		t.Fatal(err)
	}
	if r, err := ParseResult(body); err != nil || len(r.Texts) != 2 || r.Texts[1].Box.W != 10 {
		t.Fatalf("разбор %+v %v", r, err)
	}
	long := strings.Repeat("я", MaxTextBytes/2+1)
	cases := map[string]func(*Result){
		"источник без проверки": func(r *Result) { r.Checks = []Check{CheckDecode, CheckQR} },
		"ocr без проверки":      func(r *Result) { r.Texts[0].Source = SourceOCRContrast },
		"неизвестный источник":  func(r *Result) { r.Texts[0].Source = "exif" },
		"пустой текст":          func(r *Result) { r.Texts[0].Text = "" },
		"управляющий символ":    func(r *Result) { r.Texts[0].Text = "a\x1bb" },
		"C1":                    func(r *Result) { r.Texts[0].Text = "a\u0085b" },
		"не UTF-8":              func(r *Result) { r.Texts[0].Text = "a\xffb" },
		"длинный текст":         func(r *Result) { r.Texts[0].Text = long },
		"рамка за правым краем": func(r *Result) { r.Texts[1].Box.W = 11 },
		"рамка за низом":        func(r *Result) { r.Texts[1].Box.Y = 41 },
		"пустая рамка":          func(r *Result) { r.Texts[1].Box.H = 0 },
		"отрицательная рамка":   func(r *Result) { r.Texts[1].Box.X = -1 },
		"переполнение рамки":    func(r *Result) { r.Texts[1].Box.X, r.Texts[1].Box.W = 1<<62, 1<<62 },
		"текст у rejected": func(r *Result) {
			r.Status, r.Reason, r.Checks = StatusRejected, ReasonMalformed, []Check{}
		},
		"слишком много": func(r *Result) {
			r.Texts = nil
			for range MaxTexts + 1 {
				r.Texts = append(r.Texts, Text{Text: "x", Source: SourceQR})
			}
		},
		"объём": func(r *Result) {
			r.Texts = nil
			for range MaxTextsBytes/MaxTextBytes + 1 {
				r.Texts = append(r.Texts, Text{Text: strings.Repeat("x", MaxTextBytes), Source: SourceMetadata})
			}
		},
	}
	for name, mut := range cases {
		r := ok()
		mut(&r)
		if r.Validate() == nil {
			t.Errorf("%s: принят", name)
		}
	}
	if !ValidText("строка\tс\nпереводом") {
		t.Error("табуляция и перевод строки отвергнуты")
	}
}

// Задача 5.45: очищенное изображение — только PNG или JPEG по сигнатуре;
// hello_ok с sanitize разбирается, без него — прежний анализатор.
func TestSanitizeMessages(t *testing.T) {
	for b, want := range map[string]Format{"\x89PNG\r\n\x1a\nrest": FormatPNG, "\xff\xd8\xff\xe0": FormatJPEG} {
		if f, err := SanitizedFormat([]byte(b)); err != nil || f != want {
			t.Errorf("%q: %s %v", b, f, err)
		}
	}
	for _, b := range []string{"", "GIF89a", "\x89PN", "RIFF\x00\x00\x00\x00WEBP", "\xff\xd8"} {
		if _, err := SanitizedFormat([]byte(b)); !errors.Is(err, ErrBadBody) {
			t.Errorf("%q принят", b)
		}
	}
	h, err := ParseHelloOK([]byte(`{"protocol":1,"formats":["png"],"checks":["decode"],"max_bytes":1,"max_pixels":1,"sanitize":true}`))
	if err != nil || !h.Sanitize {
		t.Fatalf("hello_ok с sanitize: %+v %v", h, err)
	}
	if code, err := ParseError([]byte(`{"code":"rejected"}`)); err != nil || code != ErrRejected {
		t.Fatalf("rejected: %s %v", code, err)
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Header{Type: TypeSanitize, Timeout: 500, ID: 3}, []byte("img")); err != nil {
		t.Fatal(err)
	}
	if h, b, err := ReadFrame(&buf, ServerSide); err != nil || h.Type != TypeSanitize || h.Timeout != 500 || string(b) != "img" {
		t.Fatalf("sanitize: %+v %q %v", h, b, err)
	}
	if err := WriteFrame(&buf, Header{Type: TypeSanitized, Timeout: 1}, nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("срок у sanitized: %v", err)
	}
}
