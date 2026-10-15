package sse

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func readAll(t testing.TB, in string, lim Limits) ([]Event, error) {
	t.Helper()
	r := NewReader(strings.NewReader(in), lim)
	var out []Event
	for {
		e, err := r.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, e)
	}
}

func TestReaderSpecCases(t *testing.T) {
	cases := []struct {
		name, in string
		want     []Event
	}{
		{"openai", "data: {\"a\":1}\n\ndata: [DONE]\n\n", []Event{{Data: `{"a":1}`}, {Data: "[DONE]"}}},
		{"многострочное", "data: a\ndata: b\n\n", []Event{{Data: "a\nb"}}},
		{"CRLF", "data: a\r\ndata: b\r\n\r\n", []Event{{Data: "a\nb"}}},
		{"CR", "data: a\rdata: b\r\r", []Event{{Data: "a\nb"}}},
		{"смешанные", "data: a\r\n\rdata: b\n\r\n", []Event{{Data: "a"}, {Data: "b"}}},
		{"комментарии", ": keep-alive\n\n: x\ndata: a\n\n", []Event{{Data: "a"}}},
		{"тип и id", "event: error\nid: 7\ndata: x\n\n", []Event{{Event: "error", ID: "7", Data: "x"}}},
		{"без пробела", "data:a\n\n", []Event{{Data: "a"}}},
		{"только один пробел снимается", "data:  a\n\n", []Event{{Data: " a"}}},
		{"поле без двоеточия", "data\n\n", []Event{{Data: ""}}},
		{"двоеточие в значении", "data: a: b\n\n", []Event{{Data: "a: b"}}},
		{"без data не доставляется", "event: x\n\ndata: y\n\n", []Event{{Data: "y"}}},
		{"BOM", "\xEF\xBB\xBFdata: a\n\n", []Event{{Data: "a"}}},
		{"неизвестные поля и retry", "retry: 10\nfoo: bar\ndata: a\n\n", []Event{{Data: "a"}}},
		{"незавершённое событие отбрасывается", "data: a\n\ndata: b\n", []Event{{Data: "a"}}},
		{"незавершённая строка отбрасывается", "data: a\n\ndata: b", []Event{{Data: "a"}}},
		{"id с NUL пропускается", "id: a\x00b\ndata: x\n\n", []Event{{Data: "x"}}},
		{"пусто", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := readAll(t, c.in, Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("%+v", got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("%d: %+v, ожидалось %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

// Поток провайдера приходит кусками произвольной длины, в том числе по байту.
func TestReaderByteByByte(t *testing.T) {
	in := "data: раз\r\n\r\ndata: два\rdata: три\r\r: c\n\ndata: [DONE]\n\n"
	r := NewReader(iotest.OneByteReader(strings.NewReader(in)), Limits{})
	var got []string
	for {
		e, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, e.Data)
	}
	if strings.Join(got, "|") != "раз|два\nтри|[DONE]" {
		t.Fatalf("%q", got)
	}
}

// Событие доставляется сразу после пустой строки, не дожидаясь новых данных
// (важно для потоковой передачи: иначе шлюз задерживал бы ответ).
func TestReaderDoesNotWaitAfterCR(t *testing.T) {
	pr, pw := io.Pipe()
	r := NewReader(pr, Limits{})
	done := make(chan Event, 1)
	go func() {
		e, err := r.Next()
		if err == nil {
			done <- e
		}
		close(done)
	}()
	if _, err := pw.Write([]byte("data: a\r\r")); err != nil {
		t.Fatal(err)
	}
	if e := <-done; e.Data != "a" {
		t.Fatalf("%+v", e)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReaderLimits(t *testing.T) {
	// Граница: строка ровно в предел проходит, на байт длиннее — нет.
	ok := "data:" + strings.Repeat("a", 11) + "\n\n"
	if got, err := readAll(t, ok, Limits{MaxLine: 16}); err != nil || len(got) != 1 {
		t.Fatalf("строка в предел: %v %v", got, err)
	}
	if _, err := readAll(t, "data:"+strings.Repeat("a", 12)+"\n\n", Limits{MaxLine: 16}); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("длинная строка: %v", err)
	}
	// Много коротких строк data в одном событии.
	many := strings.Repeat("data: aaaa\n", 100) + "\n"
	if _, err := readAll(t, many, Limits{MaxEvent: 100}); !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("большое событие: %v", err)
	}
	// Длинный комментарий тоже ограничен длиной строки.
	if _, err := readAll(t, ":"+strings.Repeat("x", 100)+"\n", Limits{MaxLine: 50}); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("длинный комментарий: %v", err)
	}
}

func TestWriteRoundTrip(t *testing.T) {
	for _, e := range []Event{
		{Data: `{"a":1}`},
		{Data: "строка 1\nстрока 2"},
		{Event: "error", ID: "42", Data: ""},
		{Data: "a\r\nb\rc"},
	} {
		var b strings.Builder
		if err := Write(&b, e); err != nil {
			t.Fatal(err)
		}
		got, err := readAll(t, b.String(), Limits{})
		want := e
		want.Data = strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(e.Data)
		if err != nil || len(got) != 1 || got[0] != want {
			t.Fatalf("%+v → %q → %+v %v", e, b.String(), got, err)
		}
	}
	for _, bad := range []Event{{Event: "a\nb"}, {ID: "1\r"}, {ID: "a\x00"}} {
		if err := Write(io.Discard, bad); err == nil {
			t.Errorf("%+v: ожидалась ошибка", bad)
		}
	}
}

// Разбор потока SSE — цель фаззинга (ТЗ, 8.5): без паники, в пределах
// лимитов, и записанное событие читается обратно тем же.
func FuzzReader(f *testing.F) {
	f.Add("data: a\n\n")
	f.Add("data: a\r\ndata: b\r\r: c\n")
	f.Add("\xEF\xBB\xBFevent: x\nid: 1\ndata\n\n")
	f.Fuzz(func(t *testing.T, in string) {
		lim := Limits{MaxLine: 64, MaxEvent: 256}
		events, err := readAll(t, in, lim)
		if err != nil && !errors.Is(err, ErrLineTooLong) && !errors.Is(err, ErrEventTooLarge) {
			t.Fatalf("неожиданная ошибка: %v", err)
		}
		for _, e := range events {
			if len(e.Data) > lim.MaxEvent {
				t.Fatalf("событие больше предела: %d", len(e.Data))
			}
			var b strings.Builder
			if err := Write(&b, e); err != nil {
				continue // в event или id не может быть перевода строки после разбора, но NUL в event возможен
			}
			back, err := readAll(t, b.String(), Limits{})
			if err != nil || len(back) != 1 || back[0] != e {
				t.Fatalf("%+v → %q → %+v %v", e, b.String(), back, err)
			}
		}
	})
}
