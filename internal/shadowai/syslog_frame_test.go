package shadowai

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

func frames(t *testing.T, in string, max int) ([]string, error) {
	t.Helper()
	fr := newFrameReader(strings.NewReader(in), max, nil)
	var out []string
	for {
		f, err := fr.next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, string(f))
	}
}

// RFC 6587: octet counting и перевод строки, в том числе вперемешку в одном
// потоке; строка Squid без заголовка (модуль tcp://) начинается с цифр и
// точки — это не длина кадра.
func TestSyslogFrames(t *testing.T) {
	cases := []struct {
		name, in string
		want     []string
	}{
		{"octet counting", "11 <13>1 hello5 <1>ab", []string{"<13>1 hello", "<1>ab"}},
		{"перевод строки", "<13>hello\n<14>world\r\n", []string{"<13>hello", "<14>world"}},
		{"вперемешку", "5 <1>ab<2>line\n3 xyz", []string{"<1>ab", "<2>line", "xyz"}},
		{"пустые строки", "\n\r\n<1>a\n\n", []string{"<1>a"}},
		{"строка Squid без заголовка", "1761558000.123 15 10.0.0.1 TCP_TUNNEL/200 1 CONNECT chatgpt.com:443 u HIER_DIRECT/1.1.1.1 -\n",
			[]string{"1761558000.123 15 10.0.0.1 TCP_TUNNEL/200 1 CONNECT chatgpt.com:443 u HIER_DIRECT/1.1.1.1 -"}},
		{"цифры и перевод строки", "12\n", []string{"12"}},
		{"последняя строка без перевода", "<1>a\n<2>b", []string{"<1>a", "<2>b"}},
		{"сообщение с переводом строки внутри кадра", "6 <1>a\nb", []string{"<1>a\nb"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := frames(t, c.in, 256)
			if err != nil || strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Fatalf("%q: %q %v", c.in, got, err)
			}
		})
	}
}

// Кадр длиннее предела и обрыв внутри кадра — ошибка потока (соединение
// закрывается); строка ровно в предел — принимается.
func TestSyslogFrameLimits(t *testing.T) {
	const max = 16
	ok := strings.Repeat("a", max)
	if got, err := frames(t, ok+"\n16 "+ok, max); err != nil || len(got) != 2 {
		t.Fatalf("ровно предел: %q %v", got, err)
	}
	for name, in := range map[string]string{
		"длина больше предела": "17 " + strings.Repeat("a", 17),
		"длина из многих цифр": "99999999999 x",
		"длинная строка":       strings.Repeat("b", max+1) + "\n",
		"длинная без перевода": strings.Repeat("b", 3*max),
	} {
		if _, err := frames(t, in, max); !errors.Is(err, ErrFrameTooLarge) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, in := range map[string]string{"обрыв в длине": "12", "обрыв в теле": "10 <1>ab"} {
		if _, err := frames(t, in, max); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Буфер не растёт сверх предела: большая длина отвергается до выделения.
	fr := newFrameReader(strings.NewReader("9999999 x"), DefaultMaxLine, nil)
	if _, err := fr.next(); !errors.Is(err, ErrFrameTooLarge) || cap(fr.buf) > DefaultMaxLine {
		t.Fatalf("%v, буфер %d", err, cap(fr.buf))
	}
}

func TestSyslogBody(t *testing.T) {
	squid := "1761558000.123 15 10.0.0.1 TCP_TUNNEL/200 1 CONNECT chatgpt.com:443 u HIER_DIRECT/1.1.1.1 -"
	cases := map[string]string{
		"<134>1 2026-10-27T10:00:00Z proxy squid 123 - - " + squid:                             squid,
		`<134>1 2026-10-27T10:00:00Z proxy squid 123 ID47 [ex@1 a="x\]y"][b@2 c="d"] ` + squid: squid,
		"<134>Oct 27 10:00:00 proxy squid[123]: " + squid:                                      squid,
		squid:  squid,
		"<1>":  "",
		"<x>a": "<x>a",
	}
	for in, want := range cases {
		if got := string(syslogBody([]byte(in))); got != want {
			t.Errorf("%q: %q, ждали %q", in, got, want)
		}
	}
	if got := syslogBody([]byte("<134>1 2026 host")); got != nil {
		t.Errorf("обрезанный заголовок RFC 5424: %q", got)
	}
}

// Fuzz кадрирования (ТЗ 9, разборщик недоверенного потока): ни один кадр не
// длиннее предела, разбор не падает и не читает больше входа, а кадры,
// собранные octet counting из случайных сообщений, выделяются обратно
// без изменений.
func FuzzSyslogFrames(f *testing.F) {
	for _, s := range []string{"11 <13>1 hello5 <1>ab", "<13>hello\n<14>world\r\n", "5 <1>ab<2>line\n3 xyz", "12", "0 x",
		"99999999 x", "\n\n", "1761558000.123 15 10.0.0.1 -\n"} {
		f.Add([]byte(s), []byte("<1>msg"))
	}
	const max = 256
	f.Fuzz(func(t *testing.T, stream, msg []byte) {
		fr := newFrameReader(bytes.NewReader(stream), max, nil)
		total := 0
		for range len(stream) + 1 {
			fr2, err := fr.next()
			if err != nil {
				break
			}
			if len(fr2) == 0 || len(fr2) > max {
				t.Fatalf("кадр %d байт", len(fr2))
			}
			total += len(fr2)
		}
		if total > len(stream) {
			t.Fatalf("кадров на %d байт из %d", total, len(stream))
		}
		_ = syslogBody(stream)
		// Свойство octet counting: сообщение без завершающих \r\n
		// возвращается как есть.
		m := bytes.TrimRight(msg, "\r\n")
		if len(m) == 0 || len(m) > max {
			return
		}
		var b bytes.Buffer
		for range 2 {
			b.WriteString(strconv.Itoa(len(m)))
			b.WriteByte(' ')
			b.Write(m)
		}
		fr = newFrameReader(&b, max, nil)
		for range 2 {
			got, err := fr.next()
			if err != nil || !bytes.Equal(got, m) {
				t.Fatalf("octet counting %q: %q %v", m, got, err)
			}
		}
	})
}
