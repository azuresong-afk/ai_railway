package shadowai

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// Кадрирование потока syslog по TCP (RFC 6587; поверх TLS — RFC 5425).
// Кадр — либо octet counting («ДЛИНА пробел СООБЩЕНИЕ», длина — десятичное
// число без ведущего нуля), либо сообщение до перевода строки
// (non-transparent framing). Способ определяется по каждому кадру: цифры от
// 1 до 9, за которыми до пробела идут только цифры, — octet counting; иначе
// перевод строки. Сообщение syslog начинается с «<PRI>», строка Squid,
// присланная модулем tcp:// без заголовка, — с «секунды.миллисекунды», то
// есть цифр, за которыми идёт точка: обе читаются до перевода строки.
// Кадр длиннее предела — ошибка потока: в octet counting дальше не найти
// начало следующего кадра, а длинная строка — признак не того источника.

// ErrFrameTooLarge — кадр длиннее предела: соединение закрывается. Цифры без
// пробела после них — не ошибка длины, а кадр до перевода строки; обрыв
// внутри кадра — io.ErrUnexpectedEOF.
var ErrFrameTooLarge = errors.New("syslog: кадр длиннее допустимого")

// maxLenDigits — сколько цифр длины кадра считается числом: предел 16 КиБ —
// пять цифр, больше — заведомо слишком длинный кадр.
const maxLenDigits = 7

// frameHooks — сроки чтения: idle — перед ожиданием начала кадра, busy —
// после его первого байта (кадр должен прийти целиком за свой срок).
type frameHooks interface {
	idle()
	busy()
}

// frameReader выделяет кадры syslog из потока.
type frameReader struct {
	r     *bufio.Reader
	max   int
	hooks frameHooks
	buf   []byte
}

func newFrameReader(r io.Reader, max int, hooks frameHooks) *frameReader {
	return &frameReader{r: bufio.NewReaderSize(r, max+maxLenDigits+2), max: max, hooks: hooks}
}

// next — следующий непустой кадр без завершающих «\r\n»; io.EOF — поток
// закрыт между кадрами. Срез действует до следующего вызова.
func (f *frameReader) next() ([]byte, error) {
	for {
		if f.hooks != nil {
			f.hooks.idle()
		}
		c, err := f.r.ReadByte()
		if err != nil {
			return nil, err
		}
		if f.hooks != nil {
			f.hooks.busy()
		}
		var frame []byte
		if c >= '1' && c <= '9' {
			frame, err = f.counted(c)
		} else {
			frame, err = f.line([]byte{c})
		}
		if err != nil {
			return nil, err
		}
		frame = bytes.TrimRight(frame, "\r\n")
		if len(frame) == 0 {
			continue
		}
		return frame, nil
	}
}

// counted читает длину octet counting после первой цифры first. Если за
// цифрами идёт не пробел, кадр — строка до перевода строки.
func (f *frameReader) counted(first byte) ([]byte, error) {
	n := int(first - '0')
	prefix := []byte{first}
	for {
		c, err := f.r.ReadByte()
		if err != nil {
			return nil, unexpected(err)
		}
		switch {
		case c == ' ':
			if n > f.max {
				return nil, ErrFrameTooLarge
			}
			if cap(f.buf) < n {
				f.buf = make([]byte, n)
			}
			f.buf = f.buf[:n]
			if _, err := io.ReadFull(f.r, f.buf); err != nil {
				return nil, unexpected(err)
			}
			return f.buf, nil
		case c >= '0' && c <= '9':
			// Длинная строка цифр — ещё не ошибка: время Squid — десять
			// цифр и точка. Длина кадра из стольких цифр всё равно больше
			// предела.
			if len(prefix) >= f.max {
				return nil, ErrFrameTooLarge
			}
			prefix = append(prefix, c)
			if len(prefix) <= maxLenDigits {
				n = n*10 + int(c-'0')
			} else {
				n = f.max + 1
			}
		default:
			prefix = append(prefix, c)
			if c == '\n' {
				return prefix, nil
			}
			return f.line(prefix)
		}
	}
}

// line дочитывает кадр до перевода строки; prefix — уже прочитанное начало.
func (f *frameReader) line(prefix []byte) ([]byte, error) {
	f.buf = append(f.buf[:0], prefix...)
	if prefix[len(prefix)-1] == '\n' {
		return f.buf, nil
	}
	for {
		chunk, err := f.r.ReadSlice('\n')
		if len(f.buf)+len(chunk) > f.max+2 {
			return nil, ErrFrameTooLarge
		}
		f.buf = append(f.buf, chunk...)
		switch {
		case err == nil:
			if len(bytes.TrimRight(f.buf, "\r\n")) > f.max {
				return nil, ErrFrameTooLarge
			}
			return f.buf, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			// Последняя строка без перевода строки: источник закрыл поток.
			if len(f.buf) > f.max {
				return nil, ErrFrameTooLarge
			}
			return f.buf, nil
		default:
			return nil, err
		}
	}
}

// unexpected — конец потока внутри кадра.
func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// syslogBody — тело сообщения syslog для разборщика Squid: без «<PRI>» и
// заголовка RFC 5424 или RFC 3164. CEF разбирается с заголовком (разборщик
// ищет «CEF:» сам), поэтому тело нужно только Squid. Сообщение без «<PRI>»
// (модуль tcp:// Squid) возвращается как есть.
func syslogBody(msg []byte) []byte {
	if len(msg) < 3 || msg[0] != '<' {
		return msg
	}
	end := bytes.IndexByte(msg[:min(len(msg), 5)], '>')
	if end < 2 {
		return msg
	}
	for _, c := range msg[1:end] {
		if c < '0' || c > '9' {
			return msg
		}
	}
	rest := msg[end+1:]
	if bytes.HasPrefix(rest, []byte("1 ")) {
		// RFC 5424: VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD [MSG].
		rest = rest[2:]
		for range 5 {
			i := bytes.IndexByte(rest, ' ')
			if i < 0 {
				return nil
			}
			rest = rest[i+1:]
		}
		return skipStructuredData(rest)
	}
	// RFC 3164: «Mmm dd hh:mm:ss хост тег: сообщение». Тело — после первого
	// «: » в начале строки (тег не длиннее 48 символов по RFC 3164 и
	// имени узла).
	if i := bytes.Index(rest[:min(len(rest), 128)], []byte(": ")); i >= 0 {
		return rest[i+2:]
	}
	return rest
}

// skipStructuredData пропускает STRUCTURED-DATA RFC 5424 («-» или
// [элементы] с экранированием «\]» в значениях) и пробел перед MSG.
func skipStructuredData(b []byte) []byte {
	if len(b) > 0 && b[0] == '-' {
		return bytes.TrimPrefix(b[1:], []byte(" "))
	}
	inValue, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case esc:
			esc = false
		case inValue && c == '\\':
			esc = true
		case c == '"':
			inValue = !inValue
		case !inValue && c == ']' && (i+1 == len(b) || b[i+1] != '['):
			return bytes.TrimPrefix(b[i+1:], []byte(" "))
		}
	}
	return nil
}
