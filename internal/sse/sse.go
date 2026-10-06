// Пакет sse — разбор и запись потока Server-Sent Events (WHATWG HTML,
// «Server-sent events»). Шлюз читает поток провайдера, проверяет его и отдаёт
// приложению (ТЗ, 5.1, потоковая передача). Поток — недоверенный вход:
// длина строки и размер события ограничены, разбор не паникует.
package sse

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Event — событие потока. Поле retry шлюзу не нужно и пропускается.
type Event struct {
	Event string // тип события; пусто — «message»
	Data  string // строки data, соединённые \n
	ID    string
}

// Limits — пределы разбора.
type Limits struct {
	MaxLine  int // длина одной строки, байт; по умолчанию 1 МиБ
	MaxEvent int // суммарный размер полей события, байт; по умолчанию 4 МиБ
}

// Ошибки разбора.
var (
	ErrLineTooLong   = errors.New("sse: строка длиннее предела")
	ErrEventTooLarge = errors.New("sse: событие больше предела")
)

// Reader читает события из потока.
type Reader struct {
	br     *bufio.Reader
	lim    Limits
	line   []byte
	first  bool
	skipLF bool
}

// NewReader создаёт читателя с пределами lim (нулевые — по умолчанию).
func NewReader(r io.Reader, lim Limits) *Reader {
	if lim.MaxLine <= 0 {
		lim.MaxLine = 1 << 20
	}
	if lim.MaxEvent <= 0 {
		lim.MaxEvent = 4 << 20
	}
	return &Reader{br: bufio.NewReaderSize(r, 32<<10), lim: lim, first: true}
}

// readLine читает строку до CR, LF или CRLF. В конце потока без
// завершающего перевода строки возвращает io.EOF: незавершённая строка, как
// и незавершённое событие, по спецификации отбрасывается.
//
// После CR не ждём следующий байт (это задержало бы событие до прихода
// новых данных), а запоминаем, что LF в начале следующей строки — часть CRLF.
func (r *Reader) readLine() ([]byte, error) {
	r.line = r.line[:0]
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			return nil, err
		}
		if r.skipLF {
			r.skipLF = false
			if b == '\n' {
				continue
			}
		}
		switch b {
		case '\n':
			return r.line, nil
		case '\r':
			r.skipLF = true
			return r.line, nil
		}
		if len(r.line) >= r.lim.MaxLine {
			return nil, ErrLineTooLong
		}
		r.line = append(r.line, b)
	}
}

// Next возвращает следующее событие. Конец потока — io.EOF; событие без
// завершающей пустой строки не возвращается.
func (r *Reader) Next() (Event, error) {
	var ev Event
	var data strings.Builder
	hasData := false
	size := 0
	for {
		line, err := r.readLine()
		if err != nil {
			return Event{}, err
		}
		if r.first {
			r.first = false
			line = bytes.TrimPrefix(line, []byte("\xEF\xBB\xBF"))
		}
		if len(line) == 0 {
			if !hasData {
				// Событие без data не доставляется; поля сбрасываются,
				// кроме ID (у шлюза ID не используется).
				ev, size = Event{}, 0
				continue
			}
			ev.Data = data.String()
			return ev, nil
		}
		if line[0] == ':' {
			continue // комментарий, в том числе «: keep-alive»
		}
		field, value, found := bytes.Cut(line, []byte(":"))
		if found {
			value = bytes.TrimPrefix(value, []byte(" "))
		}
		size += len(value) + 1
		if size > r.lim.MaxEvent {
			return Event{}, ErrEventTooLarge
		}
		switch string(field) {
		case "data":
			if hasData {
				data.WriteByte('\n')
			}
			data.Write(value)
			hasData = true
		case "event":
			ev.Event = string(value)
		case "id":
			if bytes.IndexByte(value, 0) < 0 {
				ev.ID = string(value)
			}
		default: // retry и неизвестные поля пропускаются
		}
	}
}

// Write записывает событие. Поля event и id не должны содержать переводов
// строки: иначе приложение получило бы другое событие, чем проверил шлюз.
func Write(w io.Writer, e Event) error {
	if strings.ContainsAny(e.Event, "\r\n") || strings.ContainsAny(e.ID, "\r\n\x00") {
		return errors.New("sse: перевод строки в поле event или id")
	}
	var b strings.Builder
	if e.Event != "" {
		fmt.Fprintf(&b, "event: %s\n", e.Event)
	}
	if e.ID != "" {
		fmt.Fprintf(&b, "id: %s\n", e.ID)
	}
	data := strings.ReplaceAll(strings.ReplaceAll(e.Data, "\r\n", "\n"), "\r", "\n")
	for _, line := range strings.Split(data, "\n") {
		b.WriteString("data: ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	_, err := io.WriteString(w, b.String())
	return err
}
