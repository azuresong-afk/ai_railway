// Пакет wire — протокол кадров между шлюзом и изолированным анализатором
// изображений aisec-media по Unix-сокету (ADR-0032, раздел 4): заголовок,
// пределы тела по типу кадра и тела сообщений.
//
// Пакет импортируют cmd/aisec-media и клиент в шлюзе (задача 5.39);
// декодеры изображений и сервер — в internal/media, который импортирует
// только cmd/aisec-media (depguard, ADR-0032, раздел 10). Здесь нет
// декодеров, cgo и сетевых клиентов.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Заголовок кадра: magic, версия, тип, срок (у analyze; у остальных —
// нулевой резерв), номер запроса и длина тела, порядок байтов big-endian.
const (
	Magic           = "AIMD"
	ProtocolVersion = 1
	HeaderSize      = 16
)

// FrameType — тип кадра.
type FrameType uint8

// Типы кадров.
const (
	TypeHello   FrameType = 1 // шлюз → aisec-media: возможности
	TypeHelloOK FrameType = 2 // aisec-media → шлюз: форматы, проверки, пределы
	TypeAnalyze FrameType = 3 // шлюз → aisec-media: байты изображения
	TypeResult  FrameType = 4 // aisec-media → шлюз: итог анализа
	TypeError   FrameType = 5 // aisec-media → шлюз: код ошибки
)

// Пределы тела по типу кадра. Проверяются по заголовку, до чтения тела.
const (
	// MaxContent — жёсткий предел изображения в протоколе; рабочий предел
	// анализатора (-max-bytes) не больше его.
	MaxContent     = 32 << 20
	MaxHelloOKBody = 4 << 10
	MaxResultBody  = 256 << 10
	MaxErrorBody   = 1 << 10
)

// Header — разобранный заголовок кадра.
type Header struct {
	Type FrameType
	// Timeout — срок анализа в миллисекундах, который назначил шлюз (только
	// у analyze; 0 — срок анализатора по умолчанию).
	Timeout uint16
	ID      uint32
	Length  uint32
}

// ErrProtocol — кадр не соответствует протоколу: соединение закрывается.
var ErrProtocol = errors.New("aisec-media: нарушение протокола")

// ErrFrameTooLarge — длина тела больше предела типа: тело не читается,
// соединение закрывается.
var ErrFrameTooLarge = errors.New("aisec-media: кадр больше предела")

// Side — кто читает кадр: от неё зависит, какие типы допустимы.
type Side bool

// Стороны соединения.
const (
	// ServerSide — aisec-media читает кадры шлюза.
	ServerSide Side = true
	// ClientSide — шлюз читает кадры aisec-media.
	ClientSide Side = false
)

// limit — предел тела типа t для стороны, которая его читает; ok = false —
// эта сторона такой тип не принимает.
func limit(t FrameType, side Side) (max uint32, ok bool) {
	if side == ServerSide {
		switch t {
		case TypeHello:
			return 0, true
		case TypeAnalyze:
			return MaxContent, true
		}
		return 0, false
	}
	switch t {
	case TypeHelloOK:
		return MaxHelloOKBody, true
	case TypeResult:
		return MaxResultBody, true
	case TypeError:
		return MaxErrorBody, true
	}
	return 0, false
}

// AppendHeader дописывает заголовок кадра в b.
func AppendHeader(b []byte, h Header) []byte {
	b = append(b, Magic...)
	b = append(b, ProtocolVersion, byte(h.Type))
	b = binary.BigEndian.AppendUint16(b, h.Timeout)
	b = binary.BigEndian.AppendUint32(b, h.ID)
	return binary.BigEndian.AppendUint32(b, h.Length)
}

// ParseHeader проверяет заголовок: magic, версию, тип для стороны side,
// срок (не у analyze — нулевой резерв) и длину по пределу типа. Ошибка
// ErrFrameTooLarge — тело читать нельзя.
func ParseHeader(b []byte, side Side) (Header, error) {
	if len(b) != HeaderSize {
		return Header{}, ErrProtocol
	}
	if string(b[:4]) != Magic || b[4] != ProtocolVersion {
		return Header{}, ErrProtocol
	}
	h := Header{Type: FrameType(b[5]), Timeout: binary.BigEndian.Uint16(b[6:8]), ID: binary.BigEndian.Uint32(b[8:12]), Length: binary.BigEndian.Uint32(b[12:16])}
	if h.Timeout != 0 && h.Type != TypeAnalyze {
		return Header{}, ErrProtocol
	}
	maxLen, ok := limit(h.Type, side)
	if !ok {
		return Header{}, ErrProtocol
	}
	if h.Length > maxLen {
		return Header{}, ErrFrameTooLarge
	}
	return h, nil
}

// ReadFrame читает один кадр. Тело читается, только если заголовок прошёл
// проверку: кадр сверх предела отвергается после 16 байт заголовка.
func ReadFrame(r io.Reader, side Side) (Header, []byte, error) {
	h, err := ReadHeader(r, side)
	if err != nil {
		return Header{}, nil, err
	}
	body, err := ReadBody(r, h)
	if err != nil {
		return Header{}, nil, err
	}
	return h, body, nil
}

// ReadHeader читает и проверяет заголовок: тип и длина известны до
// выделения памяти под тело. Сервер сверяет длину ещё и со своим рабочим
// пределом, прежде чем вызвать ReadBody.
func ReadHeader(r io.Reader, side Side) (Header, error) {
	var hb [HeaderSize]byte
	if _, err := io.ReadFull(r, hb[:]); err != nil {
		return Header{}, err
	}
	return ParseHeader(hb[:], side)
}

// ReadBody читает тело ровно проверенной длины.
func ReadBody(r io.Reader, h Header) ([]byte, error) {
	if h.Length == 0 {
		return nil, nil
	}
	body := make([]byte, h.Length)
	if _, err := io.ReadFull(r, body); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return body, nil
}

// WriteFrame пишет кадр одним вызовом Write. Предел тела проверяется и при
// записи: сторона не отправляет того, что другая обязана отвергнуть.
func WriteFrame(w io.Writer, h Header, body []byte) error {
	maxLen, ok := limit(h.Type, sideReading(h.Type))
	if !ok || uint64(len(body)) > uint64(maxLen) {
		return fmt.Errorf("%w: тип %d, тело %d байт", ErrFrameTooLarge, h.Type, len(body))
	}
	if h.Timeout != 0 && h.Type != TypeAnalyze {
		return fmt.Errorf("%w: срок у кадра типа %d", ErrProtocol, h.Type)
	}
	h.Length = uint32(len(body)) //nolint:gosec // G115: длина ограничена пределом типа выше
	buf := make([]byte, 0, HeaderSize+len(body))
	buf = AppendHeader(buf, h)
	buf = append(buf, body...)
	_, err := w.Write(buf)
	return err
}

// sideReading — какая сторона читает кадр типа t.
func sideReading(t FrameType) Side {
	if t == TypeHello || t == TypeAnalyze {
		return ServerSide
	}
	return ClientSide
}
