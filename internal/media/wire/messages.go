package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
)

// ErrBadBody — тело кадра не соответствует протоколу.
var ErrBadBody = errors.New("aisec-media: неверное тело кадра")

// Format — формат изображения по сигнатуре (ADR-0032, раздел 6).
type Format string

// Форматы, которые распознаёт разбор заголовков.
const (
	FormatPNG  Format = "png"
	FormatJPEG Format = "jpeg"
	FormatGIF  Format = "gif"
	FormatWebP Format = "webp"
	FormatBMP  Format = "bmp"
	FormatTIFF Format = "tiff"
)

// Formats — все распознаваемые форматы.
var Formats = []Format{FormatPNG, FormatJPEG, FormatGIF, FormatWebP, FormatBMP, FormatTIFF}

// Check — выполненная проверка изображения. Шлюз считает изображение
// проверенным, только если среди проверок есть ocr (ADR-0032, раздел 8).
type Check string

// Проверки. В каркасе (задача 5.37) — только decode.
const (
	CheckDecode   Check = "decode"   // растр декодирован
	CheckOCR      Check = "ocr"      // OCR, обычный проход (5.42)
	CheckMetadata Check = "metadata" // текст метаданных (5.43)
	CheckQR       Check = "qr"       // QR-коды (5.43)
)

var checks = []Check{CheckDecode, CheckOCR, CheckMetadata, CheckQR}

// Status — итог анализа.
type Status string

// Итоги анализа.
const (
	StatusOK          Status = "ok"          // формат распознан, размеры в пределах, растр декодирован
	StatusUnsupported Status = "unsupported" // формат не распознан или декодер не подключён
	StatusRejected    Status = "rejected"    // отказ по заголовку или при декодировании, см. Reason
)

// Reason — причина отказа (StatusRejected).
type Reason string

// Причины отказа.
const (
	ReasonTooLarge      Reason = "too_large"       // файл больше -max-bytes
	ReasonTooManyPixels Reason = "too_many_pixels" // пикселей больше -max-pixels (у GIF — сумма кадров)
	ReasonTooManyFrames Reason = "too_many_frames" // кадров GIF или страниц TIFF больше предела
	ReasonTooManyScans  Reason = "too_many_scans"  // сканов прогрессивного JPEG больше предела
	ReasonMalformed     Reason = "malformed"       // заголовок или данные не разобраны
)

var reasons = []Reason{ReasonTooLarge, ReasonTooManyPixels, ReasonTooManyFrames, ReasonTooManyScans, ReasonMalformed}

// Пределы содержимого сообщений.
const (
	// MaxDimension — предел ширины и высоты в сообщении: больше не бывает ни
	// в одном из форматов (у JPEG — 65535, у PNG — 2^31-1 по спецификации,
	// но такие отвергаются по пикселям).
	MaxDimension = 1 << 31
	// MaxFrames — предел числа кадров или страниц в сообщении.
	MaxFrames = 1 << 16
	// MaxPixelsLimit — наибольший допустимый -max-pixels (ADR-0032, раздел 6).
	MaxPixelsLimit = 100_000_000
)

// HelloOK — ответ на hello: что умеет анализатор и с какими пределами.
type HelloOK struct {
	Protocol  int      `json:"protocol"`
	Formats   []Format `json:"formats"`
	Checks    []Check  `json:"checks"`
	MaxBytes  int64    `json:"max_bytes"`
	MaxPixels int64    `json:"max_pixels"`
}

// Result — итог анализа одного изображения. Извлечённого текста в
// каркасе нет; поле texts появится в задаче 5.42.
type Result struct {
	Status Status  `json:"status"`
	Reason Reason  `json:"reason,omitempty"`
	Format Format  `json:"format,omitempty"`
	Width  int64   `json:"width,omitempty"`
	Height int64   `json:"height,omitempty"`
	Frames int64   `json:"frames,omitempty"`
	Checks []Check `json:"checks"`
	Cached bool    `json:"cached,omitempty"`
}

// ErrorCode — код ошибки aisec-media.
type ErrorCode string

// Коды ошибок.
const (
	ErrOverloaded ErrorCode = "overloaded"  // очередь заполнена (DM-50)
	ErrTimeout    ErrorCode = "timeout"     // срок анализа истёк
	ErrTooLarge   ErrorCode = "too_large"   // кадр сверх предела, тело не прочитано
	ErrBadRequest ErrorCode = "bad_request" // нарушение протокола
	ErrInternal   ErrorCode = "internal"    // сбой анализа
)

var codes = []ErrorCode{ErrOverloaded, ErrTimeout, ErrTooLarge, ErrBadRequest, ErrInternal}

// ErrorMsg — тело кадра error.
type ErrorMsg struct {
	Code ErrorCode `json:"code"`
}

// decodeStrict — строгий JSON: без неизвестных полей и данных после объекта.
func decodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrBadBody
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrBadBody
	}
	return nil
}

// distinct — все элементы из allowed и без повторов.
func distinct[T comparable](items, allowed []T) bool {
	for i, v := range items {
		if !slices.Contains(allowed, v) || slices.Contains(items[:i], v) {
			return false
		}
	}
	return true
}

// ParseHelloOK разбирает ответ на hello (недоверенный вход для шлюза).
func ParseHelloOK(body []byte) (*HelloOK, error) {
	var h HelloOK
	if err := decodeStrict(body, &h); err != nil {
		return nil, err
	}
	if h.Protocol != ProtocolVersion || h.Formats == nil || h.Checks == nil ||
		!distinct(h.Formats, Formats) || !distinct(h.Checks, checks) ||
		h.MaxBytes < 1 || h.MaxBytes > MaxContent || h.MaxPixels < 1 || h.MaxPixels > MaxPixelsLimit {
		return nil, ErrBadBody
	}
	return &h, nil
}

// Validate проверяет итог анализа: согласованность статуса, причины,
// формата, размеров и проверок. Применяется и при отправке, и при разборе.
func (r *Result) Validate() error {
	if r.Checks == nil || !distinct(r.Checks, checks) {
		return ErrBadBody
	}
	if r.Format != "" && !slices.Contains(Formats, r.Format) {
		return ErrBadBody
	}
	if r.Width < 0 || r.Width > MaxDimension || r.Height < 0 || r.Height > MaxDimension || r.Frames < 0 || r.Frames > MaxFrames {
		return ErrBadBody
	}
	switch r.Status {
	case StatusOK:
		if r.Reason != "" || r.Format == "" || r.Width == 0 || r.Height == 0 || r.Frames == 0 || !slices.Contains(r.Checks, CheckDecode) {
			return ErrBadBody
		}
	case StatusUnsupported:
		if r.Reason != "" || len(r.Checks) != 0 {
			return ErrBadBody
		}
	case StatusRejected:
		if !slices.Contains(reasons, r.Reason) || len(r.Checks) != 0 {
			return ErrBadBody
		}
	default:
		return ErrBadBody
	}
	return nil
}

// ParseResult разбирает итог анализа (недоверенный вход для шлюза).
func ParseResult(body []byte) (*Result, error) {
	var r Result
	if err := decodeStrict(body, &r); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// ParseError разбирает тело кадра error.
func ParseError(body []byte) (ErrorCode, error) {
	var e ErrorMsg
	if err := decodeStrict(body, &e); err != nil {
		return "", err
	}
	if !slices.Contains(codes, e.Code) {
		return "", ErrBadBody
	}
	return e.Code, nil
}

// MarshalBody кодирует тело сообщения.
func MarshalBody(v any) ([]byte, error) { return json.Marshal(v) }
