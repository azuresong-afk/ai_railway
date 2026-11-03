package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
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

// Проверки: decode — с каркаса (5.37), metadata и qr — с 5.43, ocr — 5.42.
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
	// Sanitize — анализатор выполняет очистку (кадр sanitize, задача 5.45).
	// Анализатор прежней версии поле не присылает; шлюз прежней версии
	// отвергает неизвестное поле, поэтому шлюз обновляется раньше
	// aisec-media.
	Sanitize bool `json:"sanitize,omitempty"`
}

// Source — откуда текст на изображении (ADR-0032, раздел 4).
type Source string

// Источники текста.
const (
	SourceOCR         Source = "ocr"          // OCR, обычный проход (5.42)
	SourceOCRContrast Source = "ocr_contrast" // OCR, проход с контрастом (5.42)
	SourceMetadata    Source = "metadata"     // EXIF, XMP, текстовые чанки PNG, комментарий JPEG (5.43)
	SourceQR          Source = "qr"           // QR-код (5.43)
)

// sourceCheck — проверка, без которой текста этого источника быть не может.
var sourceCheck = map[Source]Check{
	SourceOCR: CheckOCR, SourceOCRContrast: CheckOCR, SourceMetadata: CheckMetadata, SourceQR: CheckQR,
}

// Пределы текста в итоге. Худший случай кодирования JSON — \u-экранирование
// <, >, & и U+2028/2029 (6 байт на символ): 32 КиБ текста и рамки 256
// фрагментов укладываются в MaxResultBody.
const (
	MaxTexts      = 256
	MaxTextBytes  = 4 << 10
	MaxTextsBytes = 32 << 10
)

// Box — рамка текста на изображении в пикселях первого кадра (у QR — по
// точкам шаблонов поиска). У текста метаданных рамки нет.
type Box struct {
	X int64 `json:"x"`
	Y int64 `json:"y"`
	W int64 `json:"w"`
	H int64 `json:"h"`
}

// Text — фрагмент текста с изображения. Содержимое передаётся только
// шлюзу и не кэшируется анализатором (ТЗ 5.17, ADR-0032, раздел 7).
type Text struct {
	Text   string `json:"text"`
	Source Source `json:"source"`
	Box    *Box   `json:"box,omitempty"`
}

// Result — итог анализа одного изображения: статус, размеры, выполненные
// проверки и извлечённые тексты (только у ok).
type Result struct {
	Status Status  `json:"status"`
	Reason Reason  `json:"reason,omitempty"`
	Format Format  `json:"format,omitempty"`
	Width  int64   `json:"width,omitempty"`
	Height int64   `json:"height,omitempty"`
	Frames int64   `json:"frames,omitempty"`
	Checks []Check `json:"checks"`
	Texts  []Text  `json:"texts,omitempty"`
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
	// ErrRejected — изображение нельзя очистить: формат не распознан или без
	// декодера, отказ по пределам, повреждённый файл, итог больше max_bytes
	// (только ответ на sanitize).
	ErrRejected ErrorCode = "rejected"
)

var codes = []ErrorCode{ErrOverloaded, ErrTimeout, ErrTooLarge, ErrBadRequest, ErrInternal, ErrRejected}

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
		if r.Reason != "" || len(r.Checks) != 0 || len(r.Texts) != 0 {
			return ErrBadBody
		}
	case StatusRejected:
		if !slices.Contains(reasons, r.Reason) || len(r.Checks) != 0 || len(r.Texts) != 0 {
			return ErrBadBody
		}
	default:
		return ErrBadBody
	}
	return r.validateTexts()
}

// validateTexts — тексты в пределах: не больше MaxTexts, каждый — непустой
// UTF-8 без управляющих символов (кроме перевода строки и табуляции) и не
// длиннее MaxTextBytes, вместе — не больше MaxTextsBytes; источник —
// из выполненных проверок; рамка — внутри изображения.
func (r *Result) validateTexts() error {
	if len(r.Texts) > MaxTexts {
		return ErrBadBody
	}
	total := 0
	for _, t := range r.Texts {
		total += len(t.Text)
		if !ValidText(t.Text) || total > MaxTextsBytes {
			return ErrBadBody
		}
		c, ok := sourceCheck[t.Source]
		if !ok || !slices.Contains(r.Checks, c) {
			return ErrBadBody
		}
		if t.Box != nil && !t.Box.within(r.Width, r.Height) {
			return ErrBadBody
		}
	}
	return nil
}

// ValidText — фрагмент допустим в итоге: непустой, UTF-8, не длиннее
// MaxTextBytes, без управляющих символов, кроме \t и \n.
func ValidText(s string) bool {
	if s == "" || len(s) > MaxTextBytes || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool {
		return (r < 0x20 && r != '\t' && r != '\n') || r == 0x7F || (r >= 0x80 && r < 0xA0)
	})
}

func (b *Box) within(w, h int64) bool {
	return b.X >= 0 && b.Y >= 0 && b.W >= 1 && b.H >= 1 && b.X < w && b.Y < h && b.W <= w-b.X && b.H <= h-b.Y
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

// Сигнатуры форматов очищенного изображения.
const (
	pngSignature  = "\x89PNG\r\n\x1a\n"
	jpegSignature = "\xff\xd8\xff"
)

// SanitizedFormat — формат очищенного изображения по сигнатуре: только PNG
// и JPEG (ADR-0032, дополнение 5.45). Иное — ошибка протокола: шлюз такие
// байты провайдеру не передаёт.
func SanitizedFormat(b []byte) (Format, error) {
	switch {
	case bytes.HasPrefix(b, []byte(pngSignature)):
		return FormatPNG, nil
	case bytes.HasPrefix(b, []byte(jpegSignature)):
		return FormatJPEG, nil
	}
	return "", ErrBadBody
}

// MarshalBody кодирует тело сообщения.
func MarshalBody(v any) ([]byte, error) { return json.Marshal(v) }
