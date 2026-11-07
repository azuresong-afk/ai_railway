package events

import (
	"fmt"
	"slices"
)

// Проверка изображений запроса анализатором aisec-media (ТЗ 5.17, ADR-0032,
// раздел 8; задача 5.39): по каждому изображению — проверено ли оно и
// почему нет. Содержимого изображений и извлечённого текста здесь нет: текст
// попадает в содержимое события только по режиму хранения, находки — в
// Findings с источником image и рамкой.

// SourceImage — источник находки в тексте, извлечённом из изображения.
const SourceImage = "image"

// MaxMedia — предел записей о проверке изображений в событии.
const MaxMedia = 64

// Режимы проверки изображений (media_check политики).
const (
	MediaModeOff   = "off"
	MediaModeAsync = "async"
	MediaModeSync  = "sync"
)

// Причины, по которым изображение не проверено (MediaCheck.Reason).
const (
	MediaReasonOff         = "off"       // media_check: off
	MediaReasonURL         = "url"       // ссылка https://: шлюз её не загружает (ЗИ.2)
	MediaReasonLimit       = "limit"     // изображений в запросе больше предела проверки
	MediaReasonTooLarge    = "too_large" // больше предела байт (шлюза или анализатора)
	MediaReasonPixels      = "too_many_pixels"
	MediaReasonFrames      = "too_many_frames"
	MediaReasonScans       = "too_many_scans"
	MediaReasonMalformed   = "malformed"   // base64 или файл не разобраны
	MediaReasonUnsupported = "unsupported" // формат не распознан или декодер не подключён
	MediaReasonNoOCR       = "no_ocr"      // растр разобран, но текст не извлекался (OCR — задача 5.42)
	MediaReasonUnavailable = "unavailable" // нет сокета, сбой соединения или протокола, отсрочка
	MediaReasonOverloaded  = "overloaded"  // очередь анализатора заполнена (DM-50)
	MediaReasonTimeout     = "timeout"     // срок анализа истёк
	MediaReasonError       = "error"       // сбой анализа внутри анализатора
)

// mediaFailureReasons — причины-сбои анализатора (а не свойства
// изображения): по ним ставится Decision.MediaUnavailable (DM-50).
var mediaFailureReasons = []string{MediaReasonUnavailable, MediaReasonOverloaded, MediaReasonTimeout, MediaReasonError}

var mediaReasons = []string{MediaReasonOff, MediaReasonURL, MediaReasonLimit, MediaReasonTooLarge, MediaReasonPixels,
	MediaReasonFrames, MediaReasonScans, MediaReasonMalformed, MediaReasonUnsupported, MediaReasonNoOCR,
	MediaReasonUnavailable, MediaReasonOverloaded, MediaReasonTimeout, MediaReasonError}

var mediaFormats = []string{"png", "jpeg", "gif", "webp", "bmp", "tiff"}

// MediaCheck — итог проверки одного изображения запроса.
type MediaCheck struct {
	// Location — место изображения: messages[i].content[j] в чате, images[i]
	// в Check API.
	Location string `json:"location"`
	// Mode — режим media_check, по которому шла проверка.
	Mode string `json:"mode"`
	// Checked — изображение проверено: текст извлечён и проверен
	// детекторами; non_text к нему не применялся.
	Checked bool `json:"checked"`
	// Reason — почему не проверено; у проверенного пусто.
	Reason string `json:"reason,omitempty"`
	// Format, Width, Height, Frames — что разобрал анализатор по заголовку.
	Format string `json:"format,omitempty"`
	Width  int64  `json:"width,omitempty"`
	Height int64  `json:"height,omitempty"`
	Frames int64  `json:"frames,omitempty"`
	// Cached — итог из кэша анализатора.
	Cached bool `json:"cached,omitempty"`
	// Texts — сколько фрагментов текста извлечено (без самого текста).
	Texts int `json:"texts,omitempty"`
	// LatencyMS — время анализа этого изображения.
	LatencyMS int64 `json:"latency_ms,omitempty"`
	// Sanitized — провайдеру ушло очищенное изображение (media_sanitize,
	// задача 5.45): без метаданных, перекодированное и уменьшенное.
	Sanitized bool `json:"sanitized,omitempty"`
	// Stored — изображение сохранено в содержимом события (media_store,
	// задача 6.13); StoreSkipped — почему не сохранено, хотя должно было
	// (StoreSkip*). Самих байтов здесь нет.
	Stored       bool   `json:"stored,omitempty"`
	StoreSkipped string `json:"store_skipped,omitempty"`
}

// Box — рамка находки на изображении в пикселях исходного растра (ТЗ 5.17,
// п. 5): левый верхний угол, ширина и высота.
type Box struct {
	X int64 `json:"x"`
	Y int64 `json:"y"`
	W int64 `json:"w"`
	H int64 `json:"h"`
}

// maxBoxCoord — предел координат рамки: больше ширины и высоты не бывает в
// протоколе aisec-media (wire.MaxDimension).
const maxBoxCoord = 1 << 31

func (b *Box) valid() bool {
	return b.X >= 0 && b.Y >= 0 && b.W > 0 && b.H > 0 && b.X <= maxBoxCoord && b.Y <= maxBoxCoord &&
		b.W <= maxBoxCoord && b.H <= maxBoxCoord
}

func (m *MediaCheck) validate(i int) []error {
	var errs []error
	if m.Location == "" || len(m.Location) > maxShort {
		errs = append(errs, fmt.Errorf("media[%d]: нужно место изображения до %d байт", i, maxShort))
	}
	if !slices.Contains([]string{MediaModeOff, MediaModeAsync, MediaModeSync}, m.Mode) {
		errs = append(errs, fmt.Errorf("media[%d]: режим — off, async или sync", i))
	}
	switch {
	case m.Checked && m.Reason != "":
		errs = append(errs, fmt.Errorf("media[%d]: у проверенного изображения нет причины", i))
	case !m.Checked && !slices.Contains(mediaReasons, m.Reason):
		errs = append(errs, fmt.Errorf("media[%d]: неизвестная причина %q", i, m.Reason))
	case m.Checked && m.Mode == MediaModeOff:
		errs = append(errs, fmt.Errorf("media[%d]: при off изображение не проверяется", i))
	}
	if m.Format != "" && !slices.Contains(mediaFormats, m.Format) {
		errs = append(errs, fmt.Errorf("media[%d]: неизвестный формат %q", i, m.Format))
	}
	if m.Width < 0 || m.Height < 0 || m.Frames < 0 || m.Texts < 0 || m.LatencyMS < 0 ||
		m.Width > maxBoxCoord || m.Height > maxBoxCoord {
		errs = append(errs, fmt.Errorf("media[%d]: отрицательные или слишком большие числа", i))
	}
	return errs
}

// validateMedia — проверки изображений и рамок находок.
func (e *Event) validateMedia() []error {
	var errs []error
	if len(e.Media) > 0 && e.Type != TypeGatewayRequest && e.Type != TypeCheck {
		errs = append(errs, fmt.Errorf("%s: проверка изображений бывает только у запроса чата и Check API", e.Type))
	}
	if len(e.Media) > MaxMedia {
		errs = append(errs, fmt.Errorf("media: не больше %d записей", MaxMedia))
	}
	for i := range e.Media {
		errs = append(errs, e.Media[i].validate(i)...)
	}
	for _, f := range e.Findings {
		if f.Box != nil && (f.Source != SourceImage || !f.Box.valid()) {
			errs = append(errs, fmt.Errorf("находка %s: рамка — только у источника image, с неотрицательными координатами и ненулевыми сторонами", f.Detector))
		}
	}
	if d := e.Decision; d != nil && d.MediaUnchecked && len(e.Media) == 0 {
		errs = append(errs, fmt.Errorf("%s: media_unchecked без записей о проверке изображений", e.Type))
	}
	if d := e.Decision; d != nil && d.MediaUnavailable && (!d.MediaUnchecked ||
		!slices.ContainsFunc(e.Media, func(m MediaCheck) bool { return slices.Contains(mediaFailureReasons, m.Reason) })) {
		errs = append(errs, fmt.Errorf("%s: media_unavailable — только вместе с media_unchecked и изображением, не проверенным из-за сбоя анализатора", e.Type))
	}
	return errs
}
