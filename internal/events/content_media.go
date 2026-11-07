package events

import (
	"fmt"
	"slices"
)

// Изображения запроса в содержимом события full (задача 6.13, ADR-0039).
// Шлюз кладёт их в Content.Images, только если у приложения режим хранения
// full и в политике media_store; сервер шифрует каждое ключом данных и
// хранит в event_media отдельно от текста содержимого, срок — как у
// содержимого (content_days).

const (
	// MaxStoredImages — изображений в содержимом одного события.
	MaxStoredImages = 16
	// MaxStoredImageBytes — предел байтов одного изображения.
	MaxStoredImageBytes = 3 << 20
	// MaxEventImageBytes — предел байтов всех изображений события: событие
	// в base64 укладывается в пакет MaxBatchBytes.
	MaxEventImageBytes = 4 << 20
	// DefaultQueueImageBytes — изображений в очереди шлюза в памяти сразу.
	DefaultQueueImageBytes = 64 << 20
)

// Почему изображение не сохранено, хотя media_store включено
// (MediaCheck.StoreSkipped).
const (
	StoreSkipURL          = "url"           // ссылка https://: байтов у шлюза нет
	StoreSkipNotParsed    = "not_parsed"    // заголовок не разобран aisec-media
	StoreSkipTooLarge     = "too_large"     // больше MaxStoredImageBytes
	StoreSkipEventLimit   = "event_limit"   // предел MaxEventImageBytes или MaxStoredImages
	StoreSkipQueueFull    = "queue_full"    // предел изображений в очереди шлюза
	StoreSkipNotSanitized = "not_sanitized" // media_sanitize: очистить не удалось
)

var storeSkipReasons = []string{StoreSkipURL, StoreSkipNotParsed, StoreSkipTooLarge, StoreSkipEventLimit,
	StoreSkipQueueFull, StoreSkipNotSanitized}

// ContentImage — изображение запроса в содержимом события.
type ContentImage struct {
	// Location — место изображения, как в MediaCheck.Location.
	Location string `json:"location"`
	// Format — формат сохранённых байтов: у очищенного — png или jpeg.
	Format string `json:"format"`
	// Sanitized — сохранено очищенным aisec-media (media_sanitize).
	Sanitized bool `json:"sanitized,omitempty"`
	// Data — байты изображения (в JSON — base64).
	Data []byte `json:"data"`
}

// ImageBytes — сколько байтов изображений в содержимом события.
func (e *Event) ImageBytes() int {
	if e.Content == nil {
		return 0
	}
	n := 0
	for _, img := range e.Content.Images {
		n += len(img.Data)
	}
	return n
}

// DropImages убирает изображения из содержимого события и отмечает их в
// записях media причиной reason. Содержимое и записи копируются: событие
// могли передать по значению с общими указателями.
func (e *Event) DropImages(reason string) {
	if e.Content == nil || len(e.Content.Images) == 0 {
		return
	}
	c := *e.Content
	c.Images = nil
	e.Content = &c
	if c.Request == "" && c.Response == "" {
		e.Content = nil
	}
	e.Media = slices.Clone(e.Media)
	for i := range e.Media {
		if e.Media[i].Stored {
			e.Media[i].Stored, e.Media[i].StoreSkipped = false, reason
		}
	}
}

// textOnly — содержимое без изображений: открытый текст event_content.
func (c Content) textOnly() Content {
	return Content{Request: c.Request, Response: c.Response}
}

// validateImages — изображения содержимого и отметки о хранении в media.
func (e *Event) validateImages() []error {
	var errs []error
	for i, m := range e.Media {
		if m.StoreSkipped != "" && !slices.Contains(storeSkipReasons, m.StoreSkipped) {
			errs = append(errs, fmt.Errorf("media[%d]: неизвестная причина store_skipped %q", i, m.StoreSkipped))
		}
		if m.Stored && m.StoreSkipped != "" {
			errs = append(errs, fmt.Errorf("media[%d]: stored и store_skipped вместе", i))
		}
	}
	var imgs []ContentImage
	if e.Content != nil {
		imgs = e.Content.Images
	}
	stored := 0
	for _, m := range e.Media {
		if m.Stored {
			stored++
		}
	}
	if len(imgs) == 0 {
		if stored > 0 {
			errs = append(errs, fmt.Errorf("media: отмечено сохранённых изображений %d, а в содержимом их нет", stored))
		}
		return errs
	}
	if e.Storage != StorageFull {
		errs = append(errs, fmt.Errorf("content.images: изображения хранятся только в режиме full"))
	}
	if e.Type != TypeGatewayRequest && e.Type != TypeCheck {
		errs = append(errs, fmt.Errorf("%s: изображения бывают только у запроса чата и Check API", e.Type))
	}
	if len(imgs) > MaxStoredImages {
		errs = append(errs, fmt.Errorf("content.images: не больше %d изображений", MaxStoredImages))
	}
	if len(imgs) != stored {
		errs = append(errs, fmt.Errorf("content.images: изображений %d, а отмечено сохранённых в media %d", len(imgs), stored))
	}
	total := 0
	seen := make(map[string]bool, len(imgs))
	for i, img := range imgs {
		total += len(img.Data)
		if len(img.Data) == 0 || len(img.Data) > MaxStoredImageBytes {
			errs = append(errs, fmt.Errorf("content.images[%d]: от 1 байта до %d байт", i, MaxStoredImageBytes))
		}
		if !slices.Contains(mediaFormats, img.Format) || img.Sanitized && img.Format != "png" && img.Format != "jpeg" {
			errs = append(errs, fmt.Errorf("content.images[%d]: неизвестный формат %q", i, img.Format))
		}
		if img.Location == "" || len(img.Location) > maxShort || seen[img.Location] {
			errs = append(errs, fmt.Errorf("content.images[%d]: место — непустое, до %d байт, без повторов", i, maxShort))
		}
		seen[img.Location] = true
		// Только изображение, заголовок которого разобрал анализатор
		// (ADR-0039, раздел 2): в хранилище не попадают байты под видом
		// изображения.
		if !slices.ContainsFunc(e.Media, func(m MediaCheck) bool {
			return m.Location == img.Location && m.Stored && m.Format != ""
		}) {
			errs = append(errs, fmt.Errorf("content.images[%d]: нет записи media с этим местом, разобранным форматом и stored", i))
		}
	}
	if total > MaxEventImageBytes {
		errs = append(errs, fmt.Errorf("content.images: всего не больше %d байт", MaxEventImageBytes))
	}
	return errs
}
