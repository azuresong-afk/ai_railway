package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// Изображения запроса в содержимом события full (задача 6.13, ADR-0039).
// Шлюз кладёт в событие только изображения, заголовок которых разобрал
// aisec-media; при media_sanitize — очищенные: те, что ушли провайдеру, а
// у запроса, заблокированного до очистки, — очищенные для хранения после
// ответа приложению. Изображения не декодируются (раскодируется только
// base64).

// storesImages — изображения запроса сохраняются в содержимом события:
// режим хранения full и media_store политики.
func (a *App) storesImages() bool {
	return a.Storage == events.StorageFull && a.Policy != nil && a.Policy.MediaStore
}

// keepSanitized запоминает очищенные изображения запроса для события:
// data:-адреса, подставленные в запрос (ссылки на те же строки, без копии).
func (rec *record) keepSanitized(req *chat.Request) {
	if !rec.app.storesImages() {
		return
	}
	rec.sanitizedURLs = map[string]string{}
	for _, img := range chatImages(req) {
		rec.sanitizedURLs[img.Location] = req.Messages[img.Message].Content.Parts[img.Part].ImageURL.URL
	}
}

// storeNeedsSanitize — для хранения нужна очистка, которой у запроса не
// было (Check API или запрос заблокирован до очистки): событие тогда
// собирается в фоне, как при media_check async.
func (rec *record) storeNeedsSanitize() bool {
	return rec.media != nil && rec.app.storesImages() && rec.app.Policy.MediaSanitize && rec.sanitizedURLs == nil
}

// storedImage — байты изображения для события.
type storedImage struct {
	data      []byte
	format    string
	sanitized bool
}

// storeImages кладёт изображения запроса в содержимое события и отмечает
// в rec.ev.Media, что сохранено и почему нет (StoreSkip*). Записи media
// идут в том же порядке, что итоги res (mediaResult.checks).
func (h *ChatHandler) storeImages(rec *record, res mediaResult) {
	if !rec.app.storesImages() || len(rec.ev.Media) == 0 {
		return
	}
	var sctx context.Context
	if rec.app.Policy.MediaSanitize && rec.sanitizedURLs == nil {
		ctx, cancel := context.WithTimeout(context.Background(), rec.app.Policy.MediaTimeout)
		defer cancel()
		sctx = ctx
	}
	var imgs []events.ContentImage
	total := 0
	for i := range rec.ev.Media {
		if i >= len(res.out) {
			break
		}
		m, o := &rec.ev.Media[i], res.out[i]
		switch {
		case o.img.URL:
			m.StoreSkipped = events.StoreSkipURL
			continue
		case m.Format == "":
			m.StoreSkipped = events.StoreSkipNotParsed
			continue
		case len(imgs) >= events.MaxStoredImages:
			m.StoreSkipped = events.StoreSkipEventLimit
			continue
		}
		si, skip := h.imageForStore(sctx, rec, o, m.Format)
		switch {
		case skip != "":
			m.StoreSkipped = skip
			continue
		case total+len(si.data) > events.MaxEventImageBytes:
			clear(si.data)
			m.StoreSkipped = events.StoreSkipEventLimit
			continue
		}
		total += len(si.data)
		imgs = append(imgs, events.ContentImage{Location: m.Location, Format: si.format, Sanitized: si.sanitized, Data: si.data})
		m.Stored = true
	}
	if len(imgs) == 0 {
		return
	}
	if rec.ev.Content == nil {
		rec.ev.Content = &events.Content{}
	}
	rec.ev.Content.Images = imgs
}

// imageForStore — байты одного изображения для события или причина, по
// которой его нет. sctx — срок очистки для хранения (nil — очистка не
// нужна или уже была).
func (h *ChatHandler) imageForStore(sctx context.Context, rec *record, o mediaOutcome, format string) (storedImage, string) {
	if !rec.app.Policy.MediaSanitize {
		b, err := decodeImage(o.img.Data, events.MaxStoredImageBytes)
		switch {
		case errors.Is(err, errImageTooLarge):
			return storedImage{}, events.StoreSkipTooLarge
		case err != nil:
			return storedImage{}, events.StoreSkipNotParsed
		}
		return storedImage{data: b, format: format}, ""
	}
	if u, ok := rec.sanitizedURLs[o.img.Location]; ok {
		return sanitizedFromURL(u)
	}
	if sctx == nil {
		// Очистка была, но этого изображения среди очищенных нет: хранить
		// неочищенное нельзя.
		return storedImage{}, events.StoreSkipNotSanitized
	}
	return h.sanitizeForStore(sctx, o.img)
}

// sanitizedFromURL — байты очищенного изображения из data:-адреса,
// подставленного в запрос (только PNG и JPEG).
func sanitizedFromURL(u string) (storedImage, string) {
	var format string
	switch {
	case strings.HasPrefix(u, "data:image/png;base64,"):
		format = "png"
	case strings.HasPrefix(u, "data:image/jpeg;base64,"):
		format = "jpeg"
	default:
		return storedImage{}, events.StoreSkipNotSanitized
	}
	data, _ := dataURLPayload(u)
	b, err := decodeImage(data, events.MaxStoredImageBytes)
	switch {
	case errors.Is(err, errImageTooLarge):
		return storedImage{}, events.StoreSkipTooLarge
	case err != nil:
		return storedImage{}, events.StoreSkipNotSanitized
	}
	return storedImage{data: b, format: format, sanitized: true}, ""
}

// sanitizeForStore очищает изображение только для хранения. Паника и
// любой отказ — изображение не хранится.
func (h *ChatHandler) sanitizeForStore(ctx context.Context, img mediaImage) (si storedImage, skip string) {
	defer func() {
		if p := recover(); p != nil {
			h.logger.Error("сбой очистки изображения для хранения", "location", img.Location, "panic", fmt.Sprint(p))
			si, skip = storedImage{}, events.StoreSkipNotSanitized
		}
	}()
	var s MediaSanitizer
	if h.cfg.Media != nil {
		s, _ = h.cfg.Media.(MediaSanitizer)
	}
	if s == nil || img.URL {
		return storedImage{}, events.StoreSkipNotSanitized
	}
	b, err := decodeImage(img.Data, h.cfg.Media.MaxBytes())
	if err != nil {
		return storedImage{}, events.StoreSkipNotSanitized
	}
	out, format, err := s.Sanitize(ctx, b)
	clear(b)
	if err != nil {
		return storedImage{}, events.StoreSkipNotSanitized
	}
	if len(out) > events.MaxStoredImageBytes {
		return storedImage{}, events.StoreSkipTooLarge
	}
	switch format {
	case wire.FormatPNG:
		return storedImage{data: out, format: "png", sanitized: true}, ""
	case wire.FormatJPEG:
		return storedImage{data: out, format: "jpeg", sanitized: true}, ""
	}
	return storedImage{}, events.StoreSkipNotSanitized
}
