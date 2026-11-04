package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Очистка изображений перед отправкой провайдеру (параметр политики
// media_sanitize, ТЗ 5.17, DM-47; ADR-0032, дополнение 5.45). Шлюз не
// декодирует изображения: байты из data:-адреса уходят в aisec-media
// (кадр sanitize), а в запрос к провайдеру подставляется то, что вернул
// анализатор, — PNG или JPEG без метаданных, уменьшенный до предела стороны.
// Изображение, которое не удалось очистить, провайдеру не уходит: запрос
// блокируется в любом режиме политики и при любом fail_mode — иначе
// включённая очистка не давала бы гарантии.

// ruleMediaSanitize — правило решения при отказе очистки.
const ruleMediaSanitize = "media_sanitize"

// sanitizeFailure — изображение не очищено: Reason — причина (как в
// MediaCheck.Reason или rejected), Failure — сбой анализатора, а не
// свойство изображения.
type sanitizeFailure struct {
	Location string
	Reason   string
	Failure  bool
}

// sanitizeImages очищает все изображения запроса и подставляет итог в
// req. Ссылки https:// шлюз не загружает, поэтому очистить их нельзя —
// отказ; изображений больше maxMediaImages — тоже отказ. При отказе запрос
// не меняется. Итог — места очищенных изображений.
func (h *ChatHandler) sanitizeImages(ctx context.Context, req *chat.Request, timeout time.Duration) ([]string, *sanitizeFailure) {
	imgs := chatImages(req)
	if len(imgs) == 0 {
		return nil, nil
	}
	if len(imgs) > maxMediaImages {
		return nil, &sanitizeFailure{Location: imgs[maxMediaImages].Location, Reason: events.MediaReasonLimit}
	}
	var s MediaSanitizer
	if h.cfg.Media != nil {
		s, _ = h.cfg.Media.(MediaSanitizer)
	}
	if s == nil {
		// Анализатор не установлен: очистить нечем.
		return nil, &sanitizeFailure{Location: imgs[0].Location, Reason: events.MediaReasonUnavailable, Failure: true}
	}
	raw := make([][]byte, len(imgs))
	for i, img := range imgs {
		if img.URL {
			return nil, &sanitizeFailure{Location: img.Location, Reason: events.MediaReasonURL}
		}
		b, err := decodeImage(img.Data, h.cfg.Media.MaxBytes())
		switch {
		case errors.Is(err, errImageTooLarge):
			return nil, &sanitizeFailure{Location: img.Location, Reason: events.MediaReasonTooLarge}
		case err != nil:
			return nil, &sanitizeFailure{Location: img.Location, Reason: events.MediaReasonMalformed}
		}
		raw[i] = b
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	urls := make([]string, len(imgs))
	fails := make([]*sanitizeFailure, len(imgs))
	sem := make(chan struct{}, mediaParallel)
	var wg sync.WaitGroup
	for i := range imgs {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			urls[i], fails[i] = h.sanitizeOne(sctx, s, imgs[i], raw[i])
		})
	}
	wg.Wait()
	for _, f := range fails {
		if f != nil {
			return nil, f
		}
	}
	locs := make([]string, len(imgs))
	for i, img := range imgs {
		req.Messages[img.Message].Content.Parts[img.Part].ImageURL.URL = urls[i]
		locs[i] = img.Location
	}
	return locs, nil
}

// sanitizeOne очищает одно изображение и возвращает data:-адрес итога.
// Паника — сбой, а не остановка шлюза.
func (h *ChatHandler) sanitizeOne(ctx context.Context, s MediaSanitizer, img mediaImage, b []byte) (url string, fail *sanitizeFailure) {
	defer func() {
		if p := recover(); p != nil {
			h.logger.Error("сбой очистки изображения", "location", img.Location, "panic", fmt.Sprint(p))
			url, fail = "", &sanitizeFailure{Location: img.Location, Reason: events.MediaReasonError, Failure: true}
		}
	}()
	out, format, err := s.Sanitize(ctx, b)
	if err != nil {
		var me *MediaError
		if !errors.As(err, &me) {
			me = &MediaError{Reason: events.MediaReasonError, Err: err}
		}
		return "", &sanitizeFailure{Location: img.Location, Reason: me.Reason, Failure: me.Failure()}
	}
	var mime string
	switch format {
	case wire.FormatPNG:
		mime = "image/png"
	case wire.FormatJPEG:
		mime = "image/jpeg"
	default:
		// Клиент проверяет формат по сигнатуре; сюда попадает только
		// заглушка с иным форматом.
		return "", &sanitizeFailure{Location: img.Location, Reason: events.MediaReasonError, Failure: true}
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(out), nil
}

// sanitizeDenied отвечает приложению на отказ очистки: свойство
// изображения — 400, сбой анализатора — 503 (повторить позже). Какое
// изображение и почему, приложению не сообщается: это в событии.
func sanitizeDenied(w http.ResponseWriter, f *sanitizeFailure) {
	w.Header().Set(HeaderDecision, string(policy.Block))
	if f.Failure {
		WriteError(w, http.StatusServiceUnavailable, "изображения не удалось подготовить к отправке модели, повторите позже",
			"service_unavailable", "media_sanitize_unavailable")
		return
	}
	WriteError(w, http.StatusBadRequest, "изображение в запросе нельзя подготовить к отправке модели",
		"invalid_request_error", "media_sanitize_rejected")
}

// sanitizeDecision отмечает в решении события отказ очистки: блокировка
// правилом media_sanitize и шаг трассировки с местом и причиной.
func sanitizeDecision(ed *events.Decision, f *sanitizeFailure) {
	ed.Action, ed.Rule = string(policy.Block), ruleMediaSanitize
	applied := []string{string(policy.Block)}
	for _, a := range ed.Applied {
		if a != string(policy.Block) {
			applied = append(applied, a)
		}
	}
	ed.Applied = applied
	note := "изображение " + f.Location + " не очищено (" + f.Reason + "): запрос не отправлен"
	ed.Trace = append(ed.Trace, events.TraceStep{Rule: ruleMediaSanitize, Matched: true, Action: string(policy.Block), Note: note})
}
