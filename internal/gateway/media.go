package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Изображения в запросах (ТЗ 5.17, ADR-0032, раздел 8; задача 5.39). Шлюз
// находит изображения в запросе, по длине base64 проверяет предел до
// раскодирования, раскодирует base64 (но не изображение) и передаёт байты
// aisec-media. Ссылки https:// шлюз не загружает (ЗИ.2): такое изображение
// не проверено, к нему применяется non_text. Режимы — параметр политики
// media_check: off, async, sync.

const (
	// maxMediaImages — сколько изображений одного запроса проверяется;
	// остальные — «не проверено» (limit) и non_text.
	maxMediaImages = 16
	// mediaParallel — одновременных анализов одного запроса: очередь
	// анализатора общая для всех запросов шлюза.
	mediaParallel = 4
	// mediaEmitWait — запас ожидания итога async после срока анализа:
	// событие запроса не ждёт дольше срока и этого запаса.
	mediaEmitWait = 500 * time.Millisecond
	// mediaFailureDetector — имя в сбоях проверки события (Decision.Failures)
	// для недоступного анализатора в режиме sync.
	mediaFailureDetector = "aisec-media"
)

// mediaImage — изображение запроса.
type mediaImage struct {
	// Location — место для события: messages[i].content[j] или images[i].
	Location string
	// Message, Part — номер сообщения и части в чате; -1 — Check API.
	Message, Part int
	// URL — ссылка https://, которую загрузил бы провайдер.
	URL bool
	// Data — данные base64 из data:-адреса, не раскодированные.
	Data string
}

// chatImages — изображения запроса чата (части image_url).
func chatImages(req *chat.Request) []mediaImage {
	var out []mediaImage
	for i := range req.Messages {
		for j, p := range req.Messages[i].Content.Parts {
			if p.ImageURL == nil {
				continue
			}
			img := mediaImage{Location: fmt.Sprintf("messages[%d].content[%d]", i, j), Message: i, Part: j}
			if data, ok := dataURLPayload(p.ImageURL.URL); ok {
				img.Data = data
			} else {
				img.URL = true
			}
			out = append(out, img)
		}
	}
	return out
}

// dataURLPayload — данные base64 из data:<тип>;base64,<данные>. Формат уже
// проверил разбор запроса (chat.Parse); тип из адреса не используется:
// формат определяет aisec-media по сигнатуре.
func dataURLPayload(u string) (string, bool) {
	if len(u) < 5 || !strings.EqualFold(u[:5], "data:") {
		return "", false
	}
	header, data, ok := strings.Cut(u[5:], ",")
	if !ok || !strings.HasSuffix(strings.ToLower(header), ";base64") {
		return "", false
	}
	return data, true
}

// errImageTooLarge, errImageMalformed — изображение не отправляется.
var (
	errImageTooLarge  = errors.New("изображение больше предела анализатора")
	errImageMalformed = errors.New("данные base64 не разобраны")
)

// decodeImage раскодирует base64 изображения. Предел проверяется по длине
// строки до раскодирования (ТЗ 5.1, граница «шлюз — aisec-media»).
// Принимаются стандартный и URL-алфавит, с выравниванием и без; символы вне
// алфавита и лишние биты — ошибка.
func decodeImage(data string, maxBytes int64) ([]byte, error) {
	if data == "" {
		return nil, errImageMalformed
	}
	if int64(base64.RawStdEncoding.DecodedLen(len(strings.TrimRight(data, "=")))) > maxBytes {
		return nil, errImageTooLarge
	}
	enc := base64.StdEncoding
	if strings.ContainsAny(data, "-_") {
		enc = base64.URLEncoding
	}
	if !strings.HasSuffix(data, "=") {
		enc = enc.WithPadding(base64.NoPadding)
	}
	b, err := enc.Strict().DecodeString(data)
	if err != nil || len(b) == 0 {
		return nil, errImageMalformed
	}
	return b, nil
}

// mediaOutcome — итог одного изображения.
type mediaOutcome struct {
	img   mediaImage
	check events.MediaCheck
	texts []MediaText
	// failure — сбой анализатора (а не свойство изображения).
	failure bool
}

// mediaRun — проверка изображений одного запроса. Итоги пишут
// исполнители анализа, читает обработчик запроса (sync) или отправка события
// (async) — под mu.
type mediaRun struct {
	mode    policy.MediaCheck
	timeout time.Duration
	done    chan struct{}
	mu      sync.Mutex
	out     []mediaOutcome
}

// startMedia запускает проверку изображений в режиме mode со сроком
// timeout: nil — изображений нет. В режиме off итог готов сразу: все «не
// проверено» (off), ссылки — url. ctx — контекст запроса: в режиме async
// анализ его не наследует (запрос завершится раньше).
func (h *ChatHandler) startMedia(ctx context.Context, mode policy.MediaCheck, timeout time.Duration, imgs []mediaImage) *mediaRun {
	if len(imgs) == 0 {
		return nil
	}
	run := &mediaRun{mode: mode, timeout: timeout, out: make([]mediaOutcome, len(imgs)), done: make(chan struct{})}
	var pending []int
	for i, img := range imgs {
		o := &run.out[i]
		o.img = img
		o.check = events.MediaCheck{Location: img.Location, Mode: string(run.mode)}
		switch {
		case run.mode == policy.MediaCheckOff:
			o.check.Reason = events.MediaReasonOff
		case img.URL:
			o.check.Reason = events.MediaReasonURL
		case len(pending) >= maxMediaImages:
			o.check.Reason = events.MediaReasonLimit
		default:
			pending = append(pending, i)
		}
	}
	if len(pending) == 0 {
		close(run.done)
		return run
	}
	if run.mode == policy.MediaCheckAsync {
		ctx = context.WithoutCancel(ctx)
	}
	actx, cancel := context.WithTimeout(ctx, run.timeout)
	go func() {
		defer close(run.done)
		defer cancel()
		h.analyzeAll(actx, run, pending)
	}()
	return run
}

// analyzeAll анализирует изображения pending не больше mediaParallel
// одновременно; каждое — со своим итогом.
func (h *ChatHandler) analyzeAll(ctx context.Context, run *mediaRun, pending []int) {
	sem := make(chan struct{}, mediaParallel)
	var wg sync.WaitGroup
	for _, i := range pending {
		sem <- struct{}{}
		run.mu.Lock()
		o := run.out[i]
		run.mu.Unlock()
		wg.Go(func() {
			defer func() { <-sem }()
			h.analyzeOne(ctx, &o)
			run.mu.Lock()
			run.out[i] = o
			run.mu.Unlock()
		})
	}
	wg.Wait()
}

// analyzeOne — итог одного изображения. Паника анализа — сбой, а не
// остановка шлюза.
func (h *ChatHandler) analyzeOne(ctx context.Context, o *mediaOutcome) {
	start := h.cfg.Now()
	defer func() {
		if p := recover(); p != nil {
			h.logger.Error("сбой проверки изображения", "location", o.img.Location, "panic", fmt.Sprint(p))
			o.check, o.texts, o.failure = events.MediaCheck{Location: o.img.Location, Mode: o.check.Mode, Reason: events.MediaReasonError}, nil, true
		}
		o.check.LatencyMS = h.cfg.Now().Sub(start).Milliseconds()
	}()
	if h.cfg.Media == nil {
		// Анализатор не установлен (нет -media-socket) — выбор установки, а не
		// сбой: изображение «не проверено», решает non_text, режим при отказе
		// не применяется (как до этапа 5, ADR-0032, «Откат»).
		o.check.Reason = events.MediaReasonUnavailable
		return
	}
	img, err := decodeImage(o.img.Data, h.cfg.Media.MaxBytes())
	switch {
	case errors.Is(err, errImageTooLarge):
		o.check.Reason = events.MediaReasonTooLarge
		return
	case err != nil:
		o.check.Reason = events.MediaReasonMalformed
		return
	}
	reply, err := h.cfg.Media.Analyze(ctx, img)
	if err != nil {
		var me *MediaError
		if !errors.As(err, &me) {
			me = &MediaError{Reason: events.MediaReasonError, Err: err}
		}
		o.check.Reason, o.failure = me.Reason, me.Failure()
		return
	}
	applyReply(o, reply)
}

// applyReply переносит итог анализатора в итог изображения. Проверенным
// считается только изображение с ocr в checks (ADR-0032, раздел 8); текст
// метаданных и QR (задача 5.43) проверяется детекторами и без OCR.
func applyReply(o *mediaOutcome, reply *MediaReply) {
	r := reply.Result
	o.check.Format, o.check.Width, o.check.Height, o.check.Frames, o.check.Cached = string(r.Format), r.Width, r.Height, r.Frames, r.Cached
	switch r.Status {
	case wire.StatusOK:
		o.texts = reply.Texts
		o.check.Texts = len(reply.Texts)
		if !slices.Contains(r.Checks, wire.CheckOCR) {
			o.check.Reason = events.MediaReasonNoOCR
			return
		}
		o.check.Checked = true
	case wire.StatusUnsupported:
		o.check.Reason = events.MediaReasonUnsupported
	default:
		o.check.Reason = rejectReason(r.Reason)
	}
}

func rejectReason(r wire.Reason) string {
	switch r {
	case wire.ReasonTooLarge:
		return events.MediaReasonTooLarge
	case wire.ReasonTooManyPixels:
		return events.MediaReasonPixels
	case wire.ReasonTooManyFrames:
		return events.MediaReasonFrames
	case wire.ReasonTooManyScans:
		return events.MediaReasonScans
	}
	return events.MediaReasonMalformed
}

// wait ждёт итог не дольше срока анализа и запаса и возвращает его.
// Изображение, анализ которого не завершился, — «не проверено» по сроку и
// сбой анализатора.
func (run *mediaRun) wait() mediaResult {
	t := time.NewTimer(run.timeout + mediaEmitWait)
	defer t.Stop()
	select {
	case <-run.done:
	case <-t.C:
	}
	return run.result()
}

// ready — итог готов.
func (run *mediaRun) ready() bool {
	select {
	case <-run.done:
		return true
	default:
		return false
	}
}

// result — итог на этот момент (копия).
func (run *mediaRun) result() mediaResult {
	run.mu.Lock()
	defer run.mu.Unlock()
	out := slices.Clone(run.out)
	for i := range out {
		if c := &out[i].check; !c.Checked && c.Reason == "" {
			c.Reason, out[i].failure = events.MediaReasonTimeout, true
		}
	}
	return mediaResult{mode: run.mode, out: out}
}

// mediaResult — итог проверки изображений запроса.
type mediaResult struct {
	mode policy.MediaCheck
	out  []mediaOutcome
}

// checks — записи для события.
func (r mediaResult) checks() []events.MediaCheck {
	out := make([]events.MediaCheck, 0, min(len(r.out), events.MaxMedia))
	for _, o := range r.out {
		if len(out) == events.MaxMedia {
			break
		}
		out = append(out, o.check)
	}
	return out
}

// unchecked — есть непроверенное изображение.
func (r mediaResult) unchecked() bool {
	return slices.ContainsFunc(r.out, func(o mediaOutcome) bool { return !o.check.Checked })
}

// checked — изображение сообщения m, части p проверено (чат).
func (r mediaResult) checked(m, p int) bool {
	for _, o := range r.out {
		if o.img.Message == m && o.img.Part == p {
			return o.check.Checked
		}
	}
	return false
}

// failures — сбои анализатора для режима приложения при отказе (sync).
func (r mediaResult) failures() []events.DetectorFailure {
	var out []events.DetectorFailure
	for _, o := range r.out {
		if !o.failure {
			continue
		}
		reason := events.FailureError
		if o.check.Reason == events.MediaReasonTimeout {
			reason = events.FailureTimeout
		}
		out = append(out, events.DetectorFailure{Detector: mediaFailureDetector, Location: o.img.Location, Reason: reason})
	}
	return out
}

// texts — тексты изображений для детекторов: источник image, место —
// место изображения, рамка — у находки в событии. Тексты есть только у
// разобранных изображений (ok), в том числе без OCR: метаданные и QR.
// Находки в метаданных и QR — строка DM-47 (ТЗ 5.16).
func (r mediaResult) texts() []inspectText {
	var out []inspectText
	for _, o := range r.out {
		for _, t := range o.texts {
			if t.Text == "" {
				continue
			}
			it := inspectText{Text: t.Text, Source: policy.SourceImage, Location: o.img.Location,
				Message: o.img.Message, Box: t.Box}
			if t.Origin == string(wire.SourceMetadata) || t.Origin == string(wire.SourceQR) {
				it.Threat = "DM-47"
			}
			out = append(out, it)
		}
	}
	return out
}

// chatPolicyMedia — нетекстовые части для non_text: проверенные
// изображения отмечены Checked.
func chatPolicyMedia(ms []chat.Media, r mediaResult) []policy.MediaPart {
	out := policyMedia(ms)
	for i, m := range ms {
		if m.Kind == chat.MediaImage && r.checked(m.Message, m.Part) {
			out[i].Checked = true
		}
	}
	return out
}

// imageThreat — строка матрицы находки в тексте изображения: инструкции —
// DM-45, ПДн и секреты — DM-46 (ТЗ 5.16); остальные — строка детектора.
func imageThreat(f detect.Finding) string {
	switch {
	case strings.HasPrefix(f.Category, "injection.") || strings.HasPrefix(f.Detector, "injection."):
		return "DM-45"
	case strings.HasPrefix(f.Category, "pii.") || strings.HasPrefix(f.Category, "secret."):
		return "DM-46"
	}
	return f.Threat
}
