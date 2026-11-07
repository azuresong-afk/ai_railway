package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/chat"
)

// Изображения YandexGPT (задача 6.10 этапа 6). Метод completion Foundation
// Models принимает только текст; изображения Yandex AI Studio принимает в
// OpenAI-совместимом методе того же узла (POST /v1/chat/completions):
// модель — gpt://<каталог>/<модель>, изображение — часть image_url с
// data:-адресом base64, заголовки Authorization: Api-Key и OpenAI-Project
// с каталогом (документация «Мультимодальные модели»). Отдельной загрузки
// файла нет. Адрес метода выводится из base_url провайдера (тот же узел,
// путь /foundationModels/v1 заменяется на /v1): новых адресов администратор
// не задаёт, шлюз обращается только к узлу, который он уже разрешил.
// Модели с изображениями — по документации провайдера (на момент задачи —
// мультимодальные модели AI Studio, не YandexGPT 5); проверка на настоящей
// учётной записи — задача 6.2.

// yandexImages — пределы изображений YandexGPT: форматы — из примеров
// документации (PNG, JPEG), предел размера документация не называет —
// 20 МБ как защита от чрезмерного тела (действует и предел шлюза).
var yandexImages = imageLimits{formats: []string{imagePNG, imageJPEG}, maxBytes: 20_000_000}

// visionURL — OpenAI-совместимый метод узла base_url: путь, кончающийся
// на /foundationModels/v1, заменяется на /v1/chat/completions; иной путь —
// пусто (изображения не поддерживаются: адрес не угадывается).
func visionURL(base *url.URL) string {
	path := strings.TrimSuffix(base.Path, "/")
	prefix, ok := strings.CutSuffix(path, "/foundationModels/v1")
	if !ok {
		return ""
	}
	u := *base
	u.Path, u.RawPath = prefix+"/v1/chat/completions", ""
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

// toYandexVision — запрос с изображениями в OpenAI-совместимом формате.
// Изображения передаются заново собранными data:-адресами (тип по
// сигнатуре, стандартный base64) из уже проверенных шлюзом байтов.
func toYandexVision(req *chat.Request, folder string, stream bool) ([]byte, error) {
	if err := ycCheck(req); err != nil {
		return nil, err
	}
	imgs, err := requestImages(req, "yandexgpt", yandexImages)
	if err != nil {
		return nil, err
	}
	for _, m := range req.Messages {
		for _, p := range m.Content.Parts {
			if p.ImageURL == nil && p.Text == nil && p.Refusal == nil {
				return nil, ycUnsupported("нетекстовое содержимое (" + p.Type + ")")
			}
		}
	}
	out := *req
	out.Model = "gpt://" + folder + "/" + req.Model
	out.Stream = stream
	if !stream {
		out.StreamOptions = nil
	}
	// Копия сообщений: запрос шлюза (и событие) не меняются.
	out.Messages = make([]chat.Message, len(req.Messages))
	copy(out.Messages, req.Messages)
	copied := map[int]bool{}
	for _, img := range imgs {
		m := &out.Messages[img.Message]
		if !copied[img.Message] {
			m.Content.Parts = append([]chat.Part(nil), m.Content.Parts...)
			copied[img.Message] = true
		}
		u := chat.ImageURL{URL: "data:" + img.Format + ";base64," + base64.StdEncoding.EncodeToString(img.Data),
			Detail: m.Content.Parts[img.Part].ImageURL.Detail}
		m.Content.Parts[img.Part].ImageURL = &u
	}
	return out.Marshal()
}

func (p *YandexGPT) sendVision(ctx, clientCtx context.Context, req *chat.Request, stream bool) (*http.Response, Meta, error) {
	if p.vision == "" {
		return nil, Meta{}, ycUnsupported("изображения при base_url не вида …/foundationModels/v1")
	}
	body, err := toYandexVision(req, p.yc.FolderID, stream)
	if err != nil {
		return nil, Meta{}, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, p.vision, bytes.NewReader(body))
	if err != nil {
		return nil, Meta{}, err
	}
	hr.Header.Set("Content-Type", "application/json")
	if stream {
		hr.Header.Set("Accept", "text/event-stream")
	} else {
		hr.Header.Set("Accept", "application/json")
	}
	hr.Header.Set("User-Agent", "aisec-gateway")
	hr.Header.Set("Authorization", "Api-Key "+p.yc.APIKey)
	hr.Header.Set("OpenAI-Project", p.yc.FolderID)
	hr.Header.Set("x-folder-id", p.yc.FolderID)
	return p.do(hr, clientCtx)
}

// chatImages — ответ целиком на запрос с изображениями.
func (p *YandexGPT) chatImages(ctx context.Context, req *chat.Request) (*chat.Response, Meta, error) {
	rctx, cancel := context.WithTimeout(ctx, p.cfg.ResponseTimeout)
	defer cancel()
	resp, meta, err := p.sendVision(rctx, ctx, req, false)
	if err != nil {
		return nil, meta, err
	}
	raw, err := p.readBody(ctx, resp)
	if err != nil {
		return nil, meta, err
	}
	out, err := chat.ParseResponse(raw)
	if err != nil {
		p.logger.Warn("ответ YandexGPT не разобран", "provider", p.cfg.ID)
		return nil, meta, ErrBadResponse
	}
	// Приложению — имя модели, как в запросе (без gpt://каталог/).
	out.Model = req.Model
	return out, meta, nil
}

// streamImages — потоковый ответ на запрос с изображениями (SSE формата OpenAI).
func (p *YandexGPT) streamImages(ctx context.Context, req *chat.Request) (Stream, Meta, error) {
	rctx, cancel := context.WithTimeout(ctx, p.cfg.ResponseTimeout)
	resp, meta, err := p.sendVision(rctx, ctx, req, true)
	if err != nil {
		cancel()
		return nil, meta, err
	}
	st, err := p.openStream(ctx, cancel, resp, func(data string) (*chat.Chunk, error) {
		c, err := chat.ParseChunk(data)
		if c != nil {
			c.Model = req.Model
		}
		return c, err
	})
	return st, meta, err
}
