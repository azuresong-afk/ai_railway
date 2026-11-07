package providers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/chat"
)

// Изображения в запросах к GigaChat и YandexGPT (задача 6.10 этапа 6, 5Н24
// ревью 5.r2). Приложение присылает изображения в формате OpenAI — частью
// image_url с data:-адресом; шлюз до адаптера проверяет их aisec-media
// (media_check, media_sanitize, «не проверено», пределы до декодирования),
// а адаптер переводит уже проверенные (или очищенные) байты в формат
// провайдера. Ссылки https:// провайдерам не передаются: шлюз их не
// загружает (ЗИ.2), а GigaChat и YandexGPT принимают только сами байты.
// Адаптер изображений не декодирует: формат определяется по сигнатуре
// первых байтов, растр не разбирается (CLAUDE.md, «Медиа»).

// Форматы изображений по сигнатуре.
const (
	imagePNG  = "image/png"
	imageJPEG = "image/jpeg"
	imageTIFF = "image/tiff"
	imageBMP  = "image/bmp"
	imageWEBP = "image/webp"
	imageGIF  = "image/gif"
)

// imageFormat — тип изображения по сигнатуре; пусто — не изображение
// известного формата.
func imageFormat(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return imagePNG
	case bytes.HasPrefix(b, []byte("\xff\xd8\xff")):
		return imageJPEG
	case bytes.HasPrefix(b, []byte("II*\x00")), bytes.HasPrefix(b, []byte("MM\x00*")):
		return imageTIFF
	case bytes.HasPrefix(b, []byte("BM")) && len(b) >= 26:
		return imageBMP
	case len(b) >= 12 && bytes.HasPrefix(b, []byte("RIFF")) && string(b[8:12]) == "WEBP":
		return imageWEBP
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return imageGIF
	}
	return ""
}

// imageLimits — что провайдер принимает.
type imageLimits struct {
	// formats — допустимые типы (по сигнатуре).
	formats []string
	// maxBytes — предел одного изображения после раскодирования base64.
	maxBytes int
	// perMessage, perRequest — сколько изображений в сообщении и в запросе;
	// 0 — без предела адаптера (действуют пределы шлюза).
	perMessage, perRequest int
}

// inlineImage — изображение из части image_url: номер сообщения и части,
// байты и тип по сигнатуре.
type inlineImage struct {
	Message, Part int
	Data          []byte
	Format        string
}

// dataURLBytes раскодирует data:<тип>;base64,<данные>. Предел проверяется
// по длине строки до раскодирования. Принимаются стандартный и URL-алфавит,
// с выравниванием и без (как в шлюзе); лишние биты — ошибка.
func dataURLBytes(u string, maxBytes int) ([]byte, error) {
	if len(u) < 5 || !strings.EqualFold(u[:5], "data:") {
		return nil, errImageNotData
	}
	header, data, ok := strings.Cut(u[5:], ",")
	if !ok || !strings.HasSuffix(strings.ToLower(header), ";base64") || data == "" {
		return nil, errImageNotData
	}
	if base64.RawStdEncoding.DecodedLen(len(strings.TrimRight(data, "="))) > maxBytes {
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
		return nil, errImageNotData
	}
	return b, nil
}

// Причины отказа в изображении (тексты — для приложения).
var (
	errImageNotData  = errors.New("изображение — data:-адрес с данными base64")
	errImageTooLarge = errors.New("изображение больше предела провайдера")
)

// requestImages собирает изображения запроса и проверяет их по пределам
// провайдера до любого обращения к нему: отказ — ошибка для приложения
// (400), ничего не загружено. Изображения — только в сообщениях
// пользователя; аудио, файлы и видео — по-прежнему не поддерживаются.
func requestImages(req *chat.Request, provider string, lim imageLimits) ([]inlineImage, error) {
	var out []inlineImage
	for i, m := range req.Messages {
		n := 0
		for j, p := range m.Content.Parts {
			if p.ImageURL == nil {
				continue
			}
			where := fmt.Sprintf("messages[%d].content[%d]: ", i, j)
			if m.Role != "user" {
				return nil, unsupportedBy(provider, where+"изображение вне сообщения пользователя")
			}
			if n++; lim.perMessage > 0 && n > lim.perMessage {
				return nil, unsupportedBy(provider, fmt.Sprintf("%sбольше %d изображений в одном сообщении", where, lim.perMessage))
			}
			if lim.perRequest > 0 && len(out) >= lim.perRequest {
				return nil, unsupportedBy(provider, fmt.Sprintf("%sбольше %d изображений в запросе", where, lim.perRequest))
			}
			b, err := dataURLBytes(p.ImageURL.URL, lim.maxBytes)
			switch {
			case errors.Is(err, errImageTooLarge):
				return nil, unsupportedBy(provider, fmt.Sprintf("%sизображение больше %d МБ", where, lim.maxBytes/1_000_000))
			case err != nil:
				// Ссылка https:// или неверный data:-адрес.
				return nil, unsupportedBy(provider, where+"изображение ссылкой (нужен data:-адрес с base64)")
			}
			f := imageFormat(b)
			if !containsStr(lim.formats, f) {
				return nil, unsupportedBy(provider, where+"формат изображения (допустимы "+formatList(lim.formats)+")")
			}
			out = append(out, inlineImage{Message: i, Part: j, Data: b, Format: f})
		}
	}
	return out, nil
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s && s != "" {
			return true
		}
	}
	return false
}

func formatList(formats []string) string {
	names := make([]string, len(formats))
	for i, f := range formats {
		names[i] = strings.ToUpper(strings.TrimPrefix(f, "image/"))
	}
	return strings.Join(names, ", ")
}

// hasImages — в запросе есть части image_url.
func hasImages(req *chat.Request) bool {
	for _, m := range req.Messages {
		for _, p := range m.Content.Parts {
			if p.ImageURL != nil {
				return true
			}
		}
	}
	return false
}

// textOnly — текст сообщения без частей image_url (изображения адаптер
// передаёт провайдеру отдельно).
func textOnly(m chat.Message, provider string) (string, error) {
	if m.Content.Text != nil {
		return *m.Content.Text, nil
	}
	parts := m.Content.Parts[:0:0]
	for _, p := range m.Content.Parts {
		if p.ImageURL == nil {
			parts = append(parts, p)
		}
	}
	m.Content.Parts = parts
	return textOf(m, provider)
}
