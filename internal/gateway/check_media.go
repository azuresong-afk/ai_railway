package gateway

import (
	"fmt"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Изображения в Check API (ТЗ 5.17: «Check API принимает изображения»;
// задача 5.39). Поле images — до maxMediaImages адресов data:<тип>;base64,…
// или https://; ссылку шлюз не загружает (ЗИ.2): изображение «не
// проверено», решает non_text. Check API отвечает на вопрос синхронно,
// поэтому media_check async здесь выполняется как sync; off — изображения
// не анализируются.

// maxCheckImageURL — предел ссылки https:// на изображение (как у chat).
const maxCheckImageURL = 2048

// checkImages проверяет поле images и возвращает изображения. maxMedia —
// предел длины данных одного изображения (Limits.MaxMediaBytes приложения).
func checkImages(images []string, dir string, maxMedia int) ([]mediaImage, *chat.Error) {
	if len(images) == 0 {
		return nil, nil
	}
	if dir != "input" {
		return nil, &chat.Error{Code: chat.CodeInvalid, Message: "images: изображения проверяются только во входе (direction: input)"}
	}
	if len(images) > maxMediaImages {
		return nil, &chat.Error{Code: chat.CodeTooMany, Message: fmt.Sprintf("images: не больше %d изображений", maxMediaImages)}
	}
	if maxMedia <= 0 {
		maxMedia = chat.DefaultLimits.MaxMediaBytes
	}
	out := make([]mediaImage, len(images))
	for i, u := range images {
		img := mediaImage{Location: fmt.Sprintf("images[%d]", i), Message: -1, Part: i}
		if data, ok := dataURLPayload(u); ok {
			header := u[5 : len(u)-len(data)-1]
			if len(header) > 256 || !base64Chars(data) {
				return nil, &chat.Error{Code: chat.CodeInvalid, Message: fmt.Sprintf("images[%d]: data:-адрес — data:<тип>;base64,<данные>", i)}
			}
			if len(data) > maxMedia {
				return nil, &chat.Error{Code: chat.CodeMediaTooLarge, Message: fmt.Sprintf("images[%d]: данные больше %d байт", i, maxMedia)}
			}
			img.Data = data
		} else {
			if len(u) < 8 || !strings.EqualFold(u[:8], "https://") || len(u) > maxCheckImageURL ||
				strings.ContainsFunc(u, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
				return nil, &chat.Error{Code: chat.CodeInvalid,
					Message: fmt.Sprintf("images[%d]: data:<тип>;base64,<данные> или https:// до %d байт без пробелов", i, maxCheckImageURL)}
			}
			img.URL = true
		}
		out[i] = img
	}
	return out, nil
}

// base64Chars — непустая строка из алфавита base64 (стандартного или URL) с
// выравниванием; раскодирование — позже, после проверки предела по длине.
func base64Chars(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '-', c == '_', c == '=':
		default:
			return false
		}
	}
	return true
}

// checkMediaMode — режим анализа для Check API: async выполняется как sync.
func checkMediaMode(p *policy.Policy) policy.MediaCheck {
	if p.MediaCheck == policy.MediaCheckAsync {
		return policy.MediaCheckSync
	}
	return p.MediaCheck
}

// checkPolicyMedia — изображения Check API для non_text.
func checkPolicyMedia(imgs []mediaImage, r mediaResult) []policy.MediaPart {
	out := make([]policy.MediaPart, len(imgs))
	for i, img := range imgs {
		out[i] = policy.MediaPart{Kind: chat.MediaImage, URL: img.URL, Checked: r.checked(-1, i)}
	}
	return out
}

// imagesSize — длина данных изображений для квоты размера входа.
func imagesSize(imgs []mediaImage) int {
	n := 0
	for _, img := range imgs {
		n += len(img.Data)
	}
	return n
}

// checkMediaView — итог проверки изображений в ответе Check API.
type checkMediaView = events.MediaCheck
