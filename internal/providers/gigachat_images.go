package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
)

// Изображения GigaChat (задача 6.10 этапа 6). GigaChat не принимает
// изображение внутри запроса: файл загружается в хранилище отдельным
// запросом (POST /files, multipart: file и purpose=general), а сообщение
// пользователя ссылается на него полем attachments. По документации
// developers.sber.ru: одно изображение в сообщении, до 10 в запросе, до 15 МБ
// каждое; форматы JPG, PNG, TIFF, BMP. Загруженные файлы шлюз удаляет
// (POST /files/{id}/delete) после ответа — в том числе после ошибки и
// обрыва потока: в хранилище провайдера изображения запроса не копятся.
// Проверка на настоящей учётной записи — задача 6.2.

// gigaChatImages — пределы изображений GigaChat.
var gigaChatImages = imageLimits{
	formats:  []string{imageJPEG, imagePNG, imageTIFF, imageBMP},
	maxBytes: 15_000_000, perMessage: 1, perRequest: 10,
}

const (
	// gcCleanupTimeout — срок удаления загруженных файлов после ответа.
	gcCleanupTimeout = 10 * time.Second
	// gcFileResponseMax — предел ответа хранилища о файле.
	gcFileResponseMax = 64 << 10
)

// gcFileIDRe — ID файла хранилища: идёт в путь запроса удаления и в тело
// запроса к модели, поэтому — только безопасные символы.
var gcFileIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// prepare переводит запрос и загружает его изображения. Пределы и
// параметры проверяются до загрузки: отказ приложению ничего не оставляет
// в хранилище. files — загруженные файлы (вызывающий удаляет).
func (p *GigaChat) prepare(ctx, clientCtx context.Context, req *chat.Request, stream bool) (body []byte, files []string, err error) {
	if !hasImages(req) {
		body, err = toGigaChat(req, stream)
		return body, nil, err
	}
	imgs, err := requestImages(req, "gigachat", gigaChatImages)
	if err != nil {
		return nil, nil, err
	}
	// Проверка остальных параметров запроса до загрузки — с временными ID.
	probe := map[int][]string{}
	for _, img := range imgs {
		probe[img.Message] = []string{"file"}
	}
	if _, err := toGigaChatWith(req, stream, probe); err != nil {
		return nil, nil, err
	}
	attach := map[int][]string{}
	for _, img := range imgs {
		id, err := p.uploadFile(ctx, clientCtx, img)
		if err != nil {
			return nil, files, err
		}
		files = append(files, id)
		attach[img.Message] = []string{id}
	}
	body, err = toGigaChatWith(req, stream, attach)
	return body, files, err
}

// gcExt — расширение имени файла по типу (хранилище смотрит на имя и тип).
var gcExt = map[string]string{imageJPEG: "jpg", imagePNG: "png", imageTIFF: "tiff", imageBMP: "bmp"}

// uploadFile загружает изображение в хранилище GigaChat и возвращает ID
// файла; на 401 токен обновляется и загрузка повторяется один раз.
func (p *GigaChat) uploadFile(ctx, clientCtx context.Context, img inlineImage) (string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="image.%s"`, gcExt[img.Format]))
	h.Set("Content-Type", img.Format)
	part, err := mw.CreatePart(h)
	if err != nil {
		return "", err
	}
	if _, err := part.Write(img.Data); err != nil {
		return "", err
	}
	if err := mw.WriteField("purpose", "general"); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}
	for attempt := 0; ; attempt++ {
		tok, err := p.accessToken(ctx, clientCtx, attempt > 0)
		if err != nil {
			return "", err
		}
		hr, err := http.NewRequestWithContext(ctx, http.MethodPost, p.filesURL, bytes.NewReader(buf.Bytes()))
		if err != nil {
			return "", err
		}
		hr.Header.Set("Content-Type", mw.FormDataContentType())
		hr.Header.Set("Accept", "application/json")
		hr.Header.Set("User-Agent", "aisec-gateway")
		hr.Header.Set("Authorization", "Bearer "+tok)
		resp, _, err := p.do(hr, clientCtx)
		if errors.Is(err, ErrAuth) && attempt == 0 {
			continue
		}
		if err != nil {
			return "", err
		}
		raw, err := readLimited(resp, gcFileResponseMax)
		if err != nil {
			return "", p.transportError(clientCtx, err)
		}
		var f struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &f) != nil || !gcFileIDRe.MatchString(f.ID) {
			p.logger.Warn("ответ хранилища GigaChat не разобран", "provider", p.cfg.ID)
			return "", ErrBadResponse
		}
		return f.ID, nil
	}
}

// readLimited читает ответ не длиннее limit байт и закрывает тело.
func readLimited(resp *http.Response, limit int64) ([]byte, error) {
	defer resp.Body.Close() //nolint:errcheck // тело прочитано; ошибка закрытия не важна
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrBadResponse
	}
	return raw, nil
}

// cleanupFiles удаляет загруженные файлы. Ответ приложению уже готов или
// запрос отклонён, поэтому срок — свой (gcCleanupTimeout), а не срок
// запроса клиента; неудача — предупреждение в журнале без ID и содержимого:
// файл приватный (доступен только учётной записи шлюза).
func (p *GigaChat) cleanupFiles(ctx context.Context, files []string) {
	if len(files) == 0 {
		return
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gcCleanupTimeout)
	defer cancel()
	failed := 0
	for _, id := range files {
		if err := p.deleteFile(cctx, id); err != nil {
			failed++
		}
	}
	if failed > 0 {
		p.logger.Warn("изображения не удалены из хранилища GigaChat", "provider", p.cfg.ID, "files", failed)
	}
}

func (p *GigaChat) deleteFile(ctx context.Context, id string) error {
	for attempt := 0; ; attempt++ {
		tok, err := p.accessToken(ctx, ctx, attempt > 0)
		if err != nil {
			return err
		}
		u := strings.TrimSuffix(p.filesURL, "/") + "/" + url.PathEscape(id) + "/delete"
		hr, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
		if err != nil {
			return err
		}
		hr.Header.Set("Accept", "application/json")
		hr.Header.Set("User-Agent", "aisec-gateway")
		hr.Header.Set("Authorization", "Bearer "+tok)
		resp, _, err := p.do(hr, ctx)
		if errors.Is(err, ErrAuth) && attempt == 0 {
			continue
		}
		if err != nil {
			return err
		}
		p.closeBody(resp)
		return nil
	}
}

// withCleanup — поток, который удаляет загруженные файлы при закрытии.
func (p *GigaChat) withCleanup(ctx context.Context, st Stream, files []string) Stream {
	if len(files) == 0 {
		return st
	}
	return &cleanupStream{Stream: st, cleanup: func() { p.cleanupFiles(ctx, files) }}
}

// cleanupStream — поток с действием при закрытии; приостановка срока
// простоя (Holder) передаётся внутреннему потоку.
type cleanupStream struct {
	Stream
	once    sync.Once
	cleanup func()
}

func (s *cleanupStream) Close() error {
	err := s.Stream.Close()
	s.once.Do(s.cleanup)
	return err
}

func (s *cleanupStream) Hold() (resume func()) {
	if h, ok := s.Stream.(Holder); ok {
		return h.Hold()
	}
	return func() {}
}
