package mockllm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Режимы GigaChat и YandexGPT (задача 6.10 этапа 6): тот же мок отвечает в
// форматах этих провайдеров по их опубликованной документации, чтобы e2e и
// стенд проверяли адаптеры шлюза с изображениями без учётных записей.
//
// GigaChat (маршруты /api/v2/oauth и /api/v1/…):
//   - POST /api/v2/oauth — токен доступа по ключу авторизации (Basic, RqUID, scope);
//   - POST /api/v1/files — загрузка файла (multipart: file, purpose=general),
//     только изображения JPG, PNG, TIFF, BMP до 15 МБ; хранится в памяти;
//   - POST /api/v1/files/{id}/delete — удаление;
//   - POST /api/v1/chat/completions — ответ в формате GigaChat; attachments —
//     ID загруженных файлов, одно изображение в сообщении, до 10 в запросе.
//
// YandexGPT:
//   - POST /foundationModels/v1/completion — метод completion (только текст),
//     поток — строки JSON с накопленным текстом;
//   - изображения — OpenAI-совместимый POST /v1/chat/completions с моделью
//     gpt://<каталог>/<модель>, Authorization: Api-Key и OpenAI-Project.
//
// Ответ сценария echo с изображениями дописывает сводку «[изображения: …]»
// (формат и размер), по которой тесты видят, что изображение дошло.

// Пределы режимов.
const (
	gcMaxImage      = 15_000_000
	gcMaxFiles      = 64
	gcMaxPerRequest = 10
	gcUploadBody    = 16 << 20
	// GigaChatToken — префикс токена доступа мока.
	GigaChatToken = "mock-gigachat-token-" //nolint:gosec // G101: префикс токена мока, не учётные данные
)

// LastImage — изображение последнего запроса: формат и размер.
type LastImage struct {
	Format string `json:"format"`
	Bytes  int    `json:"bytes"`
}

type gcFile struct {
	data   []byte
	format string
}

func (s *Server) vendorRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v2/oauth", s.gcOAuth)
	mux.HandleFunc("POST /api/v1/files", s.gcUpload)
	mux.HandleFunc("POST /api/v1/files/{id}/delete", s.gcDelete)
	mux.HandleFunc("POST /api/v1/chat/completions", s.gcChat)
	mux.HandleFunc("POST /foundationModels/v1/completion", s.ycCompletion)
}

// imageKind — формат изображения по сигнатуре (как в адаптерах шлюза).
func imageKind(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case bytes.HasPrefix(b, []byte("\xff\xd8\xff")):
		return "jpeg"
	case bytes.HasPrefix(b, []byte("II*\x00")), bytes.HasPrefix(b, []byte("MM\x00*")):
		return "tiff"
	case bytes.HasPrefix(b, []byte("BM")):
		return "bmp"
	}
	return ""
}

func imagesNote(imgs []LastImage) string {
	if len(imgs) == 0 {
		return ""
	}
	parts := make([]string, len(imgs))
	for i, im := range imgs {
		parts[i] = fmt.Sprintf("%s %d байт", im.Format, im.Bytes)
	}
	return " [изображения: " + strings.Join(parts, "; ") + "]"
}

// gcAuthorized — токен доступа, выданный этим моком.
func (s *Server) gcAuthorized(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !strings.HasPrefix(tok, GigaChatToken) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gcTokens[tok]
}

func (s *Server) gcOAuth(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") || r.Header.Get("RqUID") == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": 6, "message": "credentials doesn't match db data"})
		return
	}
	if err := r.ParseForm(); err != nil || !strings.HasPrefix(r.PostForm.Get("scope"), "GIGACHAT_API_") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": 7, "message": "scope from db not fully includes consumed scope"})
		return
	}
	tok := fmt.Sprintf("%s%d", GigaChatToken, s.seq.Add(1))
	s.mu.Lock()
	if s.gcTokens == nil {
		s.gcTokens = map[string]bool{}
	}
	s.gcTokens[tok] = true
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "expires_at": s.now().Add(30 * time.Minute).UnixMilli()})
}

func gcError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"status": status, "message": msg})
}

func (s *Server) gcUpload(w http.ResponseWriter, r *http.Request) {
	if !s.gcAuthorized(r) {
		gcError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, gcUploadBody)
	if err := r.ParseMultipartForm(gcUploadBody); err != nil { //nolint:gosec // G120: тело ограничено MaxBytesReader строкой выше
		gcError(w, http.StatusBadRequest, "multipart: file и purpose")
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck // временные файлы формы; ошибка удаления не важна
	if r.FormValue("purpose") != "general" {
		gcError(w, http.StatusBadRequest, "purpose must be general")
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		gcError(w, http.StatusBadRequest, "file is required")
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, gcMaxImage+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil || len(data) == 0 {
		gcError(w, http.StatusBadRequest, "file is empty")
		return
	}
	if len(data) > gcMaxImage {
		gcError(w, http.StatusRequestEntityTooLarge, "image is larger than 15 MB")
		return
	}
	kind := imageKind(data)
	if kind == "" {
		gcError(w, http.StatusUnsupportedMediaType, "unsupported file format")
		return
	}
	s.mu.Lock()
	if s.gcFiles == nil {
		s.gcFiles = map[string]gcFile{}
	}
	if len(s.gcFiles) >= gcMaxFiles {
		s.mu.Unlock()
		gcError(w, http.StatusTooManyRequests, "file storage is full")
		return
	}
	n := s.seq.Add(1)
	id := fmt.Sprintf("00000000-0000-4000-8000-%012d", n)
	s.gcFiles[id] = gcFile{data: data, format: kind}
	s.mu.Unlock()
	s.logger.Info("загружено изображение", "format", kind, "bytes", len(data))
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "object": "file", "bytes": len(data), "created_at": s.now().Unix(),
		"filename": "image." + kind, "purpose": "general", "access_policy": "private", "modalities": []string{"image"}})
}

func (s *Server) gcDelete(w http.ResponseWriter, r *http.Request) {
	if !s.gcAuthorized(r) {
		gcError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	id := r.PathValue("id")
	s.mu.Lock()
	_, ok := s.gcFiles[id]
	delete(s.gcFiles, id)
	s.mu.Unlock()
	if !ok {
		gcError(w, http.StatusNotFound, "file not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})
}

// GigaChatFiles — сколько файлов лежит в хранилище мока (проверка, что
// шлюз удаляет загруженные изображения).
func (s *Server) GigaChatFiles() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.gcFiles)
}

type gcReq struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role        string   `json:"role"`
		Content     string   `json:"content"`
		Attachments []string `json:"attachments"`
	} `json:"messages"`
}

func (s *Server) gcChat(w http.ResponseWriter, r *http.Request) {
	if !s.gcAuthorized(r) {
		gcError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	body, err := readBody(w, r)
	if err != nil {
		gcError(w, http.StatusBadRequest, "body")
		return
	}
	var req gcReq
	if json.Unmarshal(body, &req) != nil || req.Model == "" || len(req.Messages) == 0 || len(req.Messages) > MaxMessages {
		gcError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var imgs []LastImage
	last := ""
	for _, m := range req.Messages {
		if len(m.Attachments) > 1 {
			gcError(w, http.StatusUnprocessableEntity, "only one image per message")
			return
		}
		for _, id := range m.Attachments {
			s.mu.Lock()
			f, ok := s.gcFiles[id]
			s.mu.Unlock()
			if !ok {
				gcError(w, http.StatusNotFound, "file not found")
				return
			}
			imgs = append(imgs, LastImage{Format: f.format, Bytes: len(f.data)})
		}
		if m.Role == "user" {
			last = m.Content
		}
	}
	if len(imgs) > gcMaxPerRequest {
		gcError(w, http.StatusUnprocessableEntity, "too many images")
		return
	}
	s.recordVendor(r, req.Model, req.Stream, body, imgs)
	answer := FixedAnswer
	if strings.TrimPrefix(req.Model, "mock-") != ScenarioFixed {
		answer = last + imagesNote(imgs)
	}
	answer = s.decorate(answer, last)
	if req.Model == "mock-"+ScenarioError500 {
		gcError(w, http.StatusInternalServerError, "internal error (mock)")
		return
	}
	created := s.now().Unix()
	usage := map[string]int{"prompt_tokens": countTokens(last), "completion_tokens": countTokens(answer)}
	usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
	if !req.Stream {
		writeJSON(w, http.StatusOK, map[string]any{"created": created, "model": req.Model, "object": "chat.completion", "usage": usage,
			"choices": []map[string]any{{"index": 0, "finish_reason": "stop", "message": map[string]string{"role": "assistant", "content": answer}}}})
		return
	}
	s.vendorSSE(w, r, func(emit func(v any) bool) {
		for i, part := range SplitChunks(answer) {
			delta := map[string]any{"content": part}
			if i == 0 {
				delta["role"] = "assistant"
			}
			if !emit(map[string]any{"created": created, "model": req.Model, "choices": []map[string]any{{"index": 0, "delta": delta}}}) {
				return
			}
		}
		emit(map[string]any{"created": created, "model": req.Model, "usage": usage,
			"choices": []map[string]any{{"index": 0, "delta": map[string]string{"content": ""}, "finish_reason": "stop"}}})
	})
}

// vendorSSE — поток SSE с JSON-событиями и завершающим [DONE].
func (s *Server) vendorSSE(w http.ResponseWriter, r *http.Request, body func(emit func(v any) bool)) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		gcError(w, http.StatusInternalServerError, "no streaming")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	body(func(v any) bool {
		b, err := json.Marshal(v)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	})
	if r.Context().Err() == nil {
		if _, err := fmt.Fprint(w, "data: [DONE]\n\n"); err == nil {
			flusher.Flush()
		}
	}
}

// recordVendor — запись последнего запроса режимов провайдеров.
func (s *Server) recordVendor(r *http.Request, model string, stream bool, body []byte, imgs []LastImage) {
	if !s.opts.RecordLast {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = LastRequest{Received: true, Count: s.last.Count + 1, Scenario: ScenarioEcho, Model: model, Stream: stream,
		HasAuthorization: r.Header.Get("Authorization") != "", Body: string(body), Images: imgs}
}

var ycModelURIRe = regexp.MustCompile(`^gpt://([a-z0-9]{1,50})/(.+)$`)

type ycReq struct {
	ModelURI          string `json:"modelUri"`
	CompletionOptions struct {
		Stream bool `json:"stream"`
	} `json:"completionOptions"`
	Messages []struct {
		Role string `json:"role"`
		Text string `json:"text"`
	} `json:"messages"`
}

// ycCompletion — метод completion YandexGPT (только текст).
func (s *Server) ycCompletion(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Api-Key ") {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"grpcCode": 16, "httpCode": 401, "message": "Unauthenticated"}})
		return
	}
	body, err := readBody(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"httpCode": 400, "message": "body"}})
		return
	}
	var req ycReq
	m := []string(nil)
	if json.Unmarshal(body, &req) == nil {
		m = ycModelURIRe.FindStringSubmatch(req.ModelURI)
	}
	if m == nil || len(req.Messages) == 0 || len(req.Messages) > MaxMessages || r.Header.Get("x-folder-id") != m[1] {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"httpCode": 400, "message": "invalid modelUri, folder or messages"}})
		return
	}
	last := ""
	for _, msg := range req.Messages {
		if msg.Role == "user" {
			last = msg.Text
		}
	}
	s.recordVendor(r, m[2], req.CompletionOptions.Stream, body, nil)
	answer := s.decorate(last, last)
	if m[2] == "mock-"+ScenarioFixed {
		answer = s.decorate(FixedAnswer, last)
	}
	result := func(text, status string) map[string]any {
		n := countTokens(last)
		c := countTokens(text)
		return map[string]any{"result": map[string]any{
			"alternatives": []map[string]any{{"message": map[string]string{"role": "assistant", "text": text}, "status": status}},
			"usage":        map[string]string{"inputTextTokens": fmt.Sprint(n), "completionTokens": fmt.Sprint(c), "totalTokens": fmt.Sprint(n + c)},
			"modelVersion": "mock"}}
	}
	if !req.CompletionOptions.Stream {
		writeJSON(w, http.StatusOK, result(answer, "ALTERNATIVE_STATUS_FINAL"))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": map[string]any{"httpCode": 500, "message": "no streaming"}})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	acc := ""
	parts := SplitChunks(answer)
	enc := json.NewEncoder(w)
	for i, p := range parts {
		acc += p
		status := "ALTERNATIVE_STATUS_PARTIAL"
		if i == len(parts)-1 {
			status = "ALTERNATIVE_STATUS_FINAL"
		}
		if enc.Encode(result(acc, status)) != nil {
			return
		}
		flusher.Flush()
	}
	if len(parts) == 0 {
		if enc.Encode(result("", "ALTERNATIVE_STATUS_FINAL")) == nil {
			flusher.Flush()
		}
	}
}

// ycVision проверяет запрос OpenAI-совместимого метода YandexGPT (модель
// gpt://каталог/модель): ключ Api-Key и каталог в OpenAI-Project. ok=false —
// ответ уже отправлен. imgs — изображения запроса (data:-адреса).
func ycVision(w http.ResponseWriter, r *http.Request, body []byte, model string) (imgs []LastImage, ok bool) {
	m := ycModelURIRe.FindStringSubmatch(model)
	if m == nil {
		return nil, true // не режим YandexGPT
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Api-Key ") || r.Header.Get("OpenAI-Project") != m[1] {
		writeError(w, http.StatusUnauthorized, "нужны Api-Key и OpenAI-Project с каталогом из модели", "authentication_error", "invalid_api_key")
		return nil, false
	}
	var req struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &req) != nil {
		return nil, true
	}
	for _, msg := range req.Messages {
		var parts []struct {
			Type     string `json:"type"`
			ImageURL *struct {
				URL string `json:"url"`
			} `json:"image_url"`
		}
		if json.Unmarshal(msg.Content, &parts) != nil {
			continue
		}
		for _, p := range parts {
			if p.ImageURL == nil {
				continue
			}
			im, err := dataImage(p.ImageURL.URL)
			if err != nil {
				writeError(w, http.StatusBadRequest, "изображение — data:-адрес base64 PNG или JPEG", "invalid_request_error", "invalid_image")
				return nil, false
			}
			imgs = append(imgs, im)
		}
	}
	return imgs, true
}

var errDataImage = errors.New("не изображение в data-адресе")

// dataImage — формат и размер изображения из data:-адреса base64.
func dataImage(u string) (LastImage, error) {
	rest, ok := strings.CutPrefix(u, "data:")
	if !ok {
		return LastImage{}, errDataImage
	}
	header, data, ok := strings.Cut(rest, ",")
	if !ok || !strings.HasSuffix(header, ";base64") {
		return LastImage{}, errDataImage
	}
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return LastImage{}, errDataImage
	}
	kind := imageKind(b)
	if kind != "png" && kind != "jpeg" {
		return LastImage{}, errDataImage
	}
	return LastImage{Format: kind, Bytes: len(b)}, nil
}
