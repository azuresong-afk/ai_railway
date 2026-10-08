package providers

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Адаптер GigaChat API (ТЗ, 5.1). Форматы — по публичной документации
// developers.sber.ru (план этапа 1, Р8); до пилота адаптер проверяется на
// настоящей учётной записи.
//
// Авторизация: по ключу авторизации (Basic) шлюз получает токен доступа
// (POST /api/v2/oauth, scope, RqUID) на 30 минут, кеширует его и обновляет
// заранее; на 401 от API токен обновляется и запрос повторяется один раз.
// Приложение ни ключа, ни токена не видит.

// DefaultGigaChatAuthURL — адрес выдачи токена по умолчанию.
const DefaultGigaChatAuthURL = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"

// Области доступа GigaChat API.
var gigaChatScopes = map[string]bool{"GIGACHAT_API_PERS": true, "GIGACHAT_API_B2B": true, "GIGACHAT_API_CORP": true}

// GigaChatConfig — параметры провайдера GigaChat.
type GigaChatConfig struct {
	BaseConfig
	// BaseURL — адрес API с версией: https://gigachat.devices.sberbank.ru/api/v1.
	BaseURL *url.URL
	// AuthURL — адрес выдачи токена; nil — DefaultGigaChatAuthURL.
	AuthURL *url.URL
	// AuthKey — ключ авторизации из личного кабинета (передаётся как Basic).
	AuthKey string
	Scope   string
	// Random — источник случайности криптопрофиля (RqUID, идентификаторы).
	Random aisecCrypto.Random
	// Now — текущее время (для тестов); nil — time.Now.
	Now func() time.Time
}

// GigaChat — провайдер GigaChat API.
type GigaChat struct {
	base
	gc       GigaChatConfig
	endpoint string
	authURL  string

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewGigaChat проверяет параметры и создаёт провайдера.
func NewGigaChat(cfg GigaChatConfig) (*GigaChat, error) {
	if cfg.BaseURL == nil || cfg.AuthKey == "" || cfg.Random == nil {
		return nil, errors.New("провайдер gigachat: нужны base_url, ключ авторизации и источник случайности")
	}
	if !gigaChatScopes[cfg.Scope] {
		return nil, fmt.Errorf("провайдер gigachat: scope — GIGACHAT_API_PERS, GIGACHAT_API_B2B или GIGACHAT_API_CORP")
	}
	b, err := newBase(cfg.BaseConfig, cfg.AuthKey)
	if err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	authURL := DefaultGigaChatAuthURL
	if cfg.AuthURL != nil {
		authURL = endpoint(cfg.AuthURL, "")
	}
	p := &GigaChat{base: b, gc: cfg, endpoint: endpoint(cfg.BaseURL, "/chat/completions"), authURL: authURL}
	p.dynSecrets = func() []string {
		p.mu.Lock()
		defer p.mu.Unlock()
		return []string{p.token}
	}
	return p, nil
}

// tokenRefreshMargin — за сколько до истечения токен обновляется заранее.
const tokenRefreshMargin = time.Minute

// accessToken возвращает действующий токен; force — получить новый.
// Блокировка держится на время получения: одновременные запросы ждут один
// и тот же токен, а не получают каждый свой.
func (p *GigaChat) accessToken(ctx, clientCtx context.Context, force bool) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.gc.Now()
	if !force && p.token != "" && now.Add(tokenRefreshMargin).Before(p.expires) {
		return p.token, nil
	}
	rquid, err := uuid4(p.gc.Random)
	if err != nil {
		return "", err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, p.authURL, strings.NewReader(url.Values{"scope": {p.gc.Scope}}.Encode()))
	if err != nil {
		return "", err
	}
	hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("User-Agent", "aisec-gateway")
	hr.Header.Set("RqUID", rquid)
	hr.Header.Set("Authorization", "Basic "+p.gc.AuthKey)
	resp, err := p.client.Do(hr)
	if err != nil {
		return "", p.transportError(clientCtx, err)
	}
	defer resp.Body.Close() //nolint:errcheck // тело прочитано; ошибка закрытия не важна
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		p.logger.Warn("GigaChat отклонил ключ авторизации шлюза", "provider", p.cfg.ID, "status", resp.StatusCode)
		return "", ErrAuth
	}
	if resp.StatusCode != http.StatusOK {
		p.logger.Warn("GigaChat не выдал токен", "provider", p.cfg.ID, "status", resp.StatusCode)
		return "", ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", p.transportError(clientCtx, err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   int64  `json:"expires_at"` // миллисекунды Unix
	}
	if json.Unmarshal(raw, &tok) != nil || tok.AccessToken == "" || len(tok.AccessToken) > 16<<10 || validateSecret(tok.AccessToken) != nil {
		p.logger.Warn("ответ GigaChat с токеном не разобран", "provider", p.cfg.ID)
		return "", ErrBadResponse
	}
	exp := time.UnixMilli(tok.ExpiresAt)
	if !exp.After(now) || exp.After(now.Add(24*time.Hour)) {
		// Срок вне разумных пределов — считаем по документации (30 минут).
		exp = now.Add(30 * time.Minute)
	}
	p.token, p.expires = tok.AccessToken, exp
	return p.token, nil
}

// uuid4 — случайный UUID версии 4 для заголовка RqUID.
func uuid4(rnd aisecCrypto.Random) (string, error) {
	b, err := aisecCrypto.RandomBytes(rnd, 16)
	if err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

func (p *GigaChat) randomID(prefix string) (string, error) {
	b, err := aisecCrypto.RandomBytes(p.gc.Random, 12)
	if err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

// send отправляет запрос; на 401 токен обновляется и запрос повторяется
// один раз (токен мог истечь раньше срока).
func (p *GigaChat) send(ctx, clientCtx context.Context, req *chat.Request, stream bool) (*http.Response, Meta, error) {
	body, err := toGigaChat(req, stream)
	if err != nil {
		return nil, Meta{}, err
	}
	for attempt := 0; ; attempt++ {
		tok, err := p.accessToken(ctx, clientCtx, attempt > 0)
		if err != nil {
			return nil, Meta{}, err
		}
		resp, meta, err := p.post(ctx, clientCtx, p.endpoint, body, stream, "Bearer "+tok)
		if errors.Is(err, ErrAuth) && attempt == 0 {
			continue
		}
		return resp, meta, err
	}
}

// Chat — ответ целиком.
func (p *GigaChat) Chat(ctx context.Context, req *chat.Request) (*chat.Response, Meta, error) {
	rctx, cancel := context.WithTimeout(ctx, p.cfg.ResponseTimeout)
	defer cancel()
	resp, meta, err := p.send(rctx, ctx, req, false)
	if err != nil {
		return nil, meta, err
	}
	raw, err := p.readBody(ctx, resp)
	if err != nil {
		return nil, meta, err
	}
	out, err := p.fromGigaChat(raw)
	if err != nil {
		p.logger.Warn("ответ GigaChat не разобран", "provider", p.cfg.ID)
		return nil, meta, ErrBadResponse
	}
	return out, meta, nil
}

// Stream — потоковый ответ.
func (p *GigaChat) Stream(ctx context.Context, req *chat.Request) (Stream, Meta, error) {
	rctx, cancel := context.WithTimeout(ctx, p.cfg.ResponseTimeout)
	resp, meta, err := p.send(rctx, ctx, req, true)
	if err != nil {
		cancel()
		return nil, meta, err
	}
	id, err := p.randomID("chatcmpl-")
	if err != nil {
		cancel()
		if cerr := resp.Body.Close(); cerr != nil {
			p.logger.Warn("закрытие ответа провайдера", "error", ErrorClass(cerr))
		}
		return nil, meta, err
	}
	callID, err := p.randomID("call_")
	if err != nil {
		cancel()
		if cerr := resp.Body.Close(); cerr != nil {
			p.logger.Warn("закрытие ответа провайдера", "error", ErrorClass(cerr))
		}
		return nil, meta, err
	}
	st, err := p.openStream(ctx, cancel, resp, func(data string) (*chat.Chunk, error) {
		return gigaChatChunk(data, id, callID)
	})
	return st, meta, err
}

// Формат GigaChat API.
type gcFunctionCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"` // объект JSON, а не строка
}

type gcMessage struct {
	Role         string          `json:"role"`
	Content      string          `json:"content"`
	Name         string          `json:"name,omitempty"`
	FunctionCall *gcFunctionCall `json:"function_call,omitempty"`
}

type gcFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters"`
}

type gcRequest struct {
	Model        string          `json:"model"`
	Messages     []gcMessage     `json:"messages"`
	Temperature  *float64        `json:"temperature,omitempty"`
	TopP         *float64        `json:"top_p,omitempty"`
	MaxTokens    *int            `json:"max_tokens,omitempty"`
	Stream       bool            `json:"stream,omitempty"`
	Functions    []gcFunction    `json:"functions,omitempty"`
	FunctionCall json.RawMessage `json:"function_call,omitempty"`
}

// unsupported — ошибка для приложения: параметр без аналога в GigaChat.
// Молча отбрасывать параметр нельзя: приложение получило бы не то
// поведение, которое запросило.
func unsupported(what string) error { return unsupportedBy("gigachat", what) }

func unsupportedBy(provider, what string) error {
	return &Error{Status: http.StatusBadRequest, Type: "invalid_request_error", Code: "unsupported_parameter",
		Message: what + " не поддерживается провайдером " + provider}
}

func invalid(msg string) error {
	return &Error{Status: http.StatusBadRequest, Type: "invalid_request_error", Code: "invalid_request", Message: msg}
}

// textOf — текст сообщения: строка или текстовые части через перевод строки.
// Нетекстовые части GigaChat и YandexGPT принимают только в своём формате
// (загруженными файлами) — на этапе 1 это не поддерживается.
func textOf(m chat.Message, provider string) (string, error) {
	if m.Content.Text != nil {
		return *m.Content.Text, nil
	}
	var parts []string
	for _, p := range m.Content.Parts {
		switch {
		case p.Text != nil:
			parts = append(parts, *p.Text)
		case p.Refusal != nil:
			parts = append(parts, *p.Refusal)
		default:
			return "", unsupportedBy(provider, "нетекстовое содержимое ("+p.Type+")")
		}
	}
	if m.Refusal != nil {
		parts = append(parts, *m.Refusal)
	}
	return strings.Join(parts, "\n"), nil
}

// toGigaChat переводит запрос из формата OpenAI в формат GigaChat.
func toGigaChat(req *chat.Request, stream bool) ([]byte, error) {
	switch {
	case len(req.Stop) > 0:
		return nil, unsupported("параметр stop")
	case len(req.ResponseFormat) > 0:
		return nil, unsupported("параметр response_format")
	case req.Seed != nil:
		return nil, unsupported("параметр seed")
	case len(req.LogitBias) > 0:
		return nil, unsupported("параметр logit_bias")
	case req.PresencePenalty != nil && *req.PresencePenalty != 0, req.FrequencyPenalty != nil && *req.FrequencyPenalty != 0:
		return nil, unsupported("штраф за повторы (presence_penalty, frequency_penalty)")
	case req.ReasoningEffort != "":
		return nil, unsupported("параметр reasoning_effort")
	}
	out := gcRequest{Model: req.Model, TopP: req.TopP, Stream: stream}
	if mt, ok := req.EffectiveMaxTokens(); ok {
		out.MaxTokens = &mt
	}
	if t := req.Temperature; t != nil {
		v := *t
		if v <= 0 {
			// GigaChat принимает только температуру больше 0; 0 у OpenAI —
			// наиболее детерминированный ответ. Проверить на пилоте (Р8).
			v = 0.001
		}
		out.Temperature = &v
	}
	for _, t := range req.Tools {
		params := t.Function.Parameters
		if len(params) == 0 {
			params = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		out.Functions = append(out.Functions, gcFunction{Name: t.Function.Name, Description: t.Function.Description, Parameters: params})
	}
	if tc := req.ToolChoice; tc != nil {
		switch tc.Mode {
		case "none", "auto":
			out.FunctionCall = json.RawMessage(`"` + tc.Mode + `"`)
		case "required":
			return nil, unsupported("tool_choice: required")
		default:
			b, err := json.Marshal(map[string]string{"name": tc.Function})
			if err != nil {
				return nil, err
			}
			out.FunctionCall = b
		}
	}
	names := map[string]string{} // id вызова → имя функции
	for i, m := range req.Messages {
		text, err := textOf(m, "gigachat")
		if err != nil {
			return nil, err
		}
		gm := gcMessage{Role: m.Role, Content: text}
		switch m.Role {
		case "developer":
			gm.Role = "system"
		case "assistant":
			if len(m.ToolCalls) > 1 {
				return nil, unsupported("несколько вызовов инструментов в одном сообщении")
			}
			for _, tc := range m.ToolCalls {
				args := json.RawMessage(strings.TrimSpace(tc.Function.Arguments))
				if len(args) == 0 {
					args = json.RawMessage("{}")
				}
				if args[0] != '{' || !json.Valid(args) {
					return nil, invalid(fmt.Sprintf("messages[%d]: аргументы вызова — объект JSON", i))
				}
				gm.FunctionCall = &gcFunctionCall{Name: tc.Function.Name, Arguments: args}
				names[tc.ID] = tc.Function.Name
			}
		case "tool":
			name, ok := names[m.ToolCallID]
			if !ok {
				return nil, invalid(fmt.Sprintf("messages[%d]: tool_call_id не найден в предыдущих вызовах", i))
			}
			gm.Role, gm.Name = "function", name
			// Результат функции GigaChat ожидает объектом JSON.
			t := strings.TrimSpace(text)
			if isObject := strings.HasPrefix(t, "{") && json.Valid([]byte(t)); !isObject {
				b, err := json.Marshal(map[string]string{"result": text})
				if err != nil {
					return nil, err
				}
				gm.Content = string(b)
			}
		}
		out.Messages = append(out.Messages, gm)
	}
	return json.Marshal(out)
}

// gcChoice — вариант ответа GigaChat (целиком или приращение потока).
type gcChoice struct {
	Index   int `json:"index"`
	Message *struct {
		Role         string          `json:"role"`
		Content      string          `json:"content"`
		FunctionCall *gcFunctionCall `json:"function_call"`
	} `json:"message"`
	Delta *struct {
		Role         string          `json:"role"`
		Content      *string         `json:"content"`
		FunctionCall *gcFunctionCall `json:"function_call"`
	} `json:"delta"`
	FinishReason string `json:"finish_reason"`
}

type gcResponse struct {
	Choices []gcChoice  `json:"choices"`
	Created int64       `json:"created"`
	Model   string      `json:"model"`
	Usage   *chat.Usage `json:"usage"`
}

// finishReason переводит причину завершения GigaChat в формат OpenAI.
func finishReason(r string) (string, error) {
	switch r {
	case "", "stop", "length":
		return r, nil
	case "function_call":
		return "tool_calls", nil
	case "blacklist":
		return "content_filter", nil
	}
	return "", fmt.Errorf("причина завершения %q", r)
}

// argsString — аргументы вызова строкой JSON, как в формате OpenAI.
func argsString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "{}", nil
	}
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (p *GigaChat) fromGigaChat(raw []byte) (*chat.Response, error) {
	var r gcResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if len(r.Choices) != 1 || r.Choices[0].Index != 0 || r.Choices[0].Message == nil {
		return nil, errors.New("ожидается ровно один вариант ответа")
	}
	c := r.Choices[0]
	fr, err := finishReason(c.FinishReason)
	if err != nil {
		return nil, err
	}
	id, err := p.randomID("chatcmpl-")
	if err != nil {
		return nil, err
	}
	msg := chat.ResponseMessage{Role: "assistant"}
	if c.Message.Content != "" || c.Message.FunctionCall == nil {
		s := c.Message.Content
		msg.Content = &s
	}
	if fc := c.Message.FunctionCall; fc != nil {
		args, err := argsString(fc.Arguments)
		if err != nil {
			return nil, err
		}
		callID, err := p.randomID("call_")
		if err != nil {
			return nil, err
		}
		tc := chat.ToolCall{ID: callID, Type: "function"}
		tc.Function.Name, tc.Function.Arguments = fc.Name, args
		msg.ToolCalls = []chat.ToolCall{tc}
	}
	return &chat.Response{ID: id, Object: "chat.completion", Created: r.Created, Model: r.Model,
		Choices: []chat.Choice{{Index: 0, Message: msg, FinishReason: fr}}, Usage: r.Usage}, nil
}

// gigaChatChunk переводит часть потока GigaChat в часть потока OpenAI.
func gigaChatChunk(data, id, callID string) (*chat.Chunk, error) {
	var r gcResponse
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		return nil, err
	}
	if len(r.Choices) > 1 {
		return nil, errors.New("несколько вариантов в части потока")
	}
	c := &chat.Chunk{ID: id, Object: "chat.completion.chunk", Created: r.Created, Model: r.Model, Usage: r.Usage, Choices: []chat.ChunkChoice{}}
	for _, ch := range r.Choices {
		if ch.Index != 0 || ch.Delta == nil {
			return nil, errors.New("часть потока: ожидается delta варианта 0")
		}
		out := chat.ChunkChoice{Index: 0, Delta: chat.Delta{Role: ch.Delta.Role, Content: ch.Delta.Content}}
		if fc := ch.Delta.FunctionCall; fc != nil {
			args, err := argsString(fc.Arguments)
			if err != nil {
				return nil, err
			}
			td := chat.ToolCallDelta{Index: 0, ID: callID, Type: "function"}
			td.Function.Name, td.Function.Arguments = fc.Name, args
			out.Delta.ToolCalls = []chat.ToolCallDelta{td}
		}
		if ch.FinishReason != "" {
			fr, err := finishReason(ch.FinishReason)
			if err != nil {
				return nil, err
			}
			out.FinishReason = &fr
		}
		c.Choices = append(c.Choices, out)
	}
	return c, nil
}
