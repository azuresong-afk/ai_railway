package providers

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Адаптер YandexGPT — Yandex Foundation Models API, метод completion
// (ТЗ, 5.1). Форматы — по публичной документации yandex.cloud (план этапа 1,
// Р8); до пилота адаптер проверяется на настоящей учётной записи.
//
// Авторизация — API-ключ сервисного аккаунта (Authorization: Api-Key).
// IAM-токены (подпись JWT ключом сервисного аккаунта) — отдельной задачей:
// для них нужна подпись в internal/crypto.

// YandexGPTConfig — параметры провайдера YandexGPT.
type YandexGPTConfig struct {
	BaseConfig
	// BaseURL — https://llm.api.cloud.yandex.net/foundationModels/v1.
	BaseURL *url.URL
	// APIKey — API-ключ сервисного аккаунта.
	APIKey string
	// FolderID — каталог облака: modelUri = gpt://<FolderID>/<модель>.
	FolderID string
	// Random — источник случайности криптопрофиля (идентификаторы ответа).
	Random aisecCrypto.Random
}

// YandexGPT — провайдер YandexGPT.
type YandexGPT struct {
	base
	yc       YandexGPTConfig
	endpoint string
}

var folderRe = regexp.MustCompile(`^[a-z0-9]{1,50}$`)

// NewYandexGPT проверяет параметры и создаёт провайдера.
func NewYandexGPT(cfg YandexGPTConfig) (*YandexGPT, error) {
	if cfg.BaseURL == nil || cfg.APIKey == "" || cfg.Random == nil {
		return nil, errors.New("провайдер yandexgpt: нужны base_url, API-ключ и источник случайности")
	}
	if !folderRe.MatchString(cfg.FolderID) {
		return nil, errors.New("провайдер yandexgpt: folder_id — строчные латинские буквы и цифры")
	}
	b, err := newBase(cfg.BaseConfig, cfg.APIKey)
	if err != nil {
		return nil, err
	}
	return &YandexGPT{base: b, yc: cfg, endpoint: endpoint(cfg.BaseURL, "/completion")}, nil
}

func (p *YandexGPT) randomID(prefix string) (string, error) {
	b, err := aisecCrypto.RandomBytes(p.yc.Random, 12)
	if err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

// Формат Foundation Models API.
type ycFunctionCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"` // объект JSON
}

type ycToolCall struct {
	FunctionCall ycFunctionCall `json:"functionCall"`
}

type ycToolResult struct {
	FunctionResult struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	} `json:"functionResult"`
}

type ycMessage struct {
	Role         string `json:"role"`
	Text         string `json:"text,omitempty"`
	ToolCallList *struct {
		ToolCalls []ycToolCall `json:"toolCalls"`
	} `json:"toolCallList,omitempty"`
	ToolResultList *struct {
		ToolResults []ycToolResult `json:"toolResults"`
	} `json:"toolResultList,omitempty"`
}

type ycTool struct {
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type ycRequest struct {
	ModelURI          string `json:"modelUri"`
	CompletionOptions struct {
		Stream      bool     `json:"stream"`
		Temperature *float64 `json:"temperature,omitempty"`
		MaxTokens   string   `json:"maxTokens,omitempty"` // int64 строкой (формат protobuf JSON)
	} `json:"completionOptions"`
	Messages []ycMessage `json:"messages"`
	Tools    []ycTool    `json:"tools,omitempty"`
}

func ycUnsupported(what string) error { return unsupportedBy("yandexgpt", what) }

// toYandexGPT переводит запрос из формата OpenAI в формат Foundation Models.
func toYandexGPT(req *chat.Request, folder string, stream bool) ([]byte, error) {
	switch {
	case len(req.Stop) > 0:
		return nil, ycUnsupported("параметр stop")
	case len(req.ResponseFormat) > 0:
		return nil, ycUnsupported("параметр response_format")
	case req.Seed != nil:
		return nil, ycUnsupported("параметр seed")
	case len(req.LogitBias) > 0:
		return nil, ycUnsupported("параметр logit_bias")
	case req.TopP != nil && *req.TopP != 1:
		return nil, ycUnsupported("параметр top_p")
	case req.PresencePenalty != nil && *req.PresencePenalty != 0, req.FrequencyPenalty != nil && *req.FrequencyPenalty != 0:
		return nil, ycUnsupported("штраф за повторы (presence_penalty, frequency_penalty)")
	case req.ReasoningEffort != "":
		return nil, ycUnsupported("параметр reasoning_effort")
	case req.Temperature != nil && *req.Temperature > 1:
		return nil, ycUnsupported("temperature больше 1")
	}
	out := ycRequest{ModelURI: "gpt://" + folder + "/" + req.Model, Messages: []ycMessage{}}
	out.CompletionOptions.Stream = stream
	out.CompletionOptions.Temperature = req.Temperature
	if mt, ok := req.EffectiveMaxTokens(); ok {
		out.CompletionOptions.MaxTokens = strconv.Itoa(mt)
	}
	toolsOff := false
	if tc := req.ToolChoice; tc != nil {
		switch tc.Mode {
		case "auto":
		case "none":
			// «Не вызывать инструменты» — инструменты модели не передаются.
			toolsOff = true
		default:
			return nil, ycUnsupported("tool_choice, кроме auto и none,")
		}
	}
	if !toolsOff {
		for _, t := range req.Tools {
			var yt ycTool
			yt.Function.Name, yt.Function.Description = t.Function.Name, t.Function.Description
			yt.Function.Parameters = t.Function.Parameters
			if len(yt.Function.Parameters) == 0 {
				yt.Function.Parameters = json.RawMessage(`{"type":"object","properties":{}}`)
			}
			out.Tools = append(out.Tools, yt)
		}
	}
	names := map[string]string{} // id вызова → имя функции
	for i, m := range req.Messages {
		text, err := textOf(m, "yandexgpt")
		if err != nil {
			return nil, err
		}
		ym := ycMessage{Role: m.Role, Text: text}
		switch m.Role {
		case "developer":
			ym.Role = "system"
		case "assistant":
			if len(m.ToolCalls) > 0 {
				ym.ToolCallList = &struct {
					ToolCalls []ycToolCall `json:"toolCalls"`
				}{}
			}
			for _, tc := range m.ToolCalls {
				args := json.RawMessage(strings.TrimSpace(tc.Function.Arguments))
				if len(args) == 0 {
					args = json.RawMessage("{}")
				}
				if args[0] != '{' || !json.Valid(args) {
					return nil, invalid(fmt.Sprintf("messages[%d]: аргументы вызова — объект JSON", i))
				}
				ym.ToolCallList.ToolCalls = append(ym.ToolCallList.ToolCalls, ycToolCall{FunctionCall: ycFunctionCall{Name: tc.Function.Name, Arguments: args}})
				names[tc.ID] = tc.Function.Name
			}
		case "tool":
			name, ok := names[m.ToolCallID]
			if !ok {
				return nil, invalid(fmt.Sprintf("messages[%d]: tool_call_id не найден в предыдущих вызовах", i))
			}
			// Результат функции передаётся сообщением пользователя со списком
			// результатов (проверить на пилоте, Р8).
			var tr ycToolResult
			tr.FunctionResult.Name, tr.FunctionResult.Content = name, text
			ym = ycMessage{Role: "user", ToolResultList: &struct {
				ToolResults []ycToolResult `json:"toolResults"`
			}{ToolResults: []ycToolResult{tr}}}
		}
		out.Messages = append(out.Messages, ym)
	}
	return json.Marshal(out)
}

// flexInt — целое числом или строкой (int64 в protobuf JSON — строкой).
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return errors.New("ожидается неотрицательное целое")
	}
	*f = flexInt(n)
	return nil
}

type ycAlternative struct {
	Message struct {
		Role         string `json:"role"`
		Text         string `json:"text"`
		ToolCallList *struct {
			ToolCalls []ycToolCall `json:"toolCalls"`
		} `json:"toolCallList"`
	} `json:"message"`
	Status string `json:"status"`
}

type ycResult struct {
	Result *struct {
		Alternatives []ycAlternative `json:"alternatives"`
		Usage        *struct {
			InputTextTokens  flexInt `json:"inputTextTokens"`
			CompletionTokens flexInt `json:"completionTokens"`
			TotalTokens      flexInt `json:"totalTokens"`
		} `json:"usage"`
	} `json:"result"`
}

func (r *ycResult) usage() *chat.Usage {
	if r.Result == nil || r.Result.Usage == nil {
		return nil
	}
	u := r.Result.Usage
	return &chat.Usage{PromptTokens: int(u.InputTextTokens), CompletionTokens: int(u.CompletionTokens), TotalTokens: int(u.TotalTokens)}
}

// ycStatus переводит статус альтернативы в причину завершения OpenAI.
// final = false — часть потока, ответ ещё не завершён.
func ycStatus(s string) (finish string, final bool, err error) {
	switch s {
	case "ALTERNATIVE_STATUS_PARTIAL":
		return "", false, nil
	case "ALTERNATIVE_STATUS_FINAL":
		return "stop", true, nil
	case "ALTERNATIVE_STATUS_TRUNCATED_FINAL":
		return "length", true, nil
	case "ALTERNATIVE_STATUS_CONTENT_FILTER":
		return "content_filter", true, nil
	case "ALTERNATIVE_STATUS_TOOL_CALLS":
		return "tool_calls", true, nil
	}
	return "", false, fmt.Errorf("статус альтернативы %q", s)
}

func parseYC(raw []byte) (*ycResult, *ycAlternative, error) {
	var r ycResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, nil, err
	}
	if r.Result == nil || len(r.Result.Alternatives) != 1 {
		return nil, nil, errors.New("ожидается ровно одна альтернатива")
	}
	return &r, &r.Result.Alternatives[0], nil
}

func (p *YandexGPT) toolCalls(alt *ycAlternative) ([]chat.ToolCall, error) {
	if alt.Message.ToolCallList == nil {
		return nil, nil
	}
	if len(alt.Message.ToolCallList.ToolCalls) > chat.MaxResponseTools {
		return nil, errors.New("слишком много вызовов")
	}
	var out []chat.ToolCall
	for _, c := range alt.Message.ToolCallList.ToolCalls {
		args, err := argsString(c.FunctionCall.Arguments)
		if err != nil {
			return nil, err
		}
		id, err := p.randomID("call_")
		if err != nil {
			return nil, err
		}
		tc := chat.ToolCall{ID: id, Type: "function"}
		tc.Function.Name, tc.Function.Arguments = c.FunctionCall.Name, args
		out = append(out, tc)
	}
	return out, nil
}

func (p *YandexGPT) send(ctx, clientCtx context.Context, req *chat.Request, stream bool) (*http.Response, Meta, error) {
	body, err := toYandexGPT(req, p.yc.FolderID, stream)
	if err != nil {
		return nil, Meta{}, err
	}
	return p.postFolder(ctx, clientCtx, body, stream)
}

// postFolder — post с заголовком каталога облака.
func (p *YandexGPT) postFolder(ctx, clientCtx context.Context, body []byte, stream bool) (*http.Response, Meta, error) {
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, Meta{}, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("User-Agent", "aisec-gateway")
	hr.Header.Set("Authorization", "Api-Key "+p.yc.APIKey)
	hr.Header.Set("x-folder-id", p.yc.FolderID)
	return p.do(hr, clientCtx)
}

// Chat — ответ целиком.
func (p *YandexGPT) Chat(ctx context.Context, req *chat.Request) (*chat.Response, Meta, error) {
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
	out, err := p.fromYandexGPT(raw, req.Model)
	if err != nil {
		p.logger.Warn("ответ YandexGPT не разобран", "provider", p.cfg.ID)
		return nil, meta, ErrBadResponse
	}
	return out, meta, nil
}

func (p *YandexGPT) fromYandexGPT(raw []byte, model string) (*chat.Response, error) {
	r, alt, err := parseYC(raw)
	if err != nil {
		return nil, err
	}
	finish, final, err := ycStatus(alt.Status)
	if err != nil || !final {
		return nil, fmt.Errorf("незавершённый ответ: %w", err)
	}
	calls, err := p.toolCalls(alt)
	if err != nil {
		return nil, err
	}
	id, err := p.randomID("chatcmpl-")
	if err != nil {
		return nil, err
	}
	msg := chat.ResponseMessage{Role: "assistant", ToolCalls: calls}
	if alt.Message.Text != "" || len(calls) == 0 {
		t := alt.Message.Text
		msg.Content = &t
	}
	return &chat.Response{ID: id, Object: "chat.completion", Model: model,
		Choices: []chat.Choice{{Index: 0, Message: msg, FinishReason: finish}}, Usage: r.usage()}, nil
}

// Stream — потоковый ответ. В каждой части YandexGPT присылает весь текст,
// накопленный к этому моменту; приложению уходит приращение.
func (p *YandexGPT) Stream(ctx context.Context, req *chat.Request) (Stream, Meta, error) {
	rctx, cancel := context.WithTimeout(ctx, p.cfg.ResponseTimeout)
	resp, meta, err := p.send(rctx, ctx, req, true)
	if err != nil {
		cancel()
		return nil, meta, err
	}
	id, err := p.randomID("chatcmpl-")
	if err != nil {
		cancel()
		p.closeBody(resp)
		return nil, meta, err
	}
	d := &ycDelta{p: p, id: id, model: req.Model}
	return p.openNDJSON(ctx, cancel, resp, d.decode, func() bool { return d.final }), meta, nil
}

// ycDelta переводит накопленный текст частей в приращения.
type ycDelta struct {
	p        *YandexGPT
	id       string
	model    string
	sent     string // уже отправленный текст
	roleSent bool
	final    bool
}

func (d *ycDelta) decode(data string) (*chat.Chunk, error) {
	if d.final {
		return nil, errors.New("данные после завершения ответа")
	}
	r, alt, err := parseYC([]byte(data))
	if err != nil {
		return nil, err
	}
	finish, final, err := ycStatus(alt.Status)
	if err != nil {
		return nil, err
	}
	text := alt.Message.Text
	if !strings.HasPrefix(text, d.sent) {
		// Накопленный текст разошёлся с отправленным — продолжить нельзя.
		return nil, errors.New("часть потока не продолжает предыдущую")
	}
	if len(text) > chat.MaxResponseBytes {
		return nil, chat.ErrResponseTooLarge
	}
	delta := text[len(d.sent):]
	d.sent = text
	ch := chat.ChunkChoice{Index: 0}
	if !d.roleSent {
		ch.Delta.Role, d.roleSent = "assistant", true
	}
	if delta != "" {
		ch.Delta.Content = &delta
	}
	if final {
		calls, err := d.p.toolCalls(alt)
		if err != nil {
			return nil, err
		}
		for i, tc := range calls {
			td := chat.ToolCallDelta{Index: i, ID: tc.ID, Type: "function"}
			td.Function.Name, td.Function.Arguments = tc.Function.Name, tc.Function.Arguments
			ch.Delta.ToolCalls = append(ch.Delta.ToolCalls, td)
		}
		ch.FinishReason = &finish
		d.final = true
	}
	return &chat.Chunk{ID: d.id, Object: "chat.completion.chunk", Model: d.model, Choices: []chat.ChunkChoice{ch}, Usage: r.usage()}, nil
}
