package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/azuresong-afk/ai_railway/internal/chat"
)

// OpenAIConfig — параметры OpenAI-совместимого провайдера (vLLM, Ollama,
// llama.cpp server, облачные сервисы с совместимым API).
type OpenAIConfig struct {
	BaseConfig
	// BaseURL — базовый адрес вместе с версией API, например
	// https://llm.example/v1; запрос идёт на BaseURL + /chat/completions.
	BaseURL *url.URL
	Key     string // ключ API провайдера; пусто — не передаётся
}

// OpenAI — OpenAI-совместимый провайдер.
type OpenAI struct {
	base
	key      string
	endpoint string
}

// NewOpenAI проверяет параметры и создаёт провайдера.
func NewOpenAI(cfg OpenAIConfig) (*OpenAI, error) {
	if cfg.BaseURL == nil {
		return nil, errors.New("провайдер openai: не задан base_url")
	}
	b, err := newBase(cfg.BaseConfig, cfg.Key)
	if err != nil {
		return nil, err
	}
	return &OpenAI{base: b, key: cfg.Key, endpoint: endpoint(cfg.BaseURL, "/chat/completions")}, nil
}

func (p *OpenAI) send(ctx, clientCtx context.Context, req *chat.Request, stream bool) (*http.Response, Meta, error) {
	out := *req
	out.Stream = stream
	if !stream {
		out.StreamOptions = nil
	}
	body, err := out.Marshal()
	if err != nil {
		return nil, Meta{}, err
	}
	auth := ""
	if p.key != "" {
		auth = "Bearer " + p.key
	}
	return p.post(ctx, clientCtx, p.endpoint, body, stream, auth)
}

// Chat — ответ целиком.
func (p *OpenAI) Chat(ctx context.Context, req *chat.Request) (*chat.Response, Meta, error) {
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
	out, err := chat.ParseResponse(raw)
	if err != nil {
		p.logger.Warn("ответ провайдера не разобран", "provider", p.cfg.ID)
		return nil, meta, ErrBadResponse
	}
	return out, meta, nil
}

// Stream — потоковый ответ.
func (p *OpenAI) Stream(ctx context.Context, req *chat.Request) (Stream, Meta, error) {
	// Общий срок потока и срок простоя между событиями (Р11): зависший или
	// бесконечный поток не держит соединение и горутину.
	rctx, cancel := context.WithTimeout(ctx, p.cfg.ResponseTimeout)
	resp, meta, err := p.send(rctx, ctx, req, true)
	if err != nil {
		cancel()
		return nil, meta, err
	}
	st, err := p.openStream(ctx, cancel, resp, chat.ParseChunk)
	return st, meta, err
}
