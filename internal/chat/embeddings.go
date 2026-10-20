package chat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Запрос и ответ POST /v1/embeddings (ТЗ, 5.1). Как и chat/completions,
// запрос разбирается строго и собирается заново: провайдер получает только
// то, что видели проверки. Вход — строка или массив строк; массивы токенов
// не поддерживаются, потому что детекторы работают с текстом.

// Пределы эмбеддингов.
const (
	// MaxEmbeddingInputs — строк во входе одного запроса.
	MaxEmbeddingInputs = 256
	// MaxEmbeddingDims — длина одного вектора в ответе провайдера.
	MaxEmbeddingDims = 1 << 16
	maxDimensions    = MaxEmbeddingDims
)

// EmbeddingRequest — запрос эмбеддингов. Формат ответа всегда float:
// base64-вектор шлюз не разбирает.
type EmbeddingRequest struct {
	Model          string         `json:"model"`
	Input          EmbeddingInput `json:"input"`
	EncodingFormat string         `json:"encoding_format,omitempty"`
	Dimensions     *int           `json:"dimensions,omitempty"`
	User           string         `json:"user,omitempty"`
}

// EmbeddingInput — строки, которые нужно превратить в векторы.
type EmbeddingInput []string

// UnmarshalJSON принимает строку или массив строк.
func (in *EmbeddingInput) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '[' {
		var list []string
		if err := json.Unmarshal(b, &list); err != nil {
			return errf(CodeInvalid, "input: массив строк (массивы токенов не поддерживаются)")
		}
		*in = list
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errf(CodeInvalid, "input: строка или массив строк")
	}
	*in = EmbeddingInput{s}
	return nil
}

// MarshalJSON собирает вход: одна строка — как массив из одного элемента.
func (in EmbeddingInput) MarshalJSON() ([]byte, error) { return json.Marshal([]string(in)) }

// ParseEmbeddings разбирает и проверяет тело запроса эмбеддингов.
func ParseEmbeddings(body []byte) (*EmbeddingRequest, error) {
	var r EmbeddingRequest
	if err := strict(body, &r); err != nil {
		if m := fieldRe.FindStringSubmatch(err.Error()); m != nil {
			return nil, errf(CodeUnsupported, "параметр %q не поддерживается шлюзом", m[1])
		}
		var ute *json.UnmarshalTypeError
		if errors.As(err, &ute) {
			return nil, errf(CodeInvalid, "неверный тип поля %q", ute.Field)
		}
		var ce *Error
		if errors.As(err, &ce) {
			return nil, ce
		}
		return nil, errf(CodeInvalid, "тело запроса — не объект запроса embeddings")
	}
	if !modelRe.MatchString(r.Model) {
		return nil, errf(CodeInvalid, "model: недопустимое имя модели")
	}
	if len(r.Input) == 0 {
		return nil, errf(CodeInvalid, "input: нужна хотя бы одна строка")
	}
	if len(r.Input) > MaxEmbeddingInputs {
		return nil, errf(CodeTooMany, "input: больше %d строк", MaxEmbeddingInputs)
	}
	for i, s := range r.Input {
		if s == "" {
			return nil, errf(CodeInvalid, "input[%d]: пустая строка", i)
		}
	}
	if r.EncodingFormat != "" && r.EncodingFormat != "float" {
		return nil, errf(CodeUnsupported, "encoding_format: шлюз поддерживает только float")
	}
	if r.Dimensions != nil && (*r.Dimensions < 1 || *r.Dimensions > maxDimensions) {
		return nil, errf(CodeInvalid, "dimensions: от 1 до %d", maxDimensions)
	}
	if len(r.User) > maxUserLen {
		return nil, errf(CodeInvalid, "user: не длиннее %d байт", maxUserLen)
	}
	return &r, nil
}

// EmbeddingResponse — ответ провайдера на запрос эмбеддингов.
type EmbeddingResponse struct {
	Object string          `json:"object"`
	Data   []EmbeddingData `json:"data"`
	Model  string          `json:"model"`
	Usage  *EmbeddingUsage `json:"usage,omitempty"`
}

// EmbeddingData — вектор для одной строки входа.
type EmbeddingData struct {
	Object    string    `json:"object"`
	Index     int       `json:"index"`
	Embedding []float64 `json:"embedding"`
}

// EmbeddingUsage — расход токенов.
type EmbeddingUsage struct {
	PromptTokens int `json:"prompt_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// ParseEmbeddingResponse разбирает ответ провайдера. Неизвестные поля
// отбрасываются: приложению уходит только известная часть.
func ParseEmbeddingResponse(raw []byte, inputs int) (*EmbeddingResponse, error) {
	var r EmbeddingResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, errors.New("ответ эмбеддингов не разобран")
	}
	if len(r.Data) != inputs {
		return nil, fmt.Errorf("ответ эмбеддингов: %d векторов на %d строк", len(r.Data), inputs)
	}
	for i := range r.Data {
		d := &r.Data[i]
		if d.Index != i || len(d.Embedding) == 0 || len(d.Embedding) > MaxEmbeddingDims {
			return nil, errors.New("ответ эмбеддингов: неверный индекс или длина вектора")
		}
		d.Object = "embedding"
	}
	r.Object = "list"
	return &r, nil
}
