package chat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Response — ответ chat/completions (объект chat.completion). Неизвестные
// поля провайдера при разборе отбрасываются: приложению уходит только то,
// что видели выходные проверки.
type Response struct {
	ID                string   `json:"id"`
	Object            string   `json:"object"`
	Created           int64    `json:"created"`
	Model             string   `json:"model"`
	SystemFingerprint string   `json:"system_fingerprint,omitempty"`
	Choices           []Choice `json:"choices"`
	Usage             *Usage   `json:"usage,omitempty"`
}

// Choice — вариант ответа.
type Choice struct {
	Index        int             `json:"index"`
	Message      ResponseMessage `json:"message"`
	FinishReason string          `json:"finish_reason"`
}

// ResponseMessage — сообщение ассистента в ответе.
type ResponseMessage struct {
	Role      string     `json:"role"`
	Content   *string    `json:"content"`
	Refusal   *string    `json:"refusal,omitempty"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

// Usage — расход токенов.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Chunk — часть потокового ответа (объект chat.completion.chunk).
type Chunk struct {
	ID                string        `json:"id"`
	Object            string        `json:"object"`
	Created           int64         `json:"created"`
	Model             string        `json:"model"`
	SystemFingerprint string        `json:"system_fingerprint,omitempty"`
	Choices           []ChunkChoice `json:"choices"`
	Usage             *Usage        `json:"usage,omitempty"`
}

// ChunkChoice — приращение варианта ответа.
type ChunkChoice struct {
	Index        int     `json:"index"`
	Delta        Delta   `json:"delta"`
	FinishReason *string `json:"finish_reason"`
}

// Delta — приращение сообщения.
type Delta struct {
	Role      string          `json:"role,omitempty"`
	Content   *string         `json:"content,omitempty"`
	Refusal   *string         `json:"refusal,omitempty"`
	ToolCalls []ToolCallDelta `json:"tool_calls,omitempty"`
}

// ToolCallDelta — приращение вызова инструмента: id, тип и имя приходят в
// первой части, аргументы — кусками.
type ToolCallDelta struct {
	Index    int    `json:"index"`
	ID       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name      string `json:"name,omitempty"`
		Arguments string `json:"arguments,omitempty"`
	} `json:"function"`
}

// Done — данные завершающего события потока OpenAI.
const Done = "[DONE]"

// Пределы ответа: защита памяти шлюза от бесконечного или раздутого потока.
// Вариант ответа — ровно один (индекс 0): запрос с n > 1 шлюз не принимает,
// а проверка ответа смотрит один вариант; лишние варианты ушли бы приложению
// мимо выходных проверок.
const (
	MaxResponseChoices = 1
	MaxResponseTools   = 128
	MaxResponseBytes   = 16 << 20 // суммарный текст ответа
)

// ErrResponseTooLarge — ответ провайдера больше пределов.
var ErrResponseTooLarge = errors.New("ответ провайдера больше предела")

// ParseResponse разбирает ответ без потоковой передачи.
func ParseResponse(body []byte) (*Response, error) {
	var r Response
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("ответ провайдера: %w", err)
	}
	if len(r.Choices) == 0 || len(r.Choices) > MaxResponseChoices {
		return nil, fmt.Errorf("ответ провайдера: вариантов %d", len(r.Choices))
	}
	for i, c := range r.Choices {
		if c.Index != 0 || len(c.Message.ToolCalls) > MaxResponseTools {
			return nil, fmt.Errorf("ответ провайдера: вариант %d вне пределов", i)
		}
	}
	return &r, nil
}

// ParseChunk разбирает данные события потока. Для «[DONE]» возвращает nil.
func ParseChunk(data string) (*Chunk, error) {
	if data == Done {
		return nil, nil
	}
	var c Chunk
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		return nil, fmt.Errorf("часть потока: %w", err)
	}
	if len(c.Choices) > MaxResponseChoices {
		return nil, fmt.Errorf("часть потока: вариантов %d", len(c.Choices))
	}
	for _, ch := range c.Choices {
		if ch.Index != 0 {
			return nil, fmt.Errorf("часть потока: номер варианта %d", ch.Index)
		}
	}
	return &c, nil
}

// Assembler собирает потоковый ответ в полный (для проверки ответа и
// событий). Нулевое значение не годится — используйте NewAssembler.
type Assembler struct {
	resp    Response
	choices map[int]*choiceAcc
	order   []int
	size    int
}

type choiceAcc struct {
	role      string
	content   bytes.Buffer
	hasText   bool
	refusal   bytes.Buffer
	hasRef    bool
	tools     map[int]*toolAcc
	toolOrder []int
	finish    string
}

// toolAcc — вызов инструмента в сборке; аргументы копятся в буфере, а не
// склейкой строк (иначе мелкие части давали бы квадратичное копирование).
type toolAcc struct {
	call ToolCall
	args strings.Builder
}

// NewAssembler создаёт сборщик.
func NewAssembler() *Assembler {
	return &Assembler{choices: map[int]*choiceAcc{}}
}

// Add добавляет часть потока.
func (a *Assembler) Add(c *Chunk) error {
	if a.resp.ID == "" {
		a.resp.ID, a.resp.Created, a.resp.Model, a.resp.SystemFingerprint = c.ID, c.Created, c.Model, c.SystemFingerprint
	}
	if c.Usage != nil {
		u := *c.Usage
		a.resp.Usage = &u
	}
	for _, ch := range c.Choices {
		if ch.Index < 0 || ch.Index >= MaxResponseChoices {
			return fmt.Errorf("часть потока: номер варианта %d вне пределов", ch.Index)
		}
		acc, ok := a.choices[ch.Index]
		if !ok {
			acc = &choiceAcc{tools: map[int]*toolAcc{}}
			a.choices[ch.Index] = acc
			a.order = append(a.order, ch.Index)
		}
		d := ch.Delta
		if d.Role != "" && acc.role == "" {
			acc.role = d.Role
		}
		if d.Content != nil {
			acc.content.WriteString(*d.Content)
			acc.hasText = true
			a.size += len(*d.Content)
		}
		if d.Refusal != nil {
			acc.refusal.WriteString(*d.Refusal)
			acc.hasRef = true
			a.size += len(*d.Refusal)
		}
		for _, td := range d.ToolCalls {
			if td.Index < 0 || td.Index >= MaxResponseTools {
				return fmt.Errorf("часть потока: номер вызова %d вне пределов", td.Index)
			}
			ta, ok := acc.tools[td.Index]
			if !ok {
				ta = &toolAcc{call: ToolCall{Type: "function"}}
				acc.tools[td.Index] = ta
				acc.toolOrder = append(acc.toolOrder, td.Index)
			}
			tc := &ta.call
			// id, тип и имя берутся из первой части, где они есть: часть
			// провайдеров повторяет их в каждой части.
			if tc.ID == "" {
				tc.ID = td.ID
			}
			if td.Type != "" {
				tc.Type = td.Type
			}
			if tc.Function.Name == "" {
				tc.Function.Name = td.Function.Name
			}
			ta.args.WriteString(td.Function.Arguments)
			a.size += len(td.Function.Arguments) + len(td.Function.Name) + len(td.ID)
		}
		if ch.FinishReason != nil {
			acc.finish = *ch.FinishReason
		}
		if a.size > MaxResponseBytes {
			return ErrResponseTooLarge
		}
	}
	return nil
}

// Text — текущий текст варианта (для поэтапной проверки, режим incremental).
func (a *Assembler) Text(index int) string {
	if acc, ok := a.choices[index]; ok {
		return acc.content.String()
	}
	return ""
}

// Response — ответ, собранный из полученных частей.
func (a *Assembler) Response() *Response {
	r := a.resp
	r.Object = "chat.completion"
	r.Choices = nil
	slices.Sort(a.order)
	for _, i := range a.order {
		acc := a.choices[i]
		msg := ResponseMessage{Role: acc.role}
		if msg.Role == "" {
			msg.Role = "assistant"
		}
		if acc.hasText {
			s := acc.content.String()
			msg.Content = &s
		}
		if acc.hasRef {
			s := acc.refusal.String()
			msg.Refusal = &s
		}
		slices.Sort(acc.toolOrder)
		for _, j := range acc.toolOrder {
			tc := acc.tools[j].call
			tc.Function.Arguments = acc.tools[j].args.String()
			msg.ToolCalls = append(msg.ToolCalls, tc)
		}
		r.Choices = append(r.Choices, Choice{Index: i, Message: msg, FinishReason: acc.finish})
	}
	return &r
}
