package chat

import (
	"errors"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/sse"
)

// Поток в формате OpenAI: роль, текст кусками, вызов инструмента с
// аргументами кусками, причина завершения, отдельная часть с usage и [DONE].
// Поле reasoning_content (расширение некоторых провайдеров) шлюзу неизвестно.
const stream = `data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}

data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"При"},"finish_reason":null}]}

: keep-alive

data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"вет","reasoning_content":"скрытое"},"finish_reason":null}]}

data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}

data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]},"finish_reason":null}]}

data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Москва\"}"}}]},"finish_reason":null}]}

data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}

data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}

data: [DONE]

`

func assemble(t *testing.T, in string) (*Response, bool) {
	t.Helper()
	r := sse.NewReader(strings.NewReader(in), sse.Limits{})
	a := NewAssembler()
	done := false
	for {
		e, err := r.Next()
		if err != nil {
			break
		}
		c, err := ParseChunk(e.Data)
		if err != nil {
			t.Fatal(err)
		}
		if c == nil {
			done = true
			break
		}
		if err := a.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	return a.Response(), done
}

func TestAssembleStream(t *testing.T) {
	resp, done := assemble(t, stream)
	if !done || resp.ID != "c1" || resp.Model != "m" || resp.Object != "chat.completion" || len(resp.Choices) != 1 {
		t.Fatalf("%+v", resp)
	}
	m := resp.Choices[0].Message
	if m.Role != "assistant" || m.Content == nil || *m.Content != "Привет" || resp.Choices[0].FinishReason != "tool_calls" {
		t.Fatalf("%+v", m)
	}
	if len(m.ToolCalls) != 1 || m.ToolCalls[0].ID != "call_1" || m.ToolCalls[0].Function.Name != "get_weather" ||
		m.ToolCalls[0].Function.Arguments != `{"city":"Москва"}` {
		t.Fatalf("tool_calls: %+v", m.ToolCalls)
	}
	if resp.Usage == nil || resp.Usage.TotalTokens != 12 {
		t.Fatalf("usage: %+v", resp.Usage)
	}
}

// Неизвестные поля провайдера (здесь reasoning_content) в собранный ответ не
// попадают: приложению уходит только проверенное.
func TestUnknownProviderFieldsDropped(t *testing.T) {
	resp, _ := assemble(t, stream)
	b, err := marshalJSON(resp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b, "скрытое") || strings.Contains(b, "reasoning") {
		t.Fatalf("неизвестное поле в ответе: %s", b)
	}
	c, err := ParseChunk(`{"id":"x","choices":[{"index":0,"delta":{"content":"a","reasoning_content":"скрытое"}}],"extra":"скрытое"}`)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := marshalJSON(c); err != nil || strings.Contains(b, "скрытое") {
		t.Fatalf("часть потока: %s %v", b, err)
	}
}

func TestAssemblerOrderAndLimits(t *testing.T) {
	a := NewAssembler()
	s := func(v string) *string { return &v }
	// Вызовы и варианты приходят не по порядку — в ответе они упорядочены.
	for _, c := range []*Chunk{
		{Choices: []ChunkChoice{{Index: 1, Delta: Delta{Content: s("b")}}}},
		{Choices: []ChunkChoice{{Index: 0, Delta: Delta{Content: s("a"), ToolCalls: []ToolCallDelta{{Index: 2, ID: "t2"}, {Index: 0, ID: "t0"}}}}}},
		{Choices: []ChunkChoice{{Index: 0, Delta: Delta{Refusal: s("нет")}}}},
	} {
		if err := a.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	r := a.Response()
	if r.Choices[0].Index != 0 || r.Choices[1].Index != 1 || r.Choices[0].Message.ToolCalls[0].ID != "t0" ||
		*r.Choices[0].Message.Refusal != "нет" || a.Text(0) != "a" || a.Text(5) != "" {
		t.Fatalf("%+v", r)
	}
	for _, bad := range []*Chunk{
		{Choices: []ChunkChoice{{Index: MaxResponseChoices}}},
		{Choices: []ChunkChoice{{Index: -1}}},
		{Choices: []ChunkChoice{{Delta: Delta{ToolCalls: []ToolCallDelta{{Index: MaxResponseTools}}}}}},
	} {
		if err := NewAssembler().Add(bad); err == nil {
			t.Errorf("%+v: ожидалась ошибка", bad)
		}
	}
	// Бесконечный поток останавливается пределом размера.
	big := NewAssembler()
	piece := strings.Repeat("я", 1<<19)
	var err error
	for i := 0; i < 100 && err == nil; i++ {
		err = big.Add(&Chunk{Choices: []ChunkChoice{{Delta: Delta{Content: &piece}}}})
	}
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("предел размера: %v", err)
	}
}

func TestParseResponse(t *testing.T) {
	r, err := ParseResponse([]byte(`{"id":"x","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ок","annotations":[]},"finish_reason":"stop","logprobs":null}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"service_tier":"default"}`))
	if err != nil || *r.Choices[0].Message.Content != "ок" || r.Usage.TotalTokens != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []string{`{`, `{"choices":[]}`, `{"choices":[{"index":99}]}`, `[]`} {
		if _, err := ParseResponse([]byte(bad)); err == nil {
			t.Errorf("%s: ожидалась ошибка", bad)
		}
	}
	if c, err := ParseChunk(Done); c != nil || err != nil {
		t.Fatal("[DONE]")
	}
	if _, err := ParseChunk("не json"); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

// Сборка потокового ответа — цель фаззинга (ТЗ, 8.5): произвольные данные
// событий не роняют сборщик, текст варианта 0 — конкатенация приращений.
func FuzzAssembler(f *testing.F) {
	f.Add(stream)
	f.Add("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"}}]}\n\ndata: [DONE]\n\n")
	f.Fuzz(func(t *testing.T, in string) {
		r := sse.NewReader(strings.NewReader(in), sse.Limits{MaxLine: 1 << 12, MaxEvent: 1 << 14})
		a := NewAssembler()
		var want strings.Builder
		for {
			e, err := r.Next()
			if err != nil {
				break
			}
			c, err := ParseChunk(e.Data)
			if err != nil || c == nil {
				continue
			}
			if err := a.Add(c); err != nil {
				return
			}
			for _, ch := range c.Choices {
				if ch.Index == 0 && ch.Delta.Content != nil {
					want.WriteString(*ch.Delta.Content)
				}
			}
		}
		resp := a.Response()
		if a.Text(0) != want.String() {
			t.Fatalf("текст %q, ожидалось %q", a.Text(0), want.String())
		}
		if _, err := marshalJSON(resp); err != nil {
			t.Fatal(err)
		}
	})
}
