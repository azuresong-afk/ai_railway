package chat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
)

// Request — запрос chat/completions. Поля — только известные шлюзу;
// непрозрачные для шлюза (схемы JSON инструментов и формата ответа) хранятся
// как json.RawMessage и проверяются на тип и размер.
type Request struct {
	Model               string             `json:"model"`
	Messages            []Message          `json:"messages"`
	Stream              bool               `json:"stream,omitempty"`
	StreamOptions       *StreamOptions     `json:"stream_options,omitempty"`
	MaxTokens           *int               `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int               `json:"max_completion_tokens,omitempty"`
	Temperature         *float64           `json:"temperature,omitempty"`
	TopP                *float64           `json:"top_p,omitempty"`
	N                   *int               `json:"n,omitempty"`
	Stop                Stop               `json:"stop,omitempty"`
	PresencePenalty     *float64           `json:"presence_penalty,omitempty"`
	FrequencyPenalty    *float64           `json:"frequency_penalty,omitempty"`
	LogitBias           map[string]float64 `json:"logit_bias,omitempty"`
	Logprobs            *bool              `json:"logprobs,omitempty"`
	TopLogprobs         *int               `json:"top_logprobs,omitempty"`
	ResponseFormat      json.RawMessage    `json:"response_format,omitempty"`
	Seed                *int64             `json:"seed,omitempty"`
	Tools               []Tool             `json:"tools,omitempty"`
	ToolChoice          *ToolChoice        `json:"tool_choice,omitempty"`
	ParallelToolCalls   *bool              `json:"parallel_tool_calls,omitempty"`
	User                string             `json:"user,omitempty"`
	ReasoningEffort     string             `json:"reasoning_effort,omitempty"`
}

// StreamOptions — параметры потоковой передачи.
type StreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// Message — сообщение диалога.
type Message struct {
	Role       string     `json:"role"`
	Content    Content    `json:"content"`
	Name       string     `json:"name,omitempty"`
	Refusal    *string    `json:"refusal,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// Content — содержимое сообщения: строка, массив частей или null.
type Content struct {
	Text  *string
	Parts []Part
}

// UnmarshalJSON принимает строку, массив частей или null.
func (c *Content) UnmarshalJSON(b []byte) error {
	*c = Content{}
	switch t := bytes.TrimSpace(b); {
	case bytes.Equal(t, []byte("null")):
		return nil
	case len(t) > 0 && t[0] == '"':
		var s string
		if err := json.Unmarshal(t, &s); err != nil {
			return err
		}
		c.Text = &s
		return nil
	case len(t) > 0 && t[0] == '[':
		var parts []Part
		if err := strict(t, &parts); err != nil {
			return err
		}
		if parts == nil {
			parts = []Part{}
		}
		c.Parts = parts
		return nil
	}
	return errors.New("content — строка, массив частей или null")
}

// MarshalJSON записывает содержимое в том же виде, в каком оно пришло.
func (c Content) MarshalJSON() ([]byte, error) {
	switch {
	case c.Parts != nil:
		return json.Marshal(c.Parts)
	case c.Text != nil:
		return json.Marshal(*c.Text)
	}
	return []byte("null"), nil
}

// Типы частей сообщения.
const (
	PartText       = "text"
	PartRefusal    = "refusal"
	PartImageURL   = "image_url"
	PartInputAudio = "input_audio"
	PartFile       = "file"
	PartVideoURL   = "video_url"
)

// Part — часть содержимого сообщения. Заполнено ровно одно поле по типу.
type Part struct {
	Type       string      `json:"type"`
	Text       *string     `json:"text,omitempty"`
	Refusal    *string     `json:"refusal,omitempty"`
	ImageURL   *ImageURL   `json:"image_url,omitempty"`
	InputAudio *InputAudio `json:"input_audio,omitempty"`
	File       *File       `json:"file,omitempty"`
	VideoURL   *VideoURL   `json:"video_url,omitempty"`
}

// ImageURL — изображение ссылкой или data:-адресом.
type ImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

// InputAudio — аудио в base64.
type InputAudio struct {
	Data   string `json:"data"`
	Format string `json:"format"`
}

// File — файл в base64 или ссылка на файл, загруженный к провайдеру.
type File struct {
	FileData string `json:"file_data,omitempty"`
	FileID   string `json:"file_id,omitempty"`
	Filename string `json:"filename,omitempty"`
}

// VideoURL — видео ссылкой или data:-адресом (расширение vLLM).
type VideoURL struct {
	URL string `json:"url"`
}

// ToolCall — вызов инструмента в сообщении ассистента.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

// FunctionCall — имя функции и аргументы (строка JSON).
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Tool — описание инструмента, доступного модели.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction — функция инструмента.
type ToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
}

// ToolChoice — «none», «auto», «required» или конкретная функция.
type ToolChoice struct {
	Mode     string // none, auto, required; пусто — Function
	Function string
}

type toolChoiceObject struct {
	Type     string `json:"type"`
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
}

// UnmarshalJSON принимает строку режима или объект функции.
func (t *ToolChoice) UnmarshalJSON(b []byte) error {
	*t = ToolChoice{}
	if tb := bytes.TrimSpace(b); len(tb) > 0 && tb[0] == '"' {
		return json.Unmarshal(tb, &t.Mode)
	}
	var o toolChoiceObject
	if err := strict(b, &o); err != nil {
		return err
	}
	if o.Type != "function" {
		return errors.New("tool_choice: ожидается type function")
	}
	t.Function = o.Function.Name
	return nil
}

// MarshalJSON записывает режим или объект функции.
func (t ToolChoice) MarshalJSON() ([]byte, error) {
	if t.Mode != "" {
		return json.Marshal(t.Mode)
	}
	o := toolChoiceObject{Type: "function"}
	o.Function.Name = t.Function
	return json.Marshal(o)
}

// Stop — до четырёх стоп-последовательностей (строка или массив).
type Stop []string

// UnmarshalJSON принимает строку или массив строк.
func (s *Stop) UnmarshalJSON(b []byte) error {
	if tb := bytes.TrimSpace(b); len(tb) > 0 && tb[0] == '"' {
		var one string
		if err := json.Unmarshal(tb, &one); err != nil {
			return err
		}
		*s = Stop{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("stop — строка или массив строк")
	}
	*s = many
	return nil
}

// Limits — пределы запроса. Нулевые значения — по умолчанию (DefaultLimits).
type Limits struct {
	MaxMessages   int // сообщений в запросе
	MaxParts      int // частей в одном сообщении
	MaxToolCalls  int // вызовов инструментов в одном сообщении
	MaxTools      int // описаний инструментов
	MaxMediaBytes int // длина данных одной нетекстовой части (base64 или адрес)
	// MaxTokens — предел max_tokens (квота приложения, DM-15); 0 — без предела.
	MaxTokens int
}

// DefaultLimits — пределы по умолчанию.
var DefaultLimits = Limits{MaxMessages: 256, MaxParts: 64, MaxToolCalls: 64, MaxTools: 128, MaxMediaBytes: 20 << 20}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits
	if l.MaxMessages > 0 {
		d.MaxMessages = l.MaxMessages
	}
	if l.MaxParts > 0 {
		d.MaxParts = l.MaxParts
	}
	if l.MaxToolCalls > 0 {
		d.MaxToolCalls = l.MaxToolCalls
	}
	if l.MaxTools > 0 {
		d.MaxTools = l.MaxTools
	}
	if l.MaxMediaBytes > 0 {
		d.MaxMediaBytes = l.MaxMediaBytes
	}
	d.MaxTokens = l.MaxTokens
	return d
}

// Коды ошибок разбора (поле code ошибки в формате OpenAI).
const (
	CodeInvalid        = "invalid_request"
	CodeUnsupported    = "unsupported_parameter"
	CodeTooMany        = "request_too_large"
	CodeMaxTokens      = "max_tokens_exceeded"
	CodeMediaTooLarge  = "media_too_large"
	maxSchemaBytes     = 256 << 10
	maxUserLen         = 256
	maxFilenameLen     = 255
	maxRemoteURLLen    = 8 << 10
	maxLogitBias       = 300
	maxStop            = 4
	maxDescriptionSize = 16 << 10
)

// Error — ошибка запроса для приложения. Текст — без содержимого запроса.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func errf(code, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

var (
	modelRe   = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	idRe      = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	fileIDRe  = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,256}$`)
	fieldRe   = regexp.MustCompile(`unknown field "([^"]{0,64})`)
	audioFmts = map[string]bool{"wav": true, "mp3": true}
	efforts   = map[string]bool{"minimal": true, "low": true, "medium": true, "high": true}
)

// strict разбирает JSON без неизвестных полей и без данных после значения.
func strict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("данные после объекта JSON")
	}
	return nil
}

// Parse разбирает и проверяет тело запроса. Размер тела ограничивает
// вызывающий (ProxyConfig.MaxBodyBytes).
func Parse(body []byte, lim Limits) (*Request, error) {
	lim = lim.withDefaults()
	var r Request
	if err := strict(body, &r); err != nil {
		return nil, decodeError(err)
	}
	if err := r.validate(lim); err != nil {
		return nil, err
	}
	return &r, nil
}

// decodeError переводит ошибку encoding/json в ошибку для приложения: имя
// неизвестного поля — да, фрагменты содержимого — нет.
func decodeError(err error) *Error {
	if m := fieldRe.FindStringSubmatch(err.Error()); m != nil {
		return errf(CodeUnsupported, "параметр %q не поддерживается шлюзом", m[1])
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) && te.Field != "" && len(te.Field) <= 128 {
		return errf(CodeInvalid, "неверный тип поля %q", te.Field)
	}
	var ce *Error
	if errors.As(err, &ce) {
		return ce
	}
	return errf(CodeInvalid, "тело запроса — не объект запроса chat/completions")
}

func (r *Request) validate(lim Limits) error {
	if !modelRe.MatchString(r.Model) {
		return errf(CodeInvalid, "model: недопустимое имя модели")
	}
	if len(r.Messages) == 0 {
		return errf(CodeInvalid, "messages: нужно хотя бы одно сообщение")
	}
	if len(r.Messages) > lim.MaxMessages {
		return errf(CodeTooMany, "messages: больше %d сообщений", lim.MaxMessages)
	}
	for i := range r.Messages {
		if err := r.Messages[i].validate(i, lim); err != nil {
			return err
		}
	}
	if r.StreamOptions != nil && !r.Stream {
		return errf(CodeInvalid, "stream_options допустим только при stream: true")
	}
	if err := r.validateTokens(lim); err != nil {
		return err
	}
	if r.N != nil && *r.N != 1 {
		// Проверка ответа рассчитана на один вариант (choices[0]).
		return errf(CodeUnsupported, "n: шлюз поддерживает только n = 1")
	}
	for _, f := range []struct {
		name     string
		v        *float64
		min, max float64
	}{
		{"temperature", r.Temperature, 0, 2}, {"top_p", r.TopP, 0, 1},
		{"presence_penalty", r.PresencePenalty, -2, 2}, {"frequency_penalty", r.FrequencyPenalty, -2, 2},
	} {
		if f.v != nil && (math.IsNaN(*f.v) || *f.v < f.min || *f.v > f.max) {
			return errf(CodeInvalid, "%s: от %g до %g", f.name, f.min, f.max)
		}
	}
	if r.TopLogprobs != nil && (*r.TopLogprobs < 0 || *r.TopLogprobs > 20) {
		return errf(CodeInvalid, "top_logprobs: от 0 до 20")
	}
	if len(r.LogitBias) > maxLogitBias {
		return errf(CodeInvalid, "logit_bias: не больше %d элементов", maxLogitBias)
	}
	for k, v := range r.LogitBias {
		if !isDigits(k) || len(k) > 10 || v < -100 || v > 100 {
			return errf(CodeInvalid, "logit_bias: ключ — номер токена, значение от -100 до 100")
		}
	}
	if len(r.Stop) > maxStop {
		return errf(CodeInvalid, "stop: не больше %d строк", maxStop)
	}
	for _, s := range r.Stop {
		if s == "" || len(s) > 256 {
			return errf(CodeInvalid, "stop: строка от 1 до 256 байт")
		}
	}
	if err := r.validateTools(lim); err != nil {
		return err
	}
	if len(r.ResponseFormat) > 0 {
		if err := validateResponseFormat(r.ResponseFormat); err != nil {
			return err
		}
	}
	if len(r.User) > maxUserLen {
		return errf(CodeInvalid, "user: не длиннее %d байт", maxUserLen)
	}
	if r.ReasoningEffort != "" && !efforts[r.ReasoningEffort] {
		return errf(CodeInvalid, "reasoning_effort: minimal, low, medium или high")
	}
	return nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (r *Request) validateTokens(lim Limits) error {
	for _, v := range []*int{r.MaxTokens, r.MaxCompletionTokens} {
		if v != nil && *v < 1 {
			return errf(CodeInvalid, "max_tokens: больше 0")
		}
	}
	if r.MaxTokens != nil && r.MaxCompletionTokens != nil && *r.MaxTokens != *r.MaxCompletionTokens {
		return errf(CodeInvalid, "max_tokens и max_completion_tokens различаются")
	}
	if mt, ok := r.EffectiveMaxTokens(); ok && lim.MaxTokens > 0 && mt > lim.MaxTokens {
		return errf(CodeMaxTokens, "max_tokens: не больше %d для этого приложения", lim.MaxTokens)
	}
	return nil
}

// EffectiveMaxTokens — запрошенный предел токенов ответа, если он задан.
func (r *Request) EffectiveMaxTokens() (int, bool) {
	switch {
	case r.MaxCompletionTokens != nil:
		return *r.MaxCompletionTokens, true
	case r.MaxTokens != nil:
		return *r.MaxTokens, true
	}
	return 0, false
}

func (r *Request) validateTools(lim Limits) error {
	if len(r.Tools) > lim.MaxTools {
		return errf(CodeTooMany, "tools: больше %d инструментов", lim.MaxTools)
	}
	names := map[string]bool{}
	for i, t := range r.Tools {
		if t.Type != "function" || !nameRe.MatchString(t.Function.Name) {
			return errf(CodeInvalid, "tools[%d]: type function и имя [A-Za-z0-9_-]{1,64}", i)
		}
		if names[t.Function.Name] {
			return errf(CodeInvalid, "tools[%d]: имя функции повторяется", i)
		}
		names[t.Function.Name] = true
		if len(t.Function.Description) > maxDescriptionSize {
			return errf(CodeInvalid, "tools[%d]: описание длиннее %d байт", i, maxDescriptionSize)
		}
		if len(t.Function.Parameters) > 0 && !isJSONObject(t.Function.Parameters, maxSchemaBytes) {
			return errf(CodeInvalid, "tools[%d]: parameters — объект JSON Schema до %d байт", i, maxSchemaBytes)
		}
	}
	if tc := r.ToolChoice; tc != nil {
		switch {
		case tc.Mode == "none" || tc.Mode == "auto" || tc.Mode == "required":
		case tc.Mode == "" && names[tc.Function]:
		default:
			return errf(CodeInvalid, "tool_choice: none, auto, required или функция из tools")
		}
	}
	return nil
}

func isJSONObject(raw json.RawMessage, limit int) bool {
	t := bytes.TrimSpace(raw)
	return len(t) <= limit && len(t) > 0 && t[0] == '{' && json.Valid(t)
}

func validateResponseFormat(raw json.RawMessage) error {
	if !isJSONObject(raw, maxSchemaBytes) {
		return errf(CodeInvalid, "response_format: объект до %d байт", maxSchemaBytes)
	}
	var rf struct {
		Type       string          `json:"type"`
		JSONSchema json.RawMessage `json:"json_schema"`
	}
	if err := strict(raw, &rf); err != nil {
		return errf(CodeInvalid, "response_format: ожидаются только type и json_schema")
	}
	switch {
	case (rf.Type == "text" || rf.Type == "json_object") && len(rf.JSONSchema) == 0:
	case rf.Type == "json_schema" && isJSONObject(rf.JSONSchema, maxSchemaBytes):
	default:
		return errf(CodeInvalid, "response_format: type text, json_object или json_schema")
	}
	return nil
}

func (m *Message) validate(i int, lim Limits) error {
	at := fmt.Sprintf("messages[%d]", i)
	if m.Name != "" && !nameRe.MatchString(m.Name) {
		return errf(CodeInvalid, "%s.name: [A-Za-z0-9_-]{1,64}", at)
	}
	if len(m.Content.Parts) > lim.MaxParts {
		return errf(CodeTooMany, "%s.content: больше %d частей", at, lim.MaxParts)
	}
	textOnly := true
	for j := range m.Content.Parts {
		if err := m.Content.Parts[j].validate(fmt.Sprintf("%s.content[%d]", at, j), m.Role, lim); err != nil {
			return err
		}
		if t := m.Content.Parts[j].Type; t != PartText {
			textOnly = false
		}
	}
	if len(m.ToolCalls) > 0 && m.Role != "assistant" {
		return errf(CodeInvalid, "%s: tool_calls только у роли assistant", at)
	}
	if m.Refusal != nil && m.Role != "assistant" {
		return errf(CodeInvalid, "%s: refusal только у роли assistant", at)
	}
	if (m.ToolCallID != "") != (m.Role == "tool") {
		return errf(CodeInvalid, "%s: tool_call_id нужен роли tool и только ей", at)
	}
	empty := m.Content.Text == nil && m.Content.Parts == nil
	switch m.Role {
	case "system", "developer", "tool":
		if empty || !textOnly {
			return errf(CodeInvalid, "%s: у роли %s — текстовое содержимое", at, m.Role)
		}
		if m.Role == "tool" && !idRe.MatchString(m.ToolCallID) {
			return errf(CodeInvalid, "%s.tool_call_id: недопустимый идентификатор", at)
		}
	case "user":
		if empty {
			return errf(CodeInvalid, "%s: нет содержимого", at)
		}
	case "assistant":
		if empty && len(m.ToolCalls) == 0 && m.Refusal == nil {
			return errf(CodeInvalid, "%s: нужно содержимое, refusal или tool_calls", at)
		}
		if len(m.ToolCalls) > lim.MaxToolCalls {
			return errf(CodeTooMany, "%s.tool_calls: больше %d", at, lim.MaxToolCalls)
		}
		for j, tc := range m.ToolCalls {
			if tc.Type != "function" || !idRe.MatchString(tc.ID) || !nameRe.MatchString(tc.Function.Name) {
				return errf(CodeInvalid, "%s.tool_calls[%d]: type function, id и имя функции", at, j)
			}
		}
	default:
		return errf(CodeInvalid, "%s.role: system, developer, user, assistant или tool", at)
	}
	return nil
}

func (p *Part) validate(at, role string, lim Limits) error {
	set := 0
	for _, ok := range []bool{p.Text != nil, p.Refusal != nil, p.ImageURL != nil, p.InputAudio != nil, p.File != nil, p.VideoURL != nil} {
		if ok {
			set++
		}
	}
	var ok bool
	switch p.Type {
	case PartText:
		ok = p.Text != nil
	case PartRefusal:
		ok = p.Refusal != nil && role == "assistant"
	case PartImageURL, PartInputAudio, PartFile, PartVideoURL:
		if role != "user" {
			return errf(CodeInvalid, "%s: нетекстовые части — только у роли user", at)
		}
		ok = p.ImageURL != nil || p.InputAudio != nil || p.File != nil || p.VideoURL != nil
		ok = ok && (p.Type != PartImageURL || p.ImageURL != nil) && (p.Type != PartInputAudio || p.InputAudio != nil) &&
			(p.Type != PartFile || p.File != nil) && (p.Type != PartVideoURL || p.VideoURL != nil)
	default:
		return errf(CodeUnsupported, "%s: тип части не поддерживается шлюзом", at)
	}
	if !ok || set != 1 {
		return errf(CodeInvalid, "%s: поле части не соответствует типу %s", at, p.Type)
	}
	m, err := p.media()
	if err != nil {
		return errf(err.Code, "%s: %s", at, err.Message)
	}
	if m.EncodedLen > lim.MaxMediaBytes {
		return errf(CodeMediaTooLarge, "%s: данные части больше %d байт", at, lim.MaxMediaBytes)
	}
	return nil
}
