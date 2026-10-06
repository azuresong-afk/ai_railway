package chat

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// Виды нетекстового содержимого (DM-14). Шлюз медиа не декодирует (ТЗ, 5.1,
// граница «шлюз — aisec-media»): он знает только вид части, способ передачи
// и длину данных.
const (
	MediaImage = "image"
	MediaAudio = "audio"
	MediaFile  = "file"
	MediaVideo = "video"
)

// Media — нетекстовая часть запроса.
type Media struct {
	Message, Part int
	Kind          string
	// Inline — данные в самом запросе (base64); иначе ссылка, которую
	// провайдер загрузит сам, или идентификатор файла у провайдера.
	Inline bool
	// EncodedLen — длина данных base64 или адреса; лимит проверяется до
	// какой-либо обработки.
	EncodedLen int
}

// media проверяет формат нетекстовой части и возвращает её описание.
// Для текстовой части Kind пуст.
func (p *Part) media() (Media, *Error) {
	var m Media
	var err *Error
	switch {
	case p.ImageURL != nil:
		m.Kind = MediaImage
		m.Inline, m.EncodedLen, err = mediaURL(p.ImageURL.URL)
		if err == nil && p.ImageURL.Detail != "" && p.ImageURL.Detail != "auto" && p.ImageURL.Detail != "low" && p.ImageURL.Detail != "high" {
			err = errf(CodeInvalid, "detail — auto, low или high")
		}
	case p.VideoURL != nil:
		m.Kind = MediaVideo
		m.Inline, m.EncodedLen, err = mediaURL(p.VideoURL.URL)
	case p.InputAudio != nil:
		m.Kind, m.Inline, m.EncodedLen = MediaAudio, true, len(p.InputAudio.Data)
		if !audioFmts[p.InputAudio.Format] || !isBase64(p.InputAudio.Data) {
			err = errf(CodeInvalid, "input_audio: данные base64 и format wav или mp3")
		}
	case p.File != nil:
		m.Kind = MediaFile
		err = p.File.validate()
		if err == nil && p.File.FileData != "" {
			m.Inline, m.EncodedLen, err = mediaURL(p.File.FileData)
			if err == nil && !m.Inline {
				err = errf(CodeInvalid, "file_data — data:-адрес с base64")
			}
		} else if err == nil {
			m.EncodedLen = len(p.File.FileID)
		}
	default:
		return Media{}, nil // текстовая часть
	}
	if err != nil {
		return Media{}, err
	}
	return m, nil
}

func (f *File) validate() *Error {
	if (f.FileData == "") == (f.FileID == "") {
		return errf(CodeInvalid, "file: нужно ровно одно из file_data и file_id")
	}
	if f.FileID != "" && !fileIDRe.MatchString(f.FileID) {
		return errf(CodeInvalid, "file_id: недопустимый идентификатор")
	}
	if len(f.Filename) > maxFilenameLen || strings.ContainsFunc(f.Filename, unicode.IsControl) {
		return errf(CodeInvalid, "filename: до %d байт без управляющих символов", maxFilenameLen)
	}
	return nil
}

// mediaURL разбирает адрес медиа: data:<тип>;base64,<данные> или http(s).
// Другие схемы (file:, ftp: и т. п.) не принимаются.
func mediaURL(u string) (inline bool, encodedLen int, err *Error) {
	if rest, ok := cutPrefixFold(u, "data:"); ok {
		header, data, found := strings.Cut(rest, ",")
		if !found || !strings.HasSuffix(strings.ToLower(header), ";base64") || len(header) > 256 || !isBase64(data) {
			return false, 0, errf(CodeInvalid, "data:-адрес — data:<тип>;base64,<данные>")
		}
		return true, len(data), nil
	}
	_, okS := cutPrefixFold(u, "https://")
	_, okP := cutPrefixFold(u, "http://")
	if !okS && !okP {
		return false, 0, errf(CodeInvalid, "адрес медиа — data:, https:// или http://")
	}
	if len(u) > maxRemoteURLLen || strings.ContainsFunc(u, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return false, 0, errf(CodeInvalid, "адрес медиа — до %d байт без пробелов и управляющих символов", maxRemoteURLLen)
	}
	return false, len(u), nil
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

// isBase64 — непустая строка из алфавита base64 (стандартного или URL) с
// возможным выравниванием. Декодирование не выполняется.
func isBase64(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_' || c == '='
		if !ok {
			return false
		}
	}
	return true
}

// Media — все нетекстовые части запроса (для параметра политики non_text).
func (r *Request) Media() []Media {
	var out []Media
	for i := range r.Messages {
		for j := range r.Messages[i].Content.Parts {
			m, err := r.Messages[i].Content.Parts[j].media()
			if err != nil || m.Kind == "" {
				continue // запрос уже проверен Parse; текстовые части пропускаются
			}
			m.Message, m.Part = i, j
			out = append(out, m)
		}
	}
	return out
}

// Виды текстовых фрагментов.
const (
	SegContent  = "content"   // строка content или текстовая часть
	SegRefusal  = "refusal"   // отказ ассистента в истории диалога
	SegToolArgs = "tool_args" // аргументы вызова инструмента в истории диалога
)

// Segment — текстовый фрагмент запроса, который проверяют детекторы.
// Описания инструментов и схемы JSON (tools, response_format) задаёт
// приложение, а не пользователь; на этапе 1 они не проверяются.
type Segment struct {
	Message int
	Role    string
	Kind    string
	// Part — номер части в content или -1 для строки и поля refusal;
	// ToolCall — номер вызова для SegToolArgs, иначе -1.
	Part, ToolCall int
	Text           string
}

// Location — место фрагмента в запросе для событий (Finding.Location).
func (s Segment) Location() string {
	at := fmt.Sprintf("messages[%d]", s.Message)
	switch {
	case s.Kind == SegToolArgs:
		return fmt.Sprintf("%s.tool_calls[%d].function.arguments", at, s.ToolCall)
	case s.Part >= 0:
		return fmt.Sprintf("%s.content[%d]", at, s.Part)
	case s.Kind == SegRefusal:
		return at + ".refusal"
	}
	return at + ".content"
}

// Segments — текстовые фрагменты запроса в порядке диалога.
func (r *Request) Segments() []Segment {
	var out []Segment
	for i := range r.Messages {
		m := &r.Messages[i]
		add := func(kind string, part, call int, text string) {
			out = append(out, Segment{Message: i, Role: m.Role, Kind: kind, Part: part, ToolCall: call, Text: text})
		}
		if m.Content.Text != nil {
			add(SegContent, -1, -1, *m.Content.Text)
		}
		for j, p := range m.Content.Parts {
			switch {
			case p.Text != nil:
				add(SegContent, j, -1, *p.Text)
			case p.Refusal != nil:
				add(SegRefusal, j, -1, *p.Refusal)
			}
		}
		if m.Refusal != nil {
			add(SegRefusal, -1, -1, *m.Refusal)
		}
		for j, tc := range m.ToolCalls {
			add(SegToolArgs, -1, j, tc.Function.Arguments)
		}
	}
	return out
}

// SetText заменяет текст фрагмента (маскирование, псевдонимизация).
func (r *Request) SetText(s Segment, text string) error {
	if s.Message < 0 || s.Message >= len(r.Messages) {
		return fmt.Errorf("фрагмент %s: нет сообщения", s.Location())
	}
	m := &r.Messages[s.Message]
	switch {
	case s.Kind == SegToolArgs && s.ToolCall >= 0 && s.ToolCall < len(m.ToolCalls):
		m.ToolCalls[s.ToolCall].Function.Arguments = text
	case s.Part >= 0 && s.Part < len(m.Content.Parts):
		p := &m.Content.Parts[s.Part]
		switch {
		case s.Kind == SegContent && p.Text != nil:
			p.Text = &text
		case s.Kind == SegRefusal && p.Refusal != nil:
			p.Refusal = &text
		default:
			return fmt.Errorf("фрагмент %s: вид не совпадает", s.Location())
		}
	case s.Part < 0 && s.Kind == SegContent && m.Content.Text != nil:
		m.Content.Text = &text
	case s.Part < 0 && s.Kind == SegRefusal && m.Refusal != nil:
		m.Refusal = &text
	default:
		return fmt.Errorf("фрагмент %s: не найден", s.Location())
	}
	return nil
}

// Marshal собирает тело запроса к провайдеру из разобранной модели.
func (r *Request) Marshal() ([]byte, error) {
	return json.Marshal(r)
}
