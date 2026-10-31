package modelscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// tokenizer_config.json и chat_template.json (Hugging Face) — строгий JSON
// до предела: объект верхнего уровня без повторов ключей, без данных после
// него, в UTF-8. chat_template — строка или список {name, template}; каждый
// шаблон — до MaxChatTemplate. chat_template.jinja — шаблон текстом.

const (
	nameTokenizerConfig   = "tokenizer_config.json" //nolint:gosec // G101: имя файла, не секрет
	nameChatTemplateJSON  = "chat_template.json"
	nameChatTemplateJinja = "chat_template.jinja"
)

// isJSON — первый значимый символ (после BOM и пробелов) — «{» или «[».
func isJSON(head []byte) bool {
	b := bytes.TrimPrefix(head, []byte("\xef\xbb\xbf"))
	b = bytes.TrimLeft(b, " \t\r\n")
	return len(b) > 0 && (b[0] == '{' || b[0] == '[')
}

// scanTokenizerConfig читает файл целиком (до предела) и извлекает шаблоны.
func (s *Scanner) scanTokenizerConfig(r io.ReaderAt, size int64, name string, fr *FileReport) {
	if size > s.limits.MaxTokenizerConfig {
		fr.add(CodeLimitExceeded, SeverityBlock, "%s: %d байт, предел %d", name, size, s.limits.MaxTokenizerConfig)
		return
	}
	data := make([]byte, size)
	if _, err := r.ReadAt(data, 0); err != nil && !errors.Is(err, io.EOF) {
		fr.add(CodeMalformed, SeverityBlock, "%s: не прочитан", name)
		return
	}
	if name == nameChatTemplateJinja {
		s.addTemplate(fr, name, "", data)
		return
	}
	tpls, err := parseTokenizerConfig(data)
	if err != nil {
		fr.add(CodeMalformed, SeverityBlock, "%s: %v", name, err)
		return
	}
	for _, t := range tpls {
		s.addTemplate(fr, name, t.Name, []byte(t.Text))
	}
}

// maxChatTemplates — шаблонов чата в одном файле.
const maxChatTemplates = 32

func (s *Scanner) addTemplate(fr *FileReport, source, name string, text []byte) {
	if len(fr.ChatTemplates) >= maxChatTemplates {
		fr.add(CodeLimitExceeded, SeverityBlock, "%s: шаблонов чата больше %d", source, maxChatTemplates)
		return
	}
	if len(text) > s.limits.MaxChatTemplate {
		fr.add(CodeLimitExceeded, SeverityBlock, "%s: шаблон чата %s — %d байт, предел %d", source, clean(name), len(text), s.limits.MaxChatTemplate)
		return
	}
	if !utf8.Valid(text) {
		fr.add(CodeMalformed, SeverityBlock, "%s: шаблон чата не в UTF-8", source)
		return
	}
	fr.ChatTemplates = append(fr.ChatTemplates, ChatTemplate{Source: source, Name: name, Text: string(text)})
}

// parseTokenizerConfig проверяет строгий JSON и возвращает шаблоны чата.
func parseTokenizerConfig(data []byte) ([]ChatTemplate, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("не UTF-8")
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var raw json.RawMessage
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("JSON: %w", err)
		}
		key, _ := tok.(string)
		if seen[key] {
			return nil, fmt.Errorf("повтор ключа %q", clean(key))
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("JSON: %w", err)
		}
		if key == "chat_template" {
			raw = v
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data[dec.InputOffset():])) != 0 {
		return nil, errors.New("данные после объекта JSON")
	}
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []ChatTemplate{{Text: one}}, nil
	}
	var many []struct {
		Name     *string `json:"name"`
		Template *string `json:"template"`
	}
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, errors.New("chat_template — не строка и не список {name, template}")
	}
	out := make([]ChatTemplate, 0, len(many))
	for _, t := range many {
		if t.Name == nil || t.Template == nil {
			return nil, errors.New("в списке chat_template нет name или template")
		}
		out = append(out, ChatTemplate{Name: *t.Name, Text: *t.Template})
	}
	return out, nil
}
