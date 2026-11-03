package judge

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// Stand — оценщик в памяти для самотеста (ADR-0030, раздел 10) и тестов
// шлюза: отвечает на настоящий запрос Engine без сети. Запрос проверяется
// по шаблону judge-prompt/1 (системное сообщение с правилами, текст между
// разделителями с одним nonce); правило нарушено, если в тексте есть его
// слово-маркер.
type Stand struct {
	// Markers — ID правила → слово-маркер (без учёта регистра).
	Markers map[string]string
	// Err — ошибка вместо ответа: оценщик недоступен.
	Err error
}

var (
	standRuleRe = regexp.MustCompile(`(?m)^- ([a-z0-9][a-z0-9_-]*): `)
	standTextRe = regexp.MustCompile(`(?s)^<<<AISEC-TEXT-([0-9a-f]{32})>>>\n(.*)\n<<<END-AISEC-TEXT-([0-9a-f]{32})>>>$`)
)

// errStandRequest — запрос не по шаблону: ошибка кода шлюза.
var errStandRequest = errors.New("стенд-оценщик: запрос не по шаблону " + PromptVersion)

// standVerdict — вердикт в ответе стенда.
type standVerdict struct {
	Rule       string  `json:"rule"`
	Violated   bool    `json:"violated"`
	Confidence float64 `json:"confidence"`
}

// Chat отвечает вердиктами по правилам системного сообщения.
func (s Stand) Chat(ctx context.Context, req *chat.Request) (*chat.Response, providers.Meta, error) {
	if s.Err != nil {
		return nil, providers.Meta{}, s.Err
	}
	if err := ctx.Err(); err != nil {
		return nil, providers.Meta{}, err
	}
	if len(req.Messages) != 2 || req.Messages[0].Content.Text == nil || req.Messages[1].Content.Text == nil {
		return nil, providers.Meta{}, errStandRequest
	}
	sys, usr := *req.Messages[0].Content.Text, *req.Messages[1].Content.Text
	m := standTextRe.FindStringSubmatch(usr)
	if m == nil || m[1] != m[3] || !strings.Contains(sys, openMarker(m[1])) {
		return nil, providers.Meta{}, errStandRequest
	}
	text := strings.ToLower(m[2])
	var out struct {
		Verdicts []standVerdict `json:"verdicts"`
	}
	for _, rm := range standRuleRe.FindAllStringSubmatch(sys, -1) {
		v := standVerdict{Rule: rm[1], Confidence: 0.1}
		if w := s.Markers[rm[1]]; w != "" && strings.Contains(text, strings.ToLower(w)) {
			v.Violated, v.Confidence = true, 0.9
		}
		out.Verdicts = append(out.Verdicts, v)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, providers.Meta{}, err
	}
	content := string(b)
	return &chat.Response{ID: "stand", Object: "chat.completion", Model: req.Model,
		Choices: []chat.Choice{{Message: chat.ResponseMessage{Role: "assistant", Content: &content}, FinishReason: "stop"}},
		Usage:   &chat.Usage{PromptTokens: len(sys+usr)/3 + 1, CompletionTokens: len(content)/3 + 1}}, providers.Meta{}, nil
}
