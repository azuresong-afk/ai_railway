package judge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"unicode/utf8"
)

// Ошибки разбора ответа оценщика. Текст ошибки не содержит ответа: в нём
// может оказаться пересказ оцениваемого текста.
var (
	ErrReplyTooLarge = errors.New("ответ оценщика больше предела")
	ErrReplyFormat   = errors.New("ответ оценщика не в формате judge-prompt/1")
)

type replyJSON struct {
	Verdicts []verdictJSON `json:"verdicts"`
}

type verdictJSON struct {
	Rule       string   `json:"rule"`
	Violated   *bool    `json:"violated"`
	Confidence *float64 `json:"confidence"`
}

// ParseVerdicts разбирает ответ оценщика (ADR-0030, раздел 5): не больше
// MaxReply байт, валидный UTF-8, один объект JSON без лишних данных и
// неизвестных полей, ровно один вердикт на каждый критерий без повторов и
// чужих правил, confidence от 0 до 1. Вердикты — в порядке критериев.
func ParseVerdicts(data []byte, cs []Criterion) ([]Verdict, error) {
	if len(data) > MaxReply {
		return nil, ErrReplyTooLarge
	}
	if !utf8.Valid(data) {
		return nil, ErrReplyFormat
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return nil, ErrReplyFormat
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r replyJSON
	if err := dec.Decode(&r); err != nil {
		return nil, ErrReplyFormat
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrReplyFormat
	}
	if len(r.Verdicts) != len(cs) {
		return nil, fmt.Errorf("%w: вердиктов %d, правил %d", ErrReplyFormat, len(r.Verdicts), len(cs))
	}
	idx := make(map[string]int, len(cs))
	for i, c := range cs {
		idx[c.Rule] = i
	}
	out := make([]Verdict, len(cs))
	seen := make([]bool, len(cs))
	for _, v := range r.Verdicts {
		i, ok := idx[v.Rule]
		switch {
		case !ok || seen[i]:
			return nil, fmt.Errorf("%w: неизвестное или повторное правило", ErrReplyFormat)
		case v.Violated == nil || v.Confidence == nil:
			return nil, fmt.Errorf("%w: нет violated или confidence", ErrReplyFormat)
		case math.IsNaN(*v.Confidence) || *v.Confidence < 0 || *v.Confidence > 1:
			return nil, fmt.Errorf("%w: confidence вне 0–1", ErrReplyFormat)
		}
		seen[i] = true
		out[i] = Verdict{Rule: v.Rule, Violated: *v.Violated, Confidence: *v.Confidence}
	}
	return out, nil
}
