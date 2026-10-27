package ml

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"unicode/utf8"
)

// Лимиты содержимого сообщений.
const (
	MaxModels   = 16
	MaxLabels   = 64
	MaxFindings = 512
	maxVersion  = 64
)

// Направления модели — как detect.Direction (input, output).
const (
	DirectionInput  = "input"
	DirectionOutput = "output"
)

var (
	modelIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	labelRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// ValidModelID — ID модели: строчные латинские буквы, цифры, «.», «_», «-»,
// до 64 знаков.
func ValidModelID(id string) bool { return modelIDRe.MatchString(id) }

// ModelInfo — модель, которую обслуживает aisec-ml.
type ModelInfo struct {
	ID         string   `json:"id"`
	Version    string   `json:"version"`
	Labels     []string `json:"labels"`
	Directions []string `json:"directions"`
}

// HelloOK — ответ на hello.
type HelloOK struct {
	Protocol int         `json:"protocol"`
	Models   []ModelInfo `json:"models"`
}

// Score — находка модели: метка, оценка 0–1 и байтовые позиции [Start, End)
// в тексте запроса.
type Score struct {
	Label string  `json:"label"`
	Score float64 `json:"score"`
	Start int     `json:"start"`
	End   int     `json:"end"`
}

// Result — ответ на detect. Truncated — модель проверила не весь текст
// (окон больше предела).
type Result struct {
	Model     string  `json:"model"`
	Version   string  `json:"version"`
	Truncated bool    `json:"truncated,omitempty"`
	Findings  []Score `json:"findings"`
}

// ErrorCode — код ошибки aisec-ml.
type ErrorCode string

// Коды ошибок.
const (
	ErrOverloaded   ErrorCode = "overloaded"    // все исполнители заняты
	ErrUnknownModel ErrorCode = "unknown_model" // модели нет в пакете
	ErrTooLarge     ErrorCode = "too_large"     // кадр сверх предела
	ErrBadRequest   ErrorCode = "bad_request"   // неверное тело запроса
	ErrInternal     ErrorCode = "internal"      // сбой исполнителя
)

// ErrorMsg — тело кадра error.
type ErrorMsg struct {
	Code ErrorCode `json:"code"`
}

func validCode(c ErrorCode) bool {
	switch c {
	case ErrOverloaded, ErrUnknownModel, ErrTooLarge, ErrBadRequest, ErrInternal:
		return true
	}
	return false
}

// EncodeDetect — тело кадра detect: длина ID модели, ID, текст UTF-8.
func EncodeDetect(model, text string) ([]byte, error) {
	if !ValidModelID(model) {
		return nil, fmt.Errorf("aisec-ml: неверный ID модели")
	}
	if len(text) > MaxText {
		return nil, fmt.Errorf("aisec-ml: текст больше %d байт", MaxText)
	}
	if !utf8.ValidString(text) {
		return nil, fmt.Errorf("aisec-ml: текст не UTF-8")
	}
	b := make([]byte, 0, 1+len(model)+len(text))
	b = append(b, byte(len(model))) //nolint:gosec // G115: длина ID проверена ValidModelID (не больше 64)
	b = append(b, model...)
	return append(b, text...), nil
}

// ErrBadBody — тело кадра не разбирается.
var ErrBadBody = errors.New("aisec-ml: неверное тело кадра")

// ParseDetect разбирает тело кадра detect (недоверенный вход для aisec-ml;
// фаззится в FuzzServerReadFrame).
func ParseDetect(body []byte) (model, text string, err error) {
	if len(body) < 1 || len(body) > MaxDetectBody {
		return "", "", ErrBadBody
	}
	n := int(body[0])
	if n == 0 || n > MaxModelID || len(body) < 1+n {
		return "", "", ErrBadBody
	}
	model = string(body[1 : 1+n])
	if !ValidModelID(model) {
		return "", "", ErrBadBody
	}
	rest := body[1+n:]
	if len(rest) > MaxText || !utf8.Valid(rest) {
		return "", "", ErrBadBody
	}
	return model, string(rest), nil
}

// decodeStrict — строгий JSON: без неизвестных полей и данных после объекта.
func decodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrBadBody
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrBadBody
	}
	return nil
}

func printable(s string, limit int) bool {
	if s == "" || len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validLabels(labels []string) bool {
	if len(labels) == 0 || len(labels) > MaxLabels {
		return false
	}
	seen := make(map[string]bool, len(labels))
	for _, l := range labels {
		if !labelRe.MatchString(l) || seen[l] {
			return false
		}
		seen[l] = true
	}
	return true
}

func validDirections(ds []string) bool {
	if len(ds) == 0 || len(ds) > 2 {
		return false
	}
	seen := map[string]bool{}
	for _, d := range ds {
		if (d != DirectionInput && d != DirectionOutput) || seen[d] {
			return false
		}
		seen[d] = true
	}
	return true
}

// Validate проверяет описание модели.
func (m ModelInfo) Validate() error {
	if !ValidModelID(m.ID) || !printable(m.Version, maxVersion) || !validLabels(m.Labels) || !validDirections(m.Directions) {
		return fmt.Errorf("%w: описание модели", ErrBadBody)
	}
	return nil
}

// ParseHelloOK разбирает ответ на hello (недоверенный вход для шлюза).
func ParseHelloOK(body []byte) (*HelloOK, error) {
	var h HelloOK
	if err := decodeStrict(body, &h); err != nil {
		return nil, err
	}
	if h.Protocol != ProtocolVersion || len(h.Models) > MaxModels {
		return nil, ErrBadBody
	}
	seen := make(map[string]bool, len(h.Models))
	for _, m := range h.Models {
		if err := m.Validate(); err != nil {
			return nil, err
		}
		if seen[m.ID] {
			return nil, ErrBadBody
		}
		seen[m.ID] = true
	}
	return &h, nil
}

// ParseResult разбирает ответ на detect и сверяет его с запросом: модель
// та же, метки — из описания модели, позиции — в пределах текста и на
// границах символов.
func ParseResult(body []byte, info ModelInfo, text string) (*Result, error) {
	var r Result
	if err := decodeStrict(body, &r); err != nil {
		return nil, err
	}
	if r.Model != info.ID || r.Version != info.Version || len(r.Findings) > MaxFindings {
		return nil, ErrBadBody
	}
	for _, f := range r.Findings {
		if err := f.validate(info.Labels, text); err != nil {
			return nil, err
		}
	}
	return &r, nil
}

func (s Score) validate(labels []string, text string) error {
	known := false
	for _, l := range labels {
		if l == s.Label {
			known = true
			break
		}
	}
	if !known || math.IsNaN(s.Score) || s.Score < 0 || s.Score > 1 {
		return ErrBadBody
	}
	if s.Start < 0 || s.End <= s.Start || s.End > len(text) || !runeBoundary(text, s.Start) || !runeBoundary(text, s.End) {
		return ErrBadBody
	}
	return nil
}

func runeBoundary(s string, p int) bool {
	return p == len(s) || utf8.RuneStart(s[p])
}

// ParseError разбирает тело кадра error.
func ParseError(body []byte) (ErrorCode, error) {
	var e ErrorMsg
	if err := decodeStrict(body, &e); err != nil {
		return "", err
	}
	if !validCode(e.Code) {
		return "", ErrBadBody
	}
	return e.Code, nil
}

// MarshalBody кодирует тело ответа aisec-ml.
func MarshalBody(v any) ([]byte, error) { return json.Marshal(v) }
