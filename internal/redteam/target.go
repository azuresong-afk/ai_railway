package redteam

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/netguard"
)

// Пределы полей цели.
const (
	MaxName            = 100
	MaxModel           = 128
	MaxURL             = 2048
	MaxTemplate        = 16 << 10
	MaxResponsePath    = 256
	MaxHeaders         = 8
	MaxHeaderValue     = 1024
	MaxCAPEM           = 64 << 10
	MinNote, MaxNote   = 10, 500
	maxPathParts       = 16
	PlaceholderPrompt  = "{{prompt}}"
	PlaceholderHistory = "{{messages}}"
)

var (
	headerNameRe   = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
	responsePathRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}(\.[A-Za-z0-9_-]{1,64})*$`)
	slugRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	uuidRe         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// forbiddenHeaders — заголовки, которые задаёт исполнитель или которые
// меняют путь запроса (в нижнем регистре); Proxy-* — по префиксу.
var forbiddenHeaders = map[string]bool{"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"cookie": true, "content-type": true, "upgrade": true, "te": true, "trailer": true, "keep-alive": true, "expect": true}

// TargetInput — поля цели, которые задаёт администратор безопасности.
type TargetInput struct {
	Name              string   `json:"name"`
	Kind              string   `json:"kind"`
	AppID             string   `json:"app_id,omitempty"`
	Model             string   `json:"model,omitempty"`
	URL               string   `json:"url,omitempty"`
	RequestTemplate   string   `json:"request_template,omitempty"`
	ResponsePath      string   `json:"response_path,omitempty"`
	Headers           []Header `json:"headers,omitempty"`
	AuthHeader        string   `json:"auth_header,omitempty"`
	CAPEM             string   `json:"ca_pem,omitempty"`
	AuthorizationNote string   `json:"authorization_note,omitempty"`
	Storage           string   `json:"storage,omitempty"`
	JudgeProvider     string   `json:"judge_provider,omitempty"`
	JudgeModel        string   `json:"judge_model,omitempty"`
	Limits            *Limits  `json:"limits,omitempty"`
}

// bounded — n в [lo, hi]; 0 — def.
func bounded(l *errList, field string, n *int, lo, hi, def int) {
	if *n == 0 {
		*n = def
	}
	if *n < lo || *n > hi {
		l.add("%s — от %d до %d", field, lo, hi)
	}
}

func shortText(s string, lo, hi int) bool {
	n := utf8.RuneCountInString(s)
	return n >= lo && n <= hi && plainText(s, false) && strings.TrimSpace(s) == s
}

// endpointURL проверяет точный адрес цели endpoint: схема http или https,
// узел, явный порт, без учётных данных и фрагмента; узел — не localhost и
// не литерал запрещённого адреса (netguard; имя проверяется при каждом
// соединении).
func endpointURL(l *errList, raw string) {
	u, err := url.Parse(raw)
	switch {
	case raw == "" || len(raw) > MaxURL || err != nil || !plainText(raw, false):
		l.add("url — адрес до %d байт", MaxURL)
		return
	case u.Scheme != "https" && u.Scheme != "http":
		l.add("url — схема https или http")
	case u.User != nil || u.Fragment != "" || u.Opaque != "":
		l.add("url — без учётных данных и фрагмента")
	case u.Hostname() == "":
		l.add("url — нужен узел")
	}
	if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 {
		l.add("url — порт указывается явно: от 1 до 65535")
	}
	if u.Hostname() != "" && netguard.CheckHost(u.Hostname(), nil) != nil {
		l.add("url — %v", netguard.ErrBlockedHost)
	}
}

// templateHas — в шаблоне есть строковое значение placeholder.
func templateHas(v any, placeholder string) bool {
	switch x := v.(type) {
	case string:
		return x == placeholder
	case []any:
		for _, e := range x {
			if templateHas(e, placeholder) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if templateHas(e, placeholder) {
				return true
			}
		}
	}
	return false
}

func parseTemplate(s string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errTrailing
	}
	return v, nil
}

var errTrailing = invalidf("после JSON-значения есть лишние данные")

// Target проверяет поля и возвращает цель без ID и времени.
func (in TargetInput) Target() (Target, error) {
	var l errList
	t := Target{Name: in.Name, Kind: in.Kind, AppID: in.AppID, Model: in.Model, URL: in.URL, RequestTemplate: in.RequestTemplate,
		ResponsePath: in.ResponsePath, Headers: in.Headers, AuthHeader: in.AuthHeader, CAPEM: in.CAPEM,
		AuthorizationNote: in.AuthorizationNote, Storage: in.Storage, JudgeProvider: in.JudgeProvider, JudgeModel: in.JudgeModel}
	if !shortText(t.Name, 1, MaxName) {
		l.add("name — от 1 до %d символов без управляющих символов", MaxName)
	}
	if in.Limits != nil {
		t.Limits = *in.Limits
	}
	bounded(&l, "limits.rate_per_minute", &t.Limits.RatePerMinute, MinRate, MaxRate, DefaultRate)
	bounded(&l, "limits.concurrency", &t.Limits.Concurrency, MinConcurrency, MaxConcurrency, DefaultConcurrency)
	bounded(&l, "limits.request_timeout_sec", &t.Limits.RequestTimeoutSec, MinRequestTimeout, MaxRequestTimeout, DefaultRequestTimeout)
	bounded(&l, "limits.run_timeout_min", &t.Limits.RunTimeoutMin, MinRunTimeout, MaxRunTimeout, DefaultRunTimeout)
	if (t.JudgeProvider == "") != (t.JudgeModel == "") {
		l.add("judge_provider и judge_model задаются вместе")
	}
	if t.JudgeProvider != "" && !slugRe.MatchString(t.JudgeProvider) {
		l.add("judge_provider — slug провайдера")
	}
	if t.JudgeModel != "" && !shortText(t.JudgeModel, 1, MaxModel) {
		l.add("judge_model — до %d символов", MaxModel)
	}
	switch t.Kind {
	case KindGateway:
		if !uuidRe.MatchString(t.AppID) {
			l.add("app_id — ID приложения")
		}
		if !shortText(t.Model, 1, MaxModel) {
			l.add("model — модель приложения, до %d символов", MaxModel)
		}
		if t.URL != "" || t.RequestTemplate != "" || t.ResponsePath != "" || len(t.Headers) > 0 || t.AuthHeader != "" || t.CAPEM != "" {
			l.add("url, request_template, response_path, headers, auth_header и ca_pem — только у цели endpoint")
		}
		if t.Storage != "" {
			l.add("storage — только у цели endpoint: пример цели gateway — событие шлюза по режиму хранения приложения")
		}
		if t.AuthorizationNote != "" && !shortText(t.AuthorizationNote, MinNote, MaxNote) {
			l.add("authorization_note — от %d до %d символов", MinNote, MaxNote)
		}
	case KindEndpoint:
		if t.AppID != "" || t.Model != "" {
			l.add("app_id и model — только у цели gateway")
		}
		endpointURL(&l, t.URL)
		t.checkTemplate(&l)
		if len(t.ResponsePath) > MaxResponsePath || !responsePathRe.MatchString(t.ResponsePath) ||
			strings.Count(t.ResponsePath, ".") >= maxPathParts {
			l.add("response_path — путь к строке ответа через точку (choices.0.message.content), до %d частей", maxPathParts)
		}
		t.checkHeaders(&l)
		if strings.HasPrefix(t.URL, "https:") && strings.TrimSpace(t.CAPEM) == "" {
			l.add("ca_pem — корневой сертификат адреса https (системное хранилище не используется)")
		}
		if len(t.CAPEM) > MaxCAPEM || !plainText(t.CAPEM, true) {
			l.add("ca_pem — PEM до %d КиБ", MaxCAPEM>>10)
		}
		if strings.HasPrefix(t.URL, "http:") && t.CAPEM != "" {
			l.add("ca_pem — только для адреса https")
		}
		if !shortText(t.AuthorizationNote, MinNote, MaxNote) {
			l.add("authorization_note — основание для тестирования адреса (договор, письмо владельца): от %d до %d символов", MinNote, MaxNote)
		}
		if t.Storage == "" {
			t.Storage = StorageNone
		}
		if t.Storage != StorageNone && t.Storage != StorageMasked {
			l.add("storage — none или masked")
		}
	default:
		l.add("kind — gateway или endpoint")
	}
	if err := l.err(); err != nil {
		return Target{}, err
	}
	if t.Headers == nil {
		t.Headers = []Header{}
	}
	return t, nil
}

func (t *Target) checkTemplate(l *errList) {
	if t.RequestTemplate == "" || len(t.RequestTemplate) > MaxTemplate {
		l.add("request_template — JSON до %d КиБ", MaxTemplate>>10)
		return
	}
	v, err := parseTemplate(t.RequestTemplate)
	if err != nil {
		l.add("request_template — некорректный JSON")
		return
	}
	if !templateHas(v, PlaceholderPrompt) && !templateHas(v, PlaceholderHistory) {
		l.add("request_template — строковое значение %q или %q", PlaceholderPrompt, PlaceholderHistory)
	}
}

func (t *Target) checkHeaders(l *errList) {
	if len(t.Headers) > MaxHeaders {
		l.add("headers — не больше %d", MaxHeaders)
	}
	seen := map[string]bool{}
	auth := strings.ToLower(t.AuthHeader)
	if t.AuthHeader != "" && (!headerNameRe.MatchString(t.AuthHeader) || forbidden(auth)) {
		l.add("auth_header — имя заголовка (Authorization, X-Api-Key)")
	}
	for i, h := range t.Headers {
		n := strings.ToLower(h.Name)
		switch {
		case !headerNameRe.MatchString(h.Name):
			l.add("headers[%d].name — имя заголовка по RFC 9110", i)
		case forbidden(n) || n == auth:
			l.add("headers[%d].name — заголовок %s задаёт исполнитель", i, h.Name)
		case seen[n]:
			l.add("headers[%d].name — повторяется", i)
		}
		seen[n] = true
		if len(h.Value) > MaxHeaderValue || !plainText(h.Value, false) {
			l.add("headers[%d].value — до %d байт без управляющих символов", i, MaxHeaderValue)
		}
	}
}

func forbidden(lower string) bool {
	return forbiddenHeaders[lower] || strings.HasPrefix(lower, "proxy-")
}

// renderTemplate — тело запроса цели endpoint: строковые значения
// "{{prompt}}" и "{{messages}}" заменяются текстом шага и историей.
func renderTemplate(tmpl string, prompt string, history []message) ([]byte, error) {
	v, err := parseTemplate(tmpl)
	if err != nil {
		return nil, err
	}
	v = substitute(v, prompt, history)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func substitute(v any, prompt string, history []message) any {
	switch x := v.(type) {
	case string:
		switch x {
		case PlaceholderPrompt:
			return prompt
		case PlaceholderHistory:
			return history
		}
	case []any:
		for i := range x {
			x[i] = substitute(x[i], prompt, history)
		}
	case map[string]any:
		for k := range x {
			x[k] = substitute(x[k], prompt, history)
		}
	}
	return v
}

// extractPath — строка по точечному пути в JSON ответа; ok=false — пути
// нет или значение не строка.
func extractPath(body []byte, path string) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", false
	}
	for _, part := range strings.Split(path, ".") {
		switch x := v.(type) {
		case map[string]any:
			nv, ok := x[part]
			if !ok {
				return "", false
			}
			v = nv
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(x) {
				return "", false
			}
			v = x[i]
		default:
			return "", false
		}
	}
	s, ok := v.(string)
	return s, ok
}
