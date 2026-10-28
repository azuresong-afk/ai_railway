package gateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/session"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/providers"
	"github.com/azuresong-afk/ai_railway/internal/pseudonym"
	"github.com/azuresong-afk/ai_railway/internal/sse"
)

// ChatConfig — параметры обработчика POST /v1/chat/completions.
type ChatConfig struct {
	Router       *Router
	MaxBodyBytes int64
	Logger       *slog.Logger
	// BodyReadTimeout — предел времени на чтение тела запроса: медленная
	// передача тела не должна занимать соединения. Ноль — DefaultBodyReadTimeout.
	BodyReadTimeout time.Duration
	// Events и IDs — события gateway_request (ТЗ, 5.5); обязательны.
	Events EventSink
	IDs    *ids.Generator
	// Quotas — квоты приложений (DM-15, DM-36); nil — без квот.
	Quotas *Limiter
	// Budget — учёт расхода и жёсткие бюджеты приложений (DM-15, задача
	// 3.18); nil — расход не считается.
	Budget *Budget
	// UserMAC — имитовставка для псевдонима пользователя в событиях и
	// квотах (ТЗ, 5.5); nil — пользователь не учитывается.
	UserMAC aisecCrypto.MAC
	// Sessions — сессии чата (задачи 4.13, 4.14): псевдоним сессии в
	// событиях, session.risk, хеши реплик для history.integrity; nil — без
	// сессий (заголовок X-AISec-Session всё равно проверяется).
	Sessions *Sessions
	// DetectorTimeout — срок детектора на короткий текст; ноль —
	// DefaultDetectorTimeout. Срок растёт с длиной текста (pipeline.go).
	DetectorTimeout time.Duration
	// Now — часы для задержек в событии; по умолчанию time.Now.
	Now func() time.Time
	// Hasher — хеши аргументов и описаний функций для политики вызовов и
	// очереди подтверждений (задача 4.10); nil — вызовы с require_approval
	// отклоняются.
	Hasher aisecCrypto.Hasher
	// ToolRate — счётчики лимитов политики вызовов (общие с MCP-прокси);
	// nil — лимиты не считаются.
	ToolRate policy.RateCounter
}

// Заголовки шлюза (ТЗ, 5.1 и 4.3).
const (
	HeaderEventID  = "X-AISec-Event-Id"
	HeaderDecision = "X-AISec-Decision"
	HeaderUser     = "X-AISec-User"
)

// DefaultBodyReadTimeout — время на чтение тела запроса по умолчанию.
const DefaultBodyReadTimeout = 30 * time.Second

// ChatHandler разбирает запрос приложения, выбирает провайдера и модель и
// отдаёт ответ. И запрос, и ответ собираются заново из разобранной модели:
// провайдер и приложение получают только то, что видели проверки.
type ChatHandler struct {
	cfg    ChatConfig
	logger *slog.Logger
}

// NewChatHandler проверяет параметры.
func NewChatHandler(cfg ChatConfig) (*ChatHandler, error) {
	if cfg.Router == nil || cfg.MaxBodyBytes <= 0 {
		return nil, errors.New("chat: не заданы маршруты или предел размера тела")
	}
	if cfg.Events == nil || cfg.IDs == nil {
		return nil, errors.New("chat: не заданы события: запрос без события не обрабатывается")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.BodyReadTimeout <= 0 {
		cfg.BodyReadTimeout = DefaultBodyReadTimeout
	}
	return &ChatHandler{cfg: cfg, logger: cfg.Logger}, nil
}

// readLimited читает тело не больше limit байт и не дольше
// BodyReadTimeout: медленная передача тела не держит соединение и горутину
// (общий путь chat и MCP-прокси, ревью 4.r1, 4В6). Таймаут — net.Error с
// Timeout().
func (h *ChatHandler) readLimited(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(h.cfg.BodyReadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		h.logger.Warn("не удалось ограничить время чтения тела", "error", err)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	// После чтения тела срок снимается: дальше соединение нужно для ответа,
	// в том числе долгого потокового.
	if derr := rc.SetReadDeadline(time.Time{}); derr != nil && !errors.Is(derr, http.ErrNotSupported) {
		h.logger.Warn("не удалось снять срок чтения", "error", derr)
	}
	return body, err
}

// readBody читает тело с пределом размера и времени. При ошибке ответ уже
// записан.
func (h *ChatHandler) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		WriteError(w, http.StatusUnsupportedMediaType, "ожидается Content-Type: application/json", "invalid_request_error", "unsupported_media_type")
		return nil, false
	}
	body, err := h.readLimited(w, r, h.cfg.MaxBodyBytes)
	if err != nil {
		var tooLarge *http.MaxBytesError
		var ne net.Error
		switch {
		case errors.As(err, &tooLarge):
			WriteError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("тело запроса больше %d байт", h.cfg.MaxBodyBytes), "invalid_request_error", "request_too_large")
		case errors.As(err, &ne) && ne.Timeout():
			WriteError(w, http.StatusRequestTimeout, "тело запроса передавалось слишком долго", "invalid_request_error", "request_timeout")
		default:
			WriteError(w, http.StatusBadRequest, "не удалось прочитать тело запроса", "invalid_request_error", "invalid_request")
		}
		return nil, false
	}
	if !isJSONObject(body) {
		WriteError(w, http.StatusBadRequest, "тело запроса — не объект JSON", "invalid_request_error", "invalid_request")
		return nil, false
	}
	return body, true
}

func isJSONObject(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && b[0] == '{' && json.Valid(b)
}

// ServeHTTP обрабатывает POST /v1/chat/completions по шагам ТЗ, 4.3:
// пользователь, модель, квоты, входные детекторы и решение, провайдер.
// Событие gateway_request создаётся для каждого запроса, прошедшего разбор
// и проверку X-AISec-User; ошибки разбора событий не создают.
func (h *ChatHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.cfg.Now()
	app, ok := h.cfg.Router.app(r)
	if !ok {
		h.cfg.Router.noApp(w, r)
		return
	}
	body, ok := h.readBody(w, r)
	if !ok {
		return
	}
	req, err := chat.Parse(body, app.Limits)
	if err != nil {
		var ce *chat.Error
		if !errors.As(err, &ce) {
			ce = &chat.Error{Code: chat.CodeInvalid, Message: "неверный запрос"}
		}
		WriteError(w, http.StatusBadRequest, ce.Message, "invalid_request_error", ce.Code)
		return
	}
	eu, ok := h.user(w, r, app, req.User)
	if !ok {
		return
	}
	user := eu.ID
	agent, ok := h.agent(w, r, app)
	if !ok {
		return
	}
	sess, ok := h.session(w, r, app, req, user)
	if !ok {
		return
	}
	rec, ok := h.newRecord(w, app, req, user, start)
	if !ok {
		return
	}
	defer h.emit(rec)
	rec.agent, rec.tools = agent, req.Tools
	if sess != nil {
		rec.sess = sess
		rec.ev.Session = sess.ev
	}
	requested := req.Model
	model, ok := app.Resolve(requested)
	if !ok {
		// Неразрешённая модель (DM-33): список разрешённых — в GET /v1/models.
		rec.reject(ruleModel, "DM-33")
		w.Header().Set(HeaderDecision, string(policy.Block))
		WriteError(w, http.StatusNotFound, "модель недоступна для приложения", "invalid_request_error", "model_not_found")
		return
	}
	if !app.modelAllowed(requested, model, eu) {
		rec.ev.Model = model
		denyModelGroup(w, rec)
		return
	}
	req.Model = model
	rec.ev.Model = model
	texts, refs := requestTexts(req)
	if !h.admit(w, r, rec, req, user, texts) {
		return
	}
	// Словарь псевдонимов живёт только в памяти на время запроса (ТЗ, 5.1).
	// Псевдонимы, которые уже есть в тексте запроса, не выдаются.
	plain := make([]string, 0, len(texts))
	for _, t := range texts {
		if t.Parts == nil {
			plain = append(plain, t.Text)
		}
	}
	rec.vault = pseudonym.NewVault(pseudonym.Limits{}, plain...)
	defer rec.vault.Clear()
	rec.jsonMode = jsonResponseFormat(req.ResponseFormat)
	checkStart := h.cfg.Now()
	in, err := app.inspect(r.Context(), inspectRequest{
		Endpoint: policy.EndpointChat, External: app.Provider.External(), Texts: texts, Media: policyMedia(req.Media()), User: user,
		Mask: app.Storage == events.StorageMasked, Timeout: h.cfg.DetectorTimeout, Vault: rec.vault,
		Extra: app.promptFinding(req), Session: sess,
	})
	rec.ev.LatencyMS["input_check"] = h.cfg.Now().Sub(checkStart).Milliseconds()
	switch {
	case err != nil && r.Context().Err() != nil:
		// Клиент ушёл до решения: отвечать некому, решения нет.
		rec.skip = true
		h.logger.Info("клиент прервал запрос во время проверки", "path", r.URL.Path)
		return
	case err != nil:
		// Ошибка сборки конвейера (детектор политики не найден) или защиты
		// данных — запрос не проверен и не уходит, независимо от fail_mode.
		h.logger.Error("проверка запроса не выполнена", "app", app.ID, "event_id", rec.ev.ID, "error", err)
		rec.failClosed()
		w.Header().Set(HeaderDecision, string(policy.Block))
		WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
		return
	}
	rec.in, rec.texts = in, texts
	if len(in.Failures) > 0 {
		h.logger.Warn("сбой детекторов при проверке запроса", "app", app.ID, "event_id", rec.ev.ID,
			"failures", len(in.Failures), "fail_open", app.FailOpen)
	}
	w.Header().Set(HeaderDecision, in.headerDecision())
	switch {
	case in.FailBlock:
		WriteError(w, http.StatusServiceUnavailable, "запрос не удалось проверить, повторите позже", "service_unavailable", "check_unavailable")
		return
	case in.Decision.Block:
		// Какие детекторы сработали, приложению не сообщается (ТЗ, 5.1).
		WriteError(w, http.StatusBadRequest, in.Decision.Message, "invalid_request_error", "policy_violation")
		return
	}
	for i, changed := range in.Changed {
		if !changed {
			continue
		}
		if err := refs[i].set(req, in.Texts[i]); err != nil {
			// Не удалось применить маскирование — запрос не уходит.
			h.logger.Error("маскирование не применено", "app", app.ID, "event_id", rec.ev.ID, "error", err)
			rec.failClosed()
			w.Header().Set(HeaderDecision, string(policy.Block))
			WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
			return
		}
	}
	if app.Provider.External() {
		// Идентификатор пользователя (часто e-mail или ФИО) внешнему
		// провайдеру не передаётся (ТЗ, 5.4).
		req.User = ""
	}
	rec.sent = true
	providerStart := h.cfg.Now()
	defer func() { rec.ev.LatencyMS["provider"] = h.cfg.Now().Sub(providerStart).Milliseconds() }()
	if req.Stream {
		h.stream(w, r, app, req, requested, rec)
		return
	}
	pctx, sent := withSendTrace(r.Context())
	resp, meta, err := app.Provider.Chat(pctx, req)
	copyMeta(w, meta)
	if err != nil {
		rec.unknown = outcomeUnknown(r, err, sent)
		h.providerError(w, r, err)
		return
	}
	rec.usage(resp.Usage)
	outBytes := responseBytes(resp)
	rec.outBytes = func() int { return outBytes }
	// Приложение видит то имя модели, которое запросило (в том числе
	// псевдоним), а не имя у провайдера (DM-33).
	resp.Model = requested
	if !h.checkFull(w, r, app, rec, resp) {
		return
	}
	rec.issue(resp)
	writeJSON(w, http.StatusOK, resp)
}

// session — сессия запроса чата (задача 4.13): X-AISec-Session или
// отпечаток начала диалога; для history.integrity — хеши реплик
// ассистента из истории, если в политике приложения есть его правило.
// Неверный заголовок — 400 без эха значения. При ошибке ответ уже записан.
func (h *ChatHandler) session(w http.ResponseWriter, r *http.Request, app *App, req *chat.Request, user string) (*reqSession, bool) {
	vals := r.Header.Values(HeaderSession)
	if h.cfg.Sessions == nil {
		if _, err := parseSessionHeader(vals); err != nil {
			WriteError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_session")
			return nil, false
		}
		return nil, true
	}
	s, err := h.cfg.Sessions.identify(app.ID, user, vals, req)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error(), "invalid_request_error", "invalid_session")
		return nil, false
	}
	if rule, action, sev, ok := app.Policy.RuleFor(session.HistoryID, detect.Input); ok {
		s.ev.History, s.ev.HistoryRule, s.ev.HistoryAction, s.ev.HistorySeverity = h.cfg.Sessions.history(req), rule, string(action), string(sev)
	}
	return s, true
}

// user — конечный пользователь (ТЗ, 4.3, шаг 2; 5.5): из проверенного JWT
// (usertoken.go) или по user_from; псевдоним — HMAC идентификатора на
// ключе установки. Исходный идентификатор нигде не сохраняется. При ошибке
// ответ уже записан.
func (h *ChatHandler) user(w http.ResponseWriter, r *http.Request, app *App, reqUser string) (endUser, bool) {
	if u, handled, ok := h.userFromToken(w, r, app); handled || !ok {
		return u, ok
	}
	id, ok := h.userID(w, r, app, reqUser)
	return endUser{ID: id}, ok
}

// userID — псевдоним пользователя по user_from (X-AISec-User или поле
// user). При ошибке ответ уже записан.
func (h *ChatHandler) userID(w http.ResponseWriter, r *http.Request, app *App, reqUser string) (string, bool) {
	var id string
	switch app.UserFrom {
	case userFromHeader:
		vals := r.Header.Values(HeaderUser)
		if len(vals) > 1 {
			WriteError(w, http.StatusBadRequest, "заголовок X-AISec-User указан несколько раз", "invalid_request_error", "invalid_user")
			return "", false
		}
		if len(vals) == 1 {
			id = vals[0]
			if len(id) > maxUserIDLength || !utf8.ValidString(id) || strings.ContainsFunc(id, unicode.IsControl) {
				WriteError(w, http.StatusBadRequest, fmt.Sprintf("X-AISec-User — до %d байт без управляющих символов", maxUserIDLength),
					"invalid_request_error", "invalid_user")
				return "", false
			}
		}
	case userFromField:
		id = reqUser // длину и состав проверил разбор запроса
	}
	if id == "" || h.cfg.UserMAC == nil {
		return "", true
	}
	return hex.EncodeToString(h.cfg.UserMAC.Sum([]byte(id))[:16]), true
}

// admit проверяет квоты (ТЗ, 4.3, шаг 3). При отказе ответ уже записан.
func (h *ChatHandler) admit(w http.ResponseWriter, r *http.Request, rec *record, req *chat.Request, user string, texts []inspectText) bool {
	// Размер входа — проверяемый текст (без склеек, они повторяют части) и
	// схемы инструментов: они тоже уходят модели.
	size := 0
	for _, t := range texts {
		if t.Parts == nil {
			size += len(t.Text)
		}
	}
	for _, tl := range req.Tools {
		size += len(tl.Function.Parameters)
	}
	maxOut, _ := req.EffectiveMaxTokens()
	rec.inTokens = estimateTokens(size)
	rec.maxOut = max(maxOut, 0)
	return h.admitSize(w, r, rec, user, size, estimateTokens(size)+max(maxOut, 0))
}

// admitSize проверяет квоты по размеру входа и оценке токенов; общая часть
// chat/completions, embeddings и Check API. При отказе ответ уже записан.
func (h *ChatHandler) admitSize(w http.ResponseWriter, r *http.Request, rec *record, user string, size, tokens int) bool {
	// Жёсткий бюджет — до квот: отказ не тратит квоту. Check API модели
	// не вызывает и бюджет не тратит.
	if b := h.cfg.Budget; b != nil && rec.ev.Type == events.TypeGatewayRequest {
		if out, wait := b.Exhausted(rec.app.ID); out {
			rec.reject(ruleBudget, "DM-15")
			w.Header().Set(HeaderDecision, string(policy.Block))
			w.Header().Set("Retry-After", strconv.FormatInt(int64((wait+time.Second-1)/time.Second), 10))
			WriteError(w, http.StatusTooManyRequests, "исчерпан месячный бюджет приложения", "rate_limit_error", "budget_exceeded")
			return false
		}
	}
	if h.cfg.Quotas == nil {
		return true
	}
	qr := QuotaRequest{App: rec.app.ID, User: user, InputBytes: size, Tokens: tokens}
	if id, ok := IdentityFrom(r.Context()); ok {
		qr.Key = id.KeyPrefix
	}
	res, err := h.cfg.Quotas.Admit(qr)
	var ex *Exceeded
	switch {
	case err == nil:
		rec.res = res
		return true
	case errors.As(err, &ex):
		rec.reject(ruleQuotaPrefix+ex.Rule, ex.Threat)
		w.Header().Set(HeaderDecision, string(policy.Block))
		if ex.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((ex.RetryAfter+time.Second-1)/time.Second), 10))
		}
		WriteError(w, http.StatusTooManyRequests, "превышена квота приложения", "rate_limit_error", "quota_exceeded")
	default:
		// Приложения нет в квотах — ошибка сборки шлюза; не пропускаем.
		h.logger.Error("квоты не проверены", "app", rec.app.ID, "error", err)
		rec.failClosed()
		w.Header().Set(HeaderDecision, string(policy.Block))
		WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
	}
	return false
}

// estimateTokens — оценка токенов входа сверху для резерва квоты: около
// трёх байт на токен (русский текст в UTF-8 даёт больше байт на токен).
// После ответа резерв заменяется расходом из usage.
func estimateTokens(inputBytes int) int { return (inputBytes + 2) / 3 }

// textRef — куда вернуть замаскированный фрагмент: фрагмент сообщения или
// описание инструмента; у склейки частей — никуда (маскируются части).
type textRef struct {
	seg  *chat.Segment
	tool int
}

func (r textRef) set(req *chat.Request, text string) error {
	switch {
	case r.seg != nil:
		return req.SetText(*r.seg, text)
	case r.tool >= 0 && r.tool < len(req.Tools):
		req.Tools[r.tool].Function.Description = text
		return nil
	}
	return errors.New("фрагмент без места в запросе")
}

// requestTexts — текстовые фрагменты запроса для детекторов:
//   - фрагменты сообщений (chat.Segments); сообщения с ролью tool —
//     источник tool (ответы инструментов, DM-07), остальное — user:
//     системный промпт и история тоже приходят от приложения;
//   - склейки текстовых частей сообщения, если частей больше одной, — для
//     injection.* (разрезанная на части инъекция);
//   - описания инструментов tools[].function.description: модель читает их
//     как инструкции. Схемы JSON (parameters, response_format) не
//     проверяются.
func requestTexts(req *chat.Request) ([]inspectText, []textRef) {
	segs := req.Segments()
	var texts []inspectText
	var refs []textRef
	parts := map[int][]int{} // сообщение → номера фрагментов-частей content
	for i := range segs {
		s := &segs[i]
		src := detect.SourceUser
		if s.Role == "tool" {
			src = detect.SourceTool
		}
		// Текстовые части, части refusal и refusal сообщения — в том порядке,
		// в каком их склеивают адаптеры GigaChat и YandexGPT (textOf).
		if s.Kind == chat.SegContent || s.Kind == chat.SegRefusal {
			parts[s.Message] = append(parts[s.Message], len(texts))
		}
		texts = append(texts, inspectText{Text: s.Text, Source: src, Location: s.Location(), Message: s.Message})
		refs = append(refs, textRef{seg: s, tool: -1})
	}
	for m := range req.Messages {
		ps := parts[m]
		if len(ps) < 2 {
			continue
		}
		for _, sep := range []string{"", "\n"} {
			var b strings.Builder
			for j, p := range ps {
				if j > 0 {
					b.WriteString(sep)
				}
				b.WriteString(texts[p].Text)
			}
			texts = append(texts, inspectText{Text: b.String(), Source: texts[ps[0]].Source,
				Location: fmt.Sprintf("messages[%d].content", m), Parts: ps, Sep: sep, Message: m})
			refs = append(refs, textRef{tool: -1})
		}
	}
	for i, tl := range req.Tools {
		if tl.Function.Description == "" {
			continue
		}
		texts = append(texts, inspectText{Text: tl.Function.Description, Source: detect.SourceUser,
			Location: fmt.Sprintf("tools[%d].function.description", i), Message: -1})
		refs = append(refs, textRef{tool: i})
	}
	return texts, refs
}

// policyMedia — нетекстовые части для non_text. Ссылкой считается адрес
// изображения или видео, который загрузит провайдер; идентификатор файла у
// провайдера — нет.
func policyMedia(ms []chat.Media) []policy.MediaPart {
	out := make([]policy.MediaPart, 0, len(ms))
	for _, m := range ms {
		out = append(out, policy.MediaPart{Kind: m.Kind, URL: !m.Inline && (m.Kind == chat.MediaImage || m.Kind == chat.MediaVideo)})
	}
	return out
}

func copyMeta(w http.ResponseWriter, m providers.Meta) {
	for k, v := range m.Header {
		w.Header()[k] = v
	}
}

// sendTrace — запрос к провайдеру записан в соединение целиком (httptrace
// WroteRequest): только тогда модель могла его выполнить.
type sendTrace struct{ wrote atomic.Bool }

// withSendTrace — контекст вызова провайдера с учётом отправки.
func withSendTrace(ctx context.Context) (context.Context, *sendTrace) {
	st := &sendTrace{}
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(i httptrace.WroteRequestInfo) {
		if i.Err == nil {
			st.wrote.Store(true)
		}
	}}), st
}

// outcomeUnknown — исход запроса, ушедшего провайдеру, неизвестен: запрос
// записан в соединение, а затем клиент прервал запрос, истёк таймаут,
// оборвалась связь или ответ не разобран. Не ушедший запрос (отказ в
// соединении, DNS, TLS) и явный отказ провайдера (ответ со статусом, отказ
// в учётных данных) — исход известен, модель запрос не выполняла (3В22
// ревью 3.r3). Остаток: у GigaChat записанный запрос токена, на который
// сервер авторизации ответил не 200, считается ушедшим.
func outcomeUnknown(r *http.Request, err error, st *sendTrace) bool {
	if st == nil || !st.wrote.Load() {
		return false
	}
	var pe *providers.Error
	if r.Context().Err() != nil {
		return true
	}
	return !errors.As(err, &pe) && !errors.Is(err, providers.ErrAuth)
}

// providerError отвечает приложению по классу ошибки провайдера.
func (h *ChatHandler) providerError(w http.ResponseWriter, r *http.Request, err error) {
	var pe *providers.Error
	switch {
	case r.Context().Err() != nil:
		h.logger.Info("клиент прервал запрос", "path", r.URL.Path)
	case errors.As(err, &pe):
		WriteError(w, pe.Status, pe.Message, pe.Type, pe.Code)
	case errors.Is(err, providers.ErrAuth):
		WriteError(w, http.StatusBadGateway, "провайдер модели отклонил учётные данные шлюза", "upstream_error", "upstream_auth_error")
	case errors.Is(err, providers.ErrTimeout):
		WriteError(w, http.StatusGatewayTimeout, "провайдер модели не ответил вовремя", "upstream_error", "upstream_timeout")
	case errors.Is(err, providers.ErrBadResponse):
		WriteError(w, http.StatusBadGateway, "ответ провайдера модели не разобран", "upstream_error", "upstream_bad_response")
	default:
		WriteError(w, http.StatusBadGateway, "провайдер модели недоступен", "upstream_error", "upstream_unavailable")
	}
}

// stream передаёт потоковый ответ: каждая часть разбирается и собирается
// заново, неизвестные поля провайдера приложению не уходят. Ответ
// проверяется в режиме streamResponseMode (response.go).
func (h *ChatHandler) stream(w http.ResponseWriter, r *http.Request, app *App, req *chat.Request, requested string, rec *record) {
	pctx, sent := withSendTrace(r.Context())
	st, meta, err := app.Provider.Stream(pctx, req)
	copyMeta(w, meta)
	if err != nil {
		rec.unknown = outcomeUnknown(r, err, sent)
		h.providerError(w, r, err)
		return
	}
	defer func() {
		if cerr := st.Close(); cerr != nil {
			h.logger.Debug("закрытие потока провайдера", "error", providers.ErrorClass(cerr))
		}
	}()
	mode := streamResponseMode(app)
	if mode == policy.ResponseBuffered {
		h.streamBuffered(w, r, app, st, requested, rec)
		return
	}
	rec.respMode = string(mode)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	send := func(data []byte) bool {
		if err := sse.Write(w, sse.Event{Data: string(data)}); err != nil {
			return false // клиент ушёл
		}
		return rc.Flush() == nil
	}
	sp := h.newStreamProc(r, app, rec, requested, mode == policy.ResponseIncremental, send)
	if hd, ok := st.(providers.Holder); ok {
		sp.hold = hd.Hold
	}
	sp.comment = func(text string) bool {
		if err := sse.WriteComment(w, text); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	defer func() {
		rec.respMasked = sp.content.masked || sp.refusal.masked
		rec.respFailures = sp.failures
		sp.issue()
		sp.afterStream()
	}()
	for {
		c, err := st.Next()
		if errors.Is(err, io.EOF) {
			sp.end()
			return
		}
		if err != nil {
			// Ошибка внутри потока — событием с объектом error, как у OpenAI;
			// завершающего [DONE] нет: приложение видит, что ответ неполный.
			sp.upstreamFailed(err)
			return
		}
		if sp.chunk(c) != streamGo {
			return
		}
	}
}

func errorKind(err error) string {
	var pe *providers.Error
	if errors.As(err, &pe) {
		return fmt.Sprintf("ошибка провайдера %d", pe.Status)
	}
	return providers.ErrorClass(err)
}

func streamErrorBody(err error) []byte {
	msg, code := "поток провайдера модели прерван", "upstream_stream_error"
	var pe *providers.Error
	if errors.As(err, &pe) {
		msg, code = pe.Message, pe.Code
	}
	b, merr := json.Marshal(map[string]any{"error": map[string]any{"message": msg, "type": "upstream_error", "code": code}})
	if merr != nil {
		return []byte(`{"error":{"message":"поток прерван","type":"upstream_error","code":"upstream_stream_error"}}`)
	}
	return b
}
