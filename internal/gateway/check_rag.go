package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Пакетная проверка Check API для документов RAG до индексации — POST
// /guard/v1/check/batch (ТЗ 5.12, 5.16 DM-07 «RAG — 5»; задача 5.25 этапа
// 5, ADR-0029, п. 5). Индексатор заказчика присылает до MaxBatchDocuments
// текстов, которые он извлёк из документов коллекции; каждый текст
// проверяется конвейером, как Check API с source rag, и получает своё
// событие check и своё решение: allow — индексировать (текст после
// маскирования, если политика его изменила), exclude — не индексировать
// (политика заблокировала бы текст, например косвенную инъекцию DM-07, или
// текст не удалось проверить при fail_closed). Документы продукт не
// разбирает и не хранит.

// CheckBatchRoute — маршрут пакетной проверки.
const CheckBatchRoute = "POST /guard/v1/check/batch"

// Пределы пакета.
const (
	// MaxBatchDocuments — текстов в одном вызове.
	MaxBatchDocuments = 100
	// MinBatchBody — общий предел тела пакета, если предел тела запроса
	// шлюза меньше: каждый текст — до предела тела запроса (как в Check API).
	MinBatchBody = 8 << 20
	// maxBatchDocumentID — ID документа, байты (как в манифесте коллекции,
	// internal/rag).
	maxBatchDocumentID = 512
)

// Этапы и решения пакетной проверки.
const (
	StagePreIndex   = "pre_index"
	DecisionAllow   = "allow"
	DecisionExclude = "exclude"
	// ReasonPolicy — политика заблокировала бы текст; ReasonUnavailable —
	// текст не удалось проверить, а приложение настроено на fail_closed.
	ReasonPolicy      = "policy"
	ReasonUnavailable = "check_unavailable"
)

// CheckBatchHandler обслуживает CheckBatchRoute. Зависимости — те же, что у
// Check API.
type CheckBatchHandler struct{ h *ChatHandler }

// NewCheckBatchHandler проверяет параметры (те же, что у NewChatHandler).
func NewCheckBatchHandler(cfg ChatConfig) (*CheckBatchHandler, error) {
	h, err := NewChatHandler(cfg)
	if err != nil {
		return nil, err
	}
	return &CheckBatchHandler{h: h}, nil
}

// batchRequest — тело пакета.
type batchRequest struct {
	Source    string          `json:"source"`
	Stage     string          `json:"stage"`
	Documents []batchDocument `json:"documents"`
	User      string          `json:"user,omitempty"`
}

// batchDocument — текст документа и его ID у индексатора.
type batchDocument struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// batchResult — решение по документу.
type batchResult struct {
	ID       string `json:"id"`
	EventID  string `json:"event_id"`
	Decision string `json:"decision"`
	// Action — решение политики как в режиме enforce: в monitor документ
	// с инъекцией получает decision allow и action block.
	Action        string         `json:"action"`
	Reason        string         `json:"reason,omitempty"`
	Incomplete    bool           `json:"incomplete,omitempty"`
	MLUnavailable bool           `json:"ml_unavailable,omitempty"`
	Findings      []checkFinding `json:"findings"`
	Truncated     bool           `json:"findings_truncated,omitempty"`
	// Text — текст после маскирования, если политика его изменила
	// (индексировать нужно его); у exclude не возвращается.
	Text *string `json:"text,omitempty"`
}

// batchResponse — ответ пакета: решения в порядке документов запроса.
type batchResponse struct {
	Stage string `json:"stage"`
	// Unchecked — у политики нет правил для входа: ни один детектор не
	// запускался, allow не означает «проверено».
	Unchecked bool          `json:"unchecked,omitempty"`
	Excluded  int           `json:"excluded"`
	Results   []batchResult `json:"results"`
}

// validBatchID — ID документа: 1–512 байт UTF-8 без управляющих символов,
// символов форматирования Unicode и пробелов по краям (правила манифеста
// коллекции, internal/rag.CheckDocumentID).
func validBatchID(id string) bool {
	return id != "" && len(id) <= maxBatchDocumentID && utf8.ValidString(id) && id == strings.TrimSpace(id) &&
		!strings.ContainsFunc(id, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

// parseBatch разбирает тело пакета: source rag, stage pre_index, от 1 до
// MaxBatchDocuments документов с ID без повторов и непустым текстом UTF-8
// не длиннее maxText байт.
func parseBatch(body []byte, maxText int64) (*batchRequest, *errBatch) {
	var r batchRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, &errBatch{"invalid_request", "тело запроса — не объект пакетной проверки"}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, &errBatch{"invalid_request", "данные после объекта JSON"}
	}
	if r.Source != string(detect.SourceRAG) {
		return nil, &errBatch{"invalid_request", "source: пакетная проверка — только для rag"}
	}
	if r.Stage != StagePreIndex {
		return nil, &errBatch{"invalid_request", "stage: pre_index"}
	}
	if len(r.User) > maxUserIDLength {
		return nil, &errBatch{"invalid_request", fmt.Sprintf("user: не длиннее %d байт", maxUserIDLength)}
	}
	switch {
	case len(r.Documents) == 0:
		return nil, &errBatch{"invalid_request", "documents: от 1 документа"}
	case len(r.Documents) > MaxBatchDocuments:
		return nil, &errBatch{"too_many_documents", fmt.Sprintf("documents: не больше %d документов", MaxBatchDocuments)}
	}
	seen := make(map[string]struct{}, len(r.Documents))
	for i, d := range r.Documents {
		if !validBatchID(d.ID) {
			return nil, &errBatch{"invalid_request", fmt.Sprintf("documents[%d].id: от 1 до %d байт UTF-8 без управляющих символов "+
				"и символов форматирования, без пробелов в начале и в конце", i, maxBatchDocumentID)}
		}
		if _, dup := seen[d.ID]; dup {
			return nil, &errBatch{"invalid_request", fmt.Sprintf("documents[%d].id: повтор ID документа", i)}
		}
		seen[d.ID] = struct{}{}
		if d.Text == "" || !utf8.ValidString(d.Text) {
			return nil, &errBatch{"invalid_request", fmt.Sprintf("documents[%d].text: непустая строка UTF-8", i)}
		}
		if int64(len(d.Text)) > maxText {
			return nil, &errBatch{"document_too_large", fmt.Sprintf("documents[%d].text: больше %d байт", i, maxText)}
		}
	}
	return &r, nil
}

// errBatch — отказ в разборе пакета: код и текст для приложения (без
// значений из запроса).
type errBatch struct{ code, msg string }

// bodyLimit — общий предел тела пакета.
func (c *CheckBatchHandler) bodyLimit() int64 { return max(c.h.cfg.MaxBodyBytes, MinBatchBody) }

// readBody читает тело пакета с общим пределом размера и времени. При
// ошибке ответ уже записан.
func (c *CheckBatchHandler) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		WriteError(w, http.StatusUnsupportedMediaType, "ожидается Content-Type: application/json", "invalid_request_error", "unsupported_media_type")
		return nil, false
	}
	limit := c.bodyLimit()
	body, err := c.h.readLimited(w, r, limit)
	if err != nil {
		var tooLarge *http.MaxBytesError
		var ne net.Error
		switch {
		case errors.As(err, &tooLarge):
			WriteError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("тело пакета больше %d байт", limit),
				"invalid_request_error", "request_too_large")
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

// docRecord — событие check документа пакета. В отличие от
// newEventRecord заголовок X-AISec-Event-Id не ставится: ID событий — в
// теле ответа по каждому документу.
func (c *CheckBatchHandler) docRecord(app *App, user string, start time.Time) (*record, error) {
	u, err := c.h.cfg.IDs.New()
	if err != nil {
		return nil, err
	}
	return &record{start: start, app: app, tokens: -1, ev: events.Event{
		ID: u.String(), Time: start.UTC(), Type: events.TypeCheck, App: app.ID, Env: app.Env, User: user,
		Provider: app.Provider.ID(), PolicyMode: string(effectiveMode(app)), Storage: app.Storage,
		Source: string(detect.SourceRAG), LatencyMS: map[string]int64{},
	}}, nil
}

// ServeHTTP проверяет пакет документов. Отказ квоты — один на пакет (429,
// событие check с отказом); решения по документам — 200 с results.
func (c *CheckBatchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := c.h
	start := h.cfg.Now()
	app, ok := h.cfg.Router.app(r)
	if !ok {
		h.cfg.Router.noApp(w, r)
		return
	}
	body, ok := c.readBody(w, r)
	if !ok {
		return
	}
	req, perr := parseBatch(body, h.cfg.MaxBodyBytes)
	if perr != nil {
		status := http.StatusBadRequest
		if perr.code == "document_too_large" {
			status = http.StatusRequestEntityTooLarge
		}
		WriteError(w, status, perr.msg, "invalid_request_error", perr.code)
		return
	}
	eu, ok := h.user(w, r, app, req.User)
	if !ok {
		return
	}
	user := eu.ID
	size := 0
	for _, d := range req.Documents {
		size = max(size, len(d.Text))
	}
	// Квоты — на пакет целиком: частота — один запрос (индексатор шлёт
	// пакеты вместо сотен вызовов), предел размера входа — к каждому тексту,
	// как у Check API (сумма текстов пакета упиралась бы в предел одного
	// запроса). Событие отказа — одно, с source rag.
	brec, err := c.docRecord(app, user, start)
	if err != nil {
		h.logger.Error("идентификатор события", "error", err)
		WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
		return
	}
	if !h.admitSize(w, r, brec, user, size, 0) {
		h.emit(brec)
		return
	}
	defer brec.res.Settle(0)
	policyIDs := app.Policy.Detectors(detect.Input)
	resp := batchResponse{Stage: req.Stage, Unchecked: len(policyIDs) == 0, Results: make([]batchResult, 0, len(req.Documents))}
	for _, d := range req.Documents {
		rec, err := c.docRecord(app, user, h.cfg.Now())
		if err != nil {
			h.logger.Error("идентификатор события", "error", err)
			WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
			return
		}
		rec.res = brec.res // признак деградации квот — в событии документа; Settle повторно ничего не меняет
		texts := []inspectText{{Text: d.Text, Source: detect.SourceRAG, Location: "text"}}
		checkStart := h.cfg.Now()
		in, err := app.inspect(r.Context(), inspectRequest{
			Endpoint: policy.EndpointCheck, Direction: detect.Input, External: app.Provider.External(), Texts: texts, User: user,
			Mask: app.Storage == events.StorageMasked, Timeout: h.cfg.DetectorTimeout,
		})
		rec.ev.LatencyMS["input_check"] = h.cfg.Now().Sub(checkStart).Milliseconds()
		switch {
		case err != nil && r.Context().Err() != nil:
			// Клиент ушёл: проверенные документы уже записаны событиями.
			h.logger.Info("клиент прервал пакетную проверку", "path", r.URL.Path, "checked", len(resp.Results))
			return
		case err != nil:
			h.logger.Error("проверка документа не выполнена", "app", app.ID, "event_id", rec.ev.ID, "error", err)
			rec.failClosed()
			h.emit(rec)
			WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
			return
		}
		rec.in, rec.texts = in, texts
		if len(in.Failures) > 0 {
			h.logger.Warn("сбой детекторов при проверке документа", "app", app.ID, "event_id", rec.ev.ID,
				"failures", len(in.Failures), "fail_open", app.FailOpen)
		}
		res := batchResult{ID: d.ID, EventID: rec.ev.ID, Decision: DecisionAllow, Action: string(in.Decision.Action),
			Incomplete: len(in.Failures) > 0, MLUnavailable: in.MLUnavailable, Findings: []checkFinding{}}
		for _, f := range in.Findings {
			if !slices.Contains(policyIDs, f.Detector) {
				continue
			}
			if len(res.Findings) >= maxEventFindings {
				res.Truncated = true
				break
			}
			res.Findings = append(res.Findings, checkFinding{Detector: f.Detector, Category: f.Category, Score: f.Score,
				Start: f.Start, End: f.End, Location: texts[f.Text].Location, Threat: f.Threat})
		}
		switch {
		case in.FailBlock:
			res.Decision, res.Reason = DecisionExclude, ReasonUnavailable
		case in.Decision.Block:
			res.Decision, res.Reason = DecisionExclude, ReasonPolicy
		case len(in.Changed) > 0 && in.Changed[0]:
			t := in.Texts[0]
			res.Text = &t
		}
		if res.Decision == DecisionExclude {
			resp.Excluded++
		}
		h.emit(rec)
		resp.Results = append(resp.Results, res)
	}
	writeJSON(w, http.StatusOK, resp)
}
