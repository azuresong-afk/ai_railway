package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// События в консоли (ТЗ 5.5, 7.3 УПД.7; задача 2.16): список и карточка
// без содержимого, содержимое — по отдельному разрешению с причиной,
// выгрузка CSV/JSON с записью в аудит, сохранённые фильтры, сроки хранения,
// агрегаты для дашбордов. Содержимое не попадает ни в списки, ни в
// выгрузку, ни в технический журнал.

// EventsAPI — хранилище событий для консоли (events.PGStore, events.Memory).
type EventsAPI interface {
	events.Reader
	events.RetentionStore
	events.FilterStore
	events.StatsReader
	events.MarkStore
}

// AuditRecorder — запись действий консоли в журнал аудита (*audit.Log).
type AuditRecorder interface {
	Record(ctx context.Context, e audit.Entry) error
}

// Пределы эндпоинтов событий.
const (
	// DefaultEventsRange — период по умолчанию, если from не задан.
	DefaultEventsRange = 24 * time.Hour
	// MinContentReason и MaxContentReason — длина причины доступа к
	// содержимому в символах (УПД.7).
	MinContentReason = 3
	MaxContentReason = 500
	// eventsQueryMax — предел строки запроса списка: фильтр и параметры.
	eventsQueryMax      = events.MaxFilterLen*3 + 1024
	eventsReadTimeout   = 10 * time.Second
	eventsSmallBody     = 4 << 10
	eventsExportBodyMax = events.MaxFilterLen + 1024
)

func eventsConsoleRoutes(d Deps) []Route {
	need := func(h http.HandlerFunc) http.HandlerFunc { return needEvents(d, h) }
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/events", Permission: auth.PermEventsRead, Handler: need(d.listEvents)},
		{Method: http.MethodGet, Path: "/api/v1/events/{id}", Permission: auth.PermEventsRead, Handler: need(d.getEvent)},
		{Method: http.MethodPost, Path: "/api/v1/events/{id}/content", Permission: auth.PermEventsContentRead,
			MaxBody: eventsSmallBody, Handler: need(d.eventContent)},
		{Method: http.MethodPost, Path: "/api/v1/events/export", Permission: auth.PermEventsExport,
			MaxBody: eventsExportBodyMax, Handler: need(d.exportEvents)},
		{Method: http.MethodGet, Path: "/api/v1/events/stats", Permission: auth.PermEventsRead, Handler: need(d.eventStats)},
		{Method: http.MethodGet, Path: "/api/v1/events/filters", Permission: auth.PermEventsRead, Handler: need(d.listEventFilters)},
		{Method: http.MethodPost, Path: "/api/v1/events/filters", Permission: auth.PermEventsRead,
			MaxBody: eventsExportBodyMax, Handler: need(d.saveEventFilter)},
		{Method: http.MethodDelete, Path: "/api/v1/events/filters/{id}", Permission: auth.PermEventsRead, Handler: need(d.deleteEventFilter)},
		{Method: http.MethodGet, Path: "/api/v1/events/settings", Permission: auth.PermEventsRead, Handler: need(d.getEventSettings)},
		{Method: http.MethodPut, Path: "/api/v1/events/settings", Permission: auth.PermEventsRetentionManage,
			MaxBody: eventsSmallBody, Handler: need(d.putEventSettings)},
	}
}

func needEvents(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Events == nil || d.Audit == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Хранилище событий не подключено к серверу."))
			return
		}
		h(w, r)
	}
}

// eventsActor — субъект запроса для журнала аудита.
func eventsActor(p Principal) audit.Actor {
	if c := p.Caller; c != nil {
		// Запрос по токену API пишется от имени токена, как в internal/auth.
		if t := c.Token; t != nil {
			return audit.Actor{Type: audit.ActorAPIToken, ID: t.ID, Name: c.User.Login + " (" + t.Prefix + ")"}
		}
		return audit.Actor{Type: audit.ActorUser, ID: c.User.ID, Name: c.User.Login}
	}
	return audit.Actor{Type: audit.ActorAPIToken, ID: p.ID}
}

// eventsProblem — ответ на ошибку хранилища; текст ошибки — только в журнал.
func (d Deps) eventsProblem(err error, what string) *Problem {
	switch {
	case errors.Is(err, events.ErrBadRange):
		return Invalid(fmt.Sprintf("Период задан неверно: from раньше to, не длиннее %d суток.", int(events.MaxQueryRange.Hours()/24)))
	case errors.Is(err, events.ErrTooManyRows):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, "Слишком много строк: сузьте период или фильтр.")
	case errors.Is(err, context.DeadlineExceeded):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Запрос выполнялся слишком долго: сузьте период или фильтр.")
	}
	d.Logger.Error(what, "error", err)
	return errInternal()
}

// filterProblem — ошибка разбора фильтра с позицией.
func filterProblem(field string, err error) *Problem {
	var fe *events.FilterError
	msg := "Фильтр длиннее " + strconv.Itoa(events.MaxFilterLen) + " байт."
	if errors.As(err, &fe) {
		msg = fmt.Sprintf("Позиция %d: %s.", fe.Pos, fe.Msg)
	}
	return Invalid("Фильтр задан неверно.", FieldError{field, msg})
}

// eventsListParams — разобранные параметры GET /api/v1/events.
type eventsListParams struct {
	query events.Query
	page  Page
}

// parseRange разбирает from и to (RFC 3339): по умолчанию to — сейчас,
// from — to минус def.
func parseRange(q url.Values, now time.Time, def time.Duration) (from, to time.Time, bad []FieldError) {
	to, from = now, time.Time{}
	parse := func(name string, dst *time.Time) {
		vs, ok := q[name]
		if !ok {
			return
		}
		t, err := time.Parse(time.RFC3339Nano, first(vs))
		if len(vs) != 1 || err != nil {
			bad = append(bad, FieldError{name, "Укажите время в формате RFC 3339, например 2026-10-21T15:00:00Z."})
			return
		}
		*dst = t.UTC()
	}
	parse("from", &from)
	parse("to", &to)
	if from.IsZero() {
		from = to.Add(-def)
	}
	return from, to, bad
}

// parseEventsList разбирает параметры списка: from, to, filter, limit, cursor.
func parseEventsList(r *http.Request, now time.Time) (eventsListParams, *Problem) {
	if len(r.URL.RawQuery) > eventsQueryMax {
		return eventsListParams{}, Invalid("Строка запроса слишком длинная.")
	}
	q := r.URL.Query()
	for k := range q {
		switch k {
		case "from", "to", "filter", "limit", "cursor":
		default:
			return eventsListParams{}, Invalid("Неизвестный параметр запроса.", FieldError{k, "Допустимы from, to, filter, limit, cursor."})
		}
	}
	page, p := ParsePage(r)
	if p != nil {
		return eventsListParams{}, p
	}
	from, to, bad := parseRange(q, now, DefaultEventsRange)
	if len(bad) > 0 {
		return eventsListParams{}, Invalid("Период задан неверно.", bad...)
	}
	out := eventsListParams{page: page, query: events.Query{From: from, To: to, Limit: page.Limit + 1}}
	if vs, ok := q["filter"]; ok {
		if len(vs) != 1 {
			return eventsListParams{}, Invalid("Фильтр задан неверно.", FieldError{"filter", "Укажите один параметр filter."})
		}
		f, err := events.ParseFilter(vs[0])
		if err != nil {
			return eventsListParams{}, filterProblem("filter", err)
		}
		out.query.Filter = f
	}
	if c := page.Cursor; c != nil {
		out.query.After = &events.Position{TS: time.UnixMicro(c.TimeMicro).UTC(), ID: c.ID}
	}
	if err := out.query.Validate(); err != nil {
		return eventsListParams{}, Invalid(fmt.Sprintf("Период задан неверно: from раньше to, не длиннее %d суток.",
			int(events.MaxQueryRange.Hours()/24)))
	}
	return out, nil
}

// recordOptional пишет необязательное событие просмотра (РСБ.1): сбой
// записи не мешает ответу, но попадает в технический журнал.
func (d Deps) recordOptional(r *http.Request, e audit.Entry) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := d.Audit.Record(ctx, e); err != nil {
		d.Logger.Error("просмотр событий не записан в журнал аудита", "action", e.Action, "error", err)
	}
}

func (d Deps) listEvents(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	lp, prob := parseEventsList(r, time.Now().UTC())
	if prob != nil {
		WriteProblem(w, prob)
		return
	}
	ctx, cancel := contextTimeout(r, eventsReadTimeout)
	defer cancel()
	list, err := d.Events.List(ctx, lp.query)
	if err != nil {
		WriteProblem(w, d.eventsProblem(err, "список событий не прочитан"))
		return
	}
	resp := PageResponse[events.View]{Items: make([]events.View, 0, min(len(list), lp.page.Limit))}
	for i := range list {
		if i == lp.page.Limit {
			last := list[i-1]
			resp.NextCursor = Cursor{TimeMicro: last.TS.UnixMicro(), ID: last.ID}.Encode()
			break
		}
		resp.Items = append(resp.Items, list[i].View())
	}
	d.recordOptional(r, audit.Entry{
		Actor: eventsActor(p), SourceIP: clientAddr(r), Action: "events.list", Object: audit.Object{Type: "events"},
		Result: audit.ResultSuccess, Details: map[string]any{
			"filter": lp.query.Filter.String(), "from": lp.query.From, "to": lp.query.To, "count": len(resp.Items),
		},
	})
	WriteJSON(w, http.StatusOK, resp)
}

// pathEventID — ID события из пути; неверный UUIDv7 — 404, как и отсутствующее.
func pathEventID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if _, err := events.PartitionTime(id); err != nil {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Событие не найдено."))
		return "", false
	}
	return id, true
}

func (d Deps) getEvent(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	id, ok := pathEventID(w, r)
	if !ok {
		return
	}
	ctx, cancel := contextTimeout(r, eventsReadTimeout)
	defer cancel()
	rec, err := d.Events.Card(ctx, id)
	if errors.Is(err, events.ErrNotFound) {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Событие не найдено."))
		return
	}
	if err != nil {
		WriteProblem(w, d.eventsProblem(err, "событие не прочитано"))
		return
	}
	d.recordOptional(r, audit.Entry{
		Actor: eventsActor(p), SourceIP: clientAddr(r), Action: "events.view",
		Object: audit.Object{Type: "event", ID: id}, Result: audit.ResultSuccess,
	})
	if !seesFragments(p) {
		rec.Details = rec.Details.WithoutFragments()
	}
	WriteJSON(w, http.StatusOK, rec.View())
}

// seesFragments — субъекту показываются хеши фрагментов находок: только с
// правом на содержимое событий или на изменение политик (исключения по
// фрагменту). Хеш — HMAC текста находки: остальным с events.read (аналитик,
// аудитор, токен API) он позволил бы проверять, встречалось ли значение в
// запросах приложения (3Н41 ревью 3.r3).
func seesFragments(p Principal) bool {
	return p.Grants.Full(auth.PermEventsContentRead) || p.Grants.Full(auth.PermPoliciesManage)
}

type contentRequest struct {
	Reason string `json:"reason"`
}

// ContentResponse — ответ на запрос содержимого события.
type ContentResponse struct {
	EventID  string `json:"event_id"`
	Storage  string `json:"storage"`
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
}

// cleanReason — причина доступа к содержимому: 3–500 символов без
// управляющих, пробелы по краям убираются.
func cleanReason(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return "", false
	}
	n := utf8.RuneCountInString(s)
	if n < MinContentReason || n > MaxContentReason {
		return "", false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
			return "", false
		}
	}
	return s, true
}

// eventContent — содержимое события по разрешению events.content.read с
// причиной (УПД.7). Каждое обращение — запись events.content_read до
// ответа; если запись не удалась, содержимое не выдаётся.
func (d Deps) eventContent(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	id, ok := pathEventID(w, r)
	if !ok {
		return
	}
	var req contentRequest
	if prob := DecodeJSON(w, r, &req, eventsSmallBody); prob != nil {
		WriteProblem(w, prob)
		return
	}
	reason, ok := cleanReason(req.Reason)
	if !ok {
		WriteProblem(w, Invalid("Укажите причину доступа к содержимому.", FieldError{"reason",
			fmt.Sprintf("От %d до %d символов, без управляющих символов.", MinContentReason, MaxContentReason)}))
		return
	}
	ctx, cancel := contextTimeout(r, eventsReadTimeout)
	defer cancel()
	if _, err := d.Events.Card(ctx, id); err != nil {
		if errors.Is(err, events.ErrNotFound) {
			WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Событие не найдено."))
			return
		}
		WriteProblem(w, d.eventsProblem(err, "событие не прочитано"))
		return
	}
	content, err := d.Events.Content(ctx, id)
	found := err == nil
	if err != nil && !errors.Is(err, events.ErrNotFound) {
		WriteProblem(w, d.eventsProblem(err, "содержимое события не прочитано"))
		return
	}
	entry := audit.Entry{
		Actor: eventsActor(p), SourceIP: clientAddr(r), Action: "events.content_read",
		Object: audit.Object{Type: "event", ID: id}, Result: audit.ResultSuccess,
		Details: map[string]any{"reason": reason, "storage": content.Storage},
	}
	if !found {
		entry.Result = audit.ResultFailure
		entry.Details = map[string]any{"reason": reason, "outcome": "no_content"}
	}
	actx, acancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer acancel()
	if err := d.Audit.Record(actx, entry); err != nil {
		d.Logger.Error("доступ к содержимому не записан в журнал аудита: содержимое не выдано", "event_id", id, "error", err)
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
			"Не удалось записать доступ в журнал аудита: содержимое не выдано. Повторите позже."))
		return
	}
	if !found {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound,
			"Содержимое этого события не сохранялось или удалено по сроку хранения."))
		return
	}
	WriteJSON(w, http.StatusOK, ContentResponse{
		EventID: id, Storage: content.Storage, Request: content.Content.Request, Response: content.Content.Response,
	})
}

type exportRequest struct {
	Format string `json:"format"`
	// Delimiter — разделитель CSV: semicolon (по умолчанию) или comma.
	Delimiter string     `json:"delimiter"`
	From      *time.Time `json:"from"`
	To        *time.Time `json:"to"`
	Filter    string     `json:"filter"`
}

// parseExport проверяет тело выгрузки.
func parseExport(req *exportRequest, now time.Time) (events.Query, rune, *Problem) {
	var bad []FieldError
	if req.Format != events.FormatCSV && req.Format != events.FormatJSON {
		bad = append(bad, FieldError{"format", "Укажите csv или json."})
	}
	delim, okd := events.ParseDelimiter(req.Delimiter)
	if !okd {
		bad = append(bad, FieldError{"delimiter", "Укажите semicolon (точка с запятой) или comma (запятая)."})
	}
	to := now
	if req.To != nil {
		to = req.To.UTC()
	}
	from := to.Add(-DefaultEventsRange)
	if req.From != nil {
		from = req.From.UTC()
	}
	f, err := events.ParseFilter(req.Filter)
	if err != nil {
		bad = append(bad, filterProblem("filter", err).Errors...)
	}
	if len(bad) > 0 {
		return events.Query{}, 0, Invalid("Параметры выгрузки заданы неверно.", bad...)
	}
	q := events.Query{From: from, To: to, Filter: f, ReceivedBefore: now, Limit: events.MaxExportRows, WithDetails: req.Format == events.FormatJSON}
	if err := q.Validate(); err != nil {
		return events.Query{}, 0, Invalid(fmt.Sprintf("Период задан неверно: from раньше to, не длиннее %d суток.",
			int(events.MaxQueryRange.Hours()/24)))
	}
	return q, delim, nil
}

// errExportAudit — запись data.export не удалась: выгрузка отменена.
var errExportAudit = errors.New("выгрузка событий не записана в журнал аудита")

// exportSubject — ключ субъекта для ограничения одновременных выгрузок.
func exportSubject(p Principal) string {
	a := eventsActor(p)
	return string(a.Type) + ":" + a.ID
}

// exportEvents — выгрузка без содержимого. Подсчёт строк и выборка — по
// одному снимку (Н21 ревью 2.r3a); между ними запись data.export с
// фильтром и числом строк, и только после неё — данные. Одновременных
// выгрузок — не больше MaxExportsPerSubject на субъект и MaxExportsTotal
// на сервер (В11 ревью 2.r3a).
func (d Deps) exportEvents(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var req exportRequest
	if prob := DecodeJSON(w, r, &req, eventsExportBodyMax); prob != nil {
		WriteProblem(w, prob)
		return
	}
	now := time.Now().UTC()
	q, delim, prob := parseExport(&req, now)
	if prob != nil {
		WriteProblem(w, prob)
		return
	}
	subject := exportSubject(p)
	if d.Exports != nil {
		if !d.Exports.Acquire(subject) {
			d.Logger.Warn("выгрузка событий отклонена: предел одновременных выгрузок", "actor_type", eventsActor(p).Type)
			w.Header().Set("Retry-After", exportRetryAfter)
			WriteProblem(w, NewProblem(http.StatusTooManyRequests, CodeRateLimited,
				"Выгрузка уже выполняется: дождитесь её окончания и повторите."))
			return
		}
		defer d.Exports.Release(subject)
	}
	ctx, cancel := contextTimeout(r, events.ExportTimeout)
	defer cancel()
	var ex *events.Exporter
	started := false // заголовок ответа отправлен
	start := func(n int) error {
		actx, acancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer acancel()
		if err := d.Audit.Record(actx, audit.Entry{
			Actor: eventsActor(p), SourceIP: clientAddr(r), Action: "data.export", Object: audit.Object{Type: "events"},
			Result: audit.ResultSuccess, Details: map[string]any{
				"format": req.Format, "delimiter": delimName(delim, req.Format), "filter": q.Filter.String(), "from": q.From, "to": q.To, "snapshot": now, "rows": n,
			},
		}); err != nil {
			return fmt.Errorf("%w: %w", errExportAudit, err)
		}
		ctype := "text/csv; charset=utf-8"
		if req.Format == events.FormatJSON {
			ctype = "application/json"
		}
		h := w.Header()
		h.Set("Content-Type", ctype)
		h.Set("Content-Disposition", `attachment; filename="events-`+now.Format("20060102T150405Z")+"."+req.Format+`"`)
		h.Set("X-Export-Rows", strconv.Itoa(n))
		started = true
		w.WriteHeader(http.StatusOK)
		var err error
		ex, err = events.NewExporter(w, req.Format, delim)
		return err
	}
	hide := !seesFragments(p)
	err := d.Events.Export(ctx, q, start, func(rec *events.Record) error {
		if hide {
			rec.Details = rec.Details.WithoutFragments()
		}
		return ex.Write(rec)
	})
	if err == nil {
		err = ex.Close()
	}
	switch {
	case err == nil:
		d.Logger.Info("выгрузка событий завершена", "format", req.Format, "rows", ex.Rows())
	case !started && errors.Is(err, events.ErrTooManyRows):
		WriteProblem(w, NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			fmt.Sprintf("В выгрузке больше %d строк: сузьте период или фильтр.", events.MaxExportRows)))
	case !started && errors.Is(err, errExportAudit):
		d.Logger.Error("выгрузка событий не записана в журнал аудита: выгрузка отменена", "error", err)
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
			"Не удалось записать выгрузку в журнал аудита: выгрузка отменена. Повторите позже."))
	case !started:
		WriteProblem(w, d.eventsProblem(err, "события для выгрузки не прочитаны"))
	default:
		// Заголовок уже отправлен: обрываем соединение, чтобы неполный файл
		// не выглядел законченным.
		rows := 0
		if ex != nil {
			rows = ex.Rows()
		}
		d.Logger.Error("выгрузка событий прервана", "rows", rows, "error", err)
		panic(http.ErrAbortHandler)
	}
}

// StatsResponse — ответ GET /api/v1/events/stats.
type StatsResponse struct {
	Interval string             `json:"interval"`
	From     time.Time          `json:"from"`
	To       time.Time          `json:"to"`
	Items    []events.Aggregate `json:"items"`
}

func (d Deps) eventStats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k, vs := range q {
		if len(vs) != 1 {
			WriteProblem(w, Invalid("Параметр указан несколько раз.", FieldError{k, "Укажите один раз."}))
			return
		}
		switch k {
		case "interval", "from", "to", "app":
		default:
			WriteProblem(w, Invalid("Неизвестный параметр запроса.", FieldError{k, "Допустимы interval, from, to, app."}))
			return
		}
	}
	sq := events.StatsQuery{Interval: events.IntervalHour, App: q.Get("app")}
	if v := q.Get("interval"); v != "" {
		sq.Interval = v
	}
	if sq.Interval != events.IntervalMinute && sq.Interval != events.IntervalHour {
		WriteProblem(w, Invalid("Интервал задан неверно.", FieldError{"interval", "Укажите minute или hour."}))
		return
	}
	var bad []FieldError
	sq.From, sq.To, bad = parseRange(q, time.Now().UTC(), DefaultEventsRange)
	if len(bad) > 0 {
		WriteProblem(w, Invalid("Период задан неверно.", bad...))
		return
	}
	if err := sq.Validate(); err != nil {
		WriteProblem(w, Invalid("Период или приложение заданы неверно: для minute — не длиннее суток, для hour — не длиннее 31 суток."))
		return
	}
	ctx, cancel := contextTimeout(r, eventsReadTimeout)
	defer cancel()
	items, err := d.Events.Aggregates(ctx, sq)
	if err != nil {
		WriteProblem(w, d.eventsProblem(err, "агрегаты событий не прочитаны"))
		return
	}
	WriteJSON(w, http.StatusOK, StatsResponse{Interval: sq.Interval, From: sq.From, To: sq.To, Items: items})
}

// filterOwner — пользователь, чьи сохранённые фильтры доступны запросу.
func filterOwner(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, NewProblem(http.StatusForbidden, CodeForbidden, "Сохранённые фильтры доступны только пользователям консоли."))
		return "", false
	}
	return c.User.ID, true
}

func (d Deps) listEventFilters(w http.ResponseWriter, r *http.Request) {
	uid, ok := filterOwner(w, r)
	if !ok {
		return
	}
	ctx, cancel := contextTimeout(r, eventsReadTimeout)
	defer cancel()
	list, err := d.Events.Filters(ctx, uid)
	if err != nil {
		WriteProblem(w, d.eventsProblem(err, "сохранённые фильтры не прочитаны"))
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": list})
}

type saveFilterRequest struct {
	Name   string `json:"name"`
	Filter string `json:"filter"`
}

func (d Deps) saveEventFilter(w http.ResponseWriter, r *http.Request) {
	uid, ok := filterOwner(w, r)
	if !ok {
		return
	}
	var req saveFilterRequest
	if prob := DecodeJSON(w, r, &req, eventsExportBodyMax); prob != nil {
		WriteProblem(w, prob)
		return
	}
	if !events.ValidFilterName(req.Name) {
		WriteProblem(w, Invalid("Имя фильтра задано неверно.", FieldError{"name",
			fmt.Sprintf("От 1 до %d символов, без управляющих символов и пробелов по краям.", events.MaxFilterNameRunes)}))
		return
	}
	f, err := events.ParseFilter(req.Filter)
	if err != nil {
		WriteProblem(w, filterProblem("filter", err))
		return
	}
	ctx, cancel := contextTimeout(r, eventsReadTimeout)
	defer cancel()
	sf, err := d.Events.SaveFilter(ctx, uid, req.Name, f)
	switch {
	case errors.Is(err, events.ErrFilterExists):
		WriteProblem(w, NewProblem(http.StatusConflict, CodeConflict, "Фильтр с таким именем уже сохранён."))
		return
	case errors.Is(err, events.ErrTooManyFilters):
		WriteProblem(w, NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			fmt.Sprintf("Сохранено %d фильтров — это предел. Удалите ненужные.", events.MaxSavedFilters)))
		return
	case err != nil:
		WriteProblem(w, d.eventsProblem(err, "фильтр не сохранён"))
		return
	}
	WriteJSON(w, http.StatusCreated, sf)
}

func (d Deps) deleteEventFilter(w http.ResponseWriter, r *http.Request) {
	uid, ok := filterOwner(w, r)
	if !ok {
		return
	}
	id, err := parseFilterID(r.PathValue("id"))
	if err != nil {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Сохранённый фильтр не найден."))
		return
	}
	ctx, cancel := contextTimeout(r, eventsReadTimeout)
	defer cancel()
	err = d.Events.DeleteFilter(ctx, uid, id)
	if errors.Is(err, events.ErrNotFound) {
		// Чужой фильтр неотличим от отсутствующего.
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Сохранённый фильтр не найден."))
		return
	}
	if err != nil {
		WriteProblem(w, d.eventsProblem(err, "фильтр не удалён"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseFilterID(s string) (string, error) {
	if _, err := events.PartitionTime(s); err != nil {
		return "", err
	}
	return s, nil
}

func (d Deps) getEventSettings(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextTimeout(r, eventsReadTimeout)
	defer cancel()
	ret, err := d.Events.Retention(ctx)
	if err != nil {
		WriteProblem(w, d.eventsProblem(err, "сроки хранения событий не прочитаны"))
		return
	}
	WriteJSON(w, http.StatusOK, ret)
}

type retentionRequest struct {
	MetadataDays int `json:"metadata_days"`
	ContentDays  int `json:"content_days"`
	// Password или Code — повторная проверка при сокращении срока (В13).
	Password string `json:"password"`
	Code     string `json:"code"`
}

// putEventSettings — сроки хранения (ТЗ 5.5): изменение и запись
// events.settings_changed одной транзакцией. Удаление данных — фоновым
// заданием секций по новым срокам. Сокращение любого срока необратимо
// удаляет данные, поэтому требует повторной проверки текущим паролем или
// кодом TOTP, как выпуск токена (В13 ревью 2.r3a, решение владельца);
// увеличение — без неё.
func (d Deps) putEventSettings(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var req retentionRequest
	if prob := DecodeJSON(w, r, &req, eventsSmallBody); prob != nil {
		WriteProblem(w, prob)
		return
	}
	ret := events.Retention{MetadataDays: req.MetadataDays, ContentDays: req.ContentDays}
	if err := ret.Validate(); err != nil {
		WriteProblem(w, Invalid("Сроки хранения заданы неверно.",
			FieldError{"metadata_days", fmt.Sprintf("От %d до %d суток.", events.MinMetadataDays, events.MaxRetentionDays)},
			FieldError{"content_days", fmt.Sprintf("От %d до %d суток и не больше срока метаданных.", events.MinContentDays, events.MaxRetentionDays)}))
		return
	}
	ctx, cancel := contextTimeout(r, eventsReadTimeout)
	defer cancel()
	cur, err := d.Events.Retention(ctx)
	if err != nil {
		WriteProblem(w, d.eventsProblem(err, "сроки хранения событий не прочитаны"))
		return
	}
	if ret.MetadataDays < cur.MetadataDays || ret.ContentDays < cur.ContentDays {
		// Повторная проверка возможна только в сессии консоли: у токена API нет
		// пароля, и права безопасности ему не выдаются (задача 2.10).
		c, ok := callerFrom(r)
		if !ok || c.Token != nil {
			WriteProblem(w, errForbidden())
			return
		}
		if d.Auth == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
				"Повторная проверка недоступна: вход в консоль не настроен на сервере."))
			return
		}
		if err := d.Auth.Reauthenticate(ctx, c, req.Password, req.Code, "events.settings_changed"); err != nil {
			WriteProblem(w, authProblem(d.Logger, err))
			return
		}
	}
	if _, err := d.Events.SetRetention(ctx, ret, eventsActor(p), clientAddr(r)); err != nil {
		WriteProblem(w, d.eventsProblem(err, "сроки хранения событий не изменены"))
		return
	}
	cur, err = d.Events.Retention(ctx)
	if err != nil {
		WriteProblem(w, d.eventsProblem(err, "сроки хранения событий не прочитаны"))
		return
	}
	WriteJSON(w, http.StatusOK, cur)
}
