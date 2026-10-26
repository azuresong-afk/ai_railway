package api

import (
	"errors"
	"net/http"
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

// Отметки аналитиков и черновик исключения (ТЗ 5.5, 5.3; задача 3.22
// этапа 3). Отметка «ложное срабатывание» возвращает черновик исключения
// по событию: детектор, категория, шаблон детектора, хеш фрагмента и
// приложение — без содержимого запроса. Создаёт исключение по черновику
// только администратор безопасности (POST /policies/{id}/exceptions).

// maxDraftItems — условий в черновике: по одному на находку решения.
const maxDraftItems = 16

// markMaxBody — тело отметки: комментарий 1000 символов в худшей записи
// JSON (\uXXXX) — до 6 КиБ.
const markMaxBody = 8 << 10

func eventMarkRoutes(d Deps) []Route {
	need := func(h http.HandlerFunc) http.HandlerFunc { return needEvents(d, h) }
	return []Route{
		// Снятие отметки — PUT с mark = none: DELETE /events/{id}/mark
		// пересекался бы с DELETE /events/filters/{id} в ServeMux.
		{Method: http.MethodPut, Path: "/api/v1/events/{id}/mark", Permission: auth.PermEventsMark,
			MaxBody: markMaxBody, Handler: need(d.putEventMark)},
		{Method: http.MethodGet, Path: "/api/v1/events/{id}/exception-draft", Permission: auth.PermEventsRead,
			Handler: need(d.eventExceptionDraft)},
	}
}

type markRequest struct {
	Mark    string `json:"mark"`
	Comment string `json:"comment"`
}

// MarkResult — отметка события и, для «ложного срабатывания», черновик
// исключения.
type MarkResult struct {
	EventID string              `json:"event_id"`
	Mark    events.Mark         `json:"mark"`
	Draft   *ExceptionDraftView `json:"draft,omitempty"`
}

// ExceptionDraftView — черновик исключения по событию. BaseVersion —
// текущая версия политики, поверх которой создаётся исключение; Template —
// политика события — шаблон: исключение добавляется в копию шаблона.
type ExceptionDraftView struct {
	EventID       string                    `json:"event_id"`
	Policy        string                    `json:"policy,omitempty"`
	PolicyVersion int                       `json:"policy_version,omitempty"`
	BaseVersion   int                       `json:"base_version,omitempty"`
	Template      bool                      `json:"template"`
	Items         []versions.ExceptionInput `json:"items"`
}

func (d Deps) putEventMark(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	id, ok := pathEventID(w, r)
	if !ok {
		return
	}
	var req markRequest
	if prob := DecodeJSON(w, r, &req, markMaxBody); prob != nil {
		WriteProblem(w, prob)
		return
	}
	if req.Mark == events.MarkNone && req.Comment == "" {
		d.deleteEventMark(w, r, p, id)
		return
	}
	mark, comment, err := events.CleanMark(req.Mark, req.Comment)
	if err != nil {
		WriteProblem(w, Invalid("Проверьте отметку.", FieldError{"mark", "false_positive, confirmed или none (снять отметку)."},
			FieldError{"comment", "До 1000 символов без управляющих символов."}))
		return
	}
	ctx, cancel := contextTimeout(r, eventsReadTimeout)
	defer cancel()
	if _, err := d.Events.SetMark(ctx, id, events.Mark{Mark: mark, Comment: comment}, eventsActor(p), clientAddr(r)); err != nil {
		if errors.Is(err, events.ErrNotFound) {
			WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Событие не найдено."))
			return
		}
		WriteProblem(w, d.eventsProblem(err, "отметка события не сохранена"))
		return
	}
	// Отметка уже сохранена и записана в аудит: сбой чтения карточки или
	// черновика не превращает ответ в ошибку (повтор дал бы лишнюю запись) —
	// черновик доступен отдельно, GET /events/{id}/exception-draft.
	res := MarkResult{EventID: id, Mark: events.Mark{Mark: mark, Comment: comment}}
	rec, err := d.Events.Card(ctx, id)
	if err != nil {
		d.Logger.Warn("отметка сохранена, карточка события не прочитана", "event_id", id, "error", err)
		WriteJSON(w, http.StatusOK, res)
		return
	}
	if rec.Mark != nil {
		res.Mark = *rec.Mark
	}
	if mark == events.MarkFalsePositive {
		draft, err := d.exceptionDraft(r, &rec)
		if err != nil {
			d.Logger.Warn("отметка сохранена, черновик исключения не собран", "event_id", id, "error", err)
		} else {
			res.Draft = &draft
		}
	}
	WriteJSON(w, http.StatusOK, res)
}

// deleteEventMark снимает отметку (mark = none): 204, запись events.mark_removed.
func (d Deps) deleteEventMark(w http.ResponseWriter, r *http.Request, p Principal, id string) {
	ctx, cancel := contextTimeout(r, eventsReadTimeout)
	defer cancel()
	switch err := d.Events.DeleteMark(ctx, id, eventsActor(p), clientAddr(r)); {
	case errors.Is(err, events.ErrNotFound):
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Событие не найдено."))
	case errors.Is(err, events.ErrNoMark):
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "У события нет отметки."))
	case err != nil:
		WriteProblem(w, d.eventsProblem(err, "отметка события не снята"))
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (d Deps) eventExceptionDraft(w http.ResponseWriter, r *http.Request) {
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
	draft, err := d.exceptionDraft(r, &rec)
	if err != nil {
		WriteProblem(w, policiesProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, draft)
}

// exceptionDraft — условия исключения по находкам события: находки
// детекторов, давших итоговое действие (по трассировке), или все находки,
// если итог — allow или log. Уже пропущенные по исключению находки не
// предлагаются. Приложение события входит в условие всегда: черновик не
// отключает детектор для других приложений.
func (d Deps) exceptionDraft(r *http.Request, rec *events.Record) (ExceptionDraftView, error) {
	out := ExceptionDraftView{EventID: rec.ID, Items: []versions.ExceptionInput{}}
	det := rec.Details
	if det == nil {
		return out, nil
	}
	if dec := det.Decision; dec != nil {
		out.Policy, out.PolicyVersion = dec.Policy, dec.PolicyVersion
	}
	if out.Policy != "" && d.Policies != nil {
		doc, err := d.Policies.Get(r.Context(), out.Policy, 0)
		switch {
		case errors.Is(err, versions.ErrNotFound):
		case err != nil:
			return ExceptionDraftView{}, err
		case doc.Template:
			out.Template = true
		default:
			out.BaseVersion = doc.Version.Version
		}
	}
	deciding := decidingDetectors(det.Decision)
	type key struct{ detector, category, pattern, fragment, source string }
	seen := map[key]bool{}
	for _, f := range det.Findings {
		if len(out.Items) >= maxDraftItems {
			break
		}
		if f.Exception != "" || deciding != nil && !slices.Contains(deciding, f.Detector) {
			continue
		}
		in := versions.ExceptionInput{Detector: f.Detector, Category: f.Category, Fragment: f.Fragment, App: rec.App,
			ExpiresInDays: draftTTLDays, EventID: rec.ID}
		if f.Rule != "" && policy.ValidPattern(f.Rule) {
			in.Pattern = f.Rule
		}
		// Источник — всегда, если известен: исключение для ложного
		// срабатывания в ответе модели не должно действовать на вход, RAG и
		// инструменты (3В24 ревью 3.r3, ТЗ 5.3).
		switch {
		case f.Source != "":
			in.Source = f.Source
		case rec.Type == events.TypeCheck && rec.Source != "":
			in.Source = rec.Source
		}
		k := key{in.Detector, in.Category, in.Pattern, in.Fragment, in.Source}
		if seen[k] {
			continue
		}
		seen[k] = true
		out.Items = append(out.Items, in)
	}
	return out, nil
}

// decidingDetectors — детекторы правил, давших итоговое действие решения;
// nil — итог allow или log (предлагаются все находки).
func decidingDetectors(dec *events.Decision) []string {
	if dec == nil || dec.Action == "" || !policy.Stronger(policy.Action(dec.Action), policy.Log) {
		return nil
	}
	var out []string
	for _, st := range dec.Trace {
		if st.Matched && st.Action == dec.Action && st.Detector != "" && !slices.Contains(out, st.Detector) {
			out = append(out, st.Detector)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
