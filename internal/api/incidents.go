package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/incidents"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// incidentRoutes — инциденты и инструкции реагирования (ТЗ 5.7; задача 3.16
// этапа 3). Разбор доступен токену (SOAR, IRP); выгрузка карточки —
// отдельное право и запись data.export; инструкции меняет только
// администратор безопасности.
func incidentRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/incidents", Permission: auth.PermIncidentsRead, Handler: needIncidents(d, d.listIncidents)},
		{Method: http.MethodPost, Path: "/api/v1/incidents", Permission: auth.PermIncidentsManage, Idempotent: true,
			MaxBody: incidents.MaxBody, Handler: needIncidents(d, d.createIncident)},
		{Method: http.MethodGet, Path: "/api/v1/incidents/{id}", Permission: auth.PermIncidentsRead, Handler: needIncidents(d, d.getIncident)},
		{Method: http.MethodPost, Path: "/api/v1/incidents/{id}/status", Permission: auth.PermIncidentsManage,
			MaxBody: incidents.MaxBody, Handler: needIncidents(d, d.setIncidentStatus)},
		{Method: http.MethodPut, Path: "/api/v1/incidents/{id}/assignee", Permission: auth.PermIncidentsManage,
			MaxBody: smallMaxBody, Handler: needIncidents(d, d.assignIncident)},
		{Method: http.MethodPost, Path: "/api/v1/incidents/{id}/comments", Permission: auth.PermIncidentsManage, Idempotent: true,
			MaxBody: incidents.MaxCommentBody, Handler: needIncidents(d, d.addIncidentComment)},
		{Method: http.MethodPost, Path: "/api/v1/incidents/{id}/stages/{stage}", Permission: auth.PermIncidentsManage,
			MaxBody: incidents.MaxBody, Handler: needIncidents(d, d.completeIncidentStage)},
		{Method: http.MethodPost, Path: "/api/v1/incidents/{id}/alerts", Permission: auth.PermIncidentsManage,
			MaxBody: smallMaxBody, Handler: needIncidents(d, d.linkIncidentAlert)},
		{Method: http.MethodGet, Path: "/api/v1/incidents/{id}/export", Permission: auth.PermIncidentsExport,
			Handler: needIncidents(d, d.exportIncident)},
		{Method: http.MethodGet, Path: "/api/v1/incident-categories", Permission: auth.PermIncidentsRead,
			Handler: needIncidents(d, d.listIncidentCategories)},
		{Method: http.MethodPut, Path: "/api/v1/incident-categories/{category}", Permission: auth.PermIncidentCategoriesManage,
			MaxBody: incidents.MaxInstructionsBody, Handler: needIncidents(d, d.setIncidentInstructions)},
	}
}

func needIncidents(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Incidents == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Инциденты не подключены на сервере."))
			return
		}
		h(w, r)
	}
}

const incidentNotFound = "Инцидент не найден."

// incidentsProblem переводит ошибки сервиса инцидентов в ответы API.
func incidentsProblem(logger *slog.Logger, err error) *Problem {
	var ie *incidents.InputError
	var re *reauthError
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.Is(err, incidents.ErrConfirmRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Сокращение срока хранения удаляет инциденты: выполните его в консоли с вводом текущего пароля или кода.")
	case errors.As(err, &ie):
		return Invalid("Проверьте введённые данные.", inputFields(ie.Errs)...)
	case errors.Is(err, alerting.ErrSelfReview):
		return NewProblem(http.StatusConflict, CodeSelfReview,
			"Инцидент связан с оповещением безопасности о ваших собственных действиях: закрывает другой пользователь с правом разбора инцидентов.")
	case errors.Is(err, alerting.ErrTokenClose):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Инцидент с системным оповещением или оповещением безопасности закрывает пользователь в консоли, а не токен API.")
	case errors.Is(err, incidents.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, incidentNotFound)
	case errors.Is(err, incidents.ErrAlertNotFound):
		return Invalid("Проверьте введённые данные.", FieldError{"alert_id", "alert_id: оповещение не найдено"})
	case errors.Is(err, incidents.ErrCommentNotFound):
		return Invalid("Проверьте введённые данные.", FieldError{"replaces", "replaces: комментария нет в этом инциденте"})
	case errors.Is(err, incidents.ErrUserInactive):
		return Invalid("Проверьте введённые данные.", FieldError{"user_id", "user_id: пользователь не найден, не активен или не работает с инцидентами"})
	case errors.Is(err, incidents.ErrTransition):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Такой переход статуса невозможен: инцидент идёт по шагам «новый → в работе → локализован → закрыт», закрыть можно из любого незакрытого.")
	case errors.Is(err, incidents.ErrClosed):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Инцидент закрыт и не меняется. Если разбор нужно продолжить, откройте его заново: будет создан новый инцидент со ссылкой.")
	case errors.Is(err, incidents.ErrNotClosed):
		return NewProblem(http.StatusConflict, CodeConflict, "Открыть заново можно только закрытый инцидент.")
	case errors.Is(err, incidents.ErrLinked):
		return NewProblem(http.StatusConflict, CodeConflict, "Оповещение уже входит в другой инцидент.")
	case errors.Is(err, incidents.ErrStageDone):
		return NewProblem(http.StatusConflict, CodeConflict, "Этап уже отмечен.")
	case errors.Is(err, incidents.ErrSuperseded):
		return NewProblem(http.StatusConflict, CodeConflict, "Комментарий уже исправлен: правьте последнюю версию.")
	case errors.Is(err, incidents.ErrVersionConflict):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Инструкцию изменил другой пользователь: обновите страницу и повторите изменение.")
	case errors.Is(err, incidents.ErrNotAuthor):
		return NewProblem(http.StatusForbidden, CodeForbidden, "Исправить комментарий может только его автор.")
	case errors.Is(err, incidents.ErrLimit):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Достигнут предел записей инцидента: закройте его и при необходимости откройте заново.")
	}
	logger.Error("инциденты: ошибка обработки запроса", "error", err)
	return errInternal()
}

// inputFields — ошибки ввода по полям: имя поля — начало текста ошибки.
func inputFields(errs []error) []FieldError {
	fields := make([]FieldError, 0, len(errs))
	for _, e := range errs {
		f := ""
		if m := fieldRe.FindStringSubmatch(e.Error()); m != nil {
			f = m[1]
		}
		fields = append(fields, FieldError{Field: f, Detail: e.Error()})
	}
	return fields
}

// incidentsBy — субъект запроса: для токена исполнитель — его владелец.
func incidentsBy(r *http.Request) (incidents.By, bool) {
	a, ok := alertsBy(r)
	if !ok {
		return incidents.By{}, false
	}
	return incidents.By{Actor: a.Actor, IP: a.IP, UserID: a.UserID}, true
}

// IncidentPage — страница списка инцидентов.
type IncidentPage = PageResponse[incidents.View]

func (d Deps) listIncidents(w http.ResponseWriter, r *http.Request) {
	page, p := ParsePage(r)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	q, err := incidents.ParseQuery(r.URL.Query())
	if err != nil {
		var ie *incidents.InputError
		if errors.As(err, &ie) {
			WriteProblem(w, Invalid("Параметры выборки заданы неверно.", inputFields(ie.Errs)...))
			return
		}
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	if page.Cursor != nil {
		if _, err := store.ParseUUID(page.Cursor.ID); err != nil {
			WriteProblem(w, Invalid("Параметры страницы заданы неверно.", FieldError{"cursor", "Курсор неверен или устарел: начните выборку сначала."}))
			return
		}
		q.After = &incidents.Position{CreatedAt: time.UnixMicro(page.Cursor.TimeMicro).UTC(), ID: page.Cursor.ID}
	}
	q.Limit = page.Limit + 1
	list, err := d.Incidents.List(r.Context(), q)
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	now := time.Now()
	resp := IncidentPage{Items: make([]incidents.View, 0, min(len(list), page.Limit))}
	for i := range list {
		if i == page.Limit {
			last := list[i-1]
			resp.NextCursor = Cursor{TimeMicro: last.CreatedAt.UnixMicro(), ID: last.ID}.Encode()
			break
		}
		resp.Items = append(resp.Items, incidents.ViewOf(&list[i], now))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) createIncident(w http.ResponseWriter, r *http.Request) {
	by, ok := incidentsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req incidents.CreateInput
	if p := DecodeJSON(w, r, &req, incidents.MaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	inc, created, err := d.Incidents.Create(r.Context(), by, req)
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	w.Header().Set("Location", "/api/v1/incidents/"+inc.ID)
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	WriteJSON(w, status, incidents.ViewOf(&inc, time.Now()))
}

func (d Deps) getIncident(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, incidentNotFound)
	if !ok {
		return
	}
	c, err := d.Incidents.Card(r.Context(), id)
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, incidents.CardViewOf(c, time.Now()))
}

func (d Deps) setIncidentStatus(w http.ResponseWriter, r *http.Request) {
	by, ok := incidentsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, incidentNotFound)
	if !ok {
		return
	}
	var req incidents.StatusInput
	if p := DecodeJSON(w, r, &req, incidents.MaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	inc, err := d.Incidents.SetStatus(r.Context(), by, id, req)
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, incidents.ViewOf(&inc, time.Now()))
}

func (d Deps) assignIncident(w http.ResponseWriter, r *http.Request) {
	by, ok := incidentsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, incidentNotFound)
	if !ok {
		return
	}
	var req incidents.AssignInput
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	inc, err := d.Incidents.Assign(r.Context(), by, id, req)
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, incidents.ViewOf(&inc, time.Now()))
}

func (d Deps) addIncidentComment(w http.ResponseWriter, r *http.Request) {
	by, ok := incidentsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, incidentNotFound)
	if !ok {
		return
	}
	var req incidents.CommentInput
	if p := DecodeJSON(w, r, &req, incidents.MaxCommentBody); p != nil {
		WriteProblem(w, p)
		return
	}
	c, err := d.Incidents.AddComment(r.Context(), by, id, req)
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusCreated, incidents.CommentView{ID: c.ID, At: c.At.UTC(), Author: c.Author, AuthorName: c.AuthorName,
		Body: c.Body, Replaces: c.Replaces})
}

func (d Deps) completeIncidentStage(w http.ResponseWriter, r *http.Request) {
	by, ok := incidentsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, incidentNotFound)
	if !ok {
		return
	}
	var req incidents.StageInput
	if p := DecodeJSON(w, r, &req, incidents.MaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	inc, err := d.Incidents.CompleteStage(r.Context(), by, id, r.PathValue("stage"), req)
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, incidents.ViewOf(&inc, time.Now()))
}

func (d Deps) linkIncidentAlert(w http.ResponseWriter, r *http.Request) {
	by, ok := incidentsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, incidentNotFound)
	if !ok {
		return
	}
	var req incidents.LinkInput
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	inc, _, err := d.Incidents.LinkAlert(r.Context(), by, id, req)
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, incidents.ViewOf(&inc, time.Now()))
}

// exportIncident — карточка в JSON для SIEM/IRP заказчика (ТЗ 5.7, 10.1):
// без содержимого событий, запись data.export до выдачи.
func (d Deps) exportIncident(w http.ResponseWriter, r *http.Request) {
	by, ok := incidentsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, incidentNotFound)
	if !ok {
		return
	}
	doc, err := d.Incidents.Export(r.Context(), by, id)
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Disposition", `attachment; filename="incident-`+strconv.FormatInt(doc.Number, 10)+`.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n')) //nolint:gosec // G104: клиент мог закрыть соединение, запись data.export уже сделана
}

// IncidentCategoryView — категория со строками матрицы и инструкцией.
type IncidentCategoryView struct {
	ID          string                    `json:"id"`
	Title       string                    `json:"title"`
	Rows        []string                  `json:"rows"`
	Instruction incidents.InstructionView `json:"instruction"`
}

// IncidentCategoryList — справочник категорий (ТЗ 5.7).
type IncidentCategoryList struct {
	Items []IncidentCategoryView `json:"items"`
}

func (d Deps) listIncidentCategories(w http.ResponseWriter, r *http.Request) {
	list, err := d.Incidents.Categories(r.Context())
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	out := IncidentCategoryList{Items: make([]IncidentCategoryView, 0, len(list))}
	for _, c := range list {
		out.Items = append(out.Items, IncidentCategoryView{ID: c.Category.ID, Title: c.Category.Title, Rows: c.Category.Rows,
			Instruction: incidents.InstructionViewOf(c.Instruction)})
	}
	WriteJSON(w, http.StatusOK, out)
}

func (d Deps) setIncidentInstructions(w http.ResponseWriter, r *http.Request) {
	by, ok := incidentsBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	cat := r.PathValue("category")
	if _, ok := incidents.LookupCategory(cat); !ok {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "Категория инцидентов не найдена."))
		return
	}
	var req incidents.InstructionsInput
	if p := DecodeJSON(w, r, &req, incidents.MaxInstructionsBody); p != nil {
		WriteProblem(w, p)
		return
	}
	ins, err := d.Incidents.SetInstructions(r.Context(), by, cat, req)
	if err != nil {
		WriteProblem(w, incidentsProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, incidents.InstructionViewOf(ins))
}
