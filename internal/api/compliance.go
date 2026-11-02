package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/compliance"
)

// Соответствие требованиям (ТЗ 5.9, решение Р10; задача 4.24). Чтение —
// compliance.read (администратор безопасности, аудитор, администратор
// системы); ручные отметки — compliance.mark (администратор безопасности);
// загрузка обновлённой подписанной базы требований — compliance.base.load
// (администратор системы). Содержимого запросов в ответах нет: только
// настройки, счётчики и ссылки на экраны.

const (
	// complianceBaseMaxBody — подписанный файл базы (aisecCrypto.MaxServiceDBSize).
	complianceBaseMaxBody = 4 << 20
	// complianceReadTimeout — предел вычисления статусов (сбор сведений
	// обращается к нескольким сервисам).
	complianceReadTimeout = 45 * time.Second
)

var requirementIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)

func complianceRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/compliance", Permission: auth.PermComplianceRead,
			Handler: needCompliance(d, d.getCompliance)},
		{Method: http.MethodGet, Path: "/api/v1/compliance/requirements/{id}", Permission: auth.PermComplianceRead,
			Handler: needCompliance(d, d.getRequirement)},
		{Method: http.MethodPut, Path: "/api/v1/compliance/requirements/{id}/mark", Permission: auth.PermComplianceMark,
			MaxBody: smallMaxBody, Handler: needCompliance(d, d.putComplianceMark)},
		{Method: http.MethodDelete, Path: "/api/v1/compliance/requirements/{id}/mark", Permission: auth.PermComplianceMark,
			Handler: needCompliance(d, d.deleteComplianceMark)},
		{Method: http.MethodGet, Path: "/api/v1/compliance/base", Permission: auth.PermComplianceRead,
			Handler: needCompliance(d, d.getComplianceBase)},
		{Method: http.MethodPut, Path: "/api/v1/compliance/base", Permission: auth.PermComplianceBaseLoad,
			MaxBody: complianceBaseMaxBody, Handler: needCompliance(d, d.putComplianceBase)},
		// Откат на предыдущую загруженную версию (задача 5.15, ADR-0028, п. 4).
		{Method: http.MethodPost, Path: "/api/v1/compliance/base/rollback", Permission: auth.PermComplianceBaseLoad, SessionOnly: true,
			MaxBody: smallMaxBody, Handler: needCompliance(d, d.rollbackComplianceBase)},
	}
}

func needCompliance(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Compliance == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Раздел «Соответствие» не подключён на сервере."))
			return
		}
		h(w, r)
	}
}

func (d Deps) complianceBy(r *http.Request) (compliance.By, bool) {
	a, ok := actorOf(r)
	if !ok {
		return compliance.By{}, false
	}
	return compliance.By{Actor: a.Actor, IP: a.IP}, true
}

const requirementNotFound = "Пункт не найден в действующей базе требований."

// putComplianceMarkRequest — отметка и поля повторной проверки (пароль или
// код второго фактора) для «не применимо» у пункта с проверками.
type putComplianceMarkRequest struct {
	compliance.MarkInput
	reauthFields
}

func complianceProblem(logger *slog.Logger, err error) *Problem {
	var ie *compliance.InputError
	var re *reauthError
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.Is(err, compliance.ErrConfirmRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Пункт с автоматическими проверками объявляют неприменимым в консоли с вводом текущего пароля или кода: токеном API — нельзя.")
	case errors.As(err, &ie):
		fields := make([]FieldError, 0, len(ie.Fields))
		for _, k := range sortedKeys(ie.Fields) {
			fields = append(fields, FieldError{Field: k, Detail: ie.Fields[k]})
		}
		return Invalid("Проверьте введённые данные.", fields...)
	case errors.Is(err, compliance.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, requirementNotFound)
	case errors.Is(err, compliance.ErrNoMark):
		return NewProblem(http.StatusNotFound, CodeNotFound, "Ручной отметки у пункта нет.")
	case errors.Is(err, compliance.ErrMarkNotAllowed):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Статус этого пункта вычисляют проверки: вручную можно отметить только «не применимо» с комментарием.")
	case errors.Is(err, context.DeadlineExceeded):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Статусы не успели вычислиться: повторите позже.")
	}
	logger.Error("соответствие: ошибка обработки запроса", "class", "compliance", "error", err)
	return errInternal()
}

func (d Deps) getCompliance(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k, v := range q {
		if (k != "source" && k != "applies") || len(v) != 1 {
			WriteProblem(w, Invalid("Проверьте параметры запроса.", FieldError{Field: k, Detail: "Допустимы по одному разу source и applies."}))
			return
		}
	}
	f := compliance.Filter{Source: q.Get("source"), Applies: q.Get("applies")}
	if f.Applies != "" && !slices.Contains(compliance.Applicabilities(), f.Applies) {
		WriteProblem(w, Invalid("Проверьте параметры запроса.", FieldError{Field: "applies", Detail: "gis, kii, ispdn или commercial."}))
		return
	}
	if len(f.Source) > 32 {
		WriteProblem(w, Invalid("Проверьте параметры запроса.", FieldError{Field: "source", Detail: "Источник задан неверно."}))
		return
	}
	ctx, cancel := contextTimeout(r, complianceReadTimeout)
	defer cancel()
	o, err := d.Compliance.Evaluate(ctx, f)
	if err != nil {
		WriteProblem(w, complianceProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, o)
}

func reqIDFrom(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !requirementIDRe.MatchString(id) {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, requirementNotFound))
		return "", false
	}
	return id, true
}

func (d Deps) getRequirement(w http.ResponseWriter, r *http.Request) {
	id, ok := reqIDFrom(w, r)
	if !ok {
		return
	}
	ctx, cancel := contextTimeout(r, complianceReadTimeout)
	defer cancel()
	it, err := d.Compliance.Item(ctx, id)
	if err != nil {
		WriteProblem(w, complianceProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, it)
}

func (d Deps) putComplianceMark(w http.ResponseWriter, r *http.Request) {
	id, ok := reqIDFrom(w, r)
	if !ok {
		return
	}
	by, ok := d.complianceBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req putComplianceMarkRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	// «Не применимо» у пункта с проверками — ослабление (4В36): сервис
	// вызывает повторную проверку, только если она нужна.
	by.Confirm = d.confirmFunc(r, req.reauthFields, "compliance.mark_set", compliance.ErrConfirmRequired)
	ctx, cancel := contextTimeout(r, complianceReadTimeout)
	defer cancel()
	it, err := d.Compliance.SetMark(ctx, by, id, req.MarkInput)
	if err != nil {
		WriteProblem(w, complianceProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, it)
}

func (d Deps) deleteComplianceMark(w http.ResponseWriter, r *http.Request) {
	id, ok := reqIDFrom(w, r)
	if !ok {
		return
	}
	by, ok := d.complianceBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	ctx, cancel := contextTimeout(r, complianceReadTimeout)
	defer cancel()
	it, err := d.Compliance.ClearMark(ctx, by, id)
	if err != nil {
		WriteProblem(w, complianceProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, it)
}

func (d Deps) getComplianceBase(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextTimeout(r, complianceReadTimeout)
	defer cancel()
	v, err := d.Compliance.BaseView(ctx)
	if err != nil {
		WriteProblem(w, complianceProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, v)
}

// putComplianceBase принимает подписанный файл базы телом запроса
// (application/octet-stream) целиком: он не больше 4 МиБ.
func (d Deps) putComplianceBase(w http.ResponseWriter, r *http.Request) {
	by, ok := d.complianceBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	if !fileContentType(r, "application/octet-stream") {
		WriteProblem(w, NewProblem(http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
			"Тело запроса — подписанный файл базы (Content-Type: application/octet-stream)."))
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			WriteProblem(w, NewProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "Файл базы больше 4 МиБ."))
			return
		}
		d.Logger.Debug("соответствие: тело запроса не прочитано", "error", err)
		WriteProblem(w, NewProblem(http.StatusBadRequest, CodeInvalidRequest, "Тело запроса не прочитано."))
		return
	}
	ctx, cancel := contextTimeout(r, complianceReadTimeout)
	defer cancel()
	v, err := d.Compliance.UploadBase(ctx, by, data)
	if p := serviceDBProblem(err, "базу", false); p != nil {
		WriteProblem(w, p)
		return
	}
	if err != nil {
		WriteProblem(w, complianceProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, v)
}

// rollbackComplianceBase возвращает предыдущую загруженную версию базы
// после её повторной проверки; тело запроса не нужно.
func (d Deps) rollbackComplianceBase(w http.ResponseWriter, r *http.Request) {
	by, ok := d.complianceBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	ctx, cancel := contextTimeout(r, complianceReadTimeout)
	defer cancel()
	v, err := d.Compliance.RollbackBase(ctx, by)
	if p := serviceDBProblem(err, "базу", true); p != nil {
		WriteProblem(w, p)
		return
	}
	if err != nil {
		WriteProblem(w, complianceProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, v)
}
