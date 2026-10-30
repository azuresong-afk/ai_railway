package api

import (
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
)

// Пределы тел запросов теневого ИИ (ADR-0027, пп. 4, 5).
const (
	// shadowImportMaxBody — файл журнала прокси (сжатый или нет).
	shadowImportMaxBody = 256 << 20
	// shadowCatalogMaxBody — подписанный файл каталога (aisecCrypto.MaxServiceDBSize).
	shadowCatalogMaxBody = 4 << 20
	// shadowDefaultPeriod — период чтения, если from и to не заданы.
	shadowDefaultPeriod = 30 * 24 * time.Hour
	// shadowReadTimeout — предел запроса чтения сводок.
	shadowReadTimeout = 15 * time.Second
)

// shadowAIRoutes — теневой ИИ (ТЗ 5.11, DM-37; задача 4.22, ADR-0027, п. 7).
// Чтение сводок — shadow_ai.read; импорт журналов прокси, загрузка
// подписанного каталога и срок хранения — shadow_ai.manage. Сокращение
// срока хранения необратимо удаляет сводки: повторная проверка паролем или
// кодом и weakening в аудите (DM-40).
func shadowAIRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/shadow-ai/services", Permission: auth.PermShadowAIRead,
			Handler: needShadowAI(d, d.shadowServices)},
		{Method: http.MethodGet, Path: "/api/v1/shadow-ai/users", Permission: auth.PermShadowAIRead,
			Handler: needShadowAI(d, d.shadowUsers)},
		{Method: http.MethodGet, Path: "/api/v1/shadow-ai/timeline", Permission: auth.PermShadowAIRead,
			Handler: needShadowAI(d, d.shadowTimeline)},
		{Method: http.MethodGet, Path: "/api/v1/shadow-ai/catalog", Permission: auth.PermShadowAIRead,
			Handler: needShadowAI(d, d.getShadowCatalog)},
		{Method: http.MethodPut, Path: "/api/v1/shadow-ai/catalog", Permission: auth.PermShadowAIManage,
			MaxBody: shadowCatalogMaxBody, Handler: needShadowAI(d, d.putShadowCatalog)},
		{Method: http.MethodGet, Path: "/api/v1/shadow-ai/imports", Permission: auth.PermShadowAIRead,
			Handler: needShadowAI(d, d.listShadowImports)},
		{Method: http.MethodPost, Path: "/api/v1/shadow-ai/imports", Permission: auth.PermShadowAIManage,
			MaxBody: shadowImportMaxBody, Handler: needShadowAI(d, d.postShadowImport)},
		{Method: http.MethodGet, Path: "/api/v1/shadow-ai/settings", Permission: auth.PermShadowAIRead,
			Handler: needShadowAI(d, d.getShadowSettings)},
		{Method: http.MethodPut, Path: "/api/v1/shadow-ai/settings", Permission: auth.PermShadowAIManage,
			MaxBody: smallMaxBody, Handler: needShadowAI(d, d.putShadowSettings)},
		// Исключения и состояние приёма по syslog (задача 4.23).
		{Method: http.MethodGet, Path: "/api/v1/shadow-ai/exclusions", Permission: auth.PermShadowAIRead,
			Handler: needShadowAI(d, d.listShadowExclusions)},
		{Method: http.MethodPost, Path: "/api/v1/shadow-ai/exclusions", Permission: auth.PermShadowAIExclusionsManage,
			MaxBody: smallMaxBody, Handler: needShadowAI(d, d.postShadowExclusion)},
		{Method: http.MethodDelete, Path: "/api/v1/shadow-ai/exclusions/{kind}/{value}", Permission: auth.PermShadowAIExclusionsManage,
			Handler: needShadowAI(d, d.deleteShadowExclusion)},
		{Method: http.MethodGet, Path: "/api/v1/shadow-ai/syslog", Permission: auth.PermShadowAIRead,
			Handler: needShadowAI(d, d.getShadowSyslog)},
	}
}

func needShadowAI(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.ShadowAI == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Раздел «Теневой ИИ» не подключён на сервере."))
			return
		}
		h(w, r)
	}
}

func (d Deps) shadowBy(r *http.Request) (shadowai.By, bool) {
	a, ok := actorOf(r)
	if !ok {
		return shadowai.By{}, false
	}
	return shadowai.By{Actor: a.Actor, IP: a.IP}, true
}

// shadowProblem переводит ошибки теневого ИИ в ответы API.
func shadowProblem(logger *slog.Logger, err error) *Problem {
	var qe *shadowai.QueryError
	var ce *shadowai.CatalogError
	var re *reauthError
	var mbe *http.MaxBytesError
	var fce flate.CorruptInputError
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.As(err, &qe):
		return Invalid("Проверьте параметры запроса.", FieldError{Detail: qe.Msg})
	case errors.As(err, &ce):
		if ce.Reason == "stale_version" {
			return NewProblem(http.StatusConflict, CodeConflict,
				"Версия каталога не больше загруженной: загрузите каталог из более нового выпуска.")
		}
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, catalogRejectText(ce.Reason))
	case errors.As(err, &mbe):
		return NewProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "Файл больше 256 МиБ: разделите журнал на части.")
	case errors.Is(err, shadowai.ErrTooLarge):
		return NewProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "Журнал после распаковки больше 1 ГиБ: разделите его на части.")
	case errors.Is(err, shadowai.ErrTooManyLines):
		return NewProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "В журнале больше 10 млн строк: разделите его на части.")
	case errors.Is(err, shadowai.ErrTooManyKeys):
		return NewProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge,
			"В журнале слишком много разных сочетаний сервиса, пользователя и часа: разделите его по времени.")
	case errors.Is(err, shadowai.ErrHeader), errors.Is(err, shadowai.ErrEmpty), errors.Is(err, shadowai.ErrBadFormat),
		errors.Is(err, gzip.ErrHeader), errors.Is(err, gzip.ErrChecksum), errors.Is(err, io.ErrUnexpectedEOF), errors.As(err, &fce):
		return NewProblem(http.StatusBadRequest, CodeInvalidRequest, importBadText(err))
	case errors.Is(err, shadowai.ErrBusy):
		return NewProblem(http.StatusTooManyRequests, CodeRateLimited, "Уже идёт другой импорт: повторите после его завершения.")
	case errors.Is(err, shadowai.ErrDuplicate):
		return NewProblem(http.StatusConflict, CodeConflict, "Этот файл уже импортирован.")
	case errors.Is(err, shadowai.ErrNoCatalog):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Каталог ИИ-сервисов не загружен или не прошёл проверку подписи: загрузите подписанный каталог из выпуска.")
	case errors.Is(err, shadowai.ErrNotSetUp):
		return NewProblem(http.StatusConflict, CodeConflict, "Первичная настройка не выполнена: срок хранения пока не меняется.")
	case errors.Is(err, shadowai.ErrConfirmNeeded):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Сокращение срока хранения и исключения удаляют сводки: выполните действие в консоли с вводом текущего пароля или кода.")
	case errors.Is(err, shadowai.ErrNoUserKey):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Серверу не задан ключ псевдонимов пользователей (-user-hmac-key): пользователи из журналов не учитываются, исключать некого.")
	case errors.Is(err, shadowai.ErrExclusionExists):
		return NewProblem(http.StatusConflict, CodeConflict, "Такое исключение уже есть.")
	case errors.Is(err, shadowai.ErrTooManyExclusions):
		return NewProblem(http.StatusConflict, CodeConflict, "Исключений уже 1000: снимите ненужные.")
	case errors.Is(err, shadowai.ErrExclusionNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, "Исключение не найдено.")
	case errors.Is(err, context.DeadlineExceeded):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Журнал не обработан за 10 минут: разделите его на части.")
	}
	logger.Error("теневой ИИ: ошибка обработки запроса", "error", err)
	return errInternal()
}

func catalogRejectText(reason string) string {
	switch reason {
	case "signature":
		return "Подпись каталога или заверения ключа неверна: файл изменён или выпущен не производителем."
	case "purpose":
		return "Ключ, которым подписан каталог, заверен не для служебных баз."
	case "expired":
		return "Срок заверения ключа, которым подписан каталог, истёк или ещё не наступил."
	case "revoked":
		return "Ключ, которым подписан каталог, отозван производителем."
	case "kind":
		return "Файл — служебная база другого вида, а не каталог ИИ-сервисов."
	case "date":
		return "Дата каталога вне срока заверения ключа подписи."
	}
	return "Файл не похож на подписанный каталог ИИ-сервисов (.aisecdb)."
}

// importBadText — причина отказа без содержимого журнала.
func importBadText(err error) string {
	switch {
	case errors.Is(err, shadowai.ErrHeader):
		return "В первой строке CSV нужен заголовок со столбцами времени и домена (или URL)."
	case errors.Is(err, shadowai.ErrEmpty):
		return "В журнале нет ни одной строки."
	case errors.Is(err, shadowai.ErrBadFormat):
		return "format — csv, squid или cef."
	}
	return "Файл не распакован: compression=gzip задан, но файл не в формате gzip или повреждён."
}

// shadowQuery — период и фильтр из параметров: from и to (RFC 3339),
// service, step, limit. Без from и to — последние 30 суток.
func shadowQuery(r *http.Request, now time.Time) (shadowai.Query, *Problem) {
	v := r.URL.Query()
	var q shadowai.Query
	for _, f := range []struct {
		name string
		dst  *time.Time
	}{{"from", &q.From}, {"to", &q.To}} {
		s := v.Get(f.name)
		if s == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return q, Invalid("Проверьте параметры запроса.", FieldError{Field: f.name, Detail: "Время в формате RFC 3339."})
		}
		*f.dst = t
	}
	if q.To.IsZero() {
		q.To = now
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-shadowDefaultPeriod)
	}
	q.Service, q.Step = v.Get("service"), v.Get("step")
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > shadowai.MaxUsersList {
			return q, Invalid("Проверьте параметры запроса.", FieldError{Field: "limit", Detail: "Целое от 1 до 1000."})
		}
		q.Limit = n
	}
	return q, nil
}

// ShadowServiceList — сервисы за период.
type ShadowServiceList struct {
	Items []shadowai.ServiceStat `json:"items"`
}

func (d Deps) shadowServices(w http.ResponseWriter, r *http.Request) {
	q, p := shadowQuery(r, time.Now())
	if p != nil {
		WriteProblem(w, p)
		return
	}
	ctx, cancel := contextTimeout(r, shadowReadTimeout)
	defer cancel()
	list, err := d.ShadowAI.Services(ctx, q)
	if err != nil {
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, ShadowServiceList{Items: list})
}

// ShadowUserList — пользователи (псевдонимы) за период.
type ShadowUserList struct {
	Items []shadowai.UserStat `json:"items"`
}

func (d Deps) shadowUsers(w http.ResponseWriter, r *http.Request) {
	q, p := shadowQuery(r, time.Now())
	if p != nil {
		WriteProblem(w, p)
		return
	}
	ctx, cancel := contextTimeout(r, shadowReadTimeout)
	defer cancel()
	list, err := d.ShadowAI.Users(ctx, q)
	if err != nil {
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, ShadowUserList{Items: list})
}

// ShadowTimeline — динамика по часам или суткам.
type ShadowTimeline struct {
	Step  string           `json:"step"`
	Items []shadowai.Point `json:"items"`
}

func (d Deps) shadowTimeline(w http.ResponseWriter, r *http.Request) {
	q, p := shadowQuery(r, time.Now())
	if p != nil {
		WriteProblem(w, p)
		return
	}
	if q.Step == "" {
		q.Step = shadowai.StepDay
	}
	ctx, cancel := contextTimeout(r, shadowReadTimeout)
	defer cancel()
	list, err := d.ShadowAI.Timeline(ctx, q)
	if err != nil {
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, ShadowTimeline{Step: q.Step, Items: list})
}

func (d Deps) getShadowCatalog(w http.ResponseWriter, r *http.Request) {
	v, err := d.ShadowAI.Catalog(r.Context())
	if err != nil {
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, v)
}

// putShadowCatalog принимает подписанный файл каталога телом запроса
// (application/octet-stream) целиком: он не больше 4 МиБ.
func (d Deps) putShadowCatalog(w http.ResponseWriter, r *http.Request) {
	by, ok := d.shadowBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	if !fileContentType(r, "application/octet-stream") {
		WriteProblem(w, NewProblem(http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
			"Тело запроса — подписанный файл каталога (Content-Type: application/octet-stream)."))
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		WriteProblem(w, shadowProblemCatalogBody(d.Logger, err))
		return
	}
	v, err := d.ShadowAI.UploadCatalog(r.Context(), by, data)
	if err != nil {
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, v)
}

// fileContentType — тело запроса передано файлом допустимого типа. Формы
// (multipart, urlencoded) не принимаются: файл — тело запроса целиком.
func fileContentType(r *http.Request, allowed ...string) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return false
	}
	for _, a := range allowed {
		if mt == a {
			return true
		}
	}
	return false
}

func shadowProblemCatalogBody(logger *slog.Logger, err error) *Problem {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return NewProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "Файл каталога больше 4 МиБ.")
	}
	logger.Debug("теневой ИИ: тело запроса не прочитано", "error", err)
	return NewProblem(http.StatusBadRequest, CodeInvalidRequest, "Тело запроса не прочитано.")
}

// ShadowImportList — последние импорты.
type ShadowImportList struct {
	Items []shadowai.ImportRecord `json:"items"`
}

func (d Deps) listShadowImports(w http.ResponseWriter, r *http.Request) {
	list, err := d.ShadowAI.Imports(r.Context())
	if err != nil {
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, ShadowImportList{Items: list})
}

// postShadowImport принимает журнал прокси телом запроса и разбирает его
// потоком: ?format=csv|squid|cef[&compression=gzip]. Срок чтения тела
// продлевается до shadowai.ImportTimeout, обработка ограничена тем же
// сроком; в ответе и аудите — только числа.
func (d Deps) postShadowImport(w http.ResponseWriter, r *http.Request) {
	by, ok := d.shadowBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	if !fileContentType(r, "application/octet-stream", "text/plain", "text/csv", "application/gzip") {
		WriteProblem(w, NewProblem(http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
			"Тело запроса — файл журнала (Content-Type: text/plain, text/csv, application/gzip или application/octet-stream)."))
		return
	}
	v := r.URL.Query()
	format := v.Get("format")
	if format != shadowai.FormatCSV && format != shadowai.FormatSquid && format != shadowai.FormatCEF {
		WriteProblem(w, Invalid("Проверьте параметры запроса.", FieldError{Field: "format", Detail: "csv, squid или cef."}))
		return
	}
	compression := v.Get("compression")
	if compression != "" && compression != "gzip" {
		WriteProblem(w, Invalid("Проверьте параметры запроса.", FieldError{Field: "compression", Detail: "gzip или не задано."}))
		return
	}
	// Медленный клиент не держит единственное место импорта дольше срока.
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(shadowai.ImportTimeout)); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		d.Logger.Debug("теневой ИИ: срок чтения тела не задан", "error", err)
	}
	var body io.Reader = r.Body
	if compression == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			WriteProblem(w, shadowProblem(d.Logger, err))
			return
		}
		defer func() { _ = zr.Close() }() //nolint:gosec // G104: закрытие распаковщика без записи
		zr.Multistream(false)
		body = zr
	}
	imp, err := d.ShadowAI.Import(r.Context(), by, format, body)
	if err != nil {
		if errors.Is(err, shadowai.ErrBusy) {
			w.Header().Set("Retry-After", "60")
		}
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusCreated, imp)
}

func (d Deps) getShadowSettings(w http.ResponseWriter, r *http.Request) {
	st, err := d.ShadowAI.Settings(r.Context())
	if err != nil {
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, st)
}

type shadowSettingsRequest struct {
	RetentionDays int `json:"retention_days"`
	reauthFields
}

func (d Deps) putShadowSettings(w http.ResponseWriter, r *http.Request) {
	by, ok := d.shadowBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req shadowSettingsRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by.Confirm = d.confirmFunc(r, req.reauthFields, "shadow_ai.settings_changed", shadowai.ErrConfirmNeeded)
	st, err := d.ShadowAI.SetRetention(r.Context(), by, req.RetentionDays)
	if err != nil {
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, st)
}

// ShadowExclusionList — исключения теневого ИИ.
type ShadowExclusionList struct {
	Items []shadowai.Exclusion `json:"items"`
}

func (d Deps) listShadowExclusions(w http.ResponseWriter, r *http.Request) {
	list, err := d.ShadowAI.ListExclusions(r.Context())
	if err != nil {
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, ShadowExclusionList{Items: list})
}

type shadowExclusionRequest struct {
	shadowai.ExclusionInput
	reauthFields
}

// postShadowExclusion добавляет исключение. Логин пользователя сразу
// заменяется псевдонимом и не попадает ни в БД, ни в аудит, ни в ответ.
// Исключение удаляет накопленные сводки — повторная проверка паролем или
// кодом (DM-40); токен API исключений не добавляет.
func (d Deps) postShadowExclusion(w http.ResponseWriter, r *http.Request) {
	by, ok := d.shadowBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req shadowExclusionRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by.Confirm = d.confirmFunc(r, req.reauthFields, "shadow_ai.exclusion_added", shadowai.ErrConfirmNeeded)
	ex, err := d.ShadowAI.AddExclusion(r.Context(), by, req.ExclusionInput)
	if err != nil {
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusCreated, ex)
}

func (d Deps) deleteShadowExclusion(w http.ResponseWriter, r *http.Request) {
	by, ok := d.shadowBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	if err := d.ShadowAI.RemoveExclusion(r.Context(), by, r.PathValue("kind"), r.PathValue("value")); err != nil {
		WriteProblem(w, shadowProblem(d.Logger, err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getShadowSyslog — состояние приёма журналов по syslog: адрес, формат,
// режим TLS, пределы и счётчики с запуска сервера.
func (d Deps) getShadowSyslog(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, d.ShadowAI.SyslogStats())
}
