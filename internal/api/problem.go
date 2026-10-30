package api

import (
	"encoding/json"
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/license"
)

// ContentTypeProblem — тип содержимого ошибок (RFC 9457).
const ContentTypeProblem = "application/problem+json"

// problemTypeBase — префикс URN типов ошибок: ссылки наружу не ведут,
// внешних обращений нет.
const problemTypeBase = "urn:aisec:problem:"

// Problem — ошибка в формате Problem Details (RFC 9457). Detail — русский
// текст для пользователя; внутренние подробности (SQL, пути, трассы) в него
// не попадают.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	// Code — машиночитаемый код, совпадает с хвостом Type.
	Code string `json:"code"`
	// Errors — ошибки полей при валидации тела или параметров.
	Errors []FieldError `json:"errors,omitempty"`
}

// FieldError — ошибка одного поля запроса.
type FieldError struct {
	Field  string `json:"field"`
	Detail string `json:"detail"`
}

// Коды ошибок API. Новые коды добавляются сюда и в api/openapi.yaml.
const (
	CodeInvalidRequest   = "invalid_request"
	CodeUnauthorized     = "unauthorized"
	CodeForbidden        = "forbidden"
	CodeNotFound         = "not_found"
	CodeMethodNotAllowed = "method_not_allowed"
	CodeConflict         = "conflict"
	CodePayloadTooLarge  = "payload_too_large"
	CodeUnsupportedMedia = "unsupported_media_type"
	CodeUnprocessable    = "unprocessable"
	CodeRateLimited      = "rate_limited"
	CodeInternal         = "internal_error"
	CodeUnavailable      = "service_unavailable"
	// CodeReauthFailed — неверный пароль или код повторной проверки (В8 ревью 2.r2).
	CodeReauthFailed = "reauthentication_failed"
	// CodeBundleKeyMismatch — ключ получателя шлюза не совпадает с
	// закреплённым (Н27, ADR-0018, п. 7); только внутренний API.
	CodeBundleKeyMismatch = "bundle_key_mismatch"
	// CodeReissueNotNeeded — перевыпуск сертификата шлюза не нужен (3В4
	// ревью 3.r1); только внутренний API.
	CodeReissueNotNeeded = "reissue_not_needed"
	// CodeSelfReview — оповещение безопасности о собственных действиях
	// закрывает другой пользователь (3В15 ревью 3.r2).
	CodeSelfReview = "self_review"
	// CodeApprovalQueueFull — очередь подтверждений шлюза или агента
	// переполнена (DM-22, задача 4.10); только внутренний API.
	CodeApprovalQueueFull = "approval_queue_full"
	// CodeInsufficientStorage — достигнут предел хранимых сводок теневого
	// ИИ (4Н25 ревью 4.r3).
	CodeInsufficientStorage = "insufficient_storage"
	// Отказы по лицензии (ADR-0026, п. 5): изменения запрещены после
	// льготного периода, модуль не входит в лицензию, превышен предел
	// шлюзов или приложений.
	CodeLicenseRestricted = license.CodeRestricted
	CodeLicenseModule     = license.CodeModule
	CodeLicenseLimit      = license.CodeLimit
)

var problemTitles = map[string]string{
	CodeInvalidRequest:      "Неверный запрос",
	CodeUnauthorized:        "Требуется вход",
	CodeForbidden:           "Доступ запрещён",
	CodeReauthFailed:        "Повторная проверка не пройдена",
	CodeNotFound:            "Не найдено",
	CodeMethodNotAllowed:    "Метод не поддерживается",
	CodeConflict:            "Конфликт",
	CodePayloadTooLarge:     "Запрос слишком большой",
	CodeUnsupportedMedia:    "Неподдерживаемый тип содержимого",
	CodeUnprocessable:       "Запрос не может быть обработан",
	CodeRateLimited:         "Слишком много запросов",
	CodeInternal:            "Внутренняя ошибка",
	CodeUnavailable:         "Сервис недоступен",
	CodeBundleKeyMismatch:   "Ключ получателя не совпадает с закреплённым",
	CodeReissueNotNeeded:    "Перевыпуск сертификата не нужен",
	CodeSelfReview:          "Нужна проверка другим пользователем",
	CodeApprovalQueueFull:   "Очередь подтверждений переполнена",
	CodeInsufficientStorage: "Достигнут предел хранимых данных",
	CodeLicenseRestricted:   "Изменения запрещены лицензией",
	CodeLicenseModule:       "Модуль не входит в лицензию",
	CodeLicenseLimit:        "Превышен предел лицензии",
}

// NewProblem собирает ошибку по коду; заголовок берётся из таблицы.
func NewProblem(status int, code, detail string) *Problem {
	return &Problem{
		Type: problemTypeBase + code, Title: problemTitles[code],
		Status: status, Detail: detail, Code: code,
	}
}

// WriteProblem отправляет ошибку. Ответ с ошибкой не кэшируется.
func WriteProblem(w http.ResponseWriter, p *Problem) {
	h := w.Header()
	h.Set("Content-Type", ContentTypeProblem)
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(p.Status)
	// Ошибка записи означает, что клиент ушёл: сообщать некому.
	_ = json.NewEncoder(w).Encode(p) //nolint:gosec // G104: разрыв соединения не требует реакции
}

// Готовые ошибки для типовых случаев.
func errUnauthorized() *Problem {
	return NewProblem(http.StatusUnauthorized, CodeUnauthorized, "Для этого действия нужно войти в систему.")
}

func errForbidden() *Problem {
	return NewProblem(http.StatusForbidden, CodeForbidden, "Недостаточно прав для этого действия.")
}

func errNotFound() *Problem {
	return NewProblem(http.StatusNotFound, CodeNotFound, "Ресурс не найден.")
}

func errMethodNotAllowed() *Problem {
	return NewProblem(http.StatusMethodNotAllowed, CodeMethodNotAllowed, "Этот метод для адреса не поддерживается.")
}

func errInternal() *Problem {
	return NewProblem(http.StatusInternalServerError, CodeInternal,
		"Внутренняя ошибка сервера. Повторите действие позже; если ошибка повторяется, обратитесь к администратору.")
}

// Invalid — ошибка проверки запроса с перечнем полей.
func Invalid(detail string, fields ...FieldError) *Problem {
	p := NewProblem(http.StatusBadRequest, CodeInvalidRequest, detail)
	p.Errors = fields
	return p
}
