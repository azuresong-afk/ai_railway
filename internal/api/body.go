package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

// DefaultMaxBody — предел тела запроса API управления, если маршрут не задал свой.
const DefaultMaxBody int64 = 1 << 20

// DecodeJSON читает тело запроса в dst: проверяет Content-Type, размер,
// неизвестные поля и лишние данные после значения. Предел max действует и
// тогда, когда Content-Length не указан или указан неверно.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any, max int64) *Problem {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return NewProblem(http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
			"Тело запроса должно быть в формате JSON (Content-Type: application/json).")
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return bodyProblem(err)
	}
	// Второе значение или мусор после первого — ошибка.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return Invalid("После JSON-значения в теле есть лишние данные.")
		}
		return bodyProblem(err)
	}
	return nil
}

func bodyProblem(err error) *Problem {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return NewProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "Тело запроса превышает допустимый размер.")
	}
	// Текст ошибки разборщика не показываем: в нём могут быть куски тела.
	return Invalid("Тело запроса не является корректным JSON или содержит неизвестные поля.")
}

// WriteJSON отправляет успешный ответ. Ошибка кодирования возможна только при
// неподдерживаемом типе (ошибка программиста) и превращается в 500.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		WriteProblem(w, errInternal())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n')) //nolint:gosec // G104: разрыв соединения не требует реакции
}
