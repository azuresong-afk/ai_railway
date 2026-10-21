package api

import (
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Приём событий от шлюзов (ТЗ 5.5, Р9, задача 2.15): POST
// /internal/v1/events:batch на внутреннем порту с mTLS. Шлюз — из
// клиентского сертификата (GatewayAuthorizer), в теле пакета его нет.
// Ошибка структуры пакета — 400 на весь пакет, ошибка отдельного события —
// отказ только в нём (код в ответе). Содержимое событий и текст ошибок СУБД
// в журнал не пишутся.

// eventsInsertTimeout — предел записи пакета в БД.
const eventsInsertTimeout = 15 * time.Second

// eventsRetryAfter — подсказка шлюзу, когда повторить пакет при 503.
const eventsRetryAfter = "30"

func eventsRoutes(st events.Store, now func() time.Time, logger *slog.Logger) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/internal/v1/events:batch", Permission: PermGatewayInternal,
			MaxBody: events.MaxBatchBytes, Handler: eventsBatch(st, now, logger)},
	}
}

func eventsBatch(st events.Store, now func() time.Time, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			WriteProblem(w, NewProblem(http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
				"Тело запроса должно быть в формате JSON (Content-Type: application/json)."))
			return
		}
		b, err := events.DecodeBatch(r.Body)
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				WriteProblem(w, NewProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "Тело запроса превышает допустимый размер."))
				return
			}
			WriteProblem(w, Invalid("Пакет событий: нужен JSON-объект {\"events\": [...], \"stats\": {...}} без неизвестных полей, от 1 до 500 событий."))
			return
		}
		t := now().UTC()
		if s := b.Stats; s != nil && s.StartedAt.After(t.Add(events.MaxClockSkew)) {
			WriteProblem(w, Invalid("Пакет событий: stats.started_at — в будущем."))
			return
		}
		res := events.BatchResult{Rejected: []events.Rejection{}}
		valid := make([]events.Event, 0, len(b.Events))
		codes := map[string]int{}
		for i := range b.Events {
			if code := events.Check(&b.Events[i], t); code != "" {
				res.Rejected = append(res.Rejected, events.Rejection{Index: i, Code: code})
				codes[code]++
				continue
			}
			valid = append(valid, b.Events[i])
		}
		if len(res.Rejected) > 0 {
			logger.Warn("события пакета отклонены", "gateway_id", p.ID, "count", len(res.Rejected), "codes", codes)
		}
		if len(valid) > 0 || b.Stats != nil {
			ctx, cancel := contextTimeout(r, eventsInsertTimeout)
			defer cancel()
			res.Accepted, res.Duplicates, err = st.Insert(ctx, events.Ingest{
				GatewayID: p.ID, ReceivedAt: t, Events: valid, Stats: b.Stats,
			})
			switch {
			case errors.Is(err, events.ErrRejectedByDB):
				logger.Error("СУБД отвергла пакет событий", "gateway_id", p.ID, "count", len(valid), "error", err)
				WriteProblem(w, NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
					"Пакет событий не может быть сохранён: данные не прошли проверку хранилища."))
				return
			case err != nil:
				logger.Error("пакет событий не записан", "gateway_id", p.ID, "count", len(valid), "error", err)
				w.Header().Set("Retry-After", eventsRetryAfter)
				WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
					"Хранилище событий временно недоступно. Повторите пакет позже."))
				return
			}
		}
		WriteJSON(w, http.StatusOK, res)
	}
}
