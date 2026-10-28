package api

import (
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/quotalease"
)

// QuotaInternalRoutes — аренда квот шлюзом (ADR-0021, п. 3; задача 4.29):
// одним запросом на все приложения, которым нужна доля. Ограничитель — по
// ID шлюза из сертификата mTLS (quotalease.RatePerSecond), не по адресу.
func QuotaInternalRoutes(svc *quotalease.Service, logger *slog.Logger) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/internal/v1/quota-leases", Permission: PermGatewayInternal,
			MaxBody: quotalease.MaxBody, Handler: quotaLeases(svc, logger)},
	}
}

func quotaLeases(svc *quotalease.Service, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			WriteProblem(w, NewProblem(http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
				"Тело запроса должно быть в формате JSON (Content-Type: application/json)."))
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, quotalease.MaxBody))
		if err != nil {
			WriteProblem(w, bodyProblem(err))
			return
		}
		req, err := quotalease.Parse(body)
		if err != nil {
			WriteProblem(w, Invalid("Неверный запрос аренды: apps — от 1 до 2 000 приложений без повторов, у приложения — до 4 квот "+
				"(requests_per_minute, tokens_per_minute, tokens_per_day, budget), request_id — UUID без повторов, want и offline — "+
				"от 0 до 2^62, reports — до 8 отчётов о разных арендах, used от 0 до 2^62; тело до 64 КиБ."))
			return
		}
		ctx, cancel := contextTimeout(r, 5*time.Second)
		defer cancel()
		resp, err := svc.Lease(ctx, p.ID, clientAddr(r), req)
		var v *quotalease.Violation
		switch {
		case err == nil:
			WriteJSON(w, http.StatusOK, resp)
		case errors.Is(err, quotalease.ErrRateLimited):
			w.Header().Set("Retry-After", strconv.Itoa(int(quotalease.RetryAfter()/time.Second)))
			WriteProblem(w, NewProblem(http.StatusTooManyRequests, CodeRateLimited, "Аренда квот — не чаще 10 запросов в секунду на шлюз."))
		case errors.As(err, &v):
			WriteProblem(w, Invalid("Отчёт об аренде отклонён: аренда не этого шлюза, приложения или квоты, израсходовано больше "+
				"выданного или повторный отчёт с другим числом."))
		case errors.Is(err, quotalease.ErrModeLocal), errors.Is(err, quotalease.ErrNotSetUp):
			WriteProblem(w, NewProblem(http.StatusConflict, CodeConflict, "Установка в режиме квот local: аренда не выдаётся."))
		default:
			logger.Error("аренда квот не выдана", "class", "db", "gateway_id", p.ID, "error", err)
			WriteProblem(w, errInternal())
		}
	}
}
