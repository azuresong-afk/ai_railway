package api

import (
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Routes — единственное место, где собираются маршруты сервера. Следующие
// задачи добавляют свой файл (например, users.go с usersRoutes) и одну
// строку ниже; маршруты описываются в api/openapi.yaml, а контрактный тест
// сверяет их со спецификацией.
func Routes(d Deps) []Route {
	var routes []Route
	routes = append(routes, systemRoutes(d)...)
	routes = append(routes, authRoutes(d)...)
	routes = append(routes, mfaRoutes(d)...)
	routes = append(routes, userRoutes(d)...)
	routes = append(routes, gatewayRoutes(d)...)
	routes = append(routes, integrityRoutes(d)...)
	return routes
}

func systemRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/healthz", Public: true, Handler: func(w http.ResponseWriter, _ *http.Request) {
			WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}},
		{Method: http.MethodGet, Path: "/readyz", Public: true, Handler: func(w http.ResponseWriter, r *http.Request) {
			if d.Ready != nil {
				ctx, cancel := contextTimeout(r, 3*time.Second)
				defer cancel()
				if err := d.Ready(ctx); err != nil {
					// Причину не показываем без аутентификации; она в журнале.
					d.Logger.Warn("проверка готовности не пройдена", "error", err)
					w.Header().Set("Retry-After", "5")
					WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Сервер ещё не готов к работе."))
					return
				}
			}
			WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
		}},
		{Method: http.MethodGet, Path: "/api/v1/system/info", Permission: auth.PermSystemRead, Handler: func(w http.ResponseWriter, _ *http.Request) {
			WriteJSON(w, http.StatusOK, SystemInfo{Version: d.Version})
		}},
	}
}

// SystemInfo — ответ GET /api/v1/system/info.
type SystemInfo struct {
	Version string `json:"version"`
}
