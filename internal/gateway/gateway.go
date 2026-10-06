package gateway

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// Gateway — HTTP-обработчик шлюза.
type Gateway struct {
	logger *slog.Logger
	mux    *http.ServeMux
}

// Options — зависимости обработчика.
type Options struct {
	Logger *slog.Logger
	// Proxy обслуживает POST /v1/chat/completions; nil — маршрут не подключён.
	Proxy http.Handler
	// Auth — аутентификация приложений. Обязательна, если подключён хотя бы
	// один маршрут для приложений: шлюз без проверки ключей не собирается.
	Auth *AuthConfig
}

// New собирает маршруты шлюза.
func New(opts Options) (*Gateway, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	g := &Gateway{logger: logger, mux: http.NewServeMux()}
	g.mux.HandleFunc("GET /healthz", g.healthz)
	g.mux.HandleFunc("GET /readyz", g.healthz)
	if opts.Proxy != nil {
		if opts.Auth == nil {
			return nil, errors.New("шлюз: маршруты приложений без аутентификации не подключаются")
		}
		h, err := RequireAppKey(*opts.Auth, opts.Proxy)
		if err != nil {
			return nil, err
		}
		g.mux.Handle("POST /v1/chat/completions", h)
	}
	return g, nil
}

// ServeHTTP добавляет заголовки безопасности и отвечает на неизвестные
// маршруты в формате ошибок OpenAI, а не текстом ServeMux.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	_, pattern := g.mux.Handler(r)
	if pattern == "" {
		// ServeMux различает 404 и 405, но отвечает текстом; определяем сами.
		if g.pathKnown(r) {
			WriteError(w, http.StatusMethodNotAllowed, "метод не поддерживается", "invalid_request_error", "method_not_allowed")
			return
		}
		WriteError(w, http.StatusNotFound, "адрес не найден", "invalid_request_error", "not_found")
		return
	}
	g.mux.ServeHTTP(w, r)
}

// pathKnown сообщает, есть ли маршрут с тем же путём, но другим методом.
func (g *Gateway) pathKnown(r *http.Request) bool {
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		probe := r.Clone(r.Context())
		probe.Method = m
		if _, p := g.mux.Handler(probe); p != "" {
			return true
		}
	}
	return false
}

func (g *Gateway) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return // клиент ушёл; писать больше некуда
	}
}

// WriteError отвечает ошибкой в OpenAI-совместимом формате. Текст — для
// пользователя, без внутренних подробностей (ТЗ, 5.1).
func WriteError(w http.ResponseWriter, status int, msg, typ, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"message": msg, "type": typ, "code": code}})
}
