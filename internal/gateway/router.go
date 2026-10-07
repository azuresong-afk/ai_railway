package gateway

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// App — маршрут приложения: провайдер, разрешённые модели и пределы запроса.
type App struct {
	ID       string
	Env      string
	Provider providers.Provider
	models   map[string]bool
	aliases  map[string]string
	Limits   chat.Limits
}

// Resolve возвращает модель провайдера для имени из запроса: разрешённую
// модель или цель псевдонима (DM-33). Псевдоним важнее модели с тем же именем.
func (a *App) Resolve(name string) (string, bool) {
	if m, ok := a.aliases[name]; ok {
		return m, true
	}
	return name, a.models[name]
}

// Models — имена, доступные приложению: модели и псевдонимы, по алфавиту.
func (a *App) Models() []string {
	out := make([]string, 0, len(a.models)+len(a.aliases))
	for m := range a.models {
		out = append(out, m)
	}
	for al := range a.aliases {
		if !a.models[al] {
			out = append(out, al)
		}
	}
	slices.Sort(out)
	return out
}

// Router — приложения шлюза по идентификатору.
type Router struct {
	apps map[string]*App
}

// NewRouter строит маршруты из конфигурации; провайдеры уже созданы.
func NewRouter(apps []config.Application, provs map[string]providers.Provider) (*Router, error) {
	rt := &Router{apps: map[string]*App{}}
	for _, a := range apps {
		p, ok := provs[a.Provider]
		if !ok {
			return nil, fmt.Errorf("приложение %s: провайдер %q не создан", a.ID, a.Provider)
		}
		app := &App{ID: a.ID, Env: a.Env, Provider: p, models: map[string]bool{}, aliases: map[string]string{},
			Limits: chat.Limits{MaxMessages: a.Quotas.MaxMessages, MaxTokens: a.Quotas.MaxTokens}}
		for _, m := range a.Models {
			app.models[m] = true
		}
		for al, m := range a.Aliases {
			if !app.models[m] {
				return nil, fmt.Errorf("приложение %s: псевдоним %s указывает на неразрешённую модель", a.ID, al)
			}
			app.aliases[al] = m
		}
		rt.apps[a.ID] = app
	}
	return rt, nil
}

// app — приложение запроса (после RequireAppKey).
func (rt *Router) app(r *http.Request) (*App, bool) {
	id, ok := IdentityFrom(r.Context())
	if !ok {
		return nil, false
	}
	a, ok := rt.apps[id.AppID]
	return a, ok
}

// models — GET /v1/models: только модели и псевдонимы приложения (ТЗ, 5.1).
func (rt *Router) models(w http.ResponseWriter, r *http.Request) {
	a, ok := rt.app(r)
	if !ok {
		WriteError(w, http.StatusForbidden, "приложение не настроено", "invalid_request_error", "app_not_configured")
		return
	}
	type model struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		OwnedBy string `json:"owned_by"`
	}
	data := []model{}
	for _, m := range a.Models() {
		data = append(data, model{ID: m, Object: "model", OwnedBy: "aisec"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}
