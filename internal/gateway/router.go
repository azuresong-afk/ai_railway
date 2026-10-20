package gateway

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/detect/exfil"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// App — маршрут приложения: провайдер, разрешённые модели, пределы запроса
// и всё, что нужно конвейеру проверки.
type App struct {
	ID       string
	Env      string
	Provider providers.Provider
	models   map[string]bool
	aliases  map[string]string
	Limits   chat.Limits
	// Policy — политика приложения, Detectors — детекторы с его списками
	// lists и allowlist output.exfil; политика скомпилирована по ним.
	Policy    *policy.Policy
	Detectors *detect.Registry
	// Mode — режим политики приложения; пусто — режим самой политики.
	Mode policy.Mode
	// FailOpen — при сбое проверки пропустить запрос (fail_open); иначе
	// заблокировать (fail_closed, и по умолчанию).
	FailOpen bool
	// Storage — режим хранения содержимого в событиях (none, masked).
	Storage string
	// UserFrom — откуда идентификатор пользователя: header, field, none.
	UserFrom string
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
// Политика приложения ищется среди specs, затем среди шаблонов; пусто —
// «Базовая защита» (решение Р7). Детектор из политики заказчика, которого
// нет среди встроенных, — ошибка запуска.
func NewRouter(apps []config.Application, provs map[string]providers.Provider, specs []policy.Spec) (*Router, error) {
	rt := &Router{apps: map[string]*App{}}
	for _, a := range apps {
		p, ok := provs[a.Provider]
		if !ok {
			return nil, fmt.Errorf("приложение %s: провайдер %q не создан", a.ID, a.Provider)
		}
		reg, err := appDetectors(a)
		if err != nil {
			return nil, fmt.Errorf("приложение %s: %w", a.ID, err)
		}
		pol, err := policy.Resolve(a.Policy, specs, reg)
		if err != nil {
			return nil, fmt.Errorf("приложение %s: %w", a.ID, err)
		}
		storage := a.Storage
		if storage == "" {
			storage = events.StorageNone
		}
		userFrom := a.UserFrom
		if userFrom == "" {
			userFrom = userFromNone
		}
		app := &App{ID: a.ID, Env: a.Env, Provider: p, models: map[string]bool{}, aliases: map[string]string{},
			Limits: chat.Limits{MaxMessages: a.Quotas.MaxMessages, MaxTokens: a.Quotas.MaxTokens},
			Policy: pol, Detectors: reg, Mode: policy.Mode(a.PolicyMode), FailOpen: a.FailMode == failOpen,
			Storage: storage, UserFrom: userFrom}
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

// Значения полей приложения в конфигурации.
const (
	failOpen        = "fail_open"
	userFromHeader  = "header"
	userFromField   = "field"
	userFromNone    = "none"
	maxUserIDLength = 256
)

// appDetectors — встроенные детекторы с настройками приложения: lists — со
// списками заказчика вдобавок к встроенному, output.exfil — с allowlist.
func appDetectors(a config.Application) (*detect.Registry, error) {
	ds := builtin.All()
	for i, d := range ds {
		switch d.ID() {
		case lists.ID:
			if len(a.Lists) == 0 {
				continue
			}
			ld, err := lists.Compile(lists.WithDefaults(a.Lists))
			if err != nil {
				return nil, err
			}
			ds[i] = ld
		case exfil.ID:
			if len(a.ExfilAllowDomains) == 0 {
				continue
			}
			ed, err := exfil.NewWithConfig(exfil.Config{AllowDomains: a.ExfilAllowDomains})
			if err != nil {
				return nil, err
			}
			ds[i] = ed
		}
	}
	return detect.NewRegistry(ds...)
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
