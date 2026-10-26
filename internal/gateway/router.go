package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
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
	// Storage — режим хранения содержимого в событиях (none, masked, full).
	Storage string
	// UserFrom — откуда идентификатор пользователя: header, field, none.
	UserFrom string
	// fragmentMAC — ключ хешей фрагментов находок (Router.SetFragmentMAC);
	// nil — хешей нет, исключения по фрагменту не совпадают.
	fragmentMAC aisecCrypto.MAC
	// clock — часы для сроков исключений (Router.SetClock); nil — time.Now.
	clock func() time.Time
}

// now — время для сроков исключений.
func (a *App) now() time.Time {
	if a.clock != nil {
		return a.clock()
	}
	return time.Now()
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
	// unavailable — приложения, исключённые сервером из пакета конфигурации
	// (В16 ревью 2.r3b): их ключи принимаются, запросы — 503.
	unavailable map[string]bool
}

// SetUnavailable отмечает приложения, исключённые из пакета конфигурации.
// Вызывается до начала обслуживания запросов.
func (rt *Router) SetUnavailable(ids []string) {
	rt.unavailable = make(map[string]bool, len(ids))
	for _, id := range ids {
		rt.unavailable[id] = true
	}
}

// SetClock задаёт часы сроков исключений всех приложений (ServerClock.Now,
// 3Н40 ревью 3.r3); nil — часы шлюза. Вызывается до начала обслуживания
// запросов.
func (rt *Router) SetClock(now func() time.Time) {
	for _, a := range rt.apps {
		a.clock = now
	}
}

// SetFragmentMAC задаёт ключ хешей фрагментов находок (ключ псевдонимов
// пользователей, fragmentHash). Вызывается до начала обслуживания запросов.
func (rt *Router) SetFragmentMAC(mac aisecCrypto.MAC) {
	for _, a := range rt.apps {
		a.fragmentMAC = mac
	}
}

// noApp отвечает на запрос приложения, которого нет в маршрутах: 503, если
// сервер исключил его из пакета (конфигурация не прошла проверку, fail
// closed), иначе 403.
func (rt *Router) noApp(w http.ResponseWriter, r *http.Request) {
	if id, ok := IdentityFrom(r.Context()); ok && rt.unavailable[id.AppID] {
		WriteError(w, http.StatusServiceUnavailable, "конфигурация приложения не прошла проверку на сервере управления",
			"service_unavailable", "app_unavailable")
		return
	}
	WriteError(w, http.StatusForbidden, "приложение не настроено", "invalid_request_error", "app_not_configured")
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

// CheckApplications компилирует политику каждого приложения по его
// детекторам, как NewRouter при запуске: правило на категорию lists.*, для
// которой у приложения нет словаря, — ошибка. Сервер вызывает её до сборки
// пакета (задача 2.13), чтобы не подписать то, что шлюз отвергнет.
func CheckApplications(apps []config.Application, specs []policy.Spec) error {
	var errs []error
	for _, a := range apps {
		reg, err := appDetectors(a)
		if err == nil {
			_, err = policy.Resolve(a.Policy, specs, reg)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("приложение %s: %w", a.ID, err))
		}
	}
	return errors.Join(errs...)
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
		rt.noApp(w, r)
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
