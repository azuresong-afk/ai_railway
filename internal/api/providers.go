package api

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Пределы тел запросов провайдеров: корневые сертификаты до 256 КиБ,
// учётные данные до 16 КиБ (в JSON с экранированием — больше).
const (
	providerMaxBody   = apps.MaxCAPEM + 16<<10
	credentialMaxBody = 4*apps.MaxCredential + 1<<10
	smallMaxBody      = 8 << 10
)

// providerRoutes — провайдеры (ТЗ 5.4, ЗИ.1; задача 2.11). Учётные данные
// только записываются; признак «внешний» меняется отдельным маршрутом с
// правом безопасности (DM-40).
func providerRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/providers", Permission: auth.PermProvidersRead, Handler: needApps(d, d.listProviders)},
		{Method: http.MethodPost, Path: "/api/v1/providers", Permission: auth.PermProvidersManage, Idempotent: true,
			MaxBody: providerMaxBody, Handler: needApps(d, d.createProvider)},
		{Method: http.MethodGet, Path: "/api/v1/providers/{id}", Permission: auth.PermProvidersRead, Handler: needApps(d, d.getProvider)},
		{Method: http.MethodPut, Path: "/api/v1/providers/{id}", Permission: auth.PermProvidersManage,
			MaxBody: providerMaxBody, Handler: needApps(d, d.updateProvider)},
		{Method: http.MethodDelete, Path: "/api/v1/providers/{id}", Permission: auth.PermProvidersManage, Handler: needApps(d, d.deleteProvider)},
		{Method: http.MethodPut, Path: "/api/v1/providers/{id}/credentials", Permission: auth.PermProvidersManage,
			MaxBody: credentialMaxBody, Handler: needApps(d, d.setProviderCredential)},
		{Method: http.MethodPut, Path: "/api/v1/providers/{id}/external", Permission: auth.PermProvidersExternal,
			MaxBody: smallMaxBody, Handler: needApps(d, d.setProviderExternal)},
	}
}

// needApps — 503, если приложения и провайдеры не подключены (нет БД).
func needApps(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Apps == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
				"Приложения и провайдеры не подключены на сервере."))
			return
		}
		h(w, r)
	}
}

// fieldRe — начало текста ошибки «поле — …» или «поле: …».
var fieldRe = regexp.MustCompile(`^([a-z_][a-z0-9_.\[\]]*)(?: — |: )`)

// appsProblem переводит ошибки internal/apps. Неизвестная ошибка — 500,
// причина — в техническом журнале.
func appsProblem(logger *slog.Logger, err error, notFound string) *Problem {
	var ie *apps.InputError
	var re *reauthError
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.Is(err, apps.ErrPolicyRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Переход на провайдера без признака «внешний» выключает маскирование: его выполняет администратор безопасности.")
	case errors.Is(err, apps.ErrBreaksBundle):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, err.Error()+".")
	case errors.Is(err, apps.ErrConfirmRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Изменение ослабляет защиту: выполните его в консоли с вводом текущего пароля или кода.")
	case errors.As(err, &ie):
		fields := make([]FieldError, 0, len(ie.Errs))
		for _, e := range ie.Errs {
			f := ""
			if m := fieldRe.FindStringSubmatch(e.Error()); m != nil {
				f = m[1]
			}
			fields = append(fields, FieldError{Field: f, Detail: e.Error()})
		}
		return Invalid("Проверьте введённые данные.", fields...)
	case errors.Is(err, apps.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, notFound)
	case errors.Is(err, apps.ErrSlugTaken):
		return NewProblem(http.StatusConflict, CodeConflict, "Такой ID уже занят: выберите другой.")
	case errors.Is(err, apps.ErrProviderNotFound):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, "Провайдер не найден: выберите существующего провайдера.")
	case errors.Is(err, apps.ErrProviderInUse):
		return NewProblem(http.StatusConflict, CodeConflict,
			"Провайдер указан в приложениях, в том числе архивных: сначала выберите им другого провайдера.")
	case errors.Is(err, apps.ErrArchived):
		return NewProblem(http.StatusConflict, CodeConflict, "Приложение в архиве: изменить его или выпустить ключ нельзя.")
	case errors.Is(err, apps.ErrKeyInactive):
		return NewProblem(http.StatusConflict, CodeConflict, "Ключ уже отозван или истёк: выпустите новый ключ.")
	case errors.Is(err, apps.ErrTooManyKeys):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"У приложения уже 20 действующих ключей: отзовите неиспользуемые.")
	case errors.Is(err, apps.ErrTooMany):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, "Достигнут предел числа провайдеров: удалите неиспользуемых.")
	case errors.Is(err, apps.ErrNoDataKey):
		return NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
			"Ключ данных не подключён: учётные данные провайдеров сохранить нельзя. Выполните aisec-cli init и перезапустите сервер.")
	}
	logger.Error("приложения: ошибка обработки запроса", "error", err)
	return errInternal()
}

// actorOf — субъект запроса для журнала аудита (РСБ.1).
func actorOf(r *http.Request) (apps.By, bool) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		return apps.By{}, false
	}
	c := p.Caller
	by := apps.By{Actor: audit.Actor{Type: audit.ActorUser, ID: c.User.ID, Name: c.User.Login}, IP: clientAddr(r)}
	if c.Token != nil {
		by.Actor = audit.Actor{Type: audit.ActorAPIToken, ID: c.Token.ID, Name: c.User.Login + " (" + c.Token.Prefix + ")"}
	}
	return by, true
}

// pathID — UUID из пути; недопустимый — 404, как и отсутствующий объект.
func pathID(w http.ResponseWriter, r *http.Request, notFound string) (string, bool) {
	id, err := store.ParseUUID(r.PathValue("id"))
	if err != nil {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, notFound))
		return "", false
	}
	return string(id), true
}

const providerNotFound = "Провайдер не найден."

// ProviderTimeouts — таймауты провайдера, секунды; 0 — по умолчанию шлюза.
type ProviderTimeouts struct {
	Connect    int `json:"connect"`
	Header     int `json:"header"`
	Response   int `json:"response"`
	StreamIdle int `json:"stream_idle"`
}

// ProviderView — провайдер в ответах: учётных данных нет, только признак.
type ProviderView struct {
	ID              string           `json:"id"`
	Slug            string           `json:"slug"`
	Name            string           `json:"name"`
	Type            string           `json:"type"`
	BaseURL         string           `json:"base_url"`
	CAPEM           string           `json:"ca_pem"`
	AuthURL         string           `json:"auth_url,omitempty"`
	Scope           string           `json:"scope,omitempty"`
	FolderID        string           `json:"folder_id,omitempty"`
	Timeouts        ProviderTimeouts `json:"timeouts"`
	External        bool             `json:"external"`
	CredentialSet   bool             `json:"credential_set"`
	CredentialSetAt *time.Time       `json:"credential_set_at,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

func providerView(p apps.Provider) ProviderView {
	v := ProviderView{ID: p.ID, Slug: p.Slug, Name: p.Name, Type: p.Type, BaseURL: p.BaseURL, CAPEM: p.CAPEM,
		AuthURL: p.AuthURL, Scope: p.Scope, FolderID: p.FolderID,
		Timeouts: ProviderTimeouts{Connect: p.ConnectTimeout, Header: p.HeaderTimeout, Response: p.ResponseTimeout, StreamIdle: p.StreamIdleTimeout},
		External: p.External, CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC()}
	if p.Credential != nil {
		v.CredentialSet = true
		v.CredentialSetAt = optTime(p.Credential.SetAt)
	}
	return v
}

// providerFields — изменяемые поля провайдера.
type providerFields struct {
	Name     string           `json:"name"`
	Type     string           `json:"type"`
	BaseURL  string           `json:"base_url"`
	CAPEM    string           `json:"ca_pem"`
	AuthURL  string           `json:"auth_url"`
	Scope    string           `json:"scope"`
	FolderID string           `json:"folder_id"`
	Timeouts ProviderTimeouts `json:"timeouts"`
}

func (f providerFields) input(slug string) apps.ProviderInput {
	return apps.ProviderInput{Slug: slug, Name: f.Name, Type: f.Type, BaseURL: f.BaseURL, CAPEM: f.CAPEM,
		AuthURL: f.AuthURL, Scope: f.Scope, FolderID: f.FolderID, ConnectTimeout: f.Timeouts.Connect,
		HeaderTimeout: f.Timeouts.Header, ResponseTimeout: f.Timeouts.Response, StreamIdleTimeout: f.Timeouts.StreamIdle}
}

type createProviderRequest struct {
	Slug string `json:"slug"`
	providerFields
}

func (d Deps) listProviders(w http.ResponseWriter, r *http.Request) {
	ps, err := d.Apps.Providers(r.Context())
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, providerNotFound))
		return
	}
	resp := struct {
		Items []ProviderView `json:"items"`
	}{Items: make([]ProviderView, 0, len(ps))}
	for _, p := range ps {
		resp.Items = append(resp.Items, providerView(p))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) createProvider(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req createProviderRequest
	if p := DecodeJSON(w, r, &req, providerMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	p, err := d.Apps.CreateProvider(r.Context(), by, req.input(req.Slug))
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, providerNotFound))
		return
	}
	w.Header().Set("Location", "/api/v1/providers/"+p.ID)
	WriteJSON(w, http.StatusCreated, providerView(p))
}

func (d Deps) getProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, providerNotFound)
	if !ok {
		return
	}
	p, err := d.Apps.Provider(r.Context(), id)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, providerNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, providerView(p))
}

func (d Deps) updateProvider(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, providerNotFound)
	if !ok {
		return
	}
	var req providerFields
	if p := DecodeJSON(w, r, &req, providerMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	p, err := d.Apps.UpdateProvider(r.Context(), by, id, req.input(""))
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, providerNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, providerView(p))
}

func (d Deps) deleteProvider(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, providerNotFound)
	if !ok {
		return
	}
	if _, err := d.Apps.DeleteProvider(r.Context(), by, id); err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, providerNotFound))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type credentialRequest struct {
	Credential string `json:"credential"`
}

func (d Deps) setProviderCredential(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, providerNotFound)
	if !ok {
		return
	}
	var req credentialRequest
	if p := DecodeJSON(w, r, &req, credentialMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	cred := []byte(req.Credential)
	p, err := d.Apps.SetCredential(r.Context(), by, id, cred)
	clear(cred)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, providerNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, providerView(p))
}

type externalRequest struct {
	External *bool  `json:"external"`
	Reason   string `json:"reason"`
	reauthFields
}

func (d Deps) setProviderExternal(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, providerNotFound)
	if !ok {
		return
	}
	var req externalRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if req.External == nil {
		WriteProblem(w, Invalid("Проверьте введённые данные.", FieldError{"external", "Укажите true или false."}))
		return
	}
	by = d.withConfirm(r, by, req.reauthFields, "provider.external_changed")
	p, err := d.Apps.SetExternal(r.Context(), by, id, *req.External, req.Reason)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, providerNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, providerView(p))
}
