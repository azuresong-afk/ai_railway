package api

import (
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// appMaxBody — предел тела запросов приложения: списки заказчика до 20 000
// слов и 1000 доменов.
const appMaxBody = 1 << 20

// applicationRoutes — приложения и их ключи (ТЗ 5.4, ИАФ.8, УПД.8; задача
// 2.11). Чтение и ключи — со Scoped: при области own обработчик отбирает
// только приложения, где пользователь — владелец, чужие отвечают 404.
// Выпуск и ротация ключа без Idempotency-Key: сохранённый ответ содержал
// бы сам ключ.
func applicationRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/applications", Permission: auth.PermApplicationsRead, Scoped: true,
			Handler: needApps(d, d.listApplications)},
		{Method: http.MethodPost, Path: "/api/v1/applications", Permission: auth.PermApplicationsManage, Idempotent: true,
			MaxBody: appMaxBody, Handler: needApps(d, d.createApplication)},
		{Method: http.MethodGet, Path: "/api/v1/applications/{id}", Permission: auth.PermApplicationsRead, Scoped: true,
			Handler: needApps(d, d.getApplication)},
		{Method: http.MethodPut, Path: "/api/v1/applications/{id}", Permission: auth.PermApplicationsManage,
			MaxBody: appMaxBody, Handler: needApps(d, d.updateApplication)},
		{Method: http.MethodDelete, Path: "/api/v1/applications/{id}", Permission: auth.PermApplicationsManage,
			Handler: needApps(d, d.archiveApplication)},
		{Method: http.MethodPut, Path: "/api/v1/applications/{id}/protection", Permission: auth.PermApplicationsPolicy,
			MaxBody: smallMaxBody, Handler: needApps(d, d.setProtection)},
		{Method: http.MethodGet, Path: "/api/v1/applications/{id}/keys", Permission: auth.PermApplicationsRead, Scoped: true,
			Handler: needApps(d, d.listAppKeys)},
		{Method: http.MethodPost, Path: "/api/v1/applications/{id}/keys", Permission: auth.PermAppKeysManage, Scoped: true,
			MaxBody: smallMaxBody, Handler: needApps(d, d.issueAppKey)},
		{Method: http.MethodPost, Path: "/api/v1/app-keys/{id}/rotate", Permission: auth.PermAppKeysManage, Scoped: true,
			MaxBody: smallMaxBody, Handler: needApps(d, d.rotateAppKey)},
		{Method: http.MethodPost, Path: "/api/v1/app-keys/{id}/revoke", Permission: auth.PermAppKeysManage, Scoped: true,
			Handler: needApps(d, d.revokeAppKey)},
	}
}

const (
	appNotFound = "Приложение не найдено."
	keyNotFound = "Ключ приложения не найден."
)

// ownerScope — фильтр владельца для разрешения perm (УПД.8): пусто — право
// на все объекты, иначе ID пользователя запроса. ok = false — субъект не
// пользователь.
func ownerScope(r *http.Request, perm string) (string, bool) {
	p, ok := PrincipalFrom(r.Context())
	if !ok || p.Caller == nil {
		return "", false
	}
	if p.Grants.Full(perm) {
		return "", true
	}
	return p.Caller.User.ID, true
}

// ApplicationView — приложение в ответах.
type ApplicationView struct {
	ID                string            `json:"id"`
	Slug              string            `json:"slug"`
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	Department        string            `json:"department"`
	OwnerID           string            `json:"owner_id"`
	Env               string            `json:"env"`
	ProviderID        string            `json:"provider_id"`
	Models            []string          `json:"models"`
	Aliases           map[string]string `json:"aliases"`
	Policy            string            `json:"policy"`
	PolicyMode        string            `json:"policy_mode"`
	Storage           string            `json:"storage"`
	FailMode          string            `json:"fail_mode"`
	UserFrom          string            `json:"user_from"`
	Quotas            apps.Quotas       `json:"quotas"`
	Lists             []apps.List       `json:"lists"`
	ExfilAllowDomains []string          `json:"exfil_allow_domains"`
	// Status — active или archived.
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ArchivedAt *time.Time `json:"archived_at,omitempty"`
}

func applicationView(a apps.Application) ApplicationView {
	v := ApplicationView{ID: a.ID, Slug: a.Slug, Name: a.Name, Description: a.Description, Department: a.Department,
		OwnerID: a.OwnerID, Env: a.Env, ProviderID: a.ProviderID, Models: a.Models, Aliases: a.Aliases,
		Policy: a.Policy, PolicyMode: a.PolicyMode, Storage: a.Storage, FailMode: a.FailMode, UserFrom: a.UserFrom,
		Quotas: a.Quotas, Lists: a.Lists, ExfilAllowDomains: a.ExfilAllowDomains, Status: "active",
		CreatedAt: a.CreatedAt.UTC(), UpdatedAt: a.UpdatedAt.UTC(), ArchivedAt: optTime(a.ArchivedAt)}
	if a.Archived() {
		v.Status = "archived"
	}
	if v.Models == nil {
		v.Models = []string{}
	}
	if v.Aliases == nil {
		v.Aliases = map[string]string{}
	}
	if v.Lists == nil {
		v.Lists = []apps.List{}
	}
	if v.ExfilAllowDomains == nil {
		v.ExfilAllowDomains = []string{}
	}
	return v
}

// appFields — изменяемые поля приложения, кроме полей защиты.
type appFields struct {
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	Department        string            `json:"department"`
	OwnerID           string            `json:"owner_id"`
	Env               string            `json:"env"`
	ProviderID        string            `json:"provider_id"`
	Models            []string          `json:"models"`
	Aliases           map[string]string `json:"aliases"`
	FailMode          string            `json:"fail_mode"`
	UserFrom          string            `json:"user_from"`
	Quotas            apps.Quotas       `json:"quotas"`
	Lists             []apps.List       `json:"lists"`
	ExfilAllowDomains []string          `json:"exfil_allow_domains"`
}

func (f appFields) input(slug string) apps.AppInput {
	return apps.AppInput{Slug: slug, Name: f.Name, Description: f.Description, Department: f.Department, OwnerID: f.OwnerID,
		Env: f.Env, ProviderID: f.ProviderID, Models: f.Models, Aliases: f.Aliases, FailMode: f.FailMode, UserFrom: f.UserFrom,
		Quotas: f.Quotas, Lists: f.Lists, ExfilAllowDomains: f.ExfilAllowDomains}
}

type protectionFields struct {
	Policy     string `json:"policy"`
	PolicyMode string `json:"policy_mode"`
	Storage    string `json:"storage"`
}

func (p protectionFields) empty() bool { return p == protectionFields{} }

type createApplicationRequest struct {
	Slug string `json:"slug"`
	appFields
	protectionFields
}

func (d Deps) listApplications(w http.ResponseWriter, r *http.Request) {
	owner, ok := ownerScope(r, auth.PermApplicationsRead)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	page, p := ParsePage(r)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	var after *apps.Cursor
	if page.Cursor != nil {
		after = &apps.Cursor{CreatedAt: time.UnixMicro(page.Cursor.TimeMicro).UTC(), ID: page.Cursor.ID}
	}
	list, err := d.Apps.Applications(r.Context(), owner, after, page.Limit+1)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, appNotFound))
		return
	}
	resp := PageResponse[ApplicationView]{Items: make([]ApplicationView, 0, min(len(list), page.Limit))}
	for i, a := range list {
		if i == page.Limit {
			last := list[i-1]
			resp.NextCursor = Cursor{TimeMicro: last.CreatedAt.UnixMicro(), ID: last.ID}.Encode()
			break
		}
		resp.Items = append(resp.Items, applicationView(a))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) createApplication(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	pr, _ := PrincipalFrom(r.Context())
	var req createApplicationRequest
	if p := DecodeJSON(w, r, &req, appMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	in := req.input(req.Slug)
	if in.OwnerID == "" {
		in.OwnerID = pr.Caller.User.ID
	}
	// Поля защиты задаёт только администратор безопасности (УПД.2); без
	// права — умолчания, а явно переданные значения отклоняются.
	var prot *apps.ProtectionInput
	if pr.Grants.Allows(auth.PermApplicationsPolicy) {
		prot = &apps.ProtectionInput{Policy: req.Policy, PolicyMode: req.PolicyMode, Storage: req.Storage}
	} else if !req.empty() {
		WriteProblem(w, NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Политику, режим политики и режим хранения задаёт администратор безопасности: создайте приложение без них."))
		return
	}
	a, err := d.Apps.CreateApplication(r.Context(), by, in, prot)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, appNotFound))
		return
	}
	w.Header().Set("Location", "/api/v1/applications/"+a.ID)
	WriteJSON(w, http.StatusCreated, applicationView(a))
}

func (d Deps) getApplication(w http.ResponseWriter, r *http.Request) {
	owner, ok := ownerScope(r, auth.PermApplicationsRead)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	a, err := d.Apps.Application(r.Context(), id, owner)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, appNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, applicationView(a))
}

func (d Deps) updateApplication(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	var req appFields
	if p := DecodeJSON(w, r, &req, appMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	a, err := d.Apps.UpdateApplication(r.Context(), by, id, req.input(""))
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, appNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, applicationView(a))
}

func (d Deps) archiveApplication(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	a, err := d.Apps.ArchiveApplication(r.Context(), by, id)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, appNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, applicationView(a))
}

func (d Deps) setProtection(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	var req protectionFields
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	a, err := d.Apps.SetProtection(r.Context(), by, id, apps.ProtectionInput(req))
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, appNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, applicationView(a))
}

// AppKeyView — ключ приложения без секрета (ИАФ.8).
type AppKeyView struct {
	ID            string `json:"id"`
	ApplicationID string `json:"application_id"`
	Name          string `json:"name"`
	Prefix        string `json:"prefix"`
	// Status — active, expired или revoked.
	Status       string     `json:"status"`
	AllowedCIDRs []string   `json:"allowed_cidrs"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	RotatedFrom  string     `json:"rotated_from,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

func appKeyView(k apps.Key, now time.Time) AppKeyView {
	v := AppKeyView{ID: k.ID, ApplicationID: k.AppID, Name: k.Name, Prefix: k.Prefix, Status: k.Status(now),
		AllowedCIDRs: []string{}, ExpiresAt: k.ExpiresAt.UTC(), CreatedAt: k.CreatedAt.UTC(), RotatedFrom: k.RotatedFrom,
		RevokedAt: optTime(k.RevokedAt)}
	for _, c := range k.AllowedCIDRs {
		v.AllowedCIDRs = append(v.AllowedCIDRs, c.String())
	}
	return v
}

func (d Deps) listAppKeys(w http.ResponseWriter, r *http.Request) {
	owner, ok := ownerScope(r, auth.PermApplicationsRead)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	keys, err := d.Apps.Keys(r.Context(), id, owner)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, appNotFound))
		return
	}
	resp := struct {
		Items []AppKeyView `json:"items"`
	}{Items: make([]AppKeyView, 0, len(keys))}
	now := time.Now()
	for _, k := range keys {
		resp.Items = append(resp.Items, appKeyView(k, now))
	}
	WriteJSON(w, http.StatusOK, resp)
}

type issueKeyRequest struct {
	Name          string   `json:"name"`
	ExpiresInDays int      `json:"expires_in_days"`
	AllowedCIDRs  []string `json:"allowed_cidrs"`
}

// CreatedAppKey — ответ на выпуск и ротацию: ключ показывается один раз.
type CreatedAppKey struct {
	AppKey AppKeyView `json:"app_key"`
	Key    string     `json:"key"`
	// Previous — прежний ключ при ротации (с сокращённым сроком).
	Previous *AppKeyView `json:"previous,omitempty"`
}

// noStore — ответ с секретом не кэшируется (ключ показывается один раз).
func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func (d Deps) issueAppKey(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	owner, ok := ownerScope(r, auth.PermAppKeysManage)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	var req issueKeyRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	k, raw, err := d.Apps.IssueKey(r.Context(), by, id, owner, apps.KeyInput{Name: req.Name, ExpiresInDays: req.ExpiresInDays, AllowedCIDRs: req.AllowedCIDRs})
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, appNotFound))
		return
	}
	noStore(w)
	WriteJSON(w, http.StatusCreated, CreatedAppKey{AppKey: appKeyView(k, time.Now()), Key: raw})
}

type rotateKeyRequest struct {
	OverlapHours  *int `json:"overlap_hours"`
	ExpiresInDays int  `json:"expires_in_days"`
}

func (d Deps) rotateAppKey(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	owner, ok := ownerScope(r, auth.PermAppKeysManage)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, keyNotFound)
	if !ok {
		return
	}
	var req rotateKeyRequest
	if r.ContentLength != 0 {
		if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
			WriteProblem(w, p)
			return
		}
	}
	in := apps.RotateInput{ExpiresInDays: req.ExpiresInDays}
	if req.OverlapHours != nil {
		if *req.OverlapHours < 0 || *req.OverlapHours > int(apps.MaxOverlap/time.Hour) {
			WriteProblem(w, Invalid("Проверьте введённые данные.", FieldError{"overlap_hours", "От 0 до 720 часов."}))
			return
		}
		o := time.Duration(*req.OverlapHours) * time.Hour
		in.Overlap = &o
	}
	k, raw, old, err := d.Apps.RotateKey(r.Context(), by, id, owner, in)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, keyNotFound))
		return
	}
	now := time.Now()
	prev := appKeyView(old, now)
	noStore(w)
	WriteJSON(w, http.StatusCreated, CreatedAppKey{AppKey: appKeyView(k, now), Key: raw, Previous: &prev})
}

func (d Deps) revokeAppKey(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	owner, ok := ownerScope(r, auth.PermAppKeysManage)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, keyNotFound)
	if !ok {
		return
	}
	k, err := d.Apps.RevokeKey(r.Context(), by, id, owner)
	if err != nil {
		WriteProblem(w, appsProblem(d.Logger, err, keyNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, appKeyView(k, time.Now()))
}
