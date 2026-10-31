package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/inventory"
)

// inventoryRoutes — реестр ИИ (ТЗ 5.11; задача 5.17 этапа 5, ADR-0029):
// сводка приложений, ключей и провайдеров, модели с файлами и хешами,
// использование по трафику. Ручные модели и их изменения пишутся в аудит
// сервисом той же транзакцией.
func inventoryRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/inventory", Permission: auth.PermInventoryRead, Handler: needInventory(d, d.inventoryOverview)},
		{Method: http.MethodGet, Path: "/api/v1/inventory/models", Permission: auth.PermInventoryRead, Handler: needInventory(d, d.listInventoryModels)},
		{Method: http.MethodPost, Path: "/api/v1/inventory/models", Permission: auth.PermInventoryManage, Idempotent: true,
			MaxBody: inventory.MaxBody, Handler: needInventory(d, d.createInventoryModel)},
		{Method: http.MethodGet, Path: "/api/v1/inventory/models/{id}", Permission: auth.PermInventoryRead, Handler: needInventory(d, d.getInventoryModel)},
		{Method: http.MethodPatch, Path: "/api/v1/inventory/models/{id}", Permission: auth.PermInventoryManage,
			MaxBody: inventory.MaxBody, Handler: needInventory(d, d.updateInventoryModel)},
		{Method: http.MethodDelete, Path: "/api/v1/inventory/models/{id}", Permission: auth.PermInventoryManage,
			Handler: needInventory(d, d.deleteInventoryModel)},
		{Method: http.MethodGet, Path: "/api/v1/inventory/usage", Permission: auth.PermInventoryRead, Handler: needInventory(d, d.listInventoryUsage)},
		{Method: http.MethodGet, Path: "/api/v1/inventory/aibom", Permission: auth.PermInventoryExport, Handler: needInventory(d, d.exportAIBOM)},
	}
}

func needInventory(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Inventory == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Реестр ИИ не подключён на сервере."))
			return
		}
		h(w, r)
	}
}

const inventoryModelNotFound = "Модель не найдена в реестре."

// inventoryProblem переводит ошибки реестра ИИ. Неизвестная ошибка — 500,
// причина — в техническом журнале.
func inventoryProblem(logger *slog.Logger, err error) *Problem {
	var ie *inventory.InputError
	switch {
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
	case errors.Is(err, inventory.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, inventoryModelNotFound)
	case errors.Is(err, inventory.ErrExists):
		return NewProblem(http.StatusConflict, CodeConflict, "Модель с этим именем у этого провайдера уже есть в реестре: измените её.")
	case errors.Is(err, inventory.ErrTooMany):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, "В реестре уже 5 000 моделей: удалите неиспользуемые.")
	case errors.Is(err, inventory.ErrExportTooLarge):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"В реестре больше 100 000 файлов моделей: AI-BOM одним документом не выгружается.")
	case errors.Is(err, inventory.ErrNoProvider):
		return Invalid("Проверьте введённые данные.", FieldError{Field: "provider", Detail: "Провайдер не найден: укажите ID существующего провайдера."})
	}
	logger.Error("реестр ИИ: ошибка обработки запроса", "error", err)
	return errInternal()
}

func (d Deps) inventoryBy(r *http.Request) (inventory.By, bool) {
	a, ok := actorOf(r)
	if !ok {
		return inventory.By{}, false
	}
	return inventory.By{Actor: a.Actor, IP: a.IP}, true
}

// InventoryKeyView — ключ приложения в сводке: без секрета и хеша.
type InventoryKeyView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Prefix    string    `json:"prefix"`
	State     string    `json:"state"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// InventoryAppView — приложение в сводке реестра.
type InventoryAppView struct {
	ID         string             `json:"id"`
	Slug       string             `json:"slug"`
	Name       string             `json:"name"`
	Env        string             `json:"env"`
	Department string             `json:"department"`
	Provider   string             `json:"provider"`
	Models     []string           `json:"models"`
	Archived   bool               `json:"archived"`
	Keys       []InventoryKeyView `json:"keys"`
}

// InventoryProviderView — провайдер в сводке: без адреса и учётных данных.
type InventoryProviderView struct {
	ID              string     `json:"id"`
	Slug            string     `json:"slug"`
	Name            string     `json:"name"`
	Type            string     `json:"type"`
	External        bool       `json:"external"`
	CredentialSet   bool       `json:"credential_set"`
	CredentialSetAt *time.Time `json:"credential_set_at,omitempty"`
}

// InventorySyncView — состояние пополнения по трафику.
type InventorySyncView struct {
	SyncedUpto   *time.Time `json:"synced_upto,omitempty"`
	RunAt        *time.Time `json:"run_at,omitempty"`
	LimitReached bool       `json:"limit_reached"`
	Skipped      int64      `json:"skipped"`
}

// InventoryOverview — ответ GET /api/v1/inventory.
type InventoryOverview struct {
	Applications []InventoryAppView      `json:"applications"`
	Providers    []InventoryProviderView `json:"providers"`
	Models       int                     `json:"models"`
	Usage        int                     `json:"usage"`
	Limits       InventoryLimits         `json:"limits"`
	Sync         InventorySyncView       `json:"sync"`
}

// InventoryLimits — пределы реестра.
type InventoryLimits struct {
	Models int `json:"models"`
	Usage  int `json:"usage"`
}

func (d Deps) inventoryOverview(w http.ResponseWriter, r *http.Request) {
	o, err := d.Inventory.Overview(r.Context())
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	v := InventoryOverview{Applications: make([]InventoryAppView, 0, len(o.Apps)), Providers: make([]InventoryProviderView, 0, len(o.Providers)),
		Models: o.Models, Usage: o.Usage, Limits: InventoryLimits{Models: inventory.MaxModels, Usage: inventory.MaxUsage},
		Sync: InventorySyncView{SyncedUpto: o.Sync.SyncedUpto, RunAt: o.Sync.RunAt, LimitReached: o.Sync.LimitReached, Skipped: o.Sync.Skipped}}
	for _, a := range o.Apps {
		av := InventoryAppView{ID: a.ID, Slug: a.Slug, Name: a.Name, Env: a.Env, Department: a.Department, Provider: a.Provider,
			Models: a.Models, Archived: a.Archived, Keys: make([]InventoryKeyView, 0, len(a.Keys))}
		if av.Models == nil {
			av.Models = []string{}
		}
		for _, k := range a.Keys {
			av.Keys = append(av.Keys, InventoryKeyView{ID: k.ID, Name: k.Name, Prefix: k.Prefix, State: k.State, ExpiresAt: k.ExpiresAt, CreatedAt: k.CreatedAt})
		}
		v.Applications = append(v.Applications, av)
	}
	for _, p := range o.Providers {
		v.Providers = append(v.Providers, InventoryProviderView{ID: p.ID, Slug: p.Slug, Name: p.Name, Type: p.Type, External: p.External,
			CredentialSet: p.CredentialSet, CredentialSetAt: p.CredentialSetAt})
	}
	WriteJSON(w, http.StatusOK, v)
}

// InventoryFileView — файл модели.
type InventoryFileView struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Role    string `json:"role"`
	HashAlg string `json:"hash_alg"`
	SHA256  string `json:"sha256"`
}

// InventoryModelView — модель в реестре; файлы — только в карточке.
type InventoryModelView struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Provider    string     `json:"provider"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Owner       string     `json:"owner"`
	Origin      string     `json:"origin"`
	Status      string     `json:"status"`
	FirstSeen   *time.Time `json:"first_seen,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	FileCount   int        `json:"file_count"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// InventoryUsageView — тройка «приложение, провайдер, модель» из трафика.
type InventoryUsageView struct {
	Application string    `json:"application"`
	Provider    string    `json:"provider"`
	Model       string    `json:"model"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// InventoryModelCard — ответ карточки модели: модель с файлами и
// приложения, которые её вызывали.
// Files всегда в ответе, пустой — [] (по схеме поле обязательно).
type InventoryModelCard struct {
	InventoryModelView
	Files []InventoryFileView  `json:"files"`
	Usage []InventoryUsageView `json:"usage"`
}

func inventoryModelView(m inventory.Model) InventoryModelView {
	return InventoryModelView{ID: m.ID, Kind: m.Kind, Provider: m.Provider, Name: m.Name, Version: m.Version, Title: m.Title,
		Description: m.Description, Owner: m.Owner, Origin: m.Origin, Status: m.Status, FirstSeen: m.FirstSeen, LastSeen: m.LastSeen,
		FileCount: m.FileCount, CreatedAt: m.CreatedAt.UTC(), UpdatedAt: m.UpdatedAt.UTC()}
}

func inventoryFiles(m inventory.Model) []InventoryFileView {
	out := make([]InventoryFileView, 0, len(m.Files))
	for _, f := range m.Files {
		out = append(out, InventoryFileView{Path: f.Path, Size: f.Size, Role: f.Role, HashAlg: f.HashAlg, SHA256: hex.EncodeToString(f.Hash)})
	}
	return out
}

func usageView(u inventory.Usage) InventoryUsageView {
	return InventoryUsageView{Application: u.App, Provider: u.Provider, Model: u.Model, FirstSeen: u.FirstSeen, LastSeen: u.LastSeen}
}

// oneParam — необязательный параметр строки запроса: не больше одного
// значения и не длиннее max байт (содержимое проверяет сервис).
func oneParam(q url.Values, name string, max int, bad *[]FieldError) string {
	vs, ok := q[name]
	if !ok {
		return ""
	}
	if len(vs) != 1 || len(vs[0]) > max {
		*bad = append(*bad, FieldError{Field: name, Detail: "Укажите одно значение не длиннее " + strconv.Itoa(max) + " байт."})
		return ""
	}
	return vs[0]
}

func (d Deps) listInventoryModels(w http.ResponseWriter, r *http.Request) {
	page, p := ParsePage(r)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	q := r.URL.Query()
	var bad []FieldError
	f := inventory.Filter{Kind: oneParam(q, "kind", 16, &bad), Origin: oneParam(q, "origin", 16, &bad),
		Provider: oneParam(q, "provider", 64, &bad), Query: oneParam(q, "q", 1024, &bad), Limit: page.Limit + 1}
	if len(bad) > 0 {
		WriteProblem(w, Invalid("Параметры отбора заданы неверно.", bad...))
		return
	}
	if c := page.Cursor; c != nil {
		f.After = &inventory.Cursor{CreatedAt: time.UnixMicro(c.TimeMicro).UTC(), ID: c.ID}
	}
	ms, err := d.Inventory.Models(r.Context(), f)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	resp := PageResponse[InventoryModelView]{Items: make([]InventoryModelView, 0, len(ms))}
	if len(ms) > page.Limit {
		ms = ms[:page.Limit]
		last := ms[len(ms)-1]
		resp.NextCursor = Cursor{TimeMicro: last.CreatedAt.UnixMicro(), ID: last.ID}.Encode()
	}
	for _, m := range ms {
		resp.Items = append(resp.Items, inventoryModelView(m))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) getInventoryModel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, inventoryModelNotFound)
	if !ok {
		return
	}
	m, us, err := d.Inventory.Model(r.Context(), id)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	d.writeInventoryCard(w, http.StatusOK, m, us)
}

func (d Deps) writeInventoryCard(w http.ResponseWriter, status int, m inventory.Model, us []inventory.Usage) {
	card := InventoryModelCard{InventoryModelView: inventoryModelView(m), Files: inventoryFiles(m), Usage: make([]InventoryUsageView, 0, len(us))}
	for _, u := range us {
		card.Usage = append(card.Usage, usageView(u))
	}
	WriteJSON(w, status, card)
}

func (d Deps) createInventoryModel(w http.ResponseWriter, r *http.Request) {
	by, ok := d.inventoryBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var raw json.RawMessage
	if p := DecodeJSON(w, r, &raw, inventory.MaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	in, err := inventory.ParseModelInput(raw)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	m, err := d.Inventory.CreateModel(r.Context(), by, in)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	w.Header().Set("Location", "/api/v1/inventory/models/"+m.ID)
	d.writeInventoryCard(w, http.StatusCreated, m, nil)
}

func (d Deps) updateInventoryModel(w http.ResponseWriter, r *http.Request) {
	by, ok := d.inventoryBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, inventoryModelNotFound)
	if !ok {
		return
	}
	var raw json.RawMessage
	if p := DecodeJSON(w, r, &raw, inventory.MaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	patch, err := inventory.ParseModelPatch(raw)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	if _, err := d.Inventory.UpdateModel(r.Context(), by, id, patch); err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	m, us, err := d.Inventory.Model(r.Context(), id)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	d.writeInventoryCard(w, http.StatusOK, m, us)
}

func (d Deps) deleteInventoryModel(w http.ResponseWriter, r *http.Request) {
	by, ok := d.inventoryBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, inventoryModelNotFound)
	if !ok {
		return
	}
	if err := d.Inventory.DeleteModel(r.Context(), by, id); err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) listInventoryUsage(w http.ResponseWriter, r *http.Request) {
	page, p := ParsePage(r)
	if p != nil {
		WriteProblem(w, p)
		return
	}
	q := r.URL.Query()
	var bad []FieldError
	f := inventory.UsageFilter{App: oneParam(q, "application", 1024, &bad), Provider: oneParam(q, "provider", 1024, &bad),
		Model: oneParam(q, "model", 1024, &bad), Limit: page.Limit + 1}
	if c := page.Cursor; c != nil {
		n, err := strconv.ParseInt(c.ID, 10, 64)
		if err != nil || n < 0 || c.TimeMicro != 0 {
			bad = append(bad, FieldError{Field: "cursor", Detail: "Курсор неверен или устарел: начните выборку сначала."})
		}
		f.After = n
	}
	if len(bad) > 0 {
		WriteProblem(w, Invalid("Параметры отбора заданы неверно.", bad...))
		return
	}
	us, err := d.Inventory.Usage(r.Context(), f)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	resp := PageResponse[InventoryUsageView]{Items: make([]InventoryUsageView, 0, len(us))}
	if len(us) > page.Limit {
		us = us[:page.Limit]
		resp.NextCursor = Cursor{ID: strconv.FormatInt(us[len(us)-1].ID, 10)}.Encode()
	}
	for _, u := range us {
		resp.Items = append(resp.Items, usageView(u))
	}
	WriteJSON(w, http.StatusOK, resp)
}

// exportAIBOM — GET /api/v1/inventory/aibom: реестр в CycloneDX 1.6
// (ADR-0029, п. 3). Запись data.export пишется сервисом той же транзакцией,
// что читает реестр; без неё документ не выдаётся.
func (d Deps) exportAIBOM(w http.ResponseWriter, r *http.Request) {
	by, ok := d.inventoryBy(r)
	p, pok := PrincipalFrom(r.Context())
	if !ok || !pok {
		WriteProblem(w, errInternal())
		return
	}
	// Одновременных выгрузок — в общих пределах выгрузок субъекта.
	if d.Exports != nil {
		subject := exportSubject(p)
		if !d.Exports.Acquire(subject) {
			w.Header().Set("Retry-After", exportRetryAfter)
			WriteProblem(w, NewProblem(http.StatusTooManyRequests, CodeRateLimited,
				"Выгрузка уже выполняется: дождитесь её окончания и повторите."))
			return
		}
		defer d.Exports.Release(subject)
	}
	bom, err := d.Inventory.ExportAIBOM(r.Context(), by, d.Version)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/vnd.cyclonedx+json; version=1.6")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Disposition", `attachment; filename="aisec-aibom.cdx.json"`)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(append(data, '\n')); err != nil {
		d.Logger.Warn("выгрузка AI-BOM не передана клиенту", "error", err)
	}
}
