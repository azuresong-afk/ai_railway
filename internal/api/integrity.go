package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// PermIntegrityVerify — проверка целостности по команде (ОЦЛ.2); разрешение
// каталога internal/auth (задача 2.9), из предустановленных ролей — только у
// администратора безопасности.
const PermIntegrityVerify = auth.PermIntegrityVerify

// IntegrityService — контроль целостности сервера (задача 2.17).
type IntegrityService interface {
	Latest(ctx context.Context) ([]integrity.Result, error)
	CheckBy(ctx context.Context, by audit.Actor, ip netip.Addr) (integrity.Result, error)
}

// verifyTimeout — предел ручной проверки: хеширование бинарника и статики.
const verifyTimeout = 2 * time.Minute

// integrityRoutes — итоги контроля целостности и проверка по команде
// администратора (ОЦЛ.2, ОЦЛ.5).
func integrityRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/system/integrity", Permission: auth.PermSystemRead, Handler: needIntegrity(d, d.integrityLatest)},
		{Method: http.MethodPost, Path: "/api/v1/system/integrity/verify", Permission: PermIntegrityVerify, Handler: needIntegrity(d, d.integrityVerify)},
	}
}

func needIntegrity(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Integrity == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Контроль целостности не настроен на сервере."))
			return
		}
		h(w, r)
	}
}

// IntegrityFailure — файл с нарушением целостности.
type IntegrityFailure struct {
	Path    string `json:"path"`
	Problem string `json:"problem"`
}

// IntegrityCheck — итог проверки целостности компонента.
type IntegrityCheck struct {
	Component       string             `json:"component"`
	Trigger         string             `json:"trigger"`
	CheckedAt       time.Time          `json:"checked_at"`
	OK              bool               `json:"ok"`
	Reason          string             `json:"reason"`
	ManifestVersion string             `json:"manifest_version"`
	TestSigned      bool               `json:"test_signed"`
	CheckedFiles    int                `json:"checked_files"`
	Failures        []IntegrityFailure `json:"failures"`
	Omitted         int                `json:"omitted"`
}

// IntegrityList — ответ GET /api/v1/system/integrity.
type IntegrityList struct {
	Items []IntegrityCheck `json:"items"`
}

func integrityView(r integrity.Result) IntegrityCheck {
	v := IntegrityCheck{
		Component: r.Component, Trigger: string(r.Trigger), CheckedAt: r.At.UTC(), OK: r.OK(), Reason: string(r.Reason),
		ManifestVersion: r.ManifestVersion, TestSigned: r.TestSigned, CheckedFiles: r.Checked,
		Failures: make([]IntegrityFailure, 0, len(r.Failures)), Omitted: r.Omitted,
	}
	for _, f := range r.Failures {
		v.Failures = append(v.Failures, IntegrityFailure{Path: f.Path, Problem: string(f.Problem)})
	}
	return v
}

func (d Deps) integrityLatest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextTimeout(r, 10*time.Second)
	defer cancel()
	list, err := d.Integrity.Latest(ctx)
	if err != nil {
		d.Logger.Error("итоги контроля целостности не прочитаны", "error", err)
		WriteProblem(w, errInternal())
		return
	}
	resp := IntegrityList{Items: make([]IntegrityCheck, 0, len(list))}
	for _, res := range list {
		resp.Items = append(resp.Items, integrityView(res))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) integrityVerify(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	by := audit.Actor{Type: audit.ActorAPIToken, ID: p.ID}
	if p.Caller != nil {
		by = audit.Actor{Type: audit.ActorUser, ID: p.Caller.User.ID, Name: p.Caller.User.Login}
	}
	// Обрыв соединения не прерывает проверку: начатая по команде проверка
	// доходит до конца и попадает в журнал аудита.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), verifyTimeout)
	defer cancel()
	res, err := d.Integrity.CheckBy(ctx, by, clientAddr(r))
	if errors.Is(err, integrity.ErrInterrupted) {
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Проверка прервана: истёк срок или сервер останавливается."))
		return
	}
	if err != nil {
		d.Logger.Error("проверка целостности по команде не выполнена", "error", err)
		WriteProblem(w, errInternal())
		return
	}
	WriteJSON(w, http.StatusOK, integrityView(res))
}
