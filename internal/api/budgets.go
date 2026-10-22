package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// budgetRoutes — цены моделей и бюджеты приложений (ТЗ 5.8, решение Р7
// этапа 3, задача 3.18). Суммы — десятичные строки в рублях: цена — за
// 1 000 токенов, до 4 знаков после точки; бюджет — в месяц, до 2 знаков.
// Снятие или повышение жёсткого бюджета — не ослабление защиты (не DM-40):
// без повторной проверки, но с записью в аудит (relaxed).
func budgetRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/model-prices", Permission: auth.PermModelPricesRead, Handler: needApps(d, d.listPrices)},
		{Method: http.MethodPost, Path: "/api/v1/model-prices", Permission: auth.PermModelPricesManage, Idempotent: true,
			MaxBody: smallMaxBody, Handler: needApps(d, d.createPrice)},
		{Method: http.MethodPut, Path: "/api/v1/model-prices/{id}", Permission: auth.PermModelPricesManage,
			MaxBody: smallMaxBody, Handler: needApps(d, d.updatePrice)},
		{Method: http.MethodDelete, Path: "/api/v1/model-prices/{id}", Permission: auth.PermModelPricesManage,
			Handler: needApps(d, d.deletePrice)},
		{Method: http.MethodGet, Path: "/api/v1/budgets", Permission: auth.PermBudgetsRead, Handler: needApps(d, d.listBudgets)},
		{Method: http.MethodGet, Path: "/api/v1/applications/{id}/budget", Permission: auth.PermBudgetsRead,
			Handler: needApps(d, d.getBudget)},
		{Method: http.MethodPut, Path: "/api/v1/applications/{id}/budget", Permission: auth.PermBudgetsManage,
			MaxBody: smallMaxBody, Handler: needApps(d, d.setBudget)},
		{Method: http.MethodDelete, Path: "/api/v1/applications/{id}/budget", Permission: auth.PermBudgetsManage,
			Handler: needApps(d, d.deleteBudget)},
	}
}

const (
	priceNotFound  = "Цена модели не найдена."
	budgetNotFound = "Бюджет приложения не задан."
)

// budgetsProblem переводит ошибки цен и бюджетов; остальное — appsProblem.
func (d Deps) budgetsProblem(err error, notFound string) *Problem {
	switch {
	case errors.Is(err, apps.ErrPriceExists):
		return NewProblem(http.StatusConflict, CodeConflict, "Цена этой модели у провайдера уже задана: измените её.")
	case errors.Is(err, apps.ErrNoBudget):
		return NewProblem(http.StatusNotFound, CodeNotFound, budgetNotFound)
	case errors.Is(err, apps.ErrTooMany):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, "Достигнут предел числа цен: удалите неиспользуемые.")
	case errors.Is(err, apps.ErrArchived):
		return NewProblem(http.StatusConflict, CodeConflict, "Приложение в архиве: бюджет ему задать нельзя.")
	}
	return appsProblem(d.Logger, err, notFound)
}

// PriceView — цена модели в ответах.
type PriceView struct {
	ID         string    `json:"id"`
	ProviderID string    `json:"provider_id"`
	Model      string    `json:"model"`
	Input      string    `json:"input_price"`
	Output     string    `json:"output_price"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func priceView(p apps.Price) PriceView {
	return PriceView{ID: p.ID, ProviderID: p.ProviderID, Model: p.Model, Input: apps.FormatMoney(p.Input, apps.PriceDigits),
		Output: apps.FormatMoney(p.Output, apps.PriceDigits), CreatedAt: p.CreatedAt.UTC(), UpdatedAt: p.UpdatedAt.UTC()}
}

type priceRequest struct {
	ProviderID string `json:"provider_id"`
	Model      string `json:"model"`
	Input      string `json:"input_price"`
	Output     string `json:"output_price"`
}

func (d Deps) listPrices(w http.ResponseWriter, r *http.Request) {
	ps, err := d.Apps.Prices(r.Context())
	if err != nil {
		WriteProblem(w, d.budgetsProblem(err, priceNotFound))
		return
	}
	resp := struct {
		Items []PriceView `json:"items"`
	}{Items: make([]PriceView, 0, len(ps))}
	for _, p := range ps {
		resp.Items = append(resp.Items, priceView(p))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) createPrice(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req priceRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	p, err := d.Apps.CreatePrice(r.Context(), by, apps.PriceInput{ProviderID: req.ProviderID, Model: req.Model, Input: req.Input, Output: req.Output})
	if err != nil {
		WriteProblem(w, d.budgetsProblem(err, priceNotFound))
		return
	}
	w.Header().Set("Location", "/api/v1/model-prices/"+p.ID)
	WriteJSON(w, http.StatusCreated, priceView(p))
}

type priceUpdateRequest struct {
	Input  string `json:"input_price"`
	Output string `json:"output_price"`
}

func (d Deps) updatePrice(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, priceNotFound)
	if !ok {
		return
	}
	var req priceUpdateRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	p, err := d.Apps.UpdatePrice(r.Context(), by, id, apps.PriceInput{Input: req.Input, Output: req.Output})
	if err != nil {
		WriteProblem(w, d.budgetsProblem(err, priceNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, priceView(p))
}

func (d Deps) deletePrice(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, priceNotFound)
	if !ok {
		return
	}
	if _, err := d.Apps.DeletePrice(r.Context(), by, id); err != nil {
		WriteProblem(w, d.budgetsProblem(err, priceNotFound))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// BudgetView — бюджет приложения: режим и рубли в месяц.
type BudgetView struct {
	Mode      string    `json:"mode"`
	Limit     string    `json:"monthly_limit"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BudgetStatusView — бюджет и расход приложения за месяц. Расход — рубли с
// копейками (вверх); запросы к моделям без цены в расход не входят, их
// число — unpriced_requests («стоимость не определена»).
type BudgetStatusView struct {
	ApplicationID    string      `json:"application_id"`
	Application      string      `json:"application"`
	Name             string      `json:"name"`
	Month            string      `json:"month"`
	Budget           *BudgetView `json:"budget"`
	Spent            string      `json:"spent"`
	PricedTokens     int64       `json:"priced_tokens"`
	UnpricedTokens   int64       `json:"unpriced_tokens"`
	Requests         int64       `json:"requests"`
	UnpricedRequests int64       `json:"unpriced_requests"`
	Percent          int64       `json:"percent"`
	Exhausted        bool        `json:"exhausted"`
}

func budgetStatusView(st apps.BudgetStatus) BudgetStatusView {
	v := BudgetStatusView{ApplicationID: st.App.ID, Application: st.App.Slug, Name: st.App.Name, Month: st.Month,
		Spent: apps.FormatCost(st.Cost), PricedTokens: st.PricedTokens, UnpricedTokens: st.UnpricedTokens,
		Requests: st.Requests, UnpricedRequests: st.UnpricedRequests, Percent: st.Percent, Exhausted: st.Exhausted}
	if b := st.Budget; b != nil {
		v.Budget = &BudgetView{Mode: b.Mode, Limit: apps.FormatMoney(b.Limit, apps.BudgetDigits), UpdatedAt: b.UpdatedAt.UTC()}
	}
	return v
}

// monthParam — параметр month: один, до 7 символов (проверяет сервис).
func monthParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	vals := r.URL.Query()["month"]
	if len(vals) > 1 || len(vals) == 1 && len(vals[0]) > 7 {
		WriteProblem(w, Invalid("Параметр month — один месяц в виде ГГГГ-ММ, например 2026-10."))
		return "", false
	}
	if len(vals) == 0 {
		return "", true
	}
	return vals[0], true
}

func (d Deps) listBudgets(w http.ResponseWriter, r *http.Request) {
	month, ok := monthParam(w, r)
	if !ok {
		return
	}
	sts, month, err := d.Apps.BudgetStatuses(r.Context(), month)
	if err != nil {
		WriteProblem(w, d.budgetsProblem(err, appNotFound))
		return
	}
	resp := struct {
		Month string             `json:"month"`
		Items []BudgetStatusView `json:"items"`
	}{Month: month, Items: make([]BudgetStatusView, 0, len(sts))}
	for _, st := range sts {
		resp.Items = append(resp.Items, budgetStatusView(st))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) getBudget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	month, ok := monthParam(w, r)
	if !ok {
		return
	}
	st, err := d.Apps.BudgetStatus(r.Context(), id, month)
	if err != nil {
		WriteProblem(w, d.budgetsProblem(err, appNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, budgetStatusView(st))
}

type budgetRequest struct {
	Mode  string `json:"mode"`
	Limit string `json:"monthly_limit"`
}

func (d Deps) setBudget(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	var req budgetRequest
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if _, err := d.Apps.SetBudget(r.Context(), by, id, apps.BudgetInput{Mode: req.Mode, Limit: req.Limit}); err != nil {
		WriteProblem(w, d.budgetsProblem(err, appNotFound))
		return
	}
	st, err := d.Apps.BudgetStatus(r.Context(), id, "")
	if err != nil {
		WriteProblem(w, d.budgetsProblem(err, appNotFound))
		return
	}
	WriteJSON(w, http.StatusOK, budgetStatusView(st))
}

func (d Deps) deleteBudget(w http.ResponseWriter, r *http.Request) {
	by, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, appNotFound)
	if !ok {
		return
	}
	if _, err := d.Apps.DeleteBudget(r.Context(), by, id); err != nil {
		WriteProblem(w, d.budgetsProblem(err, appNotFound))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
