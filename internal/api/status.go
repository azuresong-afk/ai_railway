package api

import (
	"context"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
)

// StatusService — «Состояние системы» (задача 2.20).
type StatusService interface {
	Status(ctx context.Context) sysstatus.Status
}

// statusTimeout — предел сборки состояния: шлюзы, счётчики и размер журнала
// собираются несколькими запросами к БД (у каждого свой короткий срок).
const statusTimeout = 15 * time.Second

// statusRoutes — состояние системы: компоненты, шлюзы, целостность и
// самотест, время, отброшенные события, заполнение хранилища, уведомления
// раздела 7 (ТЗ 6.2 п. 12). Только чтение, право system.read.
func statusRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/system/status", Permission: auth.PermSystemRead, Handler: d.systemStatus},
	}
}

func (d Deps) systemStatus(w http.ResponseWriter, r *http.Request) {
	if d.Status == nil {
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Состояние системы не настроено на сервере."))
		return
	}
	ctx, cancel := contextTimeout(r, statusTimeout)
	defer cancel()
	WriteJSON(w, http.StatusOK, d.Status.Status(ctx))
}
