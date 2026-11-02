package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Служебные базы (ОБН.4; задача 5.15, ADR-0028, п. 7). Загрузка и откат —
// у модуля базы с его правом (каталог теневого ИИ — shadow_ai.manage, база
// требований — compliance.base.load); здесь — общее состояние всех видов для
// «Состояния системы» (system.read, задача 5.9) и общие тексты отказов.

// ServiceDBStates — состояние служебных баз (*servicedb.Registry).
type ServiceDBStates interface {
	States(ctx context.Context) ([]servicedb.State, error)
}

// serviceDBReadTimeout — предел чтения состояния (проверка подписей при
// первом обращении).
const serviceDBReadTimeout = 15 * time.Second

// ServiceDBList — состояние всех подключённых видов.
type ServiceDBList struct {
	Items []servicedb.State `json:"items"`
}

func serviceDBRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/service-dbs", Permission: auth.PermSystemRead, Handler: d.listServiceDBs},
	}
}

func (d Deps) listServiceDBs(w http.ResponseWriter, r *http.Request) {
	if d.ServiceDBs == nil {
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Служебные базы не подключены на сервере."))
		return
	}
	ctx, cancel := contextTimeout(r, serviceDBReadTimeout)
	defer cancel()
	list, err := d.ServiceDBs.States(ctx)
	if err != nil {
		d.Logger.Error("служебные базы: состояние не прочитано", "class", "db", "error", err)
		WriteProblem(w, errInternal())
		return
	}
	WriteJSON(w, http.StatusOK, ServiceDBList{Items: list})
}

// serviceDBProblem — ответ на отказ в загрузке или откате (rollback)
// служебной базы; what — название базы в винительном падеже («каталог»,
// «базу»). Не отказ — nil.
func serviceDBProblem(err error, what string, rollback bool) *Problem {
	var re *servicedb.RejectError
	if !errors.As(err, &re) {
		return nil
	}
	switch re.Reason {
	case servicedb.ReasonStale:
		return NewProblem(http.StatusConflict, CodeConflict,
			"Версия файла не больше текущей: загрузите "+what+" из более нового выпуска.")
	case servicedb.ReasonNoPrevious:
		return NewProblem(http.StatusConflict, CodeConflict, "Предыдущей версии нет: возвращать нечего.")
	}
	text := serviceDBRejectText(re.Reason)
	if rollback {
		text = "Предыдущая версия не прошла повторную проверку и не возвращена. " + text
	}
	return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, text)
}

// serviceDBRejectText — причина отказа без содержимого файла (ТЗ 6.7).
func serviceDBRejectText(reason string) string {
	switch reason {
	case servicedb.ReasonSignature:
		return "Подпись файла или заверения ключа неверна: файл изменён или выпущен не производителем."
	case servicedb.ReasonPurpose:
		return "Ключ, которым подписан файл, заверен не для служебных баз."
	case servicedb.ReasonExpired:
		return "Срок заверения ключа, которым подписан файл, истёк или ещё не наступил."
	case servicedb.ReasonRevoked:
		return "Ключ, которым подписан файл, отозван производителем."
	case servicedb.ReasonKind:
		return "Файл — служебная база другого вида."
	case servicedb.ReasonDate:
		return "Дата выпуска базы вне срока заверения ключа подписи."
	case servicedb.ReasonContent:
		return "Подпись верна, но содержимое базы не прошло проверку этого выпуска."
	}
	return "Файл не похож на подписанную служебную базу (.aisecdb)."
}
