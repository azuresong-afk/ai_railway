package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/agents"
	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// observeMaxBody — предел тела tools:observe: до 256 описаний; шлюз делит
// больший список на несколько сообщений (ADR-0023, раздел 1).
const observeMaxBody = 8 << 20

// AgentsInternalRoutes — сообщения шлюза об увиденных инструментах (задача
// 4.8, ADR-0023, раздел 1): сервер ведёт реестр и поднимает оповещения
// agents.tool_new и agents.tool_changed (DM-25).
func AgentsInternalRoutes(svc *agents.Service, logger *slog.Logger) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/internal/v1/agents/tools:observe", Permission: PermGatewayInternal,
			MaxBody: observeMaxBody, Handler: observeTools(svc, logger)},
	}
}

// ObserveToolsRequest — описания из tools/list одного MCP-сервера или
// функции агента из запроса к модели (server: function).
type ObserveToolsRequest struct {
	Server  string            `json:"server"`
	AgentID string            `json:"agent_id"`
	Tools   []ObservedToolRaw `json:"tools"`
}

// ObservedToolRaw — описание инструмента как его прислал MCP-сервер;
// Suspicious — детекторы шлюза нашли в описании внедрённые инструкции
// (DM-24).
type ObservedToolRaw struct {
	Descriptor json.RawMessage `json:"descriptor"`
	Suspicious bool            `json:"suspicious"`
}

// ObserveToolsResponse — итог приёма: сколько инструментов новых,
// изменённых после одобрения, вернувшихся к одобренному описанию,
// подозрительных, прежних и не принятых сверх пределов реестра.
type ObserveToolsResponse struct {
	New        int `json:"new"`
	Changed    int `json:"changed"`
	Restored   int `json:"restored"`
	Suspicious int `json:"suspicious"`
	Unchanged  int `json:"unchanged"`
	Skipped    int `json:"skipped"`
}

func observeTools(svc *agents.Service, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		var req ObserveToolsRequest
		if prob := DecodeJSON(w, r, &req, observeMaxBody); prob != nil {
			WriteProblem(w, prob)
			return
		}
		in := agents.ObserveInput{Server: req.Server, AgentID: req.AgentID, Tools: make([]agents.ObservedRaw, 0, len(req.Tools))}
		for _, t := range req.Tools {
			in.Tools = append(in.Tools, agents.ObservedRaw{Descriptor: t.Descriptor, Suspicious: t.Suspicious})
		}
		ctx, cancel := contextTimeout(r, 5*time.Second)
		defer cancel()
		by := agents.By{Actor: audit.Actor{Type: audit.ActorGateway, ID: p.ID}, IP: clientAddr(r)}
		res, err := svc.Observe(ctx, by, in)
		var ie *agents.InputError
		switch {
		case err == nil:
			WriteJSON(w, http.StatusOK, ObserveToolsResponse{New: res.New, Changed: res.Changed, Restored: res.Restored,
				Suspicious: res.Suspicious, Unchanged: res.Unchanged, Skipped: res.Skipped})
		case errors.Is(err, agents.ErrTooSoon):
			w.Header().Set("Retry-After", strconv.Itoa(int(agents.ObserveInterval/time.Second)))
			WriteProblem(w, NewProblem(http.StatusTooManyRequests, CodeRateLimited,
				"Сообщение об инструментах этого MCP-сервера — не чаще раза в 10 секунд."))
		case errors.Is(err, agents.ErrNotFound):
			WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, "MCP-сервер или агент не найден в реестре."))
		case errors.As(err, &ie):
			fields := make([]FieldError, 0, len(ie.Errs))
			for _, e := range ie.Errs {
				fields = append(fields, FieldError{Field: "tools", Detail: e.Error()})
			}
			WriteProblem(w, Invalid("Неверные описания инструментов.", fields...))
		default:
			logger.Error("агенты: приём описаний инструментов", "error", err, "gateway_id", p.ID)
			WriteProblem(w, errInternal())
		}
	}
}
