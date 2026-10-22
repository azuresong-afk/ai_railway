package gwregistry_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

// Счётчики расхода в heartbeat (задача 3.18).

type budgetSync struct {
	gateway string
	started time.Time
	rep     gwregistry.BudgetReport
	err     error
}

func (b *budgetSync) SyncBudget(_ context.Context, gatewayID string, startedAt time.Time, rep gwregistry.BudgetReport) (gwregistry.BudgetState, error) {
	b.gateway, b.started, b.rep = gatewayID, startedAt, rep
	if b.err != nil {
		return gwregistry.BudgetState{}, b.err
	}
	return gwregistry.BudgetState{Month: rep.Months[len(rep.Months)-1].Month, Others: map[string]int64{"crm": 42}}, nil
}

func TestHeartbeatBudget(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	id := reg.Gateway.ID
	started := e.clock.now().Add(-time.Hour)
	month := func(m string, apps ...gwregistry.BudgetUsage) gwregistry.BudgetMonth {
		return gwregistry.BudgetMonth{Month: m, Apps: apps}
	}
	many := make([]gwregistry.BudgetUsage, gwregistry.MaxBudgetApps+1)
	for i := range many {
		many[i].App = "a" + strconv.Itoa(i)
	}
	for name, b := range map[string]*gwregistry.BudgetReport{
		"нет месяцев":           {},
		"три месяца":            {Months: []gwregistry.BudgetMonth{month("2026-08"), month("2026-09"), month("2026-10")}},
		"месяцы не по порядку":  {Months: []gwregistry.BudgetMonth{month("2026-10"), month("2026-09")}},
		"повтор месяца":         {Months: []gwregistry.BudgetMonth{month("2026-10"), month("2026-10")}},
		"неверный месяц":        {Months: []gwregistry.BudgetMonth{month("2026-13")}},
		"неверный ID":           {Months: []gwregistry.BudgetMonth{month("2026-10", gwregistry.BudgetUsage{App: "CRM"})}},
		"повтор приложения":     {Months: []gwregistry.BudgetMonth{month("2026-10", gwregistry.BudgetUsage{App: "crm"}, gwregistry.BudgetUsage{App: "crm"})}},
		"отрицательный расход":  {Months: []gwregistry.BudgetMonth{month("2026-10", gwregistry.BudgetUsage{App: "crm", Cost: -1})}},
		"счётчик сверх предела": {Months: []gwregistry.BudgetMonth{month("2026-10", gwregistry.BudgetUsage{App: "crm", Requests: 1<<62 + 1})}},
		"слишком много":         {Months: []gwregistry.BudgetMonth{month("2026-10", many...)}},
	} {
		in := gwregistry.HeartbeatInput{Version: "1", StartedAt: started, Budget: b}
		if _, err := e.svc.Heartbeat(ctx, id, in, testIP); !errors.Is(err, gwregistry.ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
		e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	}
	good := &gwregistry.BudgetReport{Months: []gwregistry.BudgetMonth{month("2026-09", gwregistry.BudgetUsage{App: "crm", Cost: 1 << 62}),
		month("2026-10")}}
	// Без времени запуска счётчики не принимаются: они привязаны к процессу.
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", Budget: good}, testIP); !errors.Is(err, gwregistry.ErrInvalidRequest) {
		t.Fatalf("без started_at: %v", err)
	}
	e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	// Хранилище не подключено — heartbeat принимается, ответа budget нет.
	res, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", StartedAt: started, Budget: good}, testIP)
	if err != nil || res.Budget != nil {
		t.Fatalf("без хранилища: %+v %v", res, err)
	}
	e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	bs := &budgetSync{}
	e.svc.SetBudgetSync(bs)
	res, err = e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", StartedAt: started, Budget: good}, testIP)
	if err != nil || res.Budget == nil || res.Budget.Month != "2026-10" || res.Budget.Others["crm"] != 42 {
		t.Fatalf("ответ: %+v %v", res.Budget, err)
	}
	if bs.gateway != id || !bs.started.Equal(started) || len(bs.rep.Months) != 2 {
		t.Fatalf("переданы счётчики: %+v", bs)
	}
	// Сбой хранилища не ломает heartbeat: счётчики придут со следующим.
	e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	bs.err = errors.New("сбой")
	if res, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", StartedAt: started, Budget: good}, testIP); err != nil || res.Budget != nil {
		t.Fatalf("сбой хранилища: %+v %v", res, err)
	}
}
