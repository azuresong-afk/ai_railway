package gwregistry_test

import (
	"context"
	"errors"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

// Задача 5.9 этапа 5: счётчики в памяти шлюза из heartbeat — проверка
// полей, хранение последних, heartbeat без поля (шлюз прежней версии)
// принимается и данные снимает.
func TestHeartbeatLimits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	id := reg.Gateway.ID
	tr := func(keys, maxKeys, ev int64) *gwregistry.Limits {
		return &gwregistry.Limits{ToolRate: &gwregistry.ToolRateLimits{Keys: keys, MaxKeys: maxKeys, Evictions: ev}}
	}
	ss := func(n, maxN, app, ev, appEv int64) *gwregistry.Limits {
		return &gwregistry.Limits{Sessions: &gwregistry.SessionLimits{Sessions: n, MaxSessions: maxN, MaxAppSessions: app,
			Evictions: ev, AppEvictions: appEv}}
	}
	for name, l := range map[string]*gwregistry.Limits{
		"пусто": {},
		"ключей больше предела":         tr(3, 2, 0),
		"нулевой предел ключей":         tr(0, 0, 0),
		"отрицательные вытеснения":      tr(1, 2, -1),
		"вытеснения больше 2^62":        tr(1, 2, 1<<62+1),
		"сессий больше предела":         ss(5, 4, 1, 0, 0),
		"доля больше предела":           ss(1, 4, 5, 0, 0),
		"нулевая доля":                  ss(1, 4, 0, 0, 0),
		"отрицательные вытеснения доли": ss(1, 4, 1, 0, -1),
	} {
		if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", Limits: l}, testIP); !errors.Is(err, gwregistry.ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
		e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	}
	if len(e.svc.GatewayLimits()) != 0 {
		t.Fatal("неверные счётчики сохранены")
	}
	good := &gwregistry.Limits{ToolRate: tr(2, 2, 1<<62).ToolRate, Sessions: ss(4, 4, 4, 7, 9).Sessions}
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", Limits: good}, testIP); err != nil {
		t.Fatalf("допустимые счётчики: %v", err)
	}
	m, ok := e.svc.GatewayLimits()[id]
	if !ok || m.ToolRate.Evictions != 1<<62 || m.Sessions.AppEvictions != 9 || !m.At.Equal(e.clock.now().UTC()) {
		t.Fatalf("сохранено: %+v %v", m, ok)
	}
	e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1"}, testIP); err != nil {
		t.Fatalf("heartbeat без limits: %v", err)
	}
	if _, ok := e.svc.GatewayLimits()[id]; ok {
		t.Fatal("heartbeat без limits не снял данные")
	}
}
