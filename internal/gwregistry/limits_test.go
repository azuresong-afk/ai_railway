package gwregistry_test

import (
	"context"
	"errors"
	"testing"
	"time"

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

// Задача 5.44 этапа 5 (DM-50): состояние клиента aisec-media из heartbeat —
// проверка полей, хранение последнего, heartbeat без поля снимает данные.
func TestHeartbeatMedia(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	id := reg.Gateway.ID
	m := func(mod func(*gwregistry.MediaStats)) *gwregistry.MediaStats {
		s := &gwregistry.MediaStats{Inflight: 1, MaxInflight: 16, Analyzed: 3, Overloaded: 2,
			Selftest: &gwregistry.MediaSelftest{Result: gwregistry.MediaSelftestOK, At: e.clock.now().UTC()}}
		if mod != nil {
			mod(s)
		}
		return s
	}
	for name, s := range map[string]*gwregistry.MediaStats{
		"очередь больше предела": m(func(s *gwregistry.MediaStats) { s.Inflight = 17 }),
		"нулевой предел":         m(func(s *gwregistry.MediaStats) { s.MaxInflight, s.Inflight = 0, 0 }),
		"предел больше 65536":    m(func(s *gwregistry.MediaStats) { s.MaxInflight = 1<<16 + 1 }),
		"отрицательный счётчик":  m(func(s *gwregistry.MediaStats) { s.Timeout = -1 }),
		"счётчик больше 2^62":    m(func(s *gwregistry.MediaStats) { s.Analyzed = 1<<62 + 1 }),
		"неизвестный итог":       m(func(s *gwregistry.MediaStats) { s.Selftest.Result = "skip" }),
		"без времени самотеста":  m(func(s *gwregistry.MediaStats) { s.Selftest.At = time.Time{} }),
		"провалы у ok":           m(func(s *gwregistry.MediaStats) { s.Selftest.Failed = 1 }),
		"failed без провалов":    m(func(s *gwregistry.MediaStats) { s.Selftest.Result = gwregistry.MediaSelftestFailed }),
		"самотест в будущем":     m(func(s *gwregistry.MediaStats) { s.Selftest.At = e.clock.now().Add(time.Hour) }),
		"провалов больше 1000": m(func(s *gwregistry.MediaStats) {
			s.Selftest.Result, s.Selftest.Failed = gwregistry.MediaSelftestFailed, 1001
		}),
	} {
		if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", Media: s}, testIP); !errors.Is(err, gwregistry.ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
		e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	}
	if len(e.svc.GatewayMedia()) != 0 {
		t.Fatal("неверное состояние сохранено")
	}
	good := m(func(s *gwregistry.MediaStats) {
		s.Down, s.Unavailable = true, 1<<62
		s.Selftest.Result, s.Selftest.Failed = gwregistry.MediaSelftestFailed, 2
	})
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", Media: good}, testIP); err != nil {
		t.Fatalf("допустимое состояние: %v", err)
	}
	got, ok := e.svc.GatewayMedia()[id]
	if !ok || !got.Down || got.Unavailable != 1<<62 || got.Selftest.Failed != 2 || !got.At.Equal(e.clock.now().UTC()) {
		t.Fatalf("сохранено: %+v %v", got, ok)
	}
	got.Selftest.Failed = 99
	if e.svc.GatewayMedia()[id].Selftest.Failed != 2 {
		t.Fatal("GatewayMedia отдаёт не копию")
	}
	e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1"}, testIP); err != nil {
		t.Fatalf("heartbeat без media: %v", err)
	}
	if _, ok := e.svc.GatewayMedia()[id]; ok {
		t.Fatal("heartbeat без media не снял данные")
	}
}

// Задача 6.31 (ADR-0037): состояние буфера событий шлюза на диске из
// heartbeat — проверка полей, хранение последнего, heartbeat без поля
// снимает данные.
func TestHeartbeatEventBuffer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	id := reg.Gateway.ID
	b := func(mod func(*gwregistry.EventBufferStats)) *gwregistry.EventBufferStats {
		s := &gwregistry.EventBufferStats{Bytes: 4096, MaxBytes: 1 << 30, Records: 5, OldestAt: e.clock.now().Add(-time.Hour).UTC(),
			Spilled: 9, Replayed: 4, Corrupt: 1}
		if mod != nil {
			mod(s)
		}
		return s
	}
	for name, s := range map[string]*gwregistry.EventBufferStats{
		"предел меньше 64 МиБ":      b(func(s *gwregistry.EventBufferStats) { s.MaxBytes = 1 << 20 }),
		"предел больше 1 ПиБ":       b(func(s *gwregistry.EventBufferStats) { s.MaxBytes = 1<<50 + 1 }),
		"занято больше предела":     b(func(s *gwregistry.EventBufferStats) { s.Bytes = 2<<30 + 1 }),
		"отрицательный счётчик":     b(func(s *gwregistry.EventBufferStats) { s.Corrupt = -1 }),
		"счётчик больше 2^62":       b(func(s *gwregistry.EventBufferStats) { s.WriteErrors = 1<<62 + 1 }),
		"oldest_at у пустого":       b(func(s *gwregistry.EventBufferStats) { s.Records = 0 }),
		"oldest_at в будущем":       b(func(s *gwregistry.EventBufferStats) { s.OldestAt = e.clock.now().Add(time.Hour) }),
		"отрицательный размер":      b(func(s *gwregistry.EventBufferStats) { s.Bytes = -1 }),
		"отрицательные непосланные": b(func(s *gwregistry.EventBufferStats) { s.Records, s.OldestAt = -1, time.Time{} }),
	} {
		if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", EventBuffer: s}, testIP); !errors.Is(err, gwregistry.ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
		e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	}
	if len(e.svc.GatewayEventBuffer()) != 0 {
		t.Fatal("неверное состояние сохранено")
	}
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", EventBuffer: b(nil)}, testIP); err != nil {
		t.Fatalf("допустимое состояние: %v", err)
	}
	got, ok := e.svc.GatewayEventBuffer()[id]
	if !ok || got.Records != 5 || got.Corrupt != 1 || got.MaxBytes != 1<<30 || !got.At.Equal(e.clock.now().UTC()) {
		t.Fatalf("сохранено: %+v %v", got, ok)
	}
	e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1"}, testIP); err != nil {
		t.Fatalf("heartbeat без event_buffer: %v", err)
	}
	if _, ok := e.svc.GatewayEventBuffer()[id]; ok {
		t.Fatal("heartbeat без event_buffer не снял данные")
	}
}
