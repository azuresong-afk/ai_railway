package sysstatus_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
)

// raisedStates — последнее состояние каждого условия по записям system.alert.
func raisedStates(e *testEnv) map[string]string {
	got := map[string]string{}
	for _, r := range e.mem.Records {
		d := r.Details.(map[string]any)
		got[d["condition"].(string)] = d["state"].(string)
	}
	return got
}

// DM-44, задача 5.9 этапа 5 (4Н11, 4Н13): счётчики в памяти шлюза выводятся по
// шлюзу; рост вытеснений из-за общего предела поднимает gateway_limits,
// вытеснения из-за доли приложения — нет; без роста за окно условие
// снимается; шлюз прежней версии без поля — нет данных и нет условия.
func TestDM44_GatewayLimitsEvictions(t *testing.T) {
	e := newEnv()
	started := t0.Add(-time.Hour)
	limits := map[string]gwregistry.LimitsMark{}
	mark := func(tool, sess, app int64) gwregistry.LimitsMark {
		return gwregistry.LimitsMark{At: e.clock, StartedAt: started, Limits: gwregistry.Limits{
			ToolRate: &gwregistry.ToolRateLimits{Keys: 10, MaxKeys: 100, Evictions: tool},
			Sessions: &gwregistry.SessionLimits{Sessions: 5, MaxSessions: 8, MaxAppSessions: 2, Evictions: sess, AppEvictions: app}}}
	}
	o := e.opts()
	o.GatewayLimits = func() map[string]gwregistry.LimitsMark { return limits }
	s, err := sysstatus.New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e.gws.list = []gwregistry.Gateway{
		{ID: "g1", Name: "a", Status: gwregistry.StatusActive, LastSeenAt: t0, StartedAt: started},
		{ID: "g2", Name: "b", Status: gwregistry.StatusActive, LastSeenAt: t0, StartedAt: started},
	}
	limits["g1"] = mark(3, 1, 0)
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.Status(ctx)
	if g := st.Gateways[0].Limits; g == nil || g.ToolRate.Evictions != 3 || g.Sessions.MaxAppSessions != 2 || g.StartedAt == nil {
		t.Fatalf("раздел шлюза: %+v", g)
	}
	if st.Gateways[1].Limits != nil {
		t.Fatalf("шлюз прежней версии: %+v", st.Gateways[1].Limits)
	}
	// Первое наблюдение — точка отсчёта.
	if n := notif(st, sysstatus.ConditionGatewayLimits); n.Active || n.Requirement != "РСБ.7" {
		t.Fatalf("первое наблюдение: %+v", n)
	}
	// Рост только вытеснений по доле приложения — условия нет.
	e.clock = t0.Add(time.Minute)
	limits["g1"] = mark(3, 1, 50)
	if n := notif(s.Status(ctx), sysstatus.ConditionGatewayLimits); n.Active {
		t.Fatalf("вытеснения по доле: %+v", n)
	}
	// Вытеснения счётчиков лимитов выросли — условие у g1.
	e.clock = t0.Add(2 * time.Minute)
	limits["g1"] = mark(4, 1, 50)
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := raisedStates(e); got["gateway_limits:g1"] != "raised" {
		t.Fatalf("рост вытеснений: %v", got)
	}
	if n := notif(s.Status(ctx), sysstatus.ConditionGatewayLimits); !n.Active || !slices.Equal(n.Components, []string{"gateway:g1"}) {
		t.Fatalf("уведомление: %+v", n)
	}
	// Без роста за окно — снимается.
	e.clock = e.clock.Add(sysstatus.DroppedWindow + time.Minute)
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := raisedStates(e); got["gateway_limits:g1"] != "cleared" {
		t.Fatalf("после окна: %v", got)
	}
	// Новый запуск шлюза с вытеснениями сессий — рост.
	started = e.clock.Add(-time.Minute)
	limits["g1"] = mark(0, 2, 0)
	if n := notif(s.Status(ctx), sysstatus.ConditionGatewayLimits); !n.Active {
		t.Fatalf("новый запуск: %+v", n)
	}
}

// 4Н25 ревью 4.r3: предупреждение от 90 % предела сводок теневого ИИ,
// ошибка — при достижении предела; активно одно из двух; сбой источника —
// раздел недоступен, состояние условий не меняется.
func TestStatusShadowAIStorage(t *testing.T) {
	e := newEnv()
	var n int64
	var serr error
	o := e.opts()
	o.ShadowAIStorage = func(context.Context) (int64, int64, error) { return n, 1000, serr }
	s, err := sysstatus.New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, c := range []struct {
		n          int64
		warn, full bool
	}{{0, false, false}, {899, false, false}, {900, true, false}, {999, true, false}, {1000, false, true}, {1001, false, true}} {
		n = c.n
		st := s.Status(ctx)
		w, f := notif(st, sysstatus.ConditionShadowAIStorage), notif(st, sysstatus.ConditionShadowAIFull)
		if w.Active != c.warn || f.Active != c.full || st.ShadowAIStorage == nil || st.ShadowAIStorage.Aggregates != c.n ||
			st.ShadowAIStorage.WarnPercent != 90 {
			t.Fatalf("%d сводок: предупреждение %v, ошибка %v, раздел %+v", c.n, w.Active, f.Active, st.ShadowAIStorage)
		}
	}
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := raisedStates(e); got[sysstatus.ConditionShadowAIFull] != "raised" {
		t.Fatalf("запись об ошибке: %v", got)
	}
	serr = errors.New("нет связи с БД")
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.Status(ctx)
	if !slices.Contains(st.Unavailable, "shadow_ai_storage") || st.ShadowAIStorage != nil {
		t.Fatalf("сбой источника: %+v %v", st.ShadowAIStorage, st.Unavailable)
	}
	if got := raisedStates(e); got[sysstatus.ConditionShadowAIFull] != "raised" {
		t.Fatalf("при сбое условие снято: %v", got)
	}
}

// ADR-0028, задача 5.9 этапа 5: текущая сохранённая служебная база не
// прошла повторную проверку — условие по виду: работает предыдущая версия
// или база не используется; непрошедшая предыдущая при действующей
// текущей — не условие.
func TestStatusServiceDBInvalid(t *testing.T) {
	e := newEnv()
	ok := &servicedb.VersionState{Version: 1, Valid: true}
	bad := &servicedb.VersionState{Version: 2, Reason: "signature_invalid"}
	states := []servicedb.State{
		{Kind: "shadow_ai_catalog", Title: "Каталог", Active: servicedb.ActivePrevious, Current: bad, Previous: ok},
		{Kind: "compliance_requirements", Title: "База требований", Active: servicedb.ActiveNone, Current: bad},
		{Kind: "third", Title: "Третья", Active: servicedb.ActiveCurrent, Current: ok, Previous: bad},
	}
	var serr error
	o := e.opts()
	o.ServiceDBs = func(context.Context) ([]servicedb.State, error) { return states, serr }
	s, err := sysstatus.New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := s.Status(ctx)
	prev, unused := notif(st, sysstatus.ConditionServiceDBPrevious), notif(st, sysstatus.ConditionServiceDBUnused)
	if !prev.Active || prev.Requirement != "ОЦЛ.5" || !slices.Equal(prev.Components, []string{"service_db:shadow_ai_catalog"}) {
		t.Fatalf("работает предыдущая: %+v", prev)
	}
	if !unused.Active || !slices.Equal(unused.Components, []string{"service_db:compliance_requirements"}) {
		t.Fatalf("не используется: %+v", unused)
	}
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	got := raisedStates(e)
	if got["service_db_previous:shadow_ai_catalog"] != "raised" || got["service_db_unused:compliance_requirements"] != "raised" ||
		got["service_db_previous:third"] != "" {
		t.Fatalf("записи: %v", got)
	}
	// Условие по виду базы не снимается как «пропавший шлюз», а после
	// загрузки исправной версии — снимается.
	states[0] = servicedb.State{Kind: "shadow_ai_catalog", Active: servicedb.ActiveCurrent, Current: ok}
	serr = nil
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	got = raisedStates(e)
	if got["service_db_previous:shadow_ai_catalog"] != "cleared" || got["service_db_unused:compliance_requirements"] != "raised" {
		t.Fatalf("после исправления: %v", got)
	}
	serr = errors.New("нет связи с БД")
	if st := s.Status(ctx); !slices.Contains(st.Unavailable, "service_dbs") {
		t.Fatalf("сбой источника: %v", st.Unavailable)
	}
}
