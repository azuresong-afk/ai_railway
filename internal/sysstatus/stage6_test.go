package sysstatus_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
)

// DM-44, задача 6.31 (ADR-0037): буфер событий шлюза на диске выводится по
// шлюзу; заполнение от 80 % или рост повреждённых записей и ошибок записи
// за окно поднимают gateway_event_buffer; без роста и ниже порога —
// снимается; шлюз без буфера — нет данных и нет условия.
func TestDM44_GatewayEventBuffer(t *testing.T) {
	e := newEnv()
	started := t0.Add(-time.Hour)
	buffers := map[string]gwregistry.EventBufferMark{}
	mark := func(bytes, records, corrupt, writeErr int64) gwregistry.EventBufferMark {
		m := gwregistry.EventBufferMark{At: e.clock, StartedAt: started, EventBufferStats: gwregistry.EventBufferStats{
			Bytes: bytes, MaxBytes: 1000 << 20, Records: records, Spilled: records, Corrupt: corrupt, WriteErrors: writeErr}}
		if records > 0 {
			m.OldestAt = t0.Add(-30 * time.Minute)
		}
		return m
	}
	o := e.opts()
	o.GatewayEventBuffer = func() map[string]gwregistry.EventBufferMark { return buffers }
	s, err := sysstatus.New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e.gws.list = []gwregistry.Gateway{
		{ID: "g1", Name: "a", Status: gwregistry.StatusActive, LastSeenAt: t0, StartedAt: started},
		{ID: "g2", Name: "b", Status: gwregistry.StatusActive, LastSeenAt: t0, StartedAt: started},
	}
	buffers["g1"] = mark(100<<20, 40, 0, 0)
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.Status(ctx)
	g := st.Gateways[0].EventBuffer
	if g == nil || g.UsedPercent != 10 || g.WarnPercent != sysstatus.EventBufferWarnPercent || g.Records != 40 || g.OldestAt == nil || g.StartedAt == nil {
		t.Fatalf("раздел шлюза: %+v", g)
	}
	if st.Gateways[1].EventBuffer != nil {
		t.Fatalf("шлюз без буфера: %+v", st.Gateways[1].EventBuffer)
	}
	if n := notif(st, sysstatus.ConditionEventBuffer); n.Active || n.Requirement != "РСБ.7" {
		t.Fatalf("10 %%: %+v", n)
	}
	// Заполнение 80 % — условие у g1.
	e.clock = t0.Add(time.Minute)
	buffers["g1"] = mark(800<<20, 400, 0, 0)
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := raisedStates(e); got["gateway_event_buffer:g1"] != "raised" {
		t.Fatalf("заполнение: %v", got)
	}
	if n := notif(s.Status(ctx), sysstatus.ConditionEventBuffer); !n.Active || !slices.Equal(n.Components, []string{"gateway:g1"}) {
		t.Fatalf("уведомление: %+v", n)
	}
	// Досылка опустошила буфер — снимается.
	e.clock = t0.Add(2 * time.Minute)
	buffers["g1"] = mark(0, 0, 0, 0)
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := raisedStates(e); got["gateway_event_buffer:g1"] != "cleared" {
		t.Fatalf("пустой буфер: %v", got)
	}
	// Рост повреждённых записей — условие, хотя буфер почти пуст.
	e.clock = t0.Add(3 * time.Minute)
	buffers["g1"] = mark(1<<20, 1, 2, 0)
	if n := notif(s.Status(ctx), sysstatus.ConditionEventBuffer); !n.Active {
		t.Fatalf("повреждения: %+v", n)
	}
	// Без роста за окно — снимается; ошибки записи после — снова.
	e.clock = e.clock.Add(sysstatus.DroppedWindow + time.Minute)
	if n := notif(s.Status(ctx), sysstatus.ConditionEventBuffer); n.Active {
		t.Fatalf("после окна: %+v", n)
	}
	buffers["g1"] = mark(1<<20, 1, 2, 1)
	if n := notif(s.Status(ctx), sysstatus.ConditionEventBuffer); !n.Active {
		t.Fatalf("ошибка записи: %+v", n)
	}
}
