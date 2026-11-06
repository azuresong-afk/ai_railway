package events

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Агрегаты Memory, как и задание PGStore.Aggregate, не учитывают события
// запусков тестирования устойчивости (5Н31 ревью 5.r4 этапа 5).
func TestMemoryAggregatesSkipTest(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)
	evs := make([]Event, 0, 4)
	for i := range 4 {
		ts := at.Add(time.Duration(i) * time.Second)
		ms := uint64(ts.UnixMilli()) //nolint:gosec // G115: время теста положительно
		evs = append(evs, Event{ID: fmt.Sprintf("%08x-%04x-7000-8000-%012d", ms>>16, ms&0xffff, i+1), Time: ts,
			Type: TypeGatewayRequest, App: "crm", PolicyMode: ModeEnforce, Test: i > 0,
			Decision: &Decision{Action: "allow", Severity: "low"}, Tokens: &Tokens{Prompt: 5, Completion: 5}})
	}
	if _, err := m.Insert(ctx, Ingest{GatewayID: "gw", ReceivedAt: time.Now(), Events: evs}); err != nil {
		t.Fatal(err)
	}
	for _, iv := range []string{IntervalMinute, IntervalHour} {
		rows, err := m.Aggregates(ctx, StatsQuery{Interval: iv, From: at.Add(-time.Hour), To: at.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Events != 1 || rows[0].TokensPrompt != 5 {
			t.Fatalf("%s: %+v", iv, rows)
		}
	}
}
