package alerting

import (
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Задача 4.19 (ADR-0024, раздел 4): серия событий с ml_unavailable на одном
// шлюзе — оповещение frequency.ml_unavailable; одиночные пропуски ML и
// события без признака — нет.
func TestDM01_MLUnavailableSpikeAlert(t *testing.T) {
	e := newEnv(t)
	noML := func() *events.Event {
		ev := e.event(t, "crm-bot", "gigachat", "allow")
		ev.Decision.MLUnavailable = true
		return ev
	}
	e.ingest(t, repeat(MLUnavailableCount-1, noML)...)
	// События с работающим ML не считаются.
	e.ingest(t, repeat(10, func() *events.Event { return e.event(t, "crm-bot", "gigachat", "allow") })...)
	e.periodic(t, nil)
	if got := e.alerts(t, BuiltinMLUnavailable); len(got) != 0 {
		t.Fatalf("%d пропусков ML — оповещение: %+v", MLUnavailableCount-1, got)
	}
	e.ingest(t, noML())
	e.periodic(t, nil)
	got := e.alerts(t, BuiltinMLUnavailable)
	if len(got) != 1 || got[0].Values["gateway"] != testGateway || got[0].Count != MLUnavailableCount {
		t.Fatalf("всплеск ml_unavailable: %+v", got)
	}
}

func TestMLUnavailableFilterMatch(t *testing.T) {
	f, err := events.ParseFilter(`ml_unavailable = true`)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		r    *events.Record
		want bool
	}{
		{&events.Record{}, false},
		{&events.Record{Details: &events.Details{Decision: &events.Decision{}}}, false},
		{&events.Record{Details: &events.Details{Decision: &events.Decision{MLUnavailable: true}}}, true},
	} {
		if f.Match(c.r) != c.want {
			t.Errorf("%+v: ожидалось %v", c.r.Details, c.want)
		}
	}
}
