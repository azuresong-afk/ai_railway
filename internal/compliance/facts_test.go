package compliance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/notify"
)

type fakeRules struct {
	rules []alerting.Rule
	err   error
}

func (f fakeRules) Rules(context.Context) ([]alerting.Rule, error) { return f.rules, f.err }

type fakeChannels struct {
	chs []notify.Channel
	err error
}

func (f fakeChannels) Channels(context.Context) ([]notify.Channel, error) { return f.chs, f.err }

// Без источников все группы помечаются недоступными, сбор не падает.
func TestSystemFactsNoSources(t *testing.T) {
	s, err := (&SystemFacts{Now: func() time.Time { return testNow }}).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{GroupApps, GroupRoles, GroupAuditChain, GroupIntegrity, GroupAlerts, GroupChannels} {
		if !s.Unavailable[g] {
			t.Errorf("группа %s не помечена недоступной", g)
		}
	}
}

// Считаются только включённые правила и каналы; ошибка источника — недоступность группы.
func TestSystemFactsAlertsAndChannels(t *testing.T) {
	f := &SystemFacts{
		Alerts:   fakeRules{rules: []alerting.Rule{{Enabled: true}, {Enabled: false}, {Enabled: true}}},
		Channels: fakeChannels{chs: []notify.Channel{{Enabled: false}, {Enabled: true}}},
	}
	s, err := f.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.AlertRulesEnabled != 2 || s.ChannelsEnabled != 1 || s.Unavailable[GroupAlerts] || s.Unavailable[GroupChannels] {
		t.Fatalf("снимок: %+v", s)
	}
	f.Alerts, f.Channels = fakeRules{err: errors.New("сбой")}, fakeChannels{err: errors.New("сбой")}
	if s, _ = f.Snapshot(context.Background()); !s.Unavailable[GroupAlerts] || !s.Unavailable[GroupChannels] { //nolint:gosec // G104: ошибка проверяется ниже по результату
		t.Fatalf("ошибка источника не отмечена: %+v", s.Unavailable)
	}
}
