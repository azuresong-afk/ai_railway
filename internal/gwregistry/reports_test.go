package gwregistry_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

// Итоги самотеста и целостности в heartbeat (задача 2.20): проверка полей.
func TestHeartbeatReportsValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	id := reg.Gateway.ID
	now := e.clock.now()
	ok := func() *gwregistry.CheckReport { return &gwregistry.CheckReport{OK: true, At: now} }
	for name, in := range map[string]gwregistry.HeartbeatInput{
		"самотест: ok при failed":               {Version: "1", Selftest: &gwregistry.CheckReport{OK: true, At: now, Failed: 1}},
		"самотест: failed отрицательно":         {Version: "1", Selftest: &gwregistry.CheckReport{At: now, Failed: -1}},
		"самотест: failed больше предела":       {Version: "1", Selftest: &gwregistry.CheckReport{At: now, Failed: 1001}},
		"самотест: без времени":                 {Version: "1", Selftest: &gwregistry.CheckReport{OK: true}},
		"самотест: причина не используется":     {Version: "1", Selftest: &gwregistry.CheckReport{OK: true, At: now, Reason: "ok"}},
		"целостность: причина вне перечня":      {Version: "1", Integrity: &gwregistry.CheckReport{At: now, Reason: "other", Failed: 1}},
		"целостность: пустая причина":           {Version: "1", Integrity: &gwregistry.CheckReport{OK: true, At: now}},
		"целостность: ok с причиной-нарушением": {Version: "1", Integrity: &gwregistry.CheckReport{OK: true, At: now, Reason: "files_mismatch"}},
		"целостность: нарушение с reason ok":    {Version: "1", Integrity: &gwregistry.CheckReport{At: now, Reason: "ok", Failed: 1}},
		"целостность: ok при failed":            {Version: "1", Integrity: &gwregistry.CheckReport{OK: true, At: now, Reason: "ok", Failed: 2}},
		"время проверки в будущем":              {Version: "1", Selftest: &gwregistry.CheckReport{OK: true, At: now.Add(time.Hour)}},
	} {
		if _, err := e.svc.Heartbeat(ctx, id, in, testIP); !errors.Is(err, gwregistry.ErrInvalidRequest) {
			t.Errorf("%s: %v", name, err)
		}
		e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	}
	// Граница: тысяча провалов и запас по времени в пределах пяти минут.
	in := gwregistry.HeartbeatInput{Version: "1", Selftest: &gwregistry.CheckReport{At: e.clock.now().Add(4 * time.Minute), Failed: 1000}, Integrity: ok()}
	in.Integrity.Reason = "ok"
	if _, err := e.svc.Heartbeat(ctx, id, in, testIP); err != nil {
		t.Fatalf("допустимые итоги: %v", err)
	}
}

// Присланные итоги сохраняются; heartbeat без итогов (старый шлюз) их не стирает.
func TestHeartbeatReportsStored(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	id := reg.Gateway.ID
	at := e.clock.now()
	in := gwregistry.HeartbeatInput{
		Version:   "1",
		Selftest:  &gwregistry.CheckReport{OK: false, At: at, Failed: 3},
		Integrity: &gwregistry.CheckReport{OK: false, At: at, Reason: "files_mismatch", Failed: 2},
	}
	if _, err := e.svc.Heartbeat(ctx, id, in, testIP); err != nil {
		t.Fatal(err)
	}
	get := func() gwregistry.Gateway {
		list, err := e.svc.List(ctx)
		if err != nil || len(list) != 1 {
			t.Fatalf("%v %v", list, err)
		}
		return list[0]
	}
	g := get()
	if g.Selftest == nil || g.Selftest.OK || g.Selftest.Failed != 3 || g.Integrity == nil || g.Integrity.Reason != "files_mismatch" || g.Integrity.Failed != 2 {
		t.Fatalf("итоги не сохранены: %+v %+v", g.Selftest, g.Integrity)
	}
	e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "2"}, testIP); err != nil {
		t.Fatal(err)
	}
	g = get()
	if g.Version != "2" || g.Selftest == nil || g.Selftest.Failed != 3 || g.Integrity == nil {
		t.Fatalf("итоги стёрты heartbeat без итогов: %+v", g)
	}
}

// То же на PostgreSQL: столбцы миграции 0011, права aisec_app, COALESCE.
func TestPGHeartbeatReports(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	reg := e.register(t, e.issue(t, "gw-1", false))
	at := e.clock.now()
	in := gwregistry.HeartbeatInput{
		Version:   "1",
		Selftest:  &gwregistry.CheckReport{OK: true, At: at},
		Integrity: &gwregistry.CheckReport{OK: false, At: at, Reason: "manifest_missing", Failed: 1},
	}
	if _, err := e.srv.Heartbeat(ctx, reg.Gateway.ID, in, testIP); err != nil {
		t.Fatal(err)
	}
	e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	if _, err := e.srv.Heartbeat(ctx, reg.Gateway.ID, gwregistry.HeartbeatInput{Version: "2"}, testIP); err != nil {
		t.Fatal(err)
	}
	list, err := e.cli.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	g := list[0]
	if g.Version != "2" || g.Selftest == nil || !g.Selftest.OK || g.Integrity == nil || g.Integrity.OK ||
		g.Integrity.Reason != "manifest_missing" || g.Integrity.Failed != 1 || !g.Integrity.At.Equal(at) {
		t.Fatalf("%+v %+v", g.Selftest, g.Integrity)
	}
}
