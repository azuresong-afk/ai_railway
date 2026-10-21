package sysstatus_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
)

var t0 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

type fakeGateways struct {
	list []gwregistry.Gateway
	err  error
}

func (f *fakeGateways) List(context.Context) ([]gwregistry.Gateway, error) { return f.list, f.err }

type fakeIntegrity struct {
	list []integrity.Result
	err  error
}

func (f *fakeIntegrity) Latest(context.Context) ([]integrity.Result, error) { return f.list, f.err }

type testEnv struct {
	mem   *sysstatus.Memory
	gws   fakeGateways
	integ fakeIntegrity
	clock time.Time
	sync  sysstatus.ClockState
	self  *sysstatus.SelftestSummary
}

func newEnv() *testEnv {
	return &testEnv{mem: sysstatus.NewMemory(), clock: t0, sync: sysstatus.ClockState{Sync: sysstatus.SyncSynchronized},
		self: &sysstatus.SelftestSummary{OK: true, At: t0}}
}

func (e *testEnv) svc(t *testing.T) *sysstatus.Service {
	t.Helper()
	s, err := sysstatus.New(sysstatus.Options{
		Version: "1.0", StartedAt: t0, Selftest: e.self, Gateways: &e.gws, Integrity: &e.integ, Store: e.mem,
		Clock: func() time.Time { return e.clock }, Sync: func() sysstatus.ClockState { return e.sync },
		StorageLimit: 1000, WarnPercent: 80, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func notif(st sysstatus.Status, cond string) sysstatus.Notification {
	for _, n := range st.Notifications {
		if n.Condition == cond {
			return n
		}
	}
	return sysstatus.Notification{}
}

func TestNewValidation(t *testing.T) {
	if _, err := sysstatus.New(sysstatus.Options{StorageLimit: -1}); err == nil {
		t.Error("отрицательный предел принят")
	}
	for _, p := range []int{-1, 101} {
		if _, err := sysstatus.New(sysstatus.Options{WarnPercent: p}); err == nil {
			t.Errorf("порог %d принят", p)
		}
	}
	s, err := sysstatus.New(sysstatus.Options{})
	if err != nil {
		t.Fatal(err)
	}
	st := s.Status(context.Background())
	// Без источников: пустые массивы, UTC, умолчания, все пять условий.
	if st.Time.Timezone != "UTC" || st.Storage.LimitBytes != sysstatus.DefaultStorageLimit || st.Storage.WarnPercent != 80 ||
		len(st.Notifications) != 5 || st.Gateways == nil || st.Unavailable == nil || st.Server.Integrity == nil {
		t.Fatalf("%+v", st)
	}
}

func TestStatusGatewaysAndEvents(t *testing.T) {
	e := newEnv()
	ok := &gwregistry.CheckReport{OK: true, At: t0}
	bad := &gwregistry.CheckReport{OK: false, At: t0, Reason: "files_mismatch", Failed: 2}
	e.gws.list = []gwregistry.Gateway{
		{ID: "g1", Name: "a", Status: gwregistry.StatusActive, LastSeenAt: t0.Add(-20 * time.Second), Version: "1.0", Selftest: ok, Integrity: ok},
		{ID: "g2", Name: "b", Status: gwregistry.StatusActive, LastSeenAt: t0.Add(-5 * time.Minute)},
		{ID: "g3", Name: "c", Status: gwregistry.StatusActive},
		{ID: "g4", Name: "d", Status: gwregistry.StatusPending},
		{ID: "g5", Name: "e", Status: gwregistry.StatusRevoked, LastSeenAt: t0.Add(-time.Hour), Integrity: bad},
	}
	e.mem.SetEventStats("g1", sysstatus.GatewayEvents{Dropped: 5, Rejected: 1, StartedAt: t0, ReportedAt: t0})
	e.mem.SetEventStats("g2", sysstatus.GatewayEvents{Dropped: 7, Rejected: 0, StartedAt: t0, ReportedAt: t0})
	st := e.svc(t).Status(context.Background())
	want := map[string]string{"g1": "online", "g2": "offline", "g3": "offline", "g4": "pending", "g5": "revoked"}
	for _, g := range st.Gateways {
		if g.State != want[g.ID] {
			t.Errorf("%s: %s, ожидается %s", g.ID, g.State, want[g.ID])
		}
	}
	if st.Events.Dropped != 12 || st.Events.Rejected != 1 {
		t.Fatalf("суммы счётчиков: %+v", st.Events)
	}
	if st.Gateways[0].Events == nil || st.Gateways[0].Events.Dropped != 5 || st.Gateways[2].Events != nil || st.Gateways[0].Selftest == nil || st.Gateways[2].Selftest != nil {
		t.Fatalf("%+v", st.Gateways)
	}
	// Отозванный шлюз с плохим итогом не считается нарушением (ОЦЛ.5 — действующие компоненты).
	if notif(st, sysstatus.ConditionIntegrity).Active {
		t.Error("отозванный шлюз вызвал уведомление ОЦЛ.5")
	}
}

func TestStatusStorage(t *testing.T) {
	e := newEnv()
	s := e.svc(t)
	for size, want := range map[int64]struct {
		pct  int
		warn bool
	}{0: {0, false}, 799: {79, false}, 800: {80, true}, 1000: {100, true}, 5000: {100, true}} {
		e.mem.SetAuditSize(size)
		st := s.Status(context.Background())
		if !st.Storage.Available || st.Storage.UsedPercent != want.pct || st.Storage.WarnExceeded != want.warn || st.Storage.AuditBytes != size {
			t.Errorf("размер %d: %+v", size, st.Storage)
		}
		if notif(st, sysstatus.ConditionStorage).Active != want.warn {
			t.Errorf("размер %d: уведомление РСБ.5 %v", size, !want.warn)
		}
	}
}

func TestStatusSectionsUnavailable(t *testing.T) {
	e := newEnv()
	e.mem.Err = errors.New("db down")
	e.gws.err = errors.New("db down")
	e.integ.err = errors.New("db down")
	st := e.svc(t).Status(context.Background())
	got := strings.Join(st.Unavailable, ",")
	if got != "events,gateways,integrity,notifications,storage" {
		t.Fatalf("недоступные разделы: %s", got)
	}
	if st.Storage.Available || st.Time.Sync != sysstatus.SyncSynchronized || st.Server.Version != "1.0" {
		t.Fatalf("остальные разделы должны остаться: %+v", st)
	}
	// Текст ошибки БД клиенту не передаётся.
	if strings.Contains(fmt.Sprintf("%+v", st), "db down") {
		t.Error("текст ошибки в ответе")
	}
}

func TestStatusCountsAndSince(t *testing.T) {
	e := newEnv()
	e.mem.SetCounts(2, 0)
	e.sync = sysstatus.ClockState{Sync: sysstatus.SyncUnsynchronized}
	s := e.svc(t)
	if err := s.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.clock = t0.Add(time.Hour)
	st := s.Status(context.Background())
	lock, denied, tm := notif(st, sysstatus.ConditionAccount), notif(st, sysstatus.ConditionDenied), notif(st, sysstatus.ConditionTime)
	if !lock.Active || lock.Count == nil || *lock.Count != 2 || denied.Active || denied.Count == nil || *denied.Count != 0 {
		t.Fatalf("%+v %+v", lock, denied)
	}
	if !tm.Active || tm.Since == nil || !tm.Since.Equal(t0) || tm.Count != nil {
		t.Fatalf("ВРМ.1: %+v", tm)
	}
}

// Уведомление пишется в аудит только при смене состояния (ВРМ.1).
func TestEvaluateWritesOnlyOnChange(t *testing.T) {
	e := newEnv()
	s := e.svc(t)
	ctx := context.Background()
	eval := func() {
		t.Helper()
		if err := s.Evaluate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Всё в порядке: первое наблюдение неактивных условий записей не создаёт.
	eval()
	eval()
	if len(e.mem.Records) != 0 {
		t.Fatalf("записи без нарушения: %+v", e.mem.Records)
	}
	// «Неизвестно» — не нарушение.
	e.sync = sysstatus.ClockState{Sync: sysstatus.SyncUnknown}
	eval()
	if len(e.mem.Records) != 0 {
		t.Fatalf("unknown вызвал запись: %+v", e.mem.Records)
	}
	// Рассинхронизация: одна запись, сколько бы раз ни опрашивали.
	e.sync = sysstatus.ClockState{Sync: sysstatus.SyncUnsynchronized}
	for range 5 {
		e.clock = e.clock.Add(time.Minute)
		eval()
	}
	if len(e.mem.Records) != 1 || e.mem.Records[0].Action != "system.alert" || e.mem.Records[0].Result != audit.ResultFailure {
		t.Fatalf("%+v", e.mem.Records)
	}
	d := e.mem.Records[0].Details.(map[string]any)
	if d["condition"] != sysstatus.ConditionTime || d["state"] != "raised" || d["requirement"] != "ВРМ.1" {
		t.Fatalf("%v", d)
	}
	// Синхронизация вернулась: одна запись «снято».
	e.sync = sysstatus.ClockState{Sync: sysstatus.SyncSynchronized}
	eval()
	eval()
	if len(e.mem.Records) != 2 || e.mem.Records[1].Result != audit.ResultSuccess || e.mem.Records[1].Details.(map[string]any)["state"] != "cleared" {
		t.Fatalf("%+v", e.mem.Records)
	}
	for _, r := range e.mem.Records {
		if _, ok := audit.Lookup(r.Action); !ok {
			t.Errorf("код %q вне перечня аудита", r.Action)
		}
		if err := validateEntry(r); err != nil {
			t.Error(err)
		}
	}
}

func validateEntry(r audit.Entry) error {
	if r.Actor.Type != audit.ActorSystem || r.Object.Type == "" || r.Object.ID == "" {
		return fmt.Errorf("запись без субъекта или объекта: %+v", r)
	}
	return nil
}

// РСБ.5 и ОЦЛ.5: условия по порогу и по итогам проверок сервера и шлюзов.
func TestEvaluateStorageAndIntegrity(t *testing.T) {
	e := newEnv()
	s := e.svc(t)
	ctx := context.Background()
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	e.mem.SetAuditSize(900)
	e.gws.list = []gwregistry.Gateway{{ID: "g1", Name: "a", Status: gwregistry.StatusActive, LastSeenAt: t0,
		Selftest: &gwregistry.CheckReport{OK: false, At: t0, Failed: 1}}}
	for range 3 {
		if err := s.Evaluate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	conds := map[string]string{}
	for _, r := range e.mem.Records {
		d := r.Details.(map[string]any)
		conds[d["condition"].(string)] += d["state"].(string)
	}
	if len(e.mem.Records) != 2 || conds[sysstatus.ConditionStorage] != "raised" || conds[sysstatus.ConditionIntegrity] != "raised" {
		t.Fatalf("%v", conds)
	}
	if d := e.mem.Records[0].Details.(map[string]any); d["condition"] == sysstatus.ConditionStorage && d["used_percent"] != 90 {
		t.Errorf("%v", d)
	}
	// Шлюз исправился, журнал освободился.
	e.gws.list[0].Selftest = &gwregistry.CheckReport{OK: true, At: t0}
	e.mem.SetAuditSize(10)
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.mem.Records) != 4 {
		t.Fatalf("%+v", e.mem.Records)
	}
}

func TestEvaluateServerIntegrityAndSelftest(t *testing.T) {
	e := newEnv()
	s := e.svc(t)
	ctx := context.Background()
	e.integ.list = []integrity.Result{{Component: "server", Trigger: integrity.TriggerPeriodic, At: t0, Reason: integrity.ReasonFilesMismatch,
		Failures: []integrity.Failure{{Path: "bin/aisec-server", Problem: integrity.ProblemModified}}, Omitted: 3}}
	st := s.Status(ctx)
	if len(st.Server.Integrity) != 1 || st.Server.Integrity[0].OK || st.Server.Integrity[0].Failed != 4 {
		t.Fatalf("%+v", st.Server.Integrity)
	}
	if !notif(st, sysstatus.ConditionIntegrity).Active {
		t.Fatal("нарушение целостности сервера без уведомления")
	}
	// Провал самотеста сервера — тоже ОЦЛ.5.
	e.integ.list = nil
	e.self = &sysstatus.SelftestSummary{OK: false, At: t0, Failed: 1}
	if st := e.svc(t).Status(ctx); !notif(st, sysstatus.ConditionIntegrity).Active || st.Server.Selftest == nil || st.Server.Selftest.OK {
		t.Fatalf("%+v", st.Server.Selftest)
	}
}

// Сбой источника не снимает уведомление: ложное «снято» хуже паузы.
func TestEvaluateKeepsStateWhenSectionUnavailable(t *testing.T) {
	e := newEnv()
	s := e.svc(t)
	ctx := context.Background()
	e.mem.SetAuditSize(950)
	e.integ.list = []integrity.Result{{Component: "server", At: t0, Reason: integrity.ReasonSignatureInvalid}}
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.mem.Records) != 2 {
		t.Fatalf("%+v", e.mem.Records)
	}
	e.integ.err = errors.New("db")
	e.integ.list = nil
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.mem.Records) != 2 {
		t.Fatalf("уведомление снято при сбое источника: %+v", e.mem.Records)
	}
}

func TestEvaluateStoreError(t *testing.T) {
	e := newEnv()
	e.sync = sysstatus.ClockState{Sync: sysstatus.SyncUnsynchronized}
	s := e.svc(t)
	e.mem.Err = errors.New("db down")
	if err := s.Evaluate(context.Background()); err == nil {
		t.Fatal("ошибка хранилища не возвращена")
	}
	// Без хранилища (нет БД) Evaluate ничего не делает.
	s2, err := sysstatus.New(sysstatus.Options{})
	if err != nil || s2.Evaluate(context.Background()) != nil {
		t.Fatal(err)
	}
}
