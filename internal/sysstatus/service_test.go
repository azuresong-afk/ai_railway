package sysstatus_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
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

func (e *testEnv) opts() sysstatus.Options {
	return sysstatus.Options{
		Version: "1.0", StartedAt: t0, Selftest: e.self, Gateways: &e.gws, Integrity: &e.integ, Store: e.mem,
		Clock: func() time.Time { return e.clock }, Sync: func() sysstatus.ClockState { return e.sync },
		StorageLimit: 1000, WarnPercent: 80, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func (e *testEnv) svc(t *testing.T) *sysstatus.Service {
	t.Helper()
	s, err := sysstatus.New(e.opts())
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
	// Без источников: пустые массивы, UTC, умолчания, все тринадцать условий.
	if st.Time.Timezone != "UTC" || st.Storage.LimitBytes != sysstatus.DefaultStorageLimit || st.Storage.WarnPercent != 80 ||
		len(st.Notifications) != 13 || st.Bundle != nil || st.Gateways == nil || st.Unavailable == nil || st.Server.Integrity == nil {
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
	if got != "audit_chain,events,gateways,integrity,notifications,storage" {
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

// ВРМ.2, H-Р10: часовой пояс — из настроек установки; сбой чтения — раздел
// timezone недоступен, остальное время на месте.
func TestStatusTimezoneFromSettings(t *testing.T) {
	e := newEnv()
	o := e.opts()
	tz, tzErr := "Asia/Yekaterinburg", error(nil)
	o.Timezone = func(context.Context) (string, error) { return tz, tzErr }
	s, err := sysstatus.New(o)
	if err != nil {
		t.Fatal(err)
	}
	if st := s.Status(context.Background()); st.Time.Timezone != "Asia/Yekaterinburg" {
		t.Fatalf("пояс: %+v", st.Time)
	}
	tzErr = errors.New("db down")
	st := s.Status(context.Background())
	if !slices.Contains(st.Unavailable, "timezone") || st.Time.Sync != sysstatus.SyncSynchronized {
		t.Fatalf("сбой чтения пояса: %+v %v", st.Time, st.Unavailable)
	}
}

// РСБ.4 (замечание В1 ревью 2.r1): нарушение цепочки аудита поднимает
// уведомление и пишет system.alert один раз; восстановление его снимает.
func TestAuditChainNotification(t *testing.T) {
	e := newEnv()
	s := e.svc(t)
	ctx := context.Background()
	if st := s.Status(ctx); st.AuditChain != nil || notif(st, sysstatus.ConditionAuditLog).Active {
		t.Fatalf("без проверок: %+v", st.AuditChain)
	}
	seq := int64(7)
	e.mem.SetAuditChain(&sysstatus.AuditChainStatus{CheckedAt: t0, OK: false, Checked: 6, LastSeq: 6, Reason: "rewritten", BrokenSeq: &seq})
	for range 2 {
		if err := s.Evaluate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	st := s.Status(ctx)
	n := notif(st, sysstatus.ConditionAuditLog)
	if !n.Active || n.Requirement != "РСБ.4" || n.Since == nil || st.AuditChain == nil || st.AuditChain.Reason != "rewritten" {
		t.Fatalf("уведомление: %+v, цепочка: %+v", n, st.AuditChain)
	}
	if len(e.mem.Records) != 1 {
		t.Fatalf("записей system.alert: %d", len(e.mem.Records))
	}
	d := e.mem.Records[0].Details.(map[string]any)
	if d["condition"] != sysstatus.ConditionAuditLog || d["state"] != "raised" || d["reason"] != "rewritten" || d["broken_seq"] != seq {
		t.Fatalf("подробности: %+v", d)
	}
	e.mem.SetAuditChain(&sysstatus.AuditChainStatus{CheckedAt: t0.Add(time.Hour), OK: true, Checked: 8, LastSeq: 8, Reason: "ok"})
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if notif(s.Status(ctx), sysstatus.ConditionAuditLog).Active || len(e.mem.Records) != 2 {
		t.Fatalf("после восстановления: записей %d", len(e.mem.Records))
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
	if len(e.mem.Records) != 2 || conds[sysstatus.ConditionStorage] != "raised" || conds["integrity:gateway:g1"] != "raised" {
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

// В18 ревью 2.r3b: ОЦЛ.5 по компоненту — нарушение второго шлюза, пока
// первый ещё нарушен, тоже записывается; восстановление первого — запись о
// снятии только для него. В ответе — одна строка со списком компонентов.
func TestEvaluateIntegrityPerComponent(t *testing.T) {
	e := newEnv()
	s := e.svc(t)
	ctx := context.Background()
	bad := func() *gwregistry.CheckReport {
		return &gwregistry.CheckReport{OK: false, At: t0, Reason: "files_mismatch", Failed: 2}
	}
	e.gws.list = []gwregistry.Gateway{
		{ID: "g1", Name: "a", Status: gwregistry.StatusActive, LastSeenAt: t0, Integrity: bad()},
		{ID: "g2", Name: "b", Status: gwregistry.StatusActive, LastSeenAt: t0, Integrity: &gwregistry.CheckReport{OK: true, At: t0}},
	}
	alerts := func() []string {
		var out []string
		for _, r := range e.mem.Records {
			d := r.Details.(map[string]any)
			out = append(out, d["condition"].(string)+":"+d["state"].(string))
		}
		return out
	}
	eval := func() {
		t.Helper()
		if err := s.Evaluate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	eval()
	e.gws.list[1].Integrity = bad()
	eval()
	if got := alerts(); !slices.Equal(got, []string{"integrity:gateway:g1:raised", "integrity:gateway:g2:raised"}) {
		t.Fatalf("второе нарушение: %v", got)
	}
	d := e.mem.Records[1].Details.(map[string]any)
	if d["component"] != "gateway:g2" || d["requirement"] != "ОЦЛ.5" || d["violations"] != 1 {
		t.Fatalf("подробности: %v", d)
	}
	n := notif(s.Status(ctx), sysstatus.ConditionIntegrity)
	if !n.Active || !slices.Equal(n.Components, []string{"gateway:g1", "gateway:g2"}) {
		t.Fatalf("строка ОЦЛ.5: %+v", n)
	}
	e.gws.list[0].Integrity = &gwregistry.CheckReport{OK: true, At: t0}
	eval()
	if got := alerts(); len(got) != 3 || got[2] != "integrity:gateway:g1:cleared" {
		t.Fatalf("восстановление первого: %v", got)
	}
	// Отозванный шлюз: его условие снимается.
	e.gws.list[1].Status = gwregistry.StatusRevoked
	eval()
	if got := alerts(); len(got) != 4 || got[3] != "integrity:gateway:g2:cleared" {
		t.Fatalf("отзыв шлюза: %v", got)
	}
	for _, r := range e.mem.Records {
		if err := validateEntry(r); err != nil {
			t.Error(err)
		}
	}
}

// В16 и Н28 ревью 2.r3b: пакет собран не полностью; шлюз дольше 10 минут на
// другой версии.
func TestEvaluateBundle(t *testing.T) {
	e := newEnv()
	h := &sysstatus.BundleHealth{Version: 5, ETag: `"5"`, BuiltAt: t0.Add(-time.Hour)}
	o := e.opts()
	o.Bundle = func(context.Context) (*sysstatus.BundleHealth, error) { return h, nil }
	s, err := sysstatus.New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e.gws.list = []gwregistry.Gateway{{ID: "g1", Name: "a", Status: gwregistry.StatusActive, LastSeenAt: t0, BundleETag: `"5"`},
		{ID: "g2", Name: "b", Status: gwregistry.StatusActive, LastSeenAt: t0, BundleETag: `"4"`}}
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.Status(ctx)
	if st.Bundle == nil || !st.Bundle.Complete || !slices.Equal(st.Bundle.Lagging, []string{"g2"}) ||
		!notif(st, sysstatus.ConditionBundleLag).Active || notif(st, sysstatus.ConditionBundle).Active {
		t.Fatalf("пакет: %+v", st.Bundle)
	}
	h.Excluded = []sysstatus.ExcludedApp{{Application: "crm", Reason: "нет словаря"}}
	h.BuiltAt = t0.Add(-time.Minute) // новая версия: отставание пока не считается
	h.Version, h.ETag = 6, `"6"`
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range e.mem.Records {
		d := r.Details.(map[string]any)
		got = append(got, d["condition"].(string)+":"+d["state"].(string))
	}
	if !slices.Equal(got, []string{"config_bundle_lag:g2:raised", "config_bundle:raised", "config_bundle_lag:g2:cleared"}) {
		t.Fatalf("записи: %v", got)
	}
	if st := s.Status(ctx); st.Bundle.Complete || len(st.Bundle.Excluded) != 1 || !notif(st, sysstatus.ConditionBundle).Active {
		t.Fatalf("неполный пакет: %+v", st.Bundle)
	}
	// Сбой сборки — раздел недоступен, состояние не меняется.
	o.Bundle = func(context.Context) (*sysstatus.BundleHealth, error) { return nil, errors.New("db") }
	s2, err := sysstatus.New(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.mem.Records) != 3 {
		t.Fatalf("сбой источника снял условие: %+v", e.mem.Records)
	}
}

// DM-42, В19 и В20 ревью 2.r4: шлюз на выпуске старше проверенного (откат)
// и шлюз с чужим ключом проверки пакетов — нарушение целостности этого
// шлюза; Н34 — сборка с тестовым ключом манифеста видна отдельным условием.
func TestDM42_GatewayRollbackAndBundleKeys(t *testing.T) {
	e := newEnv()
	s := e.svc(t)
	ctx := context.Background()
	newer, older := t0.Add(-24*time.Hour), t0.Add(-60*24*time.Hour)
	no := false
	e.gws.list = []gwregistry.Gateway{
		{ID: "g1", Name: "a", Status: gwregistry.StatusActive, LastSeenAt: t0,
			Integrity:          &gwregistry.CheckReport{OK: true, At: t0, ManifestVersion: "1.0.0", ManifestCreated: older},
			ManifestMaxVersion: "1.1.0", ManifestMaxCreated: newer},
		{ID: "g2", Name: "b", Status: gwregistry.StatusActive, LastSeenAt: t0, BundleKeysOK: &no,
			Integrity:          &gwregistry.CheckReport{OK: true, At: t0, ManifestVersion: "1.1.0", ManifestCreated: newer, TestSigned: true},
			ManifestMaxVersion: "1.1.0", ManifestMaxCreated: newer},
	}
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.Status(ctx)
	n := notif(st, sysstatus.ConditionIntegrity)
	if !n.Active || !slices.Equal(n.Components, []string{"gateway:g1", "gateway:g2"}) {
		t.Fatalf("ОЦЛ.5: %+v", n)
	}
	tb := notif(st, sysstatus.ConditionTestBuild)
	if !tb.Active || !slices.Equal(tb.Components, []string{"gateway:g2"}) || tb.Requirement != "ОЦЛ.1" {
		t.Fatalf("тестовый ключ: %+v", tb)
	}
	var sources []string
	for _, r := range e.mem.Records {
		d := r.Details.(map[string]any)
		issues, _ := d["issues"].([]map[string]any)
		for _, is := range issues {
			sources = append(sources, fmt.Sprint(is["source"], "/", is["reason"]))
		}
		if err := validateEntry(r); err != nil {
			t.Error(err)
		}
	}
	if !slices.Contains(sources, "integrity/manifest_rollback") || !slices.Contains(sources, "bundle_keys/<nil>") {
		t.Fatalf("подробности: %v", sources)
	}
	// Намеренный откат принят (максимум сброшен), ключи совпали — условие снято.
	yes := true
	e.gws.list[0].ManifestMaxVersion, e.gws.list[0].ManifestMaxCreated = "1.0.0", older
	e.gws.list[1].BundleKeysOK = &yes
	if n := notif(s.Status(ctx), sysstatus.ConditionIntegrity); n.Active {
		t.Fatalf("после принятия отката: %+v", n)
	}
}

// Потеря связи не снимает отставание пакета: снимается оно только у
// отозванного шлюза (самопроверка H4, С2).
func TestEvaluateBundleLagOffline(t *testing.T) {
	e := newEnv()
	h := &sysstatus.BundleHealth{Version: 5, ETag: `"5"`, BuiltAt: t0.Add(-time.Hour)}
	o := e.opts()
	o.Bundle = func(context.Context) (*sysstatus.BundleHealth, error) { return h, nil }
	s, err := sysstatus.New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	states := func() []string {
		var got []string
		for _, r := range e.mem.Records {
			d := r.Details.(map[string]any)
			// Связь шлюза (DM-44) проверяет TestEvaluateGatewayBlinding.
			if c := d["condition"].(string); strings.HasPrefix(c, sysstatus.ConditionBundleLag) {
				got = append(got, c+":"+d["state"].(string))
			}
		}
		return got
	}
	gw := gwregistry.Gateway{ID: "g2", Name: "b", Status: gwregistry.StatusActive, LastSeenAt: t0, BundleETag: `"4"`}
	for _, step := range []struct {
		lastSeen time.Time
		status   string
		want     []string
	}{
		{t0, gwregistry.StatusActive, []string{"config_bundle_lag:g2:raised"}},
		{t0.Add(-time.Hour), gwregistry.StatusActive, []string{"config_bundle_lag:g2:raised"}},
		{t0.Add(-time.Hour), gwregistry.StatusRevoked, []string{"config_bundle_lag:g2:raised", "config_bundle_lag:g2:cleared"}},
	} {
		gw.LastSeenAt, gw.Status = step.lastSeen, step.status
		e.gws.list = []gwregistry.Gateway{gw}
		if err := s.Evaluate(ctx); err != nil {
			t.Fatal(err)
		}
		if got := states(); !slices.Equal(got, step.want) {
			t.Fatalf("%s, связь %v: %v", step.status, step.lastSeen, got)
		}
	}
}

// DM-44 (задача 3.11 этапа 3), Н29: условия «ослепления» по шлюзу —
// недоступен, отбрасывает события (рост счётчика), скоро истекает
// сертификат, итог целостности старше двух периодов («нет данных») —
// пишутся в журнал при смене состояния; отозванный шлюз их снимает.
func TestEvaluateGatewayBlinding(t *testing.T) {
	e := newEnv()
	s, err := sysstatus.New(e.opts())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	raised := func() map[string]string {
		got := map[string]string{}
		for _, r := range e.mem.Records {
			d := r.Details.(map[string]any)
			got[d["condition"].(string)] = d["state"].(string)
		}
		return got
	}
	fresh := &gwregistry.CheckReport{OK: true, At: t0.Add(-10 * time.Minute)}
	gw := gwregistry.Gateway{ID: "g1", Name: "gw-1", Status: gwregistry.StatusActive, LastSeenAt: t0, StartedAt: t0.Add(-5 * time.Hour),
		CertNotAfter: t0.Add(60 * 24 * time.Hour), Integrity: fresh}
	e.gws.list = []gwregistry.Gateway{gw}
	started := t0.Add(-5 * time.Hour)
	e.mem.SetEventStats("g1", sysstatus.GatewayEvents{Dropped: 3, StartedAt: started, ReportedAt: t0})
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	// Первое наблюдение счётчика — точка отсчёта, всё в порядке.
	if got := raised(); len(got) != 0 {
		t.Fatalf("исправный шлюз: %v", got)
	}
	// Счётчик вырос, сертификат истекает через 10 суток, итог целостности
	// устарел (старше двух часов).
	e.clock = t0.Add(time.Minute)
	gw.LastSeenAt = e.clock
	gw.CertNotAfter = e.clock.Add(10 * 24 * time.Hour)
	gw.Integrity = &gwregistry.CheckReport{OK: true, At: e.clock.Add(-sysstatus.StaleAfter - time.Minute)}
	e.gws.list = []gwregistry.Gateway{gw}
	e.mem.SetEventStats("g1", sysstatus.GatewayEvents{Dropped: 5, StartedAt: started, ReportedAt: e.clock})
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	got := raised()
	for _, c := range []string{"events_dropped:g1", "cert_expiry:g1", "reports_stale:g1"} {
		if got[c] != "raised" {
			t.Fatalf("%s: %v", c, got)
		}
	}
	st := s.Status(ctx)
	if g := st.Gateways[0]; g.Integrity == nil || !g.Integrity.Stale {
		t.Fatalf("устаревший итог не помечен: %+v", g.Integrity)
	}
	if n := notif(st, sysstatus.ConditionReportsStale); !n.Active || !slices.Equal(n.Components, []string{"gateway:g1"}) {
		t.Fatalf("уведомление Н29: %+v", n)
	}
	// Без роста за окно условие снимается; шлюз пропал со связи.
	e.clock = e.clock.Add(sysstatus.DroppedWindow + time.Minute)
	e.mem.SetEventStats("g1", sysstatus.GatewayEvents{Dropped: 5, StartedAt: started, ReportedAt: e.clock})
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	got = raised()
	if got["events_dropped:g1"] != "cleared" || got["gateway_offline:g1"] != "raised" {
		t.Fatalf("после окна: %v", got)
	}
	// Отзыв шлюза снимает его условия.
	gw.Status = gwregistry.StatusRevoked
	e.gws.list = []gwregistry.Gateway{gw}
	if err := s.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	got = raised()
	for _, c := range []string{"gateway_offline:g1", "cert_expiry:g1", "reports_stale:g1"} {
		if got[c] != "cleared" {
			t.Fatalf("отзыв, %s: %v", c, got)
		}
	}
}

// Н29: шлюз новой версии на связи, но итог целостности не присылает
// дольше двух периодов — «нет данных».
func TestEvaluateReportsMissing(t *testing.T) {
	e := newEnv()
	s, err := sysstatus.New(e.opts())
	if err != nil {
		t.Fatal(err)
	}
	e.gws.list = []gwregistry.Gateway{{ID: "g1", Name: "gw-1", Status: gwregistry.StatusActive, LastSeenAt: t0,
		StartedAt: t0.Add(-sysstatus.StaleAfter - time.Minute)}}
	if err := s.Evaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := notif(s.Status(context.Background()), sysstatus.ConditionReportsStale); !n.Active {
		t.Fatalf("нет итога: %+v", n)
	}
}
