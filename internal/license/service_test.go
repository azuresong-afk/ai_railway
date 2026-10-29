package license

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// fakeClock — поддельные часы теста.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

type fixture struct {
	svc   *Service
	store *Memory
	clock *fakeClock
	usage *Usage
}

func newFixture(t *testing.T, now time.Time) *fixture {
	t.Helper()
	f := &fixture{store: NewMemory(), clock: &fakeClock{t: now}, usage: &Usage{}}
	svc, err := New(Options{Store: f.store, Provider: provider(t), Clock: f.clock.now,
		Usage: func(context.Context) (Usage, error) { return *f.usage, nil }})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	return f
}

var confirmed = By{Actor: audit.Actor{Type: audit.ActorUser, ID: "u1", Name: "sysadmin"}, IP: netip.MustParseAddr("192.0.2.10"),
	Confirm: func(context.Context) error { return nil }}

func (f *fixture) upload(t *testing.T, l *License) (Info, error) {
	t.Helper()
	return f.svc.Upload(context.Background(), confirmed, signTest(t, l))
}

func (f *fixture) state(t *testing.T) State {
	t.Helper()
	st, err := f.svc.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// details — подробности записи аудита.
func details(e audit.Entry) map[string]any {
	d, _ := e.Details.(map[string]any)
	return d
}

func lastRecord(t *testing.T, m *Memory) audit.Entry {
	t.Helper()
	if len(m.Records) == 0 {
		t.Fatal("нет записей аудита")
	}
	return m.Records[len(m.Records)-1]
}

func TestNoLicenseIsUnrestricted(t *testing.T) {
	f := newFixture(t, day(2026, 10, 28))
	f.usage.Gateways, f.usage.Applications = 1000, 1000
	ctx := context.Background()
	st := f.state(t)
	if st.Phase != PhaseNone || st.Restricted() {
		t.Fatalf("состояние: %+v", st)
	}
	for _, m := range append([]string{""}, Modules...) {
		if err := f.svc.CheckMutation(ctx, m); err != nil {
			t.Fatalf("модуль %q: %v", m, err)
		}
	}
	if f.svc.CheckGateway(ctx) != nil || f.svc.CheckApplication(ctx) != nil {
		t.Fatal("пределы без лицензии")
	}
	info, err := f.svc.Info(ctx)
	if err != nil || info.State != PhaseNone || info.Number != 0 || len(info.Modules) != len(Modules) {
		t.Fatalf("сведения: %+v %v", info, err)
	}
}

func TestUploadAndTerm(t *testing.T) {
	f := newFixture(t, day(2026, 10, 28).Add(time.Hour))
	ctx := context.Background()
	info, err := f.upload(t, baseLicense(1))
	if err != nil {
		t.Fatal(err)
	}
	if info.State != PhaseActive || info.Number != 1 || *info.DaysLeft != 364 || info.Licensee.INN != testINN {
		t.Fatalf("сведения: %+v", info)
	}
	rec := lastRecord(t, f.store)
	if rec.Action != "license.loaded" || rec.Object.ID != "1" || details(rec)["number"] != uint64(1) || details(rec)["previous_state"] != PhaseNone {
		t.Fatalf("аудит: %+v", rec)
	}
	if _, ok := details(rec)["signature"]; ok {
		t.Fatal("подпись в аудите")
	}
	// Переходы срока на поддельных часах (до 30 суток, до 7, льготный
	// период, после него).
	until := day(2027, 10, 28)
	for _, tc := range []struct {
		at    time.Time
		phase string
	}{
		{until.Add(-31 * 24 * time.Hour), PhaseActive},
		{until.Add(-ExpiryWarn), PhaseExpiring},
		{until.Add(-ExpiryCritical), PhaseExpiring},
		{until, PhaseExpiring},
		{until.Add(time.Second), PhaseGrace},
		{until.Add(GracePeriod), PhaseGrace},
		{until.Add(GracePeriod + time.Second), PhaseRestricted},
	} {
		f.clock.t = tc.at
		if st := f.state(t); st.Phase != tc.phase {
			t.Fatalf("%s: состояние %s, ожидалось %s", tc.at, st.Phase, tc.phase)
		}
	}
	// После льготного периода изменения запрещены, загрузка новой — нет.
	var d *Denied
	if err := f.svc.CheckMutation(ctx, ""); !errors.As(err, &d) || d.Code != CodeRestricted {
		t.Fatalf("запрет изменений: %v", err)
	}
	next := baseLicense(2)
	next.IssuedAt, next.ValidFrom, next.ValidUntil = day(2027, 11, 28), day(2027, 11, 28), day(2028, 11, 28)
	f.clock.t = day(2027, 12, 1)
	if _, err := f.upload(t, next); err != nil {
		t.Fatal(err)
	}
	if st := f.state(t); st.Phase != PhaseActive || st.Number != 2 || f.svc.CheckMutation(ctx, "") != nil {
		t.Fatalf("после замены: %+v", st)
	}
}

func TestClockRollbackDoesNotLift(t *testing.T) {
	f := newFixture(t, day(2026, 10, 28))
	if _, err := f.upload(t, baseLicense(1)); err != nil {
		t.Fatal(err)
	}
	// Срок с льготным периодом истёк, отметка часов поднята.
	f.clock.t = day(2028, 1, 1)
	if err := f.svc.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Часы переведены назад — состояние не меняется, условие часов.
	f.clock.t = day(2027, 1, 1)
	st := f.state(t)
	if st.Phase != PhaseRestricted || !st.ClockBehind {
		t.Fatalf("часы назад: %+v", st)
	}
	// Небольшое отставание (NTP) условия не даёт.
	f.clock.t = day(2028, 1, 1).Add(-ClockTolerance)
	if st := f.state(t); st.ClockBehind {
		t.Fatal("отставание в пределах допуска")
	}
}

func TestClockBeforeIssue(t *testing.T) {
	f := newFixture(t, day(2026, 10, 28))
	if _, err := f.upload(t, baseLicense(1)); err != nil {
		t.Fatal(err)
	}
	// Новый сервер с чистой отметкой и часами до выдачи лицензии: трафик
	// не останавливается, условие часов поднято.
	f2, err := New(Options{Store: f.store, Provider: provider(t), Clock: func() time.Time { return day(2026, 10, 27) }})
	if err != nil {
		t.Fatal(err)
	}
	f.store.clock = map[string]time.Time{}
	st, err := f2.State(context.Background())
	if err != nil || !st.ClockBehind || st.Restricted() {
		t.Fatalf("часы до выдачи: %+v %v", st, err)
	}
}

func TestUploadRejects(t *testing.T) {
	f := newFixture(t, day(2026, 11, 1))
	if _, err := f.upload(t, baseLicense(5)); err != nil {
		t.Fatal(err)
	}
	issuedLater := func(n uint64, mut func(*License)) *License {
		l := baseLicense(n)
		mut(l)
		return l
	}
	for name, tc := range map[string]struct {
		data   []byte
		reason string
	}{
		"неверная подпись":     {swapPayload(t, signTest(t, baseLicense(6)), must(Encode(baseLicense(7)))(t)), ReasonSignature},
		"мусор":                {[]byte("not a license"), ReasonFormat},
		"тот же номер":         {signTest(t, baseLicense(5)), ReasonDuplicate},
		"номер старше текущей": {signTest(t, baseLicense(4)), ReasonStaleNumber},
		"выдана раньше текущей": {signTest(t, issuedLater(6, func(l *License) {
			l.IssuedAt = day(2026, 10, 20)
		})), ReasonStaleIssued},
		"ещё не действует": {signTest(t, issuedLater(6, func(l *License) {
			l.ValidFrom = day(2026, 11, 2)
		})), ReasonNotYetValid},
		"выдана в будущем": {signTest(t, issuedLater(6, func(l *License) {
			l.IssuedAt = day(2026, 11, 2)
		})), ReasonClock},
		"истекла": {signTest(t, issuedLater(6, func(l *License) {
			l.ValidFrom, l.ValidUntil = day(2026, 10, 1), day(2026, 10, 30)
			l.IssuedAt = day(2026, 10, 28)
		})), ReasonExpired},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(f.store.Records)
			_, err := f.svc.Upload(context.Background(), confirmed, tc.data)
			var rej *Rejected
			if !errors.As(err, &rej) || rej.Reason != tc.reason {
				t.Fatalf("ожидалась причина %s, получено %v", tc.reason, err)
			}
			if len(f.store.Records) != before+1 {
				t.Fatal("отказ не записан в аудит")
			}
			rec := lastRecord(t, f.store)
			if rec.Action != "license.rejected" || rec.Result != audit.ResultFailure || details(rec)["reason"] != tc.reason {
				t.Fatalf("аудит: %+v", rec)
			}
			if st := f.state(t); st.Number != 5 {
				t.Fatalf("текущая лицензия изменилась: %d", st.Number)
			}
		})
	}
	// Без повторной проверки — отказ до разбора и без записи.
	if _, err := f.svc.Upload(context.Background(), By{Actor: confirmed.Actor}, signTest(t, baseLicense(9))); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("без повторной проверки: %v", err)
	}
	wrong := confirmed
	errWrong := errors.New("неверный пароль")
	wrong.Confirm = func(context.Context) error { return errWrong }
	if _, err := f.svc.Upload(context.Background(), wrong, signTest(t, baseLicense(9))); !errors.Is(err, errWrong) {
		t.Fatalf("неверный пароль: %v", err)
	}
}

func TestUploadExpiredEndorsement(t *testing.T) {
	// Заверение тестового ключа действует до 30.09.2031.
	f := newFixture(t, day(2031, 10, 15))
	l := baseLicense(1)
	l.IssuedAt, l.ValidFrom, l.ValidUntil = day(2031, 9, 1), day(2031, 9, 1), day(2032, 9, 1)
	_, err := f.upload(t, l)
	var rej *Rejected
	if !errors.As(err, &rej) || rej.Reason != ReasonSubkeyTerm {
		t.Fatalf("истёкшее заверение: %v", err)
	}
	// Перевод часов назад не помогает: срок заверения сверяется со
	// временем лицензии (отметкой часов).
	f.clock.t = day(2031, 9, 10)
	if _, err := f.upload(t, l); !errors.As(err, &rej) || rej.Reason != ReasonSubkeyTerm {
		t.Fatalf("часы назад: %v", err)
	}
	// Уже загруженная лицензия продолжает действовать после конца срока
	// заверения: срок заверения при повторной проверке не учитывается.
	f = newFixture(t, day(2031, 9, 10))
	if _, err := f.upload(t, l); err != nil {
		t.Fatal(err)
	}
	f.clock.t = day(2032, 1, 1)
	if err := f.svc.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := f.state(t); st.Phase != PhaseActive {
		t.Fatalf("после конца срока заверения: %s", st.Phase)
	}
}

func TestLimitsAndModules(t *testing.T) {
	f := newFixture(t, day(2026, 11, 1))
	ctx := context.Background()
	if _, err := f.upload(t, baseLicense(1)); err != nil { // шлюзов 2, приложений 3, модуль agents
		t.Fatal(err)
	}
	f.usage.Gateways, f.usage.Applications = 1, 2
	if f.svc.CheckGateway(ctx) != nil || f.svc.CheckApplication(ctx) != nil {
		t.Fatal("отказ ниже предела")
	}
	f.usage.Gateways, f.usage.Applications = 2, 3
	var d *Denied
	if err := f.svc.CheckGateway(ctx); !errors.As(err, &d) || d.Code != CodeLimit {
		t.Fatalf("предел шлюзов: %v", err)
	}
	if err := f.svc.CheckApplication(ctx); !errors.As(err, &d) || d.Code != CodeLimit {
		t.Fatalf("предел приложений: %v", err)
	}
	// Модуль agents включён, shadow_ai — нет; базовая защита — не модуль.
	if f.svc.CheckMutation(ctx, ModuleAgents) != nil || f.svc.CheckMutation(ctx, "") != nil {
		t.Fatal("включённый модуль запрещён")
	}
	if err := f.svc.CheckMutation(ctx, ModuleShadowAI); !errors.As(err, &d) || d.Code != CodeModule {
		t.Fatalf("выключенный модуль: %v", err)
	}
	info, err := f.svc.Info(ctx)
	if err != nil || info.Usage == nil || info.Usage.Gateways != 2 || info.Limits.Applications != 3 {
		t.Fatalf("сведения: %+v %v", info, err)
	}
	// 0 — без ограничения.
	l := baseLicense(2)
	l.Limits = Limits{}
	if _, err := f.upload(t, l); err != nil {
		t.Fatal(err)
	}
	f.usage.Gateways, f.usage.Applications = 1000, 1000
	if f.svc.CheckGateway(ctx) != nil || f.svc.CheckApplication(ctx) != nil {
		t.Fatal("предел 0 ограничивает")
	}
}

// 4В16 ревью 4.r2: после льготного периода предел шлюзов действует, при
// недействительной лицензии новый шлюз не регистрируется.
func TestGatewayLimitRestrictedAndInvalid(t *testing.T) {
	f := newFixture(t, day(2026, 11, 1))
	ctx := context.Background()
	if _, err := f.upload(t, baseLicense(1)); err != nil { // шлюзов 2
		t.Fatal(err)
	}
	f.usage.Gateways = 2
	f.clock.t = day(2027, 10, 28).Add(GracePeriod + time.Hour)
	if st := f.state(t); st.Phase != PhaseRestricted {
		t.Fatalf("состояние: %s", st.Phase)
	}
	var d *Denied
	if err := f.svc.CheckGateway(ctx); !errors.As(err, &d) || d.Code != CodeLimit {
		t.Fatalf("restricted, предел шлюзов: %v", err)
	}
	f.usage.Gateways = 1
	if err := f.svc.CheckGateway(ctx); err != nil {
		t.Fatalf("restricted ниже предела: %v", err)
	}
	f.clock.t = day(2026, 11, 2)
	f.store.Replace(audit.DefaultOrgID, swapPayload(t, signTest(t, baseLicense(1)), must(Encode(baseLicense(3)))(t)))
	if err := f.svc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	f.usage.Gateways = 0
	if err := f.svc.CheckGateway(ctx); !errors.As(err, &d) || d.Code != CodeRestricted {
		t.Fatalf("invalid: %v", err)
	}
}

func TestTamperedStoredLicenseIsInvalid(t *testing.T) {
	f := newFixture(t, day(2026, 11, 1))
	if _, err := f.upload(t, baseLicense(1)); err != nil {
		t.Fatal(err)
	}
	// Запись в БД изменена: лицензия с большими пределами без подписи.
	f.store.Replace(audit.DefaultOrgID, swapPayload(t, signTest(t, baseLicense(1)), must(Encode(baseLicense(3)))(t)))
	if err := f.svc.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := f.state(t)
	var d *Denied
	if st.Phase != PhaseInvalid || !errors.As(f.svc.CheckMutation(context.Background(), ""), &d) || d.Code != CodeRestricted {
		t.Fatalf("изменённая запись: %+v", st)
	}
	// Новая действительная лицензия снимает запрет.
	if _, err := f.upload(t, baseLicense(2)); err != nil {
		t.Fatal(err)
	}
	if st := f.state(t); st.Phase != PhaseActive {
		t.Fatalf("после загрузки: %s", st.Phase)
	}
}

func TestStaleSaveRace(t *testing.T) {
	// Параллельная загрузка уже сохранила номер больше: отказ stale_number.
	f := newFixture(t, day(2026, 11, 1))
	if err := f.store.Save(context.Background(), audit.DefaultOrgID, Stored{Number: 10, File: []byte("{}")}, audit.Entry{}); err != nil {
		t.Fatal(err)
	}
	f.svc.loaded = true // кэш ещё не видит параллельную загрузку
	_, err := f.upload(t, baseLicense(3))
	var rej *Rejected
	if !errors.As(err, &rej) || rej.Reason != ReasonStaleNumber {
		t.Fatalf("гонка загрузок: %v", err)
	}
}

func TestVerifyUsesInstallProfile(t *testing.T) {
	// Лицензия проверяется ключом производителя, встроенным в сборку.
	p := provider(t)
	v, err := VendorVerifier(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(p, v, signTest(t, baseLicense(1)), day(2026, 11, 1)); err != nil {
		t.Fatal(err)
	}
}
