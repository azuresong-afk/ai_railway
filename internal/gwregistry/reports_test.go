package gwregistry_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
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
		"самотест: манифест":                    {Version: "1", Selftest: &gwregistry.CheckReport{OK: true, At: now, ManifestVersion: "1", ManifestCreated: now}},
		"самотест: тестовый ключ":               {Version: "1", Selftest: &gwregistry.CheckReport{OK: true, At: now, TestSigned: true}},
		"целостность: версия без времени":       {Version: "1", Integrity: &gwregistry.CheckReport{OK: true, At: now, Reason: "ok", ManifestVersion: "1"}},
		"целостность: время без версии":         {Version: "1", Integrity: &gwregistry.CheckReport{OK: true, At: now, Reason: "ok", ManifestCreated: now}},
		"целостность: манифест в будущем": {Version: "1", Integrity: &gwregistry.CheckReport{OK: true, At: now, Reason: "ok",
			ManifestVersion: "1", ManifestCreated: now.Add(time.Hour)}},
		"целостность: версия с управляющим символом": {Version: "1", Integrity: &gwregistry.CheckReport{OK: true, At: now, Reason: "ok",
			ManifestVersion: "1\n", ManifestCreated: now}},
		"ключи пакетов: не hex":      {Version: "1", BundleKeys: []string{"0123456789ABCDEF"}},
		"ключи пакетов: повтор":      {Version: "1", BundleKeys: []string{"0123456789abcdef", "0123456789abcdef"}},
		"ключи пакетов: больше двух": {Version: "1", BundleKeys: []string{"0000000000000001", "0000000000000002", "0000000000000003"}},
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

// DM-42, В20 ревью 2.r4: максимум манифеста шлюза растёт по успешным
// проверкам; меньшее время — откат, пока его не примут (aisec-cli verify
// -accept-rollback -gateway); принятие пишется в аудит.
func TestDM42_GatewayManifestRollback(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	id := reg.Gateway.ID
	newer, older := e.clock.now().Add(-24*time.Hour), e.clock.now().Add(-60*24*time.Hour)
	beat := func(version string, created time.Time, ok bool) gwregistry.Gateway {
		t.Helper()
		in := gwregistry.HeartbeatInput{Version: "1", Integrity: &gwregistry.CheckReport{OK: ok, At: e.clock.now(), Reason: "ok",
			ManifestVersion: version, ManifestCreated: created}}
		if !ok {
			in.Integrity.Reason, in.Integrity.Failed = "files_mismatch", 1
		}
		if _, err := e.svc.Heartbeat(ctx, id, in, testIP); err != nil {
			t.Fatal(err)
		}
		e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
		list, err := e.svc.List(ctx)
		if err != nil || len(list) != 1 {
			t.Fatalf("%v %v", list, err)
		}
		return list[0]
	}
	if g := beat("1.1.0", newer, true); g.Rollback() || g.ManifestMaxVersion != "1.1.0" {
		t.Fatalf("%+v", g)
	}
	actor := cliActor
	if _, err := e.svc.AcceptRollback(ctx, "gw-1", actor); !errors.Is(err, gwregistry.ErrNoRollback) {
		t.Fatalf("принят откат без отката: %v", err)
	}
	// Нарушение файлов со старым манифестом максимум не меняет и тоже откат.
	if g := beat("1.0.0", older, false); !g.Rollback() || g.ManifestMaxVersion != "1.1.0" {
		t.Fatalf("%+v", g)
	}
	// При нарушенной целостности откат не принимается (ревью исправлений).
	if _, err := e.svc.AcceptRollback(ctx, "gw-1", actor); !errors.Is(err, gwregistry.ErrRollbackViolated) {
		t.Fatalf("принят откат при нарушении: %v", err)
	}
	if g := beat("1.0.0", older, true); !g.Rollback() {
		t.Fatalf("откат не обнаружен: %+v", g)
	}
	g, err := e.svc.AcceptRollback(ctx, "gw-1", actor)
	if err != nil || g.Rollback() || g.ManifestMaxVersion != "1.0.0" {
		t.Fatalf("%+v %v", g, err)
	}
	last := e.mem.Records[len(e.mem.Records)-1]
	d := last.Details.(map[string]any)
	if last.Action != "integrity.rollback_accepted" || d["previous_version"] != "1.1.0" || d["manifest_version"] != "1.0.0" {
		t.Fatalf("%+v", last)
	}
	// Выпуск без сведений о манифесте после выпуска со сведениями — откат.
	if g := beat("", time.Time{}, true); !g.Rollback() {
		t.Fatalf("откат на выпуск без сведений не обнаружен: %+v", g)
	}
	if g, err := e.svc.AcceptRollback(ctx, "gw-1", actor); err != nil || g.Rollback() || !g.ManifestMaxCreated.IsZero() {
		t.Fatalf("%+v %v", g, err)
	}
}

// В19 ревью 2.r4: ключи проверки пакетов шлюза сверяются с ключом подписи
// сервера и вторым ключом ротации; чужой ключ — BundleKeysOK = false.
func TestHeartbeatBundleKeys(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	id := reg.Gateway.ID
	const cur, next, foreign = "00000000000000aa", "00000000000000bb", "00000000000000cc"
	beat := func(keys ...string) *bool {
		t.Helper()
		if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", BundleKeys: keys}, testIP); err != nil {
			t.Fatal(err)
		}
		e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
		list, err := e.svc.List(ctx)
		if err != nil || len(list) != 1 {
			t.Fatalf("%v %v", list, err)
		}
		return list[0].BundleKeysOK
	}
	// Ключи сервера не заданы — сверки нет.
	if ok := beat(foreign); ok != nil {
		t.Fatalf("сверка без ключей сервера: %v", *ok)
	}
	e.svc.SetBundleKeys(gwregistry.BundleKeys{Current: cur, Next: next})
	for _, c := range []struct {
		keys []string
		want bool
	}{
		{[]string{cur}, true},
		{[]string{cur, next}, true},
		{[]string{foreign}, false},      // -bundle-pub подменён
		{[]string{cur, foreign}, false}, // добавлен чужой ключ
		{[]string{next}, false},         // нет действующего ключа
	} {
		if ok := beat(c.keys...); ok == nil || *ok != c.want {
			t.Errorf("%v: %v", c.keys, ok)
		}
	}
	// Heartbeat без ключей (прежняя версия шлюза) итог не стирает.
	if ok := beat(); ok == nil || *ok {
		t.Fatalf("итог стёрт: %v", ok)
	}
}

// То же на PostgreSQL: столбцы миграции 0022, права aisec_app на UPDATE,
// принятие отката под владельцем схемы (aisec-cli).
func TestPGHeartbeatManifestAndKeys(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	reg := e.register(t, e.issue(t, "gw-1", false))
	id := reg.Gateway.ID
	e.srv.SetBundleKeys(gwregistry.BundleKeys{Current: "00000000000000aa"})
	newer, older := e.clock.now().Add(-24*time.Hour).UTC().Truncate(time.Second), e.clock.now().Add(-60*24*time.Hour).UTC().Truncate(time.Second)
	for _, c := range []struct {
		version string
		created time.Time
		key     string
	}{{"1.1.0", newer, "00000000000000aa"}, {"1.0.0", older, "00000000000000cc"}} {
		in := gwregistry.HeartbeatInput{Version: "1", BundleKeys: []string{c.key}, Integrity: &gwregistry.CheckReport{OK: true,
			At: e.clock.now(), Reason: "ok", ManifestVersion: c.version, ManifestCreated: c.created, TestSigned: true}}
		if _, err := e.srv.Heartbeat(ctx, id, in, testIP); err != nil {
			t.Fatal(err)
		}
		e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	}
	list, err := e.cli.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	g := list[0]
	if !g.Rollback() || g.ManifestMaxVersion != "1.1.0" || !g.ManifestMaxCreated.Equal(newer) || !g.Integrity.TestSigned ||
		g.BundleKeysOK == nil || *g.BundleKeysOK {
		t.Fatalf("%+v %+v", g, g.Integrity)
	}
	g, err = e.cli.AcceptRollback(ctx, "gw-1", cliActor)
	if err != nil || g.Rollback() || !g.ManifestMaxCreated.Equal(older) {
		t.Fatalf("%+v %v", g, err)
	}
}

// Н38 ревью 2.r4: проверка шлюзов по команде из консоли. Запрос уходит в
// ответе heartbeat, пока шлюз не пришлёт итог целостности именно на него;
// итог пишется в журнал аудита (integrity.check, trigger manual).
func TestGatewayVerifyRequest(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	id := reg.Gateway.ID
	n, err := e.svc.RequestVerify(ctx, cliActor, testIP)
	if err != nil || n != 1 {
		t.Fatalf("запрос: %d %v", n, err)
	}
	if r := e.mem.Records[len(e.mem.Records)-1]; r.Action != "integrity.verify_requested" || r.Details.(map[string]any)["gateways"] != 1 {
		t.Fatalf("аудит запроса: %+v", r)
	}
	beat := func(in gwregistry.HeartbeatInput) gwregistry.HeartbeatResult {
		t.Helper()
		e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
		res, err := e.svc.Heartbeat(ctx, id, in, testIP)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	res := beat(gwregistry.HeartbeatInput{Version: "1"})
	requested := res.VerifyRequestedAt
	if requested.IsZero() {
		t.Fatal("запрос не передан шлюзу")
	}
	bad := &gwregistry.CheckReport{At: e.clock.now(), Reason: "files_mismatch", Failed: 1}
	// Итог периодической проверки или на чужой запрос запрос не снимает.
	if res := beat(gwregistry.HeartbeatInput{Version: "1", Integrity: bad}); !res.VerifyRequestedAt.Equal(requested) {
		t.Fatalf("снят без ответа на запрос: %+v", res)
	}
	if res := beat(gwregistry.HeartbeatInput{Version: "1", Integrity: bad, VerifyRequest: requested.Add(-time.Second)}); res.VerifyRequestedAt.IsZero() {
		t.Fatal("снят ответом на другой запрос")
	}
	before := len(e.mem.Records)
	if res := beat(gwregistry.HeartbeatInput{Version: "1", Integrity: bad, VerifyRequest: requested}); !res.VerifyRequestedAt.IsZero() {
		t.Fatalf("не снят после ответа: %+v", res)
	}
	if len(e.mem.Records) != before+1 {
		t.Fatalf("записей итога: %d", len(e.mem.Records)-before)
	}
	r := e.mem.Records[before]
	if d := r.Details.(map[string]any); r.Action != "integrity.check" || r.Result != audit.ResultFailure || d["trigger"] != "manual" || d["reason"] != "files_mismatch" {
		t.Fatalf("аудит итога: %+v", r)
	}
	// Повтор того же ответа второй записи не даёт.
	if beat(gwregistry.HeartbeatInput{Version: "1", Integrity: bad, VerifyRequest: requested}); len(e.mem.Records) != before+1 {
		t.Fatal("повторная запись итога")
	}
	e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
	if _, err := e.svc.Heartbeat(ctx, id, gwregistry.HeartbeatInput{Version: "1", VerifyRequest: requested}, testIP); !errors.Is(err, gwregistry.ErrInvalidRequest) {
		t.Fatalf("verify_request без итога: %v", err)
	}
}

// Запуск и остановка шлюза — в журнал аудита по started_at и stopping
// (В27 ревью 2.r5, РСБ.2).
func TestGatewayStartStop(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	id := reg.Gateway.ID
	beat := func(in gwregistry.HeartbeatInput, wait bool) error {
		t.Helper()
		if wait {
			e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
		}
		_, err := e.svc.Heartbeat(ctx, id, in, testIP)
		return err
	}
	actions := func(from int) []string {
		var out []string
		for _, r := range e.mem.Records[from:] {
			out = append(out, r.Action)
		}
		return out
	}
	// Наносекунды отбрасываются: PostgreSQL хранит микросекунды.
	first := e.clock.now().Add(-time.Minute).Add(123 * time.Nanosecond)
	before := len(e.mem.Records)
	if err := beat(gwregistry.HeartbeatInput{Version: "1", StartedAt: first}, true); err != nil {
		t.Fatal(err)
	}
	if err := beat(gwregistry.HeartbeatInput{Version: "1", StartedAt: first}, true); err != nil {
		t.Fatal(err)
	}
	if got := actions(before); len(got) != 1 || got[0] != "component.start" {
		t.Fatalf("записи запуска: %v", got)
	}
	if d := e.mem.Records[before].Details.(map[string]any); d["component"] != "gateway" || d["previous_started_at"] != nil {
		t.Fatalf("подробности запуска: %v", d)
	}
	// Остановка сразу за heartbeat — не отклоняется пределом частоты; повтор
	// и остановка чужого запуска записей не дают.
	before = len(e.mem.Records)
	if err := beat(gwregistry.HeartbeatInput{Version: "1", StartedAt: first.Add(time.Second), Stopping: true}, false); err != nil {
		t.Fatal(err)
	}
	if err := beat(gwregistry.HeartbeatInput{Version: "1", StartedAt: first, Stopping: true}, true); err != nil {
		t.Fatal(err)
	}
	if err := beat(gwregistry.HeartbeatInput{Version: "1", StartedAt: first, Stopping: true}, true); err != nil {
		t.Fatal(err)
	}
	if got := actions(before); len(got) != 1 || got[0] != "component.stop" {
		t.Fatalf("записи остановки: %v", got)
	}
	list, err := e.mem.List(ctx, reg.Gateway.OrgID)
	if err != nil || len(list) != 1 || !list[0].StartedAt.IsZero() {
		t.Fatalf("время запуска не стёрто после остановки: %+v %v", list, err)
	}
	// Поток heartbeat остановки упирается в свой предел частоты.
	if err := beat(gwregistry.HeartbeatInput{Version: "1", StartedAt: first, Stopping: true}, false); !errors.Is(err, gwregistry.ErrTooFrequent) {
		t.Fatalf("повтор остановки без паузы: %v", err)
	}
	// Корректный перезапуск, затем аварийный: у второго — прежний запуск
	// без записи об остановке.
	second, third := first.Add(time.Hour), first.Add(2*time.Hour)
	e.clock.add(3 * time.Hour)
	before = len(e.mem.Records)
	if err := beat(gwregistry.HeartbeatInput{Version: "1", StartedAt: second}, true); err != nil {
		t.Fatal(err)
	}
	if err := beat(gwregistry.HeartbeatInput{Version: "2", StartedAt: third}, true); err != nil {
		t.Fatal(err)
	}
	if got := actions(before); len(got) != 2 || got[0] != "component.start" || got[1] != "component.start" {
		t.Fatalf("записи перезапусков: %v", got)
	}
	if d := e.mem.Records[before].Details.(map[string]any); d["previous_started_at"] != nil {
		t.Fatalf("корректный перезапуск помечен аварийным: %v", d)
	}
	d := e.mem.Records[before+1].Details.(map[string]any)
	if d["previous_stop_recorded"] != false || d["previous_started_at"] != second.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano) || d["version"] != "2" {
		t.Fatalf("аварийный перезапуск: %v", d)
	}
	// Шлюз прежней версии без started_at записей не даёт.
	before = len(e.mem.Records)
	if err := beat(gwregistry.HeartbeatInput{Version: "1"}, true); err != nil || len(e.mem.Records) != before {
		t.Fatalf("heartbeat без started_at: %v, записей %d", err, len(e.mem.Records)-before)
	}
}

func TestGatewayStartStopInvalid(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	reg, _ := e.register(t, e.token(t, "gw-1", false))
	for _, in := range []gwregistry.HeartbeatInput{
		{Version: "1", Stopping: true},
		{Version: "1", StartedAt: e.clock.now().Add(time.Hour)},
	} {
		e.clock.add(gwregistry.DefaultHeartbeatMinInterval)
		if _, err := e.svc.Heartbeat(ctx, reg.Gateway.ID, in, testIP); !errors.Is(err, gwregistry.ErrInvalidRequest) {
			t.Fatalf("%+v: %v", in, err)
		}
	}
}
