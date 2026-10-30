package compliance

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

func TestEvaluateOverview(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, NewMemory(), goodSnapshot())
	o, err := s.Evaluate(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if o.Base.Version != 1 || o.Base.Origin != "builtin" || len(o.Items) != 3 || len(o.Unavailable) != 0 {
		t.Fatalf("обзор: %+v", o)
	}
	// auto.one выполнен, manual.one ждёт отметки, draft.one — проект: в процент не входит.
	if o.Summary.Percent == nil || *o.Summary.Percent != 50 || o.Summary.Counted != 2 || o.Summary.Drafts != 1 {
		t.Fatalf("итог: %+v", o.Summary)
	}
	if _, err := s.Item(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("неизвестный пункт: %v", err)
	}
	// Источник недоступен — группа названа, проверка не засчитана.
	bad := goodSnapshot()
	bad.Unavailable[GroupApps] = true
	o, err = newTestService(t, NewMemory(), bad).Evaluate(ctx, Filter{})
	if err != nil || len(o.Unavailable) != 1 || o.Unavailable[0] != GroupApps || o.Items[0].Status != StatusNotMet {
		t.Fatalf("недоступная группа: %+v %v", o, err)
	}
}

func TestMarkLifecycle(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	s := newTestService(t, m, goodSnapshot())
	in := MarkInput{Status: StatusMet, Comment: "Регламент утверждён приказом № 5", Document: "СТО-ИБ-12", ReviewBy: "2027-01-31"}
	it, err := s.SetMark(ctx, testBy, "manual.one", in)
	if err != nil || it.Status != StatusMet || it.Mark == nil || it.Mark.SetBy == "" {
		t.Fatalf("отметка: %+v %v", it, err)
	}
	rec, n := lastRecord(m, "compliance.mark_set")
	d, _ := rec.Details.(map[string]any)
	if n != 1 || rec.Result != audit.ResultSuccess || d["status"] != "met" || d["requirement_id"] != "manual.one" || rec.Object.ID != "manual.one" {
		t.Fatalf("аудит отметки: %+v", rec)
	}
	// Изменение: в аудите прежний статус.
	if it, err = s.SetMark(ctx, testBy, "manual.one", MarkInput{Status: StatusPartial, Comment: "Часть приказов не подписана"}); err != nil || it.Status != StatusPartial {
		t.Fatalf("изменение: %+v %v", it, err)
	}
	rec, n = lastRecord(m, "compliance.mark_set")
	if d, _ = rec.Details.(map[string]any); n != 2 || d["previous_status"] != "met" {
		t.Fatalf("аудит изменения: %+v", rec)
	}
	// Снятие.
	if it, err = s.ClearMark(ctx, testBy, "manual.one"); err != nil || it.Status != StatusManual || it.Mark != nil {
		t.Fatalf("снятие: %+v %v", it, err)
	}
	if rec, n = lastRecord(m, "compliance.mark_cleared"); n != 1 || rec.Object.ID != "manual.one" {
		t.Fatalf("аудит снятия: %+v", rec)
	}
	if _, err = s.ClearMark(ctx, testBy, "manual.one"); !errors.Is(err, ErrNoMark) {
		t.Fatalf("повторное снятие: %v", err)
	}
	if _, err = s.ClearMark(ctx, testBy, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("снятие у неизвестного пункта: %v", err)
	}
	// Отказы не оставляют следа в аудите и в хранилище.
	before := len(m.Records())
	for name, tc := range map[string]struct {
		id string
		in MarkInput
	}{
		"без комментария":     {"manual.one", MarkInput{Status: StatusMet}},
		"пробелы":             {"manual.one", MarkInput{Status: StatusMet, Comment: "  \n "}},
		"статус «ручная»":     {"manual.one", MarkInput{Status: StatusManual, Comment: "x"}},
		"неизвестный статус":  {"manual.one", MarkInput{Status: "ok", Comment: "x"}},
		"управляющий символ":  {"manual.one", MarkInput{Status: StatusMet, Comment: "a\x00b"}},
		"длинный комментарий": {"manual.one", MarkInput{Status: StatusMet, Comment: string(bytes.Repeat([]byte("я"), MaxCommentRunes+1))}},
		"длинный документ":    {"manual.one", MarkInput{Status: StatusMet, Comment: "x", Document: string(bytes.Repeat([]byte("d"), MaxDocumentRunes+1))}},
		"срок в прошлом":      {"manual.one", MarkInput{Status: StatusMet, Comment: "x", ReviewBy: "2026-10-27"}},
		"срок далеко":         {"manual.one", MarkInput{Status: StatusMet, Comment: "x", ReviewBy: "2031-01-01"}},
		"срок не дата":        {"manual.one", MarkInput{Status: StatusMet, Comment: "x", ReviewBy: "31.12.2026"}},
		"срок 30 февраля":     {"manual.one", MarkInput{Status: StatusMet, Comment: "x", ReviewBy: "2027-02-30"}},
	} {
		_, err := s.SetMark(ctx, testBy, tc.id, tc.in)
		var ie *InputError
		if !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(m.Records()) != before {
		t.Fatal("отказ оставил запись аудита")
	}
	// Срок пересмотра сегодня допустим (граница), в прошлом — нет.
	if _, err = s.SetMark(ctx, testBy, "manual.one", MarkInput{Status: StatusMet, Comment: "x", ReviewBy: "2026-10-28"}); err != nil {
		t.Fatalf("срок сегодня: %v", err)
	}
	if _, err = s.SetMark(ctx, testBy, "nope", in); !errors.Is(err, ErrNotFound) {
		t.Fatalf("отметка неизвестного пункта: %v", err)
	}
}

// Пункт, статус которого вычисляют проверки, принимает только «не применимо».
func TestMarkOnAutoRequirement(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, NewMemory(), goodSnapshot())
	if _, err := s.SetMark(ctx, testBy, "auto.one", MarkInput{Status: StatusMet, Comment: "x"}); !errors.Is(err, ErrMarkNotAllowed) {
		t.Fatalf("ручное «выполнено» поверх проверок: %v", err)
	}
	na := MarkInput{Status: StatusNotApplicable, Comment: "Приложений в промышленной среде нет, закрыто договором"}
	// 4В36: «не применимо» поверх проверок — ослабление: без срока
	// пересмотра, без повторной проверки (токен) и с неверным паролем — отказ.
	var ie *InputError
	if _, err := s.SetMark(ctx, testBy, "auto.one", na); !errors.As(err, &ie) || ie.Fields["review_by"] == "" {
		t.Fatalf("без срока пересмотра: %v", err)
	}
	na.ReviewBy = testNow.AddDate(0, 6, 0).Format("2006-01-02")
	if _, err := s.SetMark(ctx, testBy, "auto.one", na); !errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("без повторной проверки: %v", err)
	}
	wrong := testBy
	wrong.Confirm = func(context.Context) error { return errors.New("неверный пароль") }
	if _, err := s.SetMark(ctx, wrong, "auto.one", na); err == nil || errors.Is(err, ErrConfirmRequired) {
		t.Fatalf("неверный пароль: %v", err)
	}
	confirmed := testBy
	confirmed.Confirm = func(context.Context) error { return nil }
	it, err := s.SetMark(ctx, confirmed, "auto.one", na)
	if err != nil || it.Status != StatusNotApplicable {
		t.Fatalf("«не применимо»: %+v %v", it, err)
	}
	if rec, _ := lastRecord(s.o.Store.(*Memory), "compliance.mark_set"); rec.Details.(map[string]any)["weakening"] != true {
		t.Fatalf("аудит без weakening: %+v", rec.Details)
	}
	o, _ := s.Evaluate(ctx, Filter{}) //nolint:gosec // G104: ошибка проверяется ниже по результату
	if o.Summary.Counted != 1 {
		t.Fatalf("«не применимо» не должно входить в процент: %+v", o.Summary)
	}
}

func TestUploadBase(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	s := newTestService(t, m, goodSnapshot())
	v, err := s.BaseView(ctx)
	if err != nil || v.Active.Origin != "builtin" || v.Uploaded != nil {
		t.Fatalf("до загрузки: %+v %v", v, err)
	}
	// Версия 2 с новым пунктом принимается и становится действующей.
	y2 := miniBase(2, "2026-10-28") + "  - {id: new.one, source: src-a, clause: п. 9, title: Новый, summary: Пересказ, applies: [kii], manual: true}\n"
	v, err = s.UploadBase(ctx, testBy, signBase(t, BaseKind, y2, nil))
	if err != nil || v.Active.Version != 2 || v.Active.Origin != "uploaded" || v.Uploaded == nil || !v.Uploaded.Valid || v.Active.Requirements != 4 {
		t.Fatalf("загрузка: %+v %v", v, err)
	}
	rec, n := lastRecord(m, "compliance.base_loaded")
	if d, _ := rec.Details.(map[string]any); n != 1 || d["version"] != uint64(2) || d["subkey_serial"] != uint64(1) || rec.Result != audit.ResultSuccess {
		t.Fatalf("аудит загрузки: %+v", rec)
	}
	if o, _ := s.Evaluate(ctx, Filter{}); len(o.Items) != 4 { //nolint:gosec // G104: ошибка проверяется ниже по результату
		t.Fatalf("новая база не действует: %d", len(o.Items))
	}
	// Отказы: причина и запись аудита с result=failure.
	base := signBase(t, BaseKind, miniBase(3, "2026-10-28"), nil)
	subOld := endorseTest(t, aisecCrypto.PurposeServiceDB, 1, testNow.AddDate(-5, 0, 0), testNow.AddDate(0, 0, -1))
	for name, tc := range map[string]struct {
		data   []byte
		reason string
	}{
		"та же версия":         {signBase(t, BaseKind, miniBase(2, "2026-10-28"), nil), "stale_version"},
		"версия ниже":          {signBase(t, BaseKind, miniBase(1, "2026-10-28"), nil), "stale_version"},
		"мусор":                {[]byte("\x00\x01"), "format"},
		"подмена подписи":      {bytes.Replace(base, []byte(`"signature":"`), []byte(`"signature":"AA`), 1), "format"},
		"подмена содержимого":  {bytes.Replace(base, []byte(`"payload":"`), []byte(`"payload":"AA`), 1), "format"},
		"другой вид базы":      {signBase(t, "shadow_ai_catalog", miniBase(3, "2026-10-28"), nil), "kind"},
		"заверение истекло":    {signBase(t, BaseKind, miniBase(3, "2026-10-28"), subOld), "expired"},
		"назначение":           {swapEndorsement(t, base, endorseTest(t, aisecCrypto.PurposeLicense, 1, testNow.AddDate(-1, 0, 0), testNow.AddDate(1, 0, 0))), "purpose"},
		"неизвестная проверка": {signBase(t, BaseKind, bytes.NewBufferString(miniBase(3, "2026-10-28")).String()+"  - {id: bad.one, source: src-a, clause: п., title: t, summary: s, applies: [gis], checks: [{name: shell_exec}]}\n", nil), "format"},
	} {
		_, err := s.UploadBase(ctx, testBy, tc.data)
		var be *BaseError
		if !errors.As(err, &be) || be.Reason != tc.reason {
			t.Errorf("%s: %v (ожидалась причина %s)", name, err, tc.reason)
			continue
		}
		rec, _ := lastRecord(m, "compliance.base_rejected")
		if d, _ := rec.Details.(map[string]any); rec.Result != audit.ResultFailure || d["reason"] != tc.reason {
			t.Errorf("%s: аудит отказа %+v", name, rec)
		}
	}
	if v, _ := s.BaseView(ctx); v.Active.Version != 2 { //nolint:gosec // G104: ошибка проверяется ниже по результату
		t.Fatalf("версия после отказов: %d", v.Active.Version)
	}
	// Дата базы вне срока заверения.
	oldDate := signBase(t, BaseKind, miniBase(5, "2026-01-01"), nil)
	if _, err = s.UploadBase(ctx, testBy, oldDate); RejectReason(errors.Unwrap(err)) != "date" {
		t.Fatalf("дата вне заверения: %v", err)
	}
	// Перезапуск: подпись проверяется заново; подменённый файл не используется.
	s2 := newTestService(t, m, goodSnapshot())
	if v, _ := s2.BaseView(ctx); v.Active.Version != 2 || v.Uploaded == nil || !v.Uploaded.Valid { //nolint:gosec // G104: ошибка проверяется ниже по результату
		t.Fatalf("после перезапуска: %+v", v)
	}
	m.mu.Lock()
	m.base.File = bytes.Replace(m.base.File, []byte(`"signature":"`), []byte(`"signature":"AA`), 1)
	m.mu.Unlock()
	s3 := newTestService(t, m, goodSnapshot())
	if v, _ := s3.BaseView(ctx); v.Active.Version != 1 || v.Active.Origin != "builtin" || v.Uploaded == nil || v.Uploaded.Valid { //nolint:gosec // G104: ошибка проверяется ниже по результату
		t.Fatalf("подменённая база: %+v", v)
	}
}

// Встроенная база новее загруженной — действует встроенная.
func TestEmbeddedNewerThanUploaded(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	s := newTestService(t, m, goodSnapshot())
	if _, err := s.UploadBase(ctx, testBy, signBase(t, BaseKind, miniBase(2, "2026-10-28"), nil)); err != nil {
		t.Fatal(err)
	}
	b, err := ParseBase([]byte(miniBase(3, "2026-10-28")))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := New(Options{Store: m, Provider: provider(t), Facts: &fakeFacts{snap: goodSnapshot()}, Embedded: b, Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s2.BaseView(ctx); v.Active.Version != 3 || v.Active.Origin != "builtin" { //nolint:gosec // G104: ошибка проверяется ниже по результату
		t.Fatalf("действует: %+v", v.Active)
	}
}

func TestRejectReasonUnknown(t *testing.T) {
	if RejectReason(errors.New("x")) != "format" {
		t.Fatal("по умолчанию — format")
	}
	if !hasPrefix("abc", "a") {
		t.Fatal()
	}
}

// ctxFacts — сведения, которые зависят от контекста сбора: при отменённом
// контексте все группы недоступны (как SystemFacts), ready задерживает сбор.
type ctxFacts struct {
	ready chan struct{}
	calls atomic.Int32
}

func (f *ctxFacts) Snapshot(ctx context.Context) (*Snapshot, error) {
	f.calls.Add(1)
	if f.ready != nil {
		<-f.ready
	}
	sn := goodSnapshot()
	if ctx.Err() != nil {
		sn.Unavailable = map[string]bool{GroupApps: true, GroupRoles: true}
		sn.Apps, sn.PrivilegedRoles = nil, nil
	}
	return sn, nil
}

// 4В35: отменённый первый вызов не портит снимок следующему; ожидающий с
// отменённым контекстом возвращается сразу; снимок с недоступными группами
// не кешируется.
func TestSnapshotSurvivesCancelledCaller(t *testing.T) {
	f := &ctxFacts{ready: make(chan struct{})}
	s := newTestService(t, NewMemory(), goodSnapshot())
	s.o.Facts = f
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := s.snapshot(ctx); first <- err }()
	for f.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("отменённый вызов: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ожидающий с отменённым контекстом не вернулся")
	}
	close(f.ready)
	sn, err := s.snapshot(context.Background())
	if err != nil || len(sn.Unavailable) != 0 || len(sn.Apps) == 0 {
		t.Fatalf("снимок после отмены первого вызова: %+v %v", sn, err)
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("сборов %d, нужен один общий", n)
	}
	// Снимок с недоступной группой не кешируется.
	bad := &fakeFacts{snap: goodSnapshot()}
	bad.snap.Unavailable = map[string]bool{GroupAlerts: true}
	s2 := newTestService(t, NewMemory(), bad.snap)
	if sn, err := s2.snapshot(context.Background()); err != nil || !sn.Unavailable[GroupAlerts] {
		t.Fatalf("снимок с недоступной группой: %+v %v", sn, err)
	}
	if s2.snap != nil {
		t.Fatal("снимок с недоступной группой закеширован")
	}
}

// failingPolicies — сбой хранилища политик (не «не найдена»).
type failingPolicies struct{ err error }

func (p failingPolicies) Get(context.Context, string, int) (versions.Doc, error) {
	return versions.Doc{}, p.err
}

// 4В35: сбой чтения политики делает группу приложений недоступной, а
// «политика не найдена» — приложение без политики.
func TestSystemFactsPolicyError(t *testing.T) {
	appsSrc := fakeApps{apps: []apps.Application{{Slug: "bot", Env: "prod", Policy: "p"}}}
	f := &SystemFacts{Apps: appsSrc, Policies: failingPolicies{err: errors.New("сбой БД")}}
	sn, err := f.Snapshot(context.Background())
	if err != nil || !sn.Unavailable[GroupApps] {
		t.Fatalf("сбой политики: %+v %v", sn, err)
	}
	f.Policies = failingPolicies{err: versions.ErrNotFound}
	if sn, err = f.Snapshot(context.Background()); err != nil || sn.Unavailable[GroupApps] || len(sn.Apps) != 1 || sn.Apps[0].PolicyMode != "" {
		t.Fatalf("политика не найдена: %+v %v", sn, err)
	}
}

// fakeApps — приложения без поставщиков.
type fakeApps struct{ apps []apps.Application }

func (f fakeApps) Applications(context.Context, string, *apps.Cursor, int) ([]apps.Application, error) {
	return f.apps, nil
}

func (f fakeApps) Providers(context.Context) ([]apps.Provider, error) { return nil, nil }
