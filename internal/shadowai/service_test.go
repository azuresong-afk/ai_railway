package shadowai

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

var testBy = By{Actor: audit.Actor{Type: audit.ActorUser, ID: "01900000-0000-7000-8000-0000000000a1", Name: "sysadm"}}

func newTestService(t testing.TB, st Store, mac bool) *Service {
	t.Helper()
	o := Options{Store: st, ServiceDBs: st.(*Memory).ServiceDBs(), Provider: provider(t), Clock: func() time.Time { return testNow },
		Location: func(context.Context) (*time.Location, error) { return time.LoadLocation("Europe/Moscow") }}
	if mac {
		o.UserMAC = testMAC(t)
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func lastRecord(m *Memory, action string) (audit.Entry, int) {
	var last audit.Entry
	n := 0
	for _, r := range append(m.Records(), m.ServiceDBs().Records()...) {
		if r.Action == action {
			last, n = r, n+1
		}
	}
	return last, n
}

// 4Н21 ревью 4.r3: две загрузки сразу — в памяти и в хранилище старшая
// версия, previous_version в аудите — та версия, которую заменила запись.
func TestCatalogUploadConcurrent(t *testing.T) {
	ctx := context.Background()
	files := [][]byte{signCatalog(t, catalogYAML(5, "2026-10-28"), nil), signCatalog(t, catalogYAML(6, "2026-10-28"), nil)}
	for range 20 {
		m := NewMemory()
		s := newTestService(t, m, true)
		var wg sync.WaitGroup
		for _, f := range files {
			wg.Go(func() { _, _ = s.UploadCatalog(ctx, testBy, f) }) //nolint:gosec // G104: исход проверяется по хранилищу и аудиту
		}
		wg.Wait()
		v, err := s.Catalog(ctx)
		if err != nil || v.Version != 6 {
			t.Fatalf("в памяти версия %d: %v", v.Version, err)
		}
		if sl, err := m.ServiceDBs().Slots(ctx, "", CatalogKind); err != nil || sl.Current.Version != 6 {
			t.Fatalf("в хранилище версия %+v: %v", sl.Current, err)
		}
		var prev uint64
		for _, r := range m.ServiceDBs().Records() {
			if r.Action != servicedb.ActionLoaded {
				continue
			}
			d := r.Details.(map[string]any)
			if d["previous_version"] != prev {
				t.Fatalf("previous_version %v, ожидалось %d: %+v", d["previous_version"], prev, d)
			}
			prev = d["version"].(uint64)
		}
		if prev != 6 {
			t.Fatalf("последняя загруженная версия в аудите: %d", prev)
		}
	}
}

func TestCatalogUpload(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	s := newTestService(t, m, true)
	if v, err := s.Catalog(ctx); err != nil || v.Loaded {
		t.Fatalf("пустой каталог: %+v %v", v, err)
	}
	if _, err := s.Import(ctx, testBy, FormatSquid, strings.NewReader("x\n")); !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("импорт без каталога: %v", err)
	}
	v, err := s.UploadCatalog(ctx, testBy, readFile(t, testCatalogSigned))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Loaded || !v.Valid || v.Version != 1 || v.SubkeySerial != 1 || len(v.Services) != 28 || v.Date != "2026-10-28" {
		t.Fatalf("каталог: %+v", v)
	}
	rec, n := lastRecord(m, servicedb.ActionLoaded)
	if d, _ := rec.Details.(map[string]any); n != 1 || d["version"] != uint64(1) || d["subkey_serial"] != uint64(1) {
		t.Fatalf("аудит загрузки: %+v", rec)
	}
	// Та же версия, мусор, подмена — отказ с причиной и записью аудита.
	for name, tc := range map[string]struct {
		data   []byte
		reason string
	}{
		"та же версия": {readFile(t, testCatalogSigned), "stale_version"},
		"мусор":        {[]byte("\x00\x01"), "format"},
		"подмена":      {bytes.Replace(readFile(t, testCatalogSigned), []byte(`"payload":"`), []byte(`"payload":"AA`), 1), "format"},
	} {
		_, err := s.UploadCatalog(ctx, testBy, tc.data)
		var ce *servicedb.RejectError
		if !errors.As(err, &ce) || ce.Reason != tc.reason {
			t.Fatalf("%s: %v", name, err)
		}
		rec, _ := lastRecord(m, servicedb.ActionRejected)
		if d, _ := rec.Details.(map[string]any); rec.Result != audit.ResultFailure || d["reason"] != tc.reason || d["kind"] != CatalogKind {
			t.Fatalf("%s: аудит отказа %+v", name, rec)
		}
	}
	if v, err := s.Catalog(ctx); err != nil || v.Version != 1 {
		t.Fatalf("версия после отказов: %d", v.Version)
	}
	// Версия 2 принимается; новый сервис на том же хранилище читает её и
	// проверяет подпись заново.
	if v, err = s.UploadCatalog(ctx, testBy, signCatalog(t, catalogYAML(2, "2026-10-28"), nil)); err != nil || v.Version != 2 || len(v.Services) != 2 {
		t.Fatalf("версия 2: %+v %v", v, err)
	}
	s2 := newTestService(t, m, true)
	if v, err := s2.Catalog(ctx); err != nil || !v.Valid || v.Version != 2 {
		t.Fatalf("после перезапуска: %+v %v", v, err)
	}
	// Подменённые в хранилище текущая и предыдущая версии не используются:
	// импорт невозможен, в аудите — service_db.stored_invalid.
	sl, err := m.ServiceDBs().Slots(ctx, "", CatalogKind)
	if err != nil {
		t.Fatal(err)
	}
	for slot, st := range map[string]*servicedb.Stored{servicedb.SlotCurrent: sl.Current, servicedb.SlotPrevious: sl.Previous} {
		st.File = bytes.Replace(st.File, []byte(`"signature":"`), []byte(`"signature":"AA`), 1)
		m.ServiceDBs().Put(CatalogKind, slot, st)
	}
	s3 := newTestService(t, m, true)
	if v, err := s3.Catalog(ctx); err != nil || v.Valid || !v.Loaded || v.Active != servicedb.ActiveNone {
		t.Fatalf("подменённый каталог: %+v %v", v, err)
	}
	if _, n := lastRecord(m, servicedb.ActionStoredInvalid); n != 2 {
		t.Fatalf("записей stored_invalid: %d", n)
	}
	if _, err := s3.Import(ctx, testBy, FormatSquid, strings.NewReader("x\n")); !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("импорт с подменённым каталогом: %v", err)
	}
}

func uploaded(t *testing.T, mac bool) (*Service, *Memory) {
	t.Helper()
	m := NewMemory()
	s := newTestService(t, m, mac)
	if _, err := s.UploadCatalog(context.Background(), testBy, readFile(t, testCatalogSigned)); err != nil {
		t.Fatal(err)
	}
	return s, m
}

func TestServiceImportAndRead(t *testing.T) {
	ctx := context.Background()
	s, m := uploaded(t, true)
	imp, err := s.Import(ctx, testBy, FormatSquid, bytes.NewReader(readFile(t, "../../testdata/shadowai/access-squid.log")))
	if err != nil {
		t.Fatal(err)
	}
	if imp.Matched != 5 || imp.CatalogVersion != 1 || imp.ID == "" || imp.CreatedBy != "user:"+testBy.Actor.ID {
		t.Fatalf("импорт: %+v", imp)
	}
	rec, n := lastRecord(m, "shadow_ai.import")
	d, _ := rec.Details.(map[string]any)
	if n != 1 || d["matched"] != int64(5) || d["sha256"] != imp.SHA256 || rec.Object.ID != imp.ID {
		t.Fatalf("аудит импорта: %+v", rec)
	}
	// Ни логинов, ни адресов, ни узлов в записи аудита.
	for _, bad := range []string{"ivanov", "10.0.12", "chatgpt.com", "example.ru"} {
		if strings.Contains(strings.ToLower(fmtAny(rec.Details)), bad) {
			t.Fatalf("в аудите %q: %+v", bad, rec.Details)
		}
	}
	if _, err := s.Import(ctx, testBy, FormatSquid, bytes.NewReader(readFile(t, "../../testdata/shadowai/access-squid.log"))); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("повтор: %v", err)
	}
	if _, err := s.Import(ctx, testBy, FormatCEF, bytes.NewReader(readFile(t, "../../testdata/shadowai/usergate-cef.log"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import(ctx, testBy, "json", strings.NewReader("{}")); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("формат: %v", err)
	}
	s.busy <- struct{}{}
	if _, err := s.Import(ctx, testBy, FormatCSV, strings.NewReader("x")); !errors.Is(err, ErrBusy) {
		t.Fatalf("второй импорт: %v", err)
	}
	<-s.busy

	q := Query{From: testNow.AddDate(0, 0, -7), To: testNow}
	svcs, err := s.Services(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 5 || svcs[0].ID != "chatgpt" || svcs[0].Requests != 3 || svcs[0].Name != "ChatGPT" || svcs[0].Users != 1 {
		t.Fatalf("сервисы: %+v", svcs)
	}
	users, err := s.Users(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	ivanov := pseudonym(testMAC(t), "ivanov.ia")
	if len(users) == 0 || users[0].Alias != ivanov || users[0].Requests != 3 || len(users[0].Services) != 1 {
		t.Fatalf("пользователи: %+v", users)
	}
	q.Service = "deepseek"
	if users, err = s.Users(ctx, q); err != nil || len(users) != 1 || users[0].Alias != pseudonym(testMAC(t), "petrova.ms") {
		t.Fatalf("пользователи сервиса: %+v", users)
	}
	q.Service, q.Step = "", StepHour
	pts, err := s.Timeline(ctx, q)
	if err != nil || len(pts) != 3 || pts[0].Requests != 1 || pts[1].Requests != 4 || pts[2].Requests != 2 {
		t.Fatalf("динамика по часам: %+v %v", pts, err)
	}
	q.Step = StepDay
	pts, err = s.Timeline(ctx, q)
	// Сутки — в часовом поясе установки (МСК): 27.10 00:00 МСК = 26.10 21:00 UTC.
	if err != nil || len(pts) != 1 || pts[0].Requests != 7 || !pts[0].Bucket.Equal(time.Date(2026, 10, 26, 21, 0, 0, 0, time.UTC)) ||
		pts[0].Services != 5 {
		t.Fatalf("динамика по суткам: %+v %v", pts, err)
	}
	imps, err := s.Imports(ctx)
	if err != nil || len(imps) != 2 || imps[0].Format != FormatCEF {
		t.Fatalf("журнал импорта: %+v %v", imps, err)
	}
	var qe *QueryError
	for name, q := range map[string]Query{
		"нет периода":    {},
		"наоборот":       {From: testNow, To: testNow.Add(-time.Hour)},
		"длинный":        {From: testNow.AddDate(-6, 0, 0), To: testNow},
		"сервис":         {From: q.From, To: q.To, Service: "Bad_ID"},
		"шаг":            {From: q.From, To: q.To, Step: "week"},
		"часы за 2 года": {From: testNow.AddDate(-2, 0, 0), To: testNow, Step: StepHour},
	} {
		var err error
		if name == "шаг" || name == "часы за 2 года" {
			_, err = s.Timeline(ctx, q)
		} else {
			_, err = s.Services(ctx, q)
		}
		if !errors.As(err, &qe) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func fmtAny(v any) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fmt.Sprint(v)), "\n", " "))
}

func TestRetention(t *testing.T) {
	ctx := context.Background()
	s, m := uploaded(t, true)
	if _, err := s.Import(ctx, testBy, FormatSquid, bytes.NewReader(readFile(t, "../../testdata/shadowai/access-squid.log"))); err != nil {
		t.Fatal(err)
	}
	st, err := s.Settings(ctx)
	if err != nil || st.RetentionDays != DefaultRetentionDays || !st.UsersPseudonymized {
		t.Fatalf("настройки: %+v %v", st, err)
	}
	if _, err := s.SetRetention(ctx, testBy, 400); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRetention(ctx, testBy, 30); !errors.Is(err, ErrConfirmNeeded) {
		t.Fatalf("сокращение без проверки: %v", err)
	}
	var qe *QueryError
	for _, d := range []int{29, 1826} {
		if _, err := s.SetRetention(ctx, testBy, d); !errors.As(err, &qe) {
			t.Fatalf("%d: %v", d, err)
		}
	}
	by := testBy
	by.Confirm = func(context.Context) error { return nil }
	if _, err := s.SetRetention(ctx, by, 30); err != nil {
		t.Fatal(err)
	}
	rec, _ := lastRecord(m, "shadow_ai.settings_changed")
	if d, _ := rec.Details.(map[string]any); d["weakening"] != true {
		t.Fatalf("ослабление: %+v", rec)
	}
	// Через 31 сутки агрегаты удаляются с записью аудита.
	m.SetClock(func() time.Time { return testNow.AddDate(0, 0, 31) })
	n, err := m.PurgeExpired(ctx, "")
	if err != nil || n == 0 || len(m.Aggregates()) != 0 {
		t.Fatalf("очистка: %d %v", n, err)
	}
	if _, cnt := lastRecord(m, "shadow_ai.retention"); cnt != 1 {
		t.Fatal("нет записи об очистке")
	}
	m.SetNotSetUp()
	if _, err := s.SetRetention(ctx, by, 60); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("без первичной настройки: %v", err)
	}
}

// Задача 5.9 этапа 5 (4Н25): заполнение хранилища сводок для «Состояния
// системы» — счёт кэшируется на StorageCacheTTL, импорт сбрасывает кэш.
func TestStorageCache(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	m.SetMaxAggregates(1000)
	now := testNow
	o := Options{Store: m, ServiceDBs: m.ServiceDBs(), Provider: provider(t), Clock: func() time.Time { return now }}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if n, limit, err := s.Storage(ctx); err != nil || n != 0 || limit != 1000 {
		t.Fatalf("пусто: %d из %d, %v", n, limit, err)
	}
	if _, err := s.UploadCatalog(ctx, testBy, readFile(t, testCatalogSigned)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import(ctx, testBy, FormatSquid, bytes.NewReader(readFile(t, "../../testdata/shadowai/access-squid.log"))); err != nil {
		t.Fatal(err)
	}
	n, _, err := s.Storage(ctx)
	if err != nil || n == 0 || n != int64(len(m.Aggregates())) {
		t.Fatalf("после импорта: %d, %v", n, err)
	}
	// Сводки изменились без импорта (очистка по сроку): до истечения кэша —
	// прежний счёт, после — новый.
	m.mu.Lock()
	clear(m.aggs)
	m.mu.Unlock()
	if got, _, _ := s.Storage(ctx); got != n {
		t.Fatalf("кэш: %d, ожидалось %d", got, n)
	}
	now = now.Add(StorageCacheTTL)
	if got, _, _ := s.Storage(ctx); got != 0 {
		t.Fatalf("после срока кэша: %d", got)
	}
}
