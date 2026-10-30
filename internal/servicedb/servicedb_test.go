package servicedb

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func TestVerifyRejects(t *testing.T) {
	p := provider(t)
	vendor := testVendor(t)
	good := sign(t, testKindName, payload(2, "2026-10-28"), nil)
	v, err := Verify(p, vendor, testKind(), good, testNow)
	if err != nil || v.Content.Version != 2 || v.Content.Records != 3 || v.Endorsement.Serial != 1 || v.Fingerprint == "" {
		t.Fatalf("верный файл: %+v %v", v, err)
	}
	foreign, err := p.NewSigner(make([]byte, aisecCrypto.SigningSeedSize))
	if err != nil {
		t.Fatal(err)
	}
	foreignV, err := p.NewVerifier(foreign.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	from, until := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		vendor aisecCrypto.Verifier
		data   []byte
		at     time.Time
		reason string
	}{
		"чужой ключ производителя": {foreignV, good, testNow, ReasonSignature},
		"подпись испорчена":        {vendor, corrupt(good), testNow, ReasonSignature},
		"другой вид":               {vendor, sign(t, "other_db", payload(2, "2026-10-28"), nil), testNow, ReasonKind},
		"заверение лицензий":       {vendor, swapEndorsement(t, good, endorse(t, aisecCrypto.PurposeLicense, 2, from, until)), testNow, ReasonPurpose},
		"истёкшее заверение":       {vendor, good, time.Date(2031, 10, 1, 0, 0, 0, 0, time.UTC), ReasonExpired},
		"дата вне заверения":       {vendor, sign(t, testKindName, payload(2, "2027-12-01"), endorse(t, aisecCrypto.PurposeServiceDB, 3, from, until)), time.Time{}, ReasonDate},
		"содержимое":               {vendor, sign(t, testKindName, `{"version":2,"date":"2026-10-28","x":1}`, nil), testNow, ReasonContent},
		"версия 0":                 {vendor, sign(t, testKindName, `{"version":0,"date":"2026-10-28"}`, nil), testNow, ReasonContent},
		"мусор":                    {vendor, []byte("\x00\x01"), testNow, ReasonFormat},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(p, tc.vendor, testKind(), tc.data, tc.at)
			if err == nil || Reason(err) != tc.reason {
				t.Fatalf("ожидалась причина %s, получено %v (%s)", tc.reason, err, Reason(err))
			}
		})
	}
	if _, err := Verify(p, vendor, Kind{Name: testKindName}, good, testNow); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("вид без разборщика: %v", err)
	}
}

// Загрузка, правило версии, откат и повторная загрузка откатанной версии
// (ADR-0028, пп. 3–4).
func TestManagerUploadAndRollback(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	m := newManager(t, st, 0)
	if v, err := m.Active(ctx); err != nil || v != nil {
		t.Fatalf("пусто: %+v %v", v, err)
	}
	v1, v2 := sign(t, testKindName, payload(1, "2026-10-28"), nil), sign(t, testKindName, payload(2, "2026-10-28"), nil)
	if _, err := m.Upload(ctx, testBy, v1); err != nil {
		t.Fatal(err)
	}
	rec, n := count(st, ActionLoaded, audit.ResultSuccess)
	if d := rec.Details.(map[string]any); n != 1 || d["version"] != uint64(1) || d["previous_version"] != uint64(0) || d["kind"] != testKindName ||
		rec.Object != (audit.Object{Type: ObjectType, ID: testKindName}) {
		t.Fatalf("аудит загрузки: %+v", rec)
	}
	// Версия не выше текущей — отказ с причиной и записью аудита.
	for _, data := range [][]byte{v1, sign(t, testKindName, payload(1, "2026-10-29"), nil)} {
		_, err := m.Upload(ctx, testBy, data)
		var re *RejectError
		if !errors.As(err, &re) || re.Reason != ReasonStale || re.Kind != testKindName {
			t.Fatalf("та же версия: %v", err)
		}
	}
	if rec, n := count(st, ActionRejected, audit.ResultFailure); n != 2 || rec.Details.(map[string]any)["reason"] != ReasonStale {
		t.Fatalf("аудит отказа: %d %+v", n, rec)
	}
	if _, err := m.Upload(ctx, testBy, v2); err != nil {
		t.Fatal(err)
	}
	s, err := m.State(ctx)
	if err != nil || s.Active != ActiveCurrent || s.Current.Version != 2 || s.Previous == nil || s.Previous.Version != 1 || !s.Previous.Valid ||
		s.Current.SubkeyNotAfter == nil || s.Current.Records != 3 || s.Current.Date != "2026-10-28" {
		t.Fatalf("после v2: %+v %v", s, err)
	}
	// Откат: v1 становится текущей, слот предыдущей пустеет.
	got, err := m.Rollback(ctx, testBy)
	if err != nil || got.Content.Version != 1 {
		t.Fatalf("откат: %+v %v", got, err)
	}
	if a, _ := m.Active(ctx); a == nil || a.Content.Version != 1 { //nolint:gosec // G104: ошибка проверяется значением
		t.Fatalf("действует после отката: %+v", a)
	}
	if rec, n := count(st, ActionRolledBack, audit.ResultSuccess); n != 1 || rec.Details.(map[string]any)["from_version"] != uint64(2) ||
		rec.Details.(map[string]any)["version"] != uint64(1) {
		t.Fatalf("аудит отката: %d %+v", n, rec)
	}
	// Второй откат — некуда.
	_, err = m.Rollback(ctx, testBy)
	var re *RejectError
	if !errors.As(err, &re) || re.Reason != ReasonNoPrevious {
		t.Fatalf("откат без предыдущей: %v", err)
	}
	if rec, n := count(st, ActionRolledBack, audit.ResultFailure); n != 1 || rec.Details.(map[string]any)["reason"] != ReasonNoPrevious {
		t.Fatalf("аудит отказа в откате: %d %+v", n, rec)
	}
	// Откатанную версию можно загрузить снова.
	if _, err := m.Upload(ctx, testBy, v2); err != nil {
		t.Fatalf("повторная загрузка откатанной: %v", err)
	}
	if s, _ := m.State(ctx); s.Current.Version != 2 || s.Previous.Version != 1 { //nolint:gosec // G104: ошибка проверяется значением
		t.Fatalf("после повторной загрузки: %+v", s)
	}
}

// Нижний предел модуля (встроенная база): загружаемая должна быть новее.
func TestManagerMinVersion(t *testing.T) {
	m := newManager(t, NewMemory(), 5)
	_, err := m.Upload(context.Background(), testBy, sign(t, testKindName, payload(5, "2026-10-28"), nil))
	var re *RejectError
	if !errors.As(err, &re) || re.Reason != ReasonStale {
		t.Fatalf("версия не выше встроенной: %v", err)
	}
	if _, err := m.Upload(context.Background(), testBy, sign(t, testKindName, payload(6, "2026-10-28"), nil)); err != nil {
		t.Fatal(err)
	}
}

// Повреждённая сохранённая база (ADR-0028, п. 5): не используется,
// действует предыдущая, запись аудита — одна на версию за процесс.
func TestManagerStoredInvalid(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	m := newManager(t, st, 0)
	for v := 1; v <= 2; v++ {
		if _, err := m.Upload(ctx, testBy, sign(t, testKindName, payload(v, "2026-10-28"), nil)); err != nil {
			t.Fatal(err)
		}
	}
	sl, _ := st.Slots(ctx, "", testKindName) //nolint:gosec // G104: Memory не возвращает ошибку
	bad := *sl.Current
	bad.File = corrupt(bad.File)
	st.Put(testKindName, SlotCurrent, &bad)
	m2 := newManager(t, st, 0)
	if err := m2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := m2.Active(ctx)
	if err != nil || a == nil || a.Content.Version != 1 {
		t.Fatalf("действует: %+v %v", a, err)
	}
	s, _ := m2.State(ctx) //nolint:gosec // G104: проверено выше
	if s.Active != ActivePrevious || s.Current.Valid || s.Current.Reason != ReasonSignature || !s.Previous.Valid {
		t.Fatalf("состояние: %+v", s)
	}
	rec, n := count(st, ActionStoredInvalid, audit.ResultFailure)
	if d := rec.Details.(map[string]any); n != 1 || d["slot"] != SlotCurrent || d["version"] != uint64(2) || d["reason"] != ReasonSignature ||
		d["active"] != ActivePrevious || rec.Actor.Type != audit.ActorSystem {
		t.Fatalf("аудит: %d %+v", n, rec)
	}
	// Повторное чтение в том же процессе запись не дублирует.
	if err := m2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, n := count(st, ActionStoredInvalid, audit.ResultFailure); n != 1 {
		t.Fatalf("повтор записи: %d", n)
	}
	// Загрузка при повреждённой текущей: она не уходит в предыдущую —
	// предыдущей остаётся проверенная v1.
	if _, err := m2.Upload(ctx, testBy, sign(t, testKindName, payload(3, "2026-10-28"), nil)); err != nil {
		t.Fatal(err)
	}
	if s, _ := m2.State(ctx); s.Current.Version != 3 || s.Previous == nil || s.Previous.Version != 1 || !s.Previous.Valid { //nolint:gosec // G104: ошибка проверяется значением
		t.Fatalf("после загрузки: %+v", s)
	}
	// Номер в строке не совпадает с подписанным — строка изменена.
	sl, _ = st.Slots(ctx, "", testKindName) //nolint:gosec // G104: Memory не возвращает ошибку
	forged := *sl.Current
	forged.Version = 9
	st.Put(testKindName, SlotCurrent, &forged)
	bad1 := *sl.Previous
	bad1.File = corrupt(bad1.File)
	st.Put(testKindName, SlotPrevious, &bad1)
	m3 := newManager(t, st, 0)
	if a, err := m3.Active(ctx); err != nil || a != nil {
		t.Fatalf("обе версии негодны: %+v %v", a, err)
	}
	s, _ = m3.State(ctx) //nolint:gosec // G104: проверено выше
	if s.Active != ActiveNone || s.Current.Reason != ReasonContent || s.Previous.Reason != ReasonSignature {
		t.Fatalf("состояние: %+v", s)
	}
}

// Откат с повреждённой предыдущей — отказ, текущая не меняется.
func TestManagerRollbackCorruptedPrevious(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	m := newManager(t, st, 0)
	for v := 1; v <= 2; v++ {
		if _, err := m.Upload(ctx, testBy, sign(t, testKindName, payload(v, "2026-10-28"), nil)); err != nil {
			t.Fatal(err)
		}
	}
	sl, _ := st.Slots(ctx, "", testKindName) //nolint:gosec // G104: Memory не возвращает ошибку
	bad := *sl.Previous
	bad.File = corrupt(bad.File)
	st.Put(testKindName, SlotPrevious, &bad)
	_, err := m.Rollback(ctx, testBy)
	var re *RejectError
	if !errors.As(err, &re) || re.Reason != ReasonSignature {
		t.Fatalf("откат на повреждённую: %v", err)
	}
	if rec, n := count(st, ActionRolledBack, audit.ResultFailure); n != 1 || rec.Details.(map[string]any)["reason"] != ReasonSignature {
		t.Fatalf("аудит: %d %+v", n, rec)
	}
	if a, _ := m.Active(ctx); a == nil || a.Content.Version != 2 { //nolint:gosec // G104: ошибка проверяется значением
		t.Fatalf("текущая изменилась: %+v", a)
	}
	if sl, _ := st.Slots(ctx, "", testKindName); sl.Current.Version != 2 || sl.Previous == nil { //nolint:gosec // G104: Memory не возвращает ошибку
		t.Fatalf("слоты: %+v", sl)
	}
}

// Две загрузки сразу: в памяти — то же, что в хранилище (4Н21).
func TestManagerConcurrentUpload(t *testing.T) {
	ctx := context.Background()
	files := [][]byte{sign(t, testKindName, payload(5, "2026-10-28"), nil), sign(t, testKindName, payload(6, "2026-10-28"), nil)}
	for range 10 {
		st := NewMemory()
		m := newManager(t, st, 0)
		var wg sync.WaitGroup
		for _, f := range files {
			wg.Go(func() { _, _ = m.Upload(ctx, testBy, f) }) //nolint:gosec // G104: исход проверяется по хранилищу
		}
		wg.Wait()
		a, err := m.Active(ctx)
		sl, _ := st.Slots(ctx, "", testKindName) //nolint:gosec // G104: Memory не возвращает ошибку
		if err != nil || a == nil || a.Content.Version != 6 || sl.Current.Version != 6 {
			t.Fatalf("в памяти %+v, в хранилище %+v: %v", a, sl.Current, err)
		}
	}
}

func TestRegistryStates(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()
	m := newManager(t, st, 0)
	if _, err := m.Upload(ctx, testBy, sign(t, testKindName, payload(1, "2026-10-28"), nil)); err != nil {
		t.Fatal(err)
	}
	list, err := NewRegistry(m, nil).States(ctx)
	if err != nil || len(list) != 1 || list[0].Kind != testKindName || list[0].Title != "Тестовая база" || list[0].Active != ActiveCurrent {
		t.Fatalf("состояние: %+v %v", list, err)
	}
}

func TestInspect(t *testing.T) {
	p := provider(t)
	vendor := testVendor(t)
	kinds := []Kind{testKind()}
	r, err := Inspect(p, vendor, kinds, sign(t, testKindName, payload(4, "2026-10-28"), nil), testNow)
	if err != nil || !r.Verified || r.Version != 4 || r.Records != 3 || r.Endorsement.Serial != 1 || r.Fingerprint == "" || r.Title != "Тестовая база" {
		t.Fatalf("верный файл: %+v %v", r, err)
	}
	r, err = Inspect(p, vendor, kinds, sign(t, "other_db", payload(4, "2026-10-28"), nil), testNow)
	if err != nil || r.Verified || r.Reason != ReasonKind || r.Endorsement.Serial != 1 {
		t.Fatalf("неизвестный вид: %+v %v", r, err)
	}
	r, err = Inspect(p, vendor, kinds, sign(t, testKindName, payload(4, "2026-10-28"), nil), time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || r.Verified || r.Reason != ReasonExpired || r.Version != 0 {
		t.Fatalf("истёкшее заверение: %+v %v", r, err)
	}
	if _, err := Inspect(p, vendor, kinds, []byte("{}"), testNow); err == nil {
		t.Fatal("не служебная база принята")
	}
	if _, err := KindByName(kinds, "x"); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("KindByName: %v", err)
	}
}

// flakyStore — хранилище со сбоями чтения и записи аудита по признаку.
type flakyStore struct {
	*Memory
	failSlots, failRecord atomic.Bool
}

var errFlaky = errors.New("сбой хранилища")

func (f *flakyStore) Slots(ctx context.Context, org, kind string) (Slots, error) {
	if f.failSlots.Load() {
		return Slots{}, errFlaky
	}
	return f.Memory.Slots(ctx, org, kind)
}

func (f *flakyStore) Record(ctx context.Context, rec audit.Entry) error {
	if f.failRecord.Load() {
		return errFlaky
	}
	return f.Memory.Record(ctx, rec)
}

// Сбой чтения после зафиксированной записи — не отказ: база записана,
// состояние перечитывается при следующем обращении. Сбой записи аудита
// stored_invalid при запуске не теряет запись: менеджер перечитывает и
// пишет её снова. Сведения проверенной версии — из подписанного файла,
// а не из строки хранилища.
func TestManagerStoreFailures(t *testing.T) {
	ctx := context.Background()
	st := &flakyStore{Memory: NewMemory()}
	m := newManager(t, st, 0)
	if _, err := m.Upload(ctx, testBy, sign(t, testKindName, payload(1, "2026-10-28"), nil)); err != nil {
		t.Fatal(err)
	}
	st.failSlots.Store(true)
	if v, err := m.Upload(ctx, testBy, sign(t, testKindName, payload(2, "2026-10-28"), nil)); err != nil || v.Content.Version != 2 {
		t.Fatalf("записанная база — отказ: %+v %v", v, err)
	}
	if _, err := m.State(ctx); !errors.Is(err, errFlaky) {
		t.Fatalf("состояние при сбое: %v", err)
	}
	st.failSlots.Store(false)
	if s, err := m.State(ctx); err != nil || s.Current.Version != 2 || s.Previous.Version != 1 {
		t.Fatalf("после сбоя: %+v %v", s, err)
	}

	sl, _ := st.Memory.Slots(ctx, "", testKindName) //nolint:gosec // G104: Memory не возвращает ошибку
	bad := *sl.Current
	bad.File = corrupt(bad.File)
	st.Put(testKindName, SlotCurrent, &bad)
	forged := *sl.Previous
	forged.SubkeySerial, forged.Records, forged.Fingerprint = 77, 999, "чужой"
	st.Put(testKindName, SlotPrevious, &forged)
	st.failRecord.Store(true)
	m2 := newManager(t, st, 0)
	if err := m2.Load(ctx); !errors.Is(err, errFlaky) {
		t.Fatalf("сбой аудита при запуске: %v", err)
	}
	if a, err := m2.Active(ctx); !errors.Is(err, errFlaky) || a != nil {
		t.Fatalf("непроверенное состояние отдано: %+v %v", a, err)
	}
	st.failRecord.Store(false)
	s, err := m2.State(ctx)
	if err != nil || s.Active != ActivePrevious {
		t.Fatalf("после сбоя аудита: %+v %v", s, err)
	}
	if _, n := count(st.Memory, ActionStoredInvalid, audit.ResultFailure); n != 1 {
		t.Fatalf("записей stored_invalid: %d", n)
	}
	if p := s.Previous; p.SubkeySerial == 77 || p.Records == 999 || p.Fingerprint == "чужой" || p.UploadedBy == "" {
		t.Fatalf("сведения из строки хранилища: %+v", p)
	}
}
