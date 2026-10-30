package servicedb

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Коды аудита (ADR-0028, п. 6): общие для всех видов, вид — в подробностях
// и в объекте. Файл и содержимое базы в аудит не пишутся.
const (
	ActionLoaded        = "service_db.loaded"
	ActionRejected      = "service_db.rejected"
	ActionRolledBack    = "service_db.rolled_back"
	ActionStoredInvalid = "service_db.stored_invalid"
)

// ObjectType — тип объекта в записях аудита; ID объекта — вид базы.
const ObjectType = "service_db"

// Какая версия действует.
const (
	ActiveCurrent  = "current"
	ActivePrevious = "previous"
	ActiveNone     = "none"
)

// systemActor — субъект проверки сохранённых баз при запуске.
var systemActor = audit.Actor{Type: audit.ActorSystem, ID: "service-db", Name: "Проверка служебных баз"}

// By — субъект действия.
type By struct {
	Actor audit.Actor
	IP    netip.Addr
}

func (b By) ref() string {
	s := string(b.Actor.Type) + ":" + b.Actor.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

// Options — зависимости менеджера одного вида.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	Kind     Kind
	OrgID    string
	Clock    func() time.Time
	Logger   *slog.Logger
	// MinVersion — версия, которую загружаемая база должна превышать сверх
	// текущей сохранённой (встроенная в выпуск база модуля); 0 — нет.
	MinVersion uint64
	// Vendor — ключ производителя только для тестов; nil — встроенный
	// (EmbeddedVendor). Сервер его не задаёт.
	Vendor aisecCrypto.Verifier
}

// slotState — сохранённая версия и итог её проверки.
type slotState struct {
	stored   *Stored
	verified *Verified
	err      error
}

// Manager — служебная база одного вида: проверка, загрузка, откат,
// проверка сохранённых файлов и состояние.
type Manager struct {
	o Options

	mu       sync.Mutex
	loaded   bool
	cur      slotState
	prev     slotState
	reported map[reportKey]bool
}

// reportKey — сохранённая база, о непрошедшей проверке которой уже есть
// запись аудита в этом процессе: повторное чтение (после загрузки или
// отката) не дублирует запись.
type reportKey struct {
	slot    string
	version uint64
	reason  string
}

// NewManager создаёт менеджер вида. Сохранённые версии читаются и
// проверяются при Load или первом обращении.
func NewManager(o Options) (*Manager, error) {
	if o.Store == nil || o.Provider == nil {
		return nil, errors.New("служебные базы: нет хранилища или криптопрофиля")
	}
	if o.Kind.Name == "" || o.Kind.Parse == nil {
		return nil, ErrUnknownKind
	}
	if o.OrgID == "" {
		o.OrgID = audit.DefaultOrgID
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Vendor == nil {
		v, err := EmbeddedVendor(o.Provider)
		if err != nil {
			return nil, err
		}
		o.Vendor = v
	}
	return &Manager{o: o, reported: map[reportKey]bool{}}, nil
}

// Kind — вид базы.
func (m *Manager) Kind() Kind { return m.o.Kind }

// verifyStored проверяет сохранённый файл как при запуске: подпись,
// заверение, отзыв, дата внутри срока заверения, содержимое; срок
// заверения на текущее время не проверяется (ADR-0027, п. 3).
func (m *Manager) verifyStored(s Stored) (Verified, error) {
	v, err := Verify(m.o.Provider, m.o.Vendor, m.o.Kind, s.File, time.Time{})
	if err == nil && v.Content.Version != s.Version {
		// Номер в строке не совпадает с подписанным: строка изменена.
		err = ErrContent
	}
	return v, err
}

// Load читает сохранённые версии и проверяет их заново. Не прошедшая
// проверку версия не используется: действует предыдущая, если она
// проверяется, иначе вид работает как без базы. На каждую такую версию —
// запись аудита service_db.stored_invalid и признак в состоянии.
func (m *Manager) Load(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadLocked(ctx)
}

func (m *Manager) loadLocked(ctx context.Context) error {
	sl, err := m.o.Store.Slots(ctx, m.o.OrgID, m.o.Kind.Name)
	if err != nil {
		return err
	}
	cur, prev := m.check(sl.Current), m.check(sl.Previous)
	// Состояние меняется только после всех записей аудита: при сбое записи
	// следующее обращение перечитает и запишет снова (ADR-0028, п. 5).
	for _, s := range []struct {
		slot string
		st   slotState
	}{{SlotCurrent, cur}, {SlotPrevious, prev}} {
		if s.st.stored == nil || s.st.err == nil {
			continue
		}
		reason := Reason(s.st.err)
		key := reportKey{slot: s.slot, version: s.st.stored.Version, reason: reason}
		if m.reported[key] {
			continue
		}
		m.o.Logger.Error("служебная база: сохранённая версия не прошла проверку и не используется", "class", "integrity",
			"kind", m.o.Kind.Name, "slot", s.slot, "version", s.st.stored.Version, "reason", reason)
		rec := audit.Entry{Actor: systemActor, Action: ActionStoredInvalid, Object: audit.Object{Type: ObjectType, ID: m.o.Kind.Name},
			Result: audit.ResultFailure, Details: map[string]any{"kind": m.o.Kind.Name, "slot": s.slot, "version": s.st.stored.Version,
				"subkey_serial": s.st.stored.SubkeySerial, "reason": reason, "active": active(cur, prev)}}
		rec.OrgID = m.o.OrgID
		if err := m.o.Store.Record(ctx, rec); err != nil {
			return err
		}
		m.reported[key] = true
	}
	m.cur, m.prev, m.loaded = cur, prev, true
	return nil
}

func (m *Manager) check(s *Stored) slotState {
	if s == nil {
		return slotState{}
	}
	v, err := m.verifyStored(*s)
	if err != nil {
		return slotState{stored: s, err: err}
	}
	return slotState{stored: s, verified: &v}
}

func (m *Manager) ensure(ctx context.Context) error {
	if m.loaded {
		return nil
	}
	return m.loadLocked(ctx)
}

func (m *Manager) activeLocked() string { return active(m.cur, m.prev) }

func active(cur, prev slotState) string {
	switch {
	case cur.verified != nil:
		return ActiveCurrent
	case prev.verified != nil:
		return ActivePrevious
	}
	return ActiveNone
}

func (m *Manager) activeVerifiedLocked() *Verified {
	switch m.activeLocked() {
	case ActiveCurrent:
		return m.cur.verified
	case ActivePrevious:
		return m.prev.verified
	}
	return nil
}

// Active — действующая проверенная база; nil — нет ни одной.
func (m *Manager) Active(ctx context.Context) (*Verified, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensure(ctx); err != nil {
		return nil, err
	}
	return m.activeVerifiedLocked(), nil
}

// VersionState — сохранённая версия в состоянии.
type VersionState struct {
	Version        uint64     `json:"version"`
	Date           string     `json:"date"`
	Records        int        `json:"records"`
	SubkeySerial   uint64     `json:"subkey_serial"`
	SubkeyNotAfter *time.Time `json:"subkey_not_after,omitempty"`
	Fingerprint    string     `json:"fingerprint"`
	UploadedAt     time.Time  `json:"uploaded_at"`
	// UploadedBy — кто загрузил («user:ID», «token:ID»).
	UploadedBy string `json:"uploaded_by"`
	// Valid — подпись и содержимое сохранённого файла проверены.
	Valid bool `json:"valid"`
	// Reason — причина, по которой версия не прошла проверку.
	Reason string `json:"reason,omitempty"`
}

// State — состояние служебной базы одного вида (для «Состояния системы»,
// задача 5.9, и экранов модулей).
type State struct {
	Kind  string `json:"kind"`
	Title string `json:"title"`
	// Active — какая версия действует: current, previous или none.
	Active   string        `json:"active"`
	Current  *VersionState `json:"current,omitempty"`
	Previous *VersionState `json:"previous,omitempty"`
}

func versionState(s slotState) *VersionState {
	if s.stored == nil {
		return nil
	}
	v := &VersionState{Version: s.stored.Version, Date: s.stored.Date.UTC().Format(time.DateOnly), Records: s.stored.Records,
		SubkeySerial: s.stored.SubkeySerial, Fingerprint: s.stored.Fingerprint, UploadedAt: s.stored.UploadedAt.UTC(),
		UploadedBy: s.stored.UploadedBy, Valid: s.verified != nil}
	if s.verified != nil {
		// У проверенной версии сведения — из подписанного файла, а не из
		// строки БД, которую можно изменить, не трогая файл.
		c, e := s.verified.Content, s.verified.Endorsement
		until := e.NotAfter
		v.Date, v.Records, v.SubkeySerial, v.Fingerprint, v.SubkeyNotAfter = c.Date.UTC().Format(time.DateOnly), c.Records, e.Serial, s.verified.Fingerprint, &until
	} else {
		v.Reason = Reason(s.err)
	}
	return v
}

// State — состояние вида.
func (m *Manager) State(ctx context.Context) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensure(ctx); err != nil {
		return State{}, err
	}
	return State{Kind: m.o.Kind.Name, Title: m.o.Kind.Title, Active: m.activeLocked(),
		Current: versionState(m.cur), Previous: versionState(m.prev)}, nil
}

// Snapshot — состояние и действующая база из одного чтения под одной
// блокировкой: при одновременной загрузке версия и содержимое в ответе не
// расходятся.
func (m *Manager) Snapshot(ctx context.Context) (State, *Verified, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensure(ctx); err != nil {
		return State{}, nil, err
	}
	return State{Kind: m.o.Kind.Name, Title: m.o.Kind.Title, Active: m.activeLocked(),
		Current: versionState(m.cur), Previous: versionState(m.prev)}, m.activeVerifiedLocked(), nil
}

func (m *Manager) entry(by By, action string, result audit.Result, details map[string]any) audit.Entry {
	details["kind"] = m.o.Kind.Name
	return audit.Entry{OrgID: m.o.OrgID, Actor: by.Actor, SourceIP: by.IP, Action: action,
		Object: audit.Object{Type: ObjectType, ID: m.o.Kind.Name}, Result: result, Details: details}
}

// reload перечитывает сохранённые версии после записи: в памяти — то, что
// в хранилище (две загрузки сразу дают одну старшую версию, 4Н21). Запись
// уже зафиксирована, поэтому сбой чтения не делает её отказом: состояние
// помечается непрочитанным и перечитывается при следующем обращении.
func (m *Manager) reload(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.loadLocked(ctx); err != nil {
		m.loaded = false
		m.o.Logger.Error("служебная база: состояние не перечитано после записи", "kind", m.o.Kind.Name, "err", err)
	}
}

// Upload проверяет файл (срок заверения — на текущее время) и сохраняет его
// текущей версией, если номер больше текущей сохранённой и MinVersion.
// Прежняя текущая становится предыдущей. И успех, и отказ пишутся в аудит
// без содержимого; отказ — *RejectError.
func (m *Manager) Upload(ctx context.Context, by By, data []byte) (Verified, error) {
	now := m.o.Clock().UTC()
	v, err := Verify(m.o.Provider, m.o.Vendor, m.o.Kind, data, now)
	if err == nil && v.Content.Version <= m.o.MinVersion {
		err = ErrStale
	}
	if err == nil {
		st := Stored{Version: v.Content.Version, Date: v.Content.Date.UTC(), Records: v.Content.Records,
			SubkeySerial: v.Endorsement.Serial, Fingerprint: v.Fingerprint, File: data, UploadedAt: now.Truncate(time.Microsecond), UploadedBy: by.ref()}
		keep := func(s Stored) error { _, err := m.verifyStored(s); return err }
		err = m.o.Store.Save(ctx, m.o.OrgID, m.o.Kind.Name, st, keep, func(prev *Stored) audit.Entry {
			d := map[string]any{"version": st.Version, "date": st.Date.Format(time.DateOnly), "records": st.Records,
				"subkey_serial": st.SubkeySerial, "fingerprint": st.Fingerprint, "previous_version": uint64(0)}
			if prev != nil {
				d["previous_version"] = prev.Version
				// Не прошедшая проверку текущая не становится предыдущей.
				if _, perr := m.verifyStored(*prev); perr != nil {
					d["previous_dropped"], d["previous_reason"] = true, Reason(perr)
				}
			}
			return m.entry(by, ActionLoaded, audit.ResultSuccess, d)
		})
		if err == nil {
			m.reload(ctx)
			return v, nil
		}
		if !errors.Is(err, ErrStale) {
			return Verified{}, err
		}
	}
	reason := Reason(err)
	d := map[string]any{"reason": reason, "bytes": len(data)}
	if v.Content.Version > 0 {
		d["version"], d["subkey_serial"] = v.Content.Version, v.Endorsement.Serial
	}
	if aerr := m.o.Store.Record(ctx, m.entry(by, ActionRejected, audit.ResultFailure, d)); aerr != nil {
		return Verified{}, aerr
	}
	return Verified{}, &RejectError{Kind: m.o.Kind.Name, Reason: reason, Err: err}
}

// Rollback делает текущей хранимую предыдущую версию после её повторной
// проверки (как сохранённой базы при запуске). Откатанная версия
// удаляется, её можно загрузить снова. Отказ — *RejectError и запись
// аудита service_db.rolled_back с результатом «отказ».
func (m *Manager) Rollback(ctx context.Context, by By) (Verified, error) {
	var v Verified
	check := func(s Stored) error {
		var err error
		v, err = m.verifyStored(s)
		return err
	}
	_, err := m.o.Store.Rollback(ctx, m.o.OrgID, m.o.Kind.Name, check, func(from *Stored, to Stored) audit.Entry {
		d := map[string]any{"version": to.Version, "from_version": uint64(0), "subkey_serial": v.Endorsement.Serial}
		if from != nil {
			d["from_version"] = from.Version
		}
		return m.entry(by, ActionRolledBack, audit.ResultSuccess, d)
	})
	if err == nil {
		m.reload(ctx)
		return v, nil
	}
	if !errors.Is(err, ErrNoPrevious) && !isVerifyError(err) {
		return Verified{}, err
	}
	reason := Reason(err)
	if aerr := m.o.Store.Record(ctx, m.entry(by, ActionRolledBack, audit.ResultFailure, map[string]any{"reason": reason})); aerr != nil {
		return Verified{}, aerr
	}
	return Verified{}, &RejectError{Kind: m.o.Kind.Name, Reason: reason, Err: err}
}

// isVerifyError — ошибка проверки файла (а не хранилища).
func isVerifyError(err error) bool {
	for _, e := range []error{aisecCrypto.ErrEndorsementSignature, aisecCrypto.ErrServiceDBSignature, aisecCrypto.ErrEndorsementPurpose,
		aisecCrypto.ErrEndorsementExpired, aisecCrypto.ErrEndorsementRevoked, aisecCrypto.ErrServiceDBKind, aisecCrypto.ErrServiceDBFormat,
		aisecCrypto.ErrEndorsementFormat, ErrDate, ErrContent, ErrUnknownKind} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// Registry — менеджеры всех подключённых видов для общего состояния.
type Registry struct {
	managers []*Manager
}

// NewRegistry — реестр из менеджеров; nil пропускаются (модуль не подключён).
func NewRegistry(ms ...*Manager) *Registry {
	r := &Registry{}
	for _, m := range ms {
		if m != nil {
			r.managers = append(r.managers, m)
		}
	}
	return r
}

// States — состояние всех видов в порядке регистрации.
func (r *Registry) States(ctx context.Context) ([]State, error) {
	out := make([]State, 0, len(r.managers))
	for _, m := range r.managers {
		s, err := m.State(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
