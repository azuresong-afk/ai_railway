package compliance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Ошибки сервиса.
var (
	ErrNotFound  = errors.New("соответствие: пункт не найден")
	ErrNoMark    = errors.New("соответствие: ручной отметки нет")
	ErrStaleBase = errors.New("соответствие: версия базы не больше действующей")
	// ErrMarkNotAllowed — для пункта допустима только отметка «не применимо»:
	// его статус вычисляют проверки.
	ErrMarkNotAllowed = errors.New("соответствие: статус пункта вычисляют проверки")
)

// Пределы ручной отметки.
const (
	MaxCommentRunes  = 1000
	MaxDocumentRunes = 300
	// MaxReviewDays — самый дальний срок пересмотра от текущего дня.
	MaxReviewDays = 3 * 366
	// snapshotTTL — сколько снимок сведений переиспользуется между запросами.
	snapshotTTL = 10 * time.Second
	// snapshotTimeout — предел сбора снимка.
	snapshotTimeout = 30 * time.Second
)

// StoredBase — загруженная подписанная база в хранилище.
type StoredBase struct {
	Version      uint64
	Date         time.Time
	SubkeySerial uint64
	Fingerprint  string
	Requirements int
	File         []byte
	UploadedAt   time.Time
	UploadedBy   string
}

// Store — хранилище ручных отметок и загруженной базы.
type Store interface {
	Marks(ctx context.Context, orgID string) ([]Mark, error)
	// SetMark сохраняет отметку (заменяя прежнюю) и пишет запись аудита
	// fn(прежняя отметка или nil) одной транзакцией.
	SetMark(ctx context.Context, orgID string, m Mark, fn func(prev *Mark) audit.Entry) error
	// ClearMark снимает отметку и пишет fn(прежняя); нет отметки — ErrNoMark.
	ClearMark(ctx context.Context, orgID, requirementID string, fn func(prev Mark) audit.Entry) error
	// Base — загруженная база; нет — ErrNoBase.
	Base(ctx context.Context, orgID string) (StoredBase, error)
	// SaveBase сохраняет базу, если её версия больше сохранённой (иначе
	// ErrStaleBase), и пишет rec той же транзакцией.
	SaveBase(ctx context.Context, orgID string, b StoredBase, rec audit.Entry) error
	// Record пишет запись аудита вне транзакции данных (отказ в загрузке).
	Record(ctx context.Context, rec audit.Entry) error
}

// ErrNoBase — загруженной базы нет, действует встроенная.
var ErrNoBase = errors.New("соответствие: загруженной базы нет")

// Facts — источник снимка настроек и состояния.
type Facts interface {
	Snapshot(ctx context.Context) (*Snapshot, error)
}

// Options — зависимости сервиса.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	Facts    Facts
	OrgID    string
	Clock    func() time.Time
	Logger   *slog.Logger
	// Embedded — встроенная база; nil — requirements/*.yaml из сборки.
	Embedded *Base
	// vendor — ключ производителя для тестов; nil — встроенный.
	vendor aisecCrypto.Verifier
}

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

func (b By) entry(action string, obj audit.Object, result audit.Result, details map[string]any) audit.Entry {
	return audit.Entry{Actor: b.Actor, SourceIP: b.IP, Action: action, Object: obj, Result: result, Details: details}
}

// Service — модуль соответствия требованиям.
type Service struct {
	o Options

	mu     sync.Mutex
	loaded bool
	// signed — проверенная загруженная база; nil — нет или не прошла проверку.
	signed *SignedBase
	stored StoredBase

	snapMu   sync.Mutex
	snap     *Snapshot
	snapAt   time.Time
	snapWait sync.Mutex
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Provider == nil || o.Facts == nil {
		return nil, errors.New("соответствие: нет хранилища, криптопрофиля или источника сведений")
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
	if o.Embedded == nil {
		b, err := Embedded()
		if err != nil {
			return nil, err
		}
		o.Embedded = b
	}
	if o.vendor == nil {
		v, err := vendorVerifier(o.Provider)
		if err != nil {
			return nil, err
		}
		o.vendor = v
	}
	return &Service{o: o}, nil
}

func (s *Service) now() time.Time { return s.o.Clock().UTC().Truncate(time.Microsecond) }

// Load читает загруженную базу из хранилища и проверяет подпись заново.
// База, не прошедшая проверку, не используется: действует встроенная,
// причина — в техническом журнале.
func (s *Service) Load(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked(ctx)
}

func (s *Service) loadLocked(ctx context.Context) error {
	st, err := s.o.Store.Base(ctx, s.o.OrgID)
	if errors.Is(err, ErrNoBase) {
		s.signed, s.stored, s.loaded = nil, StoredBase{}, true
		return nil
	}
	if err != nil {
		return err
	}
	sb, err := VerifyBase(s.o.Provider, s.o.vendor, st.File, time.Time{})
	if err != nil {
		s.o.Logger.Error("соответствие: сохранённая база требований не прошла проверку подписи, действует встроенная",
			"class", "compliance", "error", err)
		s.signed, s.stored, s.loaded = nil, st, true
		return nil
	}
	s.signed, s.stored, s.loaded = &sb, st, true
	return nil
}

// current — действующая база: загруженная, если её версия больше встроенной.
func (s *Service) current(ctx context.Context) (*Base, *SignedBase, StoredBase, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		if err := s.loadLocked(ctx); err != nil {
			return nil, nil, StoredBase{}, err
		}
	}
	if s.signed != nil && s.signed.Base.Version > s.o.Embedded.Version {
		return s.signed.Base, s.signed, s.stored, nil
	}
	return s.o.Embedded, s.signed, s.stored, nil
}

// snapshot возвращает снимок сведений; повторные запросы в пределах
// snapshotTTL используют один и тот же (сбор обращается ко многим сервисам).
func (s *Service) snapshot(ctx context.Context) (*Snapshot, error) {
	s.snapWait.Lock()
	defer s.snapWait.Unlock()
	s.snapMu.Lock()
	if s.snap != nil && s.now().Sub(s.snapAt) < snapshotTTL {
		sn := s.snap
		s.snapMu.Unlock()
		return sn, nil
	}
	s.snapMu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	sn, err := s.o.Facts.Snapshot(cctx)
	if err != nil {
		return nil, err
	}
	if sn.Now.IsZero() {
		sn.Now = s.now()
	}
	s.snapMu.Lock()
	s.snap, s.snapAt = sn, s.now()
	s.snapMu.Unlock()
	return sn, nil
}

// BaseInfo — сведения о действующей базе.
type BaseInfo struct {
	Version uint64 `json:"version"`
	Date    string `json:"date"`
	// Origin — builtin (встроенная) или uploaded (загруженная подписанная).
	Origin       string `json:"origin"`
	Requirements int    `json:"requirements"`
}

// Overview — обзор соответствия.
type Overview struct {
	GeneratedAt time.Time `json:"generated_at"`
	Base        BaseInfo  `json:"base"`
	Sources     []Source  `json:"sources"`
	Summary     Summary   `json:"summary"`
	Items       []Item    `json:"items"`
	// Unavailable — группы сведений, которые не удалось прочитать.
	Unavailable []string `json:"unavailable"`
}

// Evaluate вычисляет статусы всех пунктов, подходящих под фильтр.
func (s *Service) Evaluate(ctx context.Context, f Filter) (Overview, error) {
	base, _, _, err := s.current(ctx)
	if err != nil {
		return Overview{}, err
	}
	snap, err := s.snapshot(ctx)
	if err != nil {
		return Overview{}, err
	}
	marks, err := s.o.Store.Marks(ctx, s.o.OrgID)
	if err != nil {
		return Overview{}, err
	}
	byID := make(map[string]Mark, len(marks))
	for _, m := range marks {
		byID[m.RequirementID] = m
	}
	now := s.now()
	items := make([]Item, 0, len(base.Requirements))
	for _, r := range base.Requirements {
		if !f.match(r) {
			continue
		}
		var mp *Mark
		if m, ok := byID[r.ID]; ok {
			mp = &m
		}
		items = append(items, Evaluate(r, base, snap, mp, now))
	}
	o := Overview{GeneratedAt: now, Base: s.baseInfo(base), Sources: append([]Source{}, base.Sources...),
		Summary: Summarize(items), Items: items, Unavailable: []string{}}
	for _, g := range []string{GroupApps, GroupRoles, GroupAuditChain, GroupIntegrity, GroupAlerts, GroupChannels} {
		if snap.Unavailable[g] {
			o.Unavailable = append(o.Unavailable, g)
		}
	}
	return o, nil
}

func (s *Service) baseInfo(b *Base) BaseInfo {
	origin := "builtin"
	if b != s.o.Embedded {
		origin = "uploaded"
	}
	return BaseInfo{Version: b.Version, Date: b.Date, Origin: origin, Requirements: len(b.Requirements)}
}

// Item возвращает один пункт с проверками и отметкой.
func (s *Service) Item(ctx context.Context, id string) (Item, error) {
	base, _, _, err := s.current(ctx)
	if err != nil {
		return Item{}, err
	}
	r, ok := base.ByID(id)
	if !ok {
		return Item{}, ErrNotFound
	}
	snap, err := s.snapshot(ctx)
	if err != nil {
		return Item{}, err
	}
	marks, err := s.o.Store.Marks(ctx, s.o.OrgID)
	if err != nil {
		return Item{}, err
	}
	var mp *Mark
	for _, m := range marks {
		if m.RequirementID == id {
			m := m
			mp = &m
		}
	}
	return Evaluate(r, base, snap, mp, s.now()), nil
}

// InputError — неверные данные отметки.
type InputError struct{ Fields map[string]string }

func (e *InputError) Error() string {
	return "соответствие: неверные данные отметки"
}

// MarkInput — данные ручной отметки.
type MarkInput struct {
	Status   Status `json:"status"`
	Comment  string `json:"comment"`
	Document string `json:"document"`
	ReviewBy string `json:"review_by"`
}

func plainText(s string, maxRunes int, multiline bool) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxRunes {
		return false
	}
	for _, r := range s {
		if r == '\n' && multiline {
			continue
		}
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return false
		}
	}
	return true
}

func (in MarkInput) validate(now time.Time) map[string]string {
	f := map[string]string{}
	if !ValidMarkStatus(in.Status) {
		f["status"] = "Выберите статус: выполнено, частично, не выполнено или не применимо."
	}
	if c := strings.TrimSpace(in.Comment); c == "" || !plainText(in.Comment, MaxCommentRunes, true) {
		f["comment"] = fmt.Sprintf("Комментарий обязателен: до %d символов, без управляющих.", MaxCommentRunes)
	}
	if !plainText(in.Document, MaxDocumentRunes, false) {
		f["document"] = fmt.Sprintf("Ссылка на документ: до %d символов, без управляющих.", MaxDocumentRunes)
	}
	if in.ReviewBy != "" {
		d, err := time.Parse(baseDateLayout, in.ReviewBy)
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		switch {
		case err != nil || d.Format(baseDateLayout) != in.ReviewBy:
			f["review_by"] = "Дата в формате ГГГГ-ММ-ДД."
		case d.Before(today):
			f["review_by"] = "Срок пересмотра не может быть в прошлом."
		case d.After(today.AddDate(0, 0, MaxReviewDays)):
			f["review_by"] = "Срок пересмотра — не позже чем через три года."
		}
	}
	return f
}

func reqObject(id string) audit.Object { return audit.Object{Type: "compliance_requirement", ID: id} }

// SetMark ставит ручную отметку. Пункт, статус которого вычисляют только
// проверки, принимает лишь «не применимо» (решение человека с комментарием).
func (s *Service) SetMark(ctx context.Context, by By, id string, in MarkInput) (Item, error) {
	base, _, _, err := s.current(ctx)
	if err != nil {
		return Item{}, err
	}
	r, ok := base.ByID(id)
	if !ok {
		return Item{}, ErrNotFound
	}
	now := s.now()
	if f := in.validate(now); len(f) > 0 {
		return Item{}, &InputError{Fields: f}
	}
	if len(r.Checks) > 0 && !r.Manual && in.Status != StatusNotApplicable {
		return Item{}, ErrMarkNotAllowed
	}
	m := Mark{RequirementID: id, Status: in.Status, Comment: in.Comment, Document: in.Document, ReviewBy: in.ReviewBy,
		SetAt: now, SetBy: by.ref()}
	err = s.o.Store.SetMark(ctx, s.o.OrgID, m, func(prev *Mark) audit.Entry {
		d := map[string]any{"requirement_id": id, "status": string(m.Status), "review_by": m.ReviewBy, "comment": m.Comment,
			"document": m.Document}
		if prev != nil {
			d["previous_status"] = string(prev.Status)
		}
		return by.entry("compliance.mark_set", reqObject(id), audit.ResultSuccess, d)
	})
	if err != nil {
		return Item{}, err
	}
	return s.Item(ctx, id)
}

// ClearMark снимает ручную отметку.
func (s *Service) ClearMark(ctx context.Context, by By, id string) (Item, error) {
	base, _, _, err := s.current(ctx)
	if err != nil {
		return Item{}, err
	}
	if _, ok := base.ByID(id); !ok {
		return Item{}, ErrNotFound
	}
	err = s.o.Store.ClearMark(ctx, s.o.OrgID, id, func(prev Mark) audit.Entry {
		return by.entry("compliance.mark_cleared", reqObject(id), audit.ResultSuccess,
			map[string]any{"requirement_id": id, "previous_status": string(prev.Status)})
	})
	if err != nil {
		return Item{}, err
	}
	return s.Item(ctx, id)
}

// BaseView — сведения о базе требований в ответах API.
type BaseView struct {
	// Active — действующая база (встроенная или загруженная).
	Active BaseInfo `json:"active"`
	// Builtin — версия и дата встроенной базы.
	Builtin BaseInfo `json:"builtin"`
	// Uploaded — загруженная подписанная база; nil — не загружалась.
	Uploaded *UploadedInfo `json:"uploaded,omitempty"`
}

// UploadedInfo — загруженная подписанная база.
type UploadedInfo struct {
	Version      uint64     `json:"version"`
	Date         string     `json:"date"`
	Requirements int        `json:"requirements"`
	SubkeySerial uint64     `json:"subkey_serial"`
	SubkeyUntil  *time.Time `json:"subkey_not_after,omitempty"`
	Fingerprint  string     `json:"fingerprint"`
	UploadedAt   time.Time  `json:"uploaded_at"`
	// Valid — подпись сохранённого файла проверена при запуске.
	Valid bool `json:"valid"`
}

// BaseView — сведения о действующей и загруженной базе.
func (s *Service) BaseView(ctx context.Context) (BaseView, error) {
	base, sb, st, err := s.current(ctx)
	if err != nil {
		return BaseView{}, err
	}
	v := BaseView{Active: s.baseInfo(base), Builtin: s.baseInfo(s.o.Embedded)}
	if st.Version > 0 {
		u := &UploadedInfo{Version: st.Version, Date: st.Date.Format(baseDateLayout), Requirements: st.Requirements,
			SubkeySerial: st.SubkeySerial, Fingerprint: st.Fingerprint, UploadedAt: st.UploadedAt.UTC(), Valid: sb != nil}
		if sb != nil {
			until := sb.Endorsement.NotAfter
			u.SubkeyUntil = &until
		}
		v.Uploaded = u
	}
	return v, nil
}

// BaseError — отказ в загрузке базы с кодом причины.
type BaseError struct {
	Reason string
	Err    error
}

func (e *BaseError) Error() string { return e.Err.Error() }
func (e *BaseError) Unwrap() error { return e.Err }

// RejectReason — код причины отказа в загрузке базы.
func RejectReason(err error) string {
	switch {
	case errors.Is(err, aisecCrypto.ErrEndorsementSignature), errors.Is(err, aisecCrypto.ErrServiceDBSignature):
		return "signature"
	case errors.Is(err, aisecCrypto.ErrEndorsementPurpose):
		return "purpose"
	case errors.Is(err, aisecCrypto.ErrEndorsementExpired):
		return "expired"
	case errors.Is(err, aisecCrypto.ErrEndorsementRevoked):
		return "revoked"
	case errors.Is(err, aisecCrypto.ErrServiceDBKind):
		return "kind"
	case errors.Is(err, ErrBaseDate):
		return "date"
	case errors.Is(err, ErrStaleBase):
		return "stale_version"
	}
	return "format"
}

// UploadBase проверяет подписанный файл (срок заверения — на текущее
// время) и сохраняет его, если версия больше действующей. Каждая
// попытка — запись аудита без содержимого файла.
func (s *Service) UploadBase(ctx context.Context, by By, data []byte) (BaseView, error) {
	now := s.now()
	sb, err := VerifyBase(s.o.Provider, s.o.vendor, data, now)
	obj := audit.Object{Type: "compliance_base"}
	if err == nil {
		var cur *Base
		if cur, _, _, err = s.current(ctx); err == nil && sb.Base.Version <= cur.Version {
			err = ErrStaleBase
		}
	}
	if err == nil {
		st := StoredBase{Version: sb.Base.Version, Date: sb.Base.Day(), SubkeySerial: sb.Endorsement.Serial, Fingerprint: sb.Fingerprint,
			Requirements: len(sb.Base.Requirements), File: data, UploadedAt: now, UploadedBy: by.ref()}
		rec := by.entry("compliance.base_loaded", obj, audit.ResultSuccess, map[string]any{"version": st.Version, "date": sb.Base.Date,
			"requirements": st.Requirements, "subkey_serial": st.SubkeySerial, "fingerprint": st.Fingerprint})
		if err = s.o.Store.SaveBase(ctx, s.o.OrgID, st, rec); err == nil {
			s.mu.Lock()
			s.signed, s.stored, s.loaded = &sb, st, true
			s.mu.Unlock()
			s.dropSnapshot()
			return s.BaseView(ctx)
		}
		if !errors.Is(err, ErrStaleBase) {
			return BaseView{}, err
		}
	}
	reason := RejectReason(err)
	details := map[string]any{"reason": reason, "bytes": len(data)}
	if sb.Base != nil {
		details["version"], details["subkey_serial"] = sb.Base.Version, sb.Endorsement.Serial
	}
	if aerr := s.o.Store.Record(ctx, by.entry("compliance.base_rejected", obj, audit.ResultFailure, details)); aerr != nil {
		return BaseView{}, aerr
	}
	return BaseView{}, &BaseError{Reason: reason, Err: err}
}

func (s *Service) dropSnapshot() {
	s.snapMu.Lock()
	s.snap = nil
	s.snapMu.Unlock()
}
