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
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Ошибки сервиса.
var (
	ErrNotFound = errors.New("соответствие: пункт не найден")
	ErrNoMark   = errors.New("соответствие: ручной отметки нет")
	// ErrMarkNotAllowed — для пункта допустима только отметка «не применимо»:
	// его статус вычисляют проверки.
	ErrMarkNotAllowed = errors.New("соответствие: статус пункта вычисляют проверки")
	// ErrConfirmRequired — «не применимо» для пункта с проверками снимает
	// невыполненные проверки (ослабление, DM-40): только в сессии консоли с
	// повторной проверкой (4В36).
	ErrConfirmRequired = errors.New("соответствие: «не применимо» для пункта с проверками — только с повторной проверкой")
)

// weakeningNotApplicable — причина ослабления в аудите: пункт с
// автоматическими проверками исключён отметкой «не применимо».
const weakeningNotApplicable = "compliance_not_applicable"

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

// Store — хранилище ручных отметок. Загруженная база — служебная база
// вида compliance_requirements в servicedb.Store (ADR-0028).
type Store interface {
	Marks(ctx context.Context, orgID string) ([]Mark, error)
	// SetMark сохраняет отметку (заменяя прежнюю) и пишет запись аудита
	// fn(прежняя отметка или nil) одной транзакцией.
	SetMark(ctx context.Context, orgID string, m Mark, fn func(prev *Mark) audit.Entry) error
	// ClearMark снимает отметку и пишет fn(прежняя); нет отметки — ErrNoMark.
	ClearMark(ctx context.Context, orgID, requirementID string, fn func(prev Mark) audit.Entry) error
}

// Facts — источник снимка настроек и состояния.
type Facts interface {
	Snapshot(ctx context.Context) (*Snapshot, error)
}

// Options — зависимости сервиса.
type Options struct {
	Store Store
	// ServiceDBs — хранилище служебных баз (база требований, ADR-0028).
	ServiceDBs servicedb.Store
	Provider   aisecCrypto.Provider
	Facts      Facts
	OrgID      string
	Clock      func() time.Time
	Logger     *slog.Logger
	// Embedded — встроенная база; nil — requirements/*.yaml из сборки.
	Embedded *Base
	// vendor — ключ производителя для тестов; nil — встроенный.
	vendor aisecCrypto.Verifier
}

// By — субъект действия.
type By struct {
	Actor audit.Actor
	IP    netip.Addr
	// Confirm — повторная проверка субъекта (пароль или код) перед
	// ослаблением; nil — не из сессии консоли (токен API).
	Confirm func(context.Context) error
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

	// db — загруженная база: служебная база вида compliance_requirements.
	db *servicedb.Manager

	snapMu sync.Mutex
	snap   *Snapshot
	snapAt time.Time
	// collecting — идущий сбор снимка: остальные вызовы ждут его, а не
	// начинают свой (4В35).
	collecting *snapCall
}

// snapCall — сбор снимка: результат готов после закрытия done.
type snapCall struct {
	done chan struct{}
	sn   *Snapshot
	err  error
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.ServiceDBs == nil || o.Provider == nil || o.Facts == nil {
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
	// Загружаемая база должна быть новее и встроенной в выпуск.
	db, err := servicedb.NewManager(servicedb.Options{Store: o.ServiceDBs, Provider: o.Provider, Kind: DBKind(), OrgID: o.OrgID,
		Clock: o.Clock, Logger: o.Logger, MinVersion: o.Embedded.Version, Vendor: o.vendor})
	if err != nil {
		return nil, err
	}
	return &Service{o: o, db: db}, nil
}

// DB — база требований как служебная база (состояние для
// GET /api/v1/service-dbs).
func (s *Service) DB() *servicedb.Manager { return s.db }

func (s *Service) now() time.Time { return s.o.Clock().UTC().Truncate(time.Microsecond) }

// Load читает загруженную базу из хранилища и проверяет подпись заново
// (ADR-0028, п. 5). Текущая версия, не прошедшая проверку, не
// используется: действует предыдущая, если она проверяется, иначе
// встроенная; запись аудита — service_db.stored_invalid.
func (s *Service) Load(ctx context.Context) error {
	return s.db.Load(ctx)
}

// current — действующая база: загруженная (текущая или, если та не прошла
// проверку, предыдущая), если её версия больше встроенной, иначе встроенная.
func (s *Service) current(ctx context.Context) (*Base, *SignedBase, error) {
	v, err := s.db.Active(ctx)
	if err != nil {
		return nil, nil, err
	}
	base, sb := s.pick(v)
	return base, sb, nil
}

func (s *Service) pick(v *servicedb.Verified) (*Base, *SignedBase) {
	if v == nil {
		return s.o.Embedded, nil
	}
	sb := signedBase(*v)
	if sb.Base.Version > s.o.Embedded.Version {
		return sb.Base, &sb
	}
	return s.o.Embedded, &sb
}

// snapshot возвращает снимок сведений; повторные запросы в пределах
// snapshotTTL используют один и тот же (сбор обращается ко многим сервисам).
// Сбор идёт в своей горутине с контекстом без отмены вызвавшего (4В35):
// ушедший клиент не портит снимок остальным, а каждый ожидающий
// возвращается по своей отмене сразу.
func (s *Service) snapshot(ctx context.Context) (*Snapshot, error) {
	s.snapMu.Lock()
	if s.snap != nil && s.now().Sub(s.snapAt) < snapshotTTL {
		sn := s.snap
		s.snapMu.Unlock()
		return sn, nil
	}
	c := s.collecting
	if c == nil {
		c = &snapCall{done: make(chan struct{})}
		s.collecting = c
		go s.collect(context.WithoutCancel(ctx), c)
	}
	s.snapMu.Unlock()
	select {
	case <-c.done:
		return c.sn, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// collect собирает снимок для c. Снимок с недоступными группами не
// кешируется: сбой источника не должен на snapshotTTL показывать «не
// выполнено» всем (4В35).
func (s *Service) collect(ctx context.Context, c *snapCall) {
	cctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	sn, err := s.o.Facts.Snapshot(cctx)
	if err == nil && sn.Now.IsZero() {
		sn.Now = s.now()
	}
	s.snapMu.Lock()
	if err == nil && len(sn.Unavailable) == 0 {
		s.snap, s.snapAt = sn, s.now()
	}
	s.collecting = nil
	s.snapMu.Unlock()
	c.sn, c.err = sn, err
	close(c.done)
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
	base, _, err := s.current(ctx)
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
	base, _, err := s.current(ctx)
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
	base, _, err := s.current(ctx)
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
	// «Не применимо» у пункта с автоматическими проверками убирает их из
	// процента: ослабление (DM-40) — со сроком пересмотра и повторной
	// проверкой, как исключения теневого ИИ (4В36).
	weakening := len(r.Checks) > 0 && in.Status == StatusNotApplicable
	if weakening {
		if in.ReviewBy == "" {
			return Item{}, &InputError{Fields: map[string]string{"review_by": "Для пункта с автоматическими проверками «не применимо» — только со сроком пересмотра."}}
		}
		if by.Confirm == nil {
			return Item{}, ErrConfirmRequired
		}
		if err := by.Confirm(ctx); err != nil {
			return Item{}, err
		}
	}
	m := Mark{RequirementID: id, Status: in.Status, Comment: in.Comment, Document: in.Document, ReviewBy: in.ReviewBy,
		SetAt: now, SetBy: by.ref()}
	err = s.o.Store.SetMark(ctx, s.o.OrgID, m, func(prev *Mark) audit.Entry {
		d := map[string]any{"requirement_id": id, "status": string(m.Status), "review_by": m.ReviewBy, "comment": m.Comment,
			"document": m.Document}
		if prev != nil {
			d["previous_status"] = string(prev.Status)
		}
		if weakening {
			d["weakening"], d["weakening_reasons"] = true, []string{weakeningNotApplicable}
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
	base, _, err := s.current(ctx)
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
	// Uploaded — текущая загруженная подписанная база; nil — не загружалась.
	Uploaded *servicedb.VersionState `json:"uploaded,omitempty"`
	// Previous — предыдущая загруженная версия (откат — на неё); nil — нет.
	Previous *servicedb.VersionState `json:"previous,omitempty"`
	// Slot — какая загруженная версия действует: current, previous, none.
	Slot string `json:"slot"`
}

// BaseView — сведения о действующей и загруженных базах.
func (s *Service) BaseView(ctx context.Context) (BaseView, error) {
	// Состояние и действующая база — из одного снимка менеджера.
	st, v, err := s.db.Snapshot(ctx)
	if err != nil {
		return BaseView{}, err
	}
	base, _ := s.pick(v)
	return BaseView{Active: s.baseInfo(base), Builtin: s.baseInfo(s.o.Embedded), Uploaded: st.Current, Previous: st.Previous,
		Slot: st.Active}, nil
}

func (b By) db() servicedb.By { return servicedb.By{Actor: b.Actor, IP: b.IP} }

// UploadBase проверяет подписанный файл (срок заверения — на текущее
// время) и сохраняет его, если версия больше текущей загруженной и
// встроенной; прежняя загруженная становится предыдущей. Каждая попытка —
// запись аудита без содержимого файла; отказ — *servicedb.RejectError.
func (s *Service) UploadBase(ctx context.Context, by By, data []byte) (BaseView, error) {
	if _, err := s.db.Upload(ctx, by.db(), data); err != nil {
		return BaseView{}, err
	}
	s.dropSnapshot()
	return s.BaseView(ctx)
}

// RollbackBase возвращает предыдущую загруженную версию после её повторной
// проверки (ADR-0028, п. 4). Если она не новее встроенной, действует
// встроенная. Отказ — *servicedb.RejectError.
func (s *Service) RollbackBase(ctx context.Context, by By) (BaseView, error) {
	if _, err := s.db.Rollback(ctx, by.db()); err != nil {
		return BaseView{}, err
	}
	s.dropSnapshot()
	return s.BaseView(ctx)
}

func (s *Service) dropSnapshot() {
	s.snapMu.Lock()
	s.snap = nil
	s.snapMu.Unlock()
}
