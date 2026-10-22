package incidents

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// Ошибки.
var (
	ErrNotFound = errors.New("инцидент не найден")
	// ErrAlertNotFound — оповещения, из которого создаётся инцидент, нет.
	ErrAlertNotFound = errors.New("оповещение не найдено")
	// ErrTransition — недопустимый переход статуса.
	ErrTransition = errors.New("недопустимый переход статуса")
	// ErrClosed — закрытый инцидент не меняется.
	ErrClosed = errors.New("закрытый инцидент не меняется")
	// ErrNotClosed — открыть заново можно только закрытый инцидент.
	ErrNotClosed = errors.New("инцидент ещё не закрыт")
	// ErrLinked — оповещение уже связано с другим инцидентом.
	ErrLinked = alerting.ErrLinked
	// ErrLimit — достигнут предел записей инцидента.
	ErrLimit = errors.New("достигнут предел записей инцидента")
	// ErrCommentNotFound — правится комментарий, которого нет в инциденте.
	ErrCommentNotFound = errors.New("комментарий не найден")
	// ErrSuperseded — у комментария уже есть следующая версия: правится последняя.
	ErrSuperseded = errors.New("комментарий уже исправлен")
	// ErrNotAuthor — править комментарий может только его автор.
	ErrNotAuthor = errors.New("править комментарий может только его автор")
	// ErrStageDone — этап уже отмечен.
	ErrStageDone = errors.New("этап уже отмечен")
	// ErrVersionConflict — инструкцию изменили после того, как её открыли.
	ErrVersionConflict = errors.New("инструкция изменена другим пользователем")
	// ErrUserInactive — ответственный не найден или не активен.
	ErrUserInactive = errors.New("пользователь не найден или не активен")
)

// Source — источник нового инцидента под блокировкой: оповещение со
// ссылками на события или закрытый инцидент.
type Source struct {
	Alert    *alerting.Alert
	Previous *Incident
	// Refs — ссылки на события источника.
	Refs []EventRef
}

// Creation — новый инцидент для Store.Create. Номер присваивает хранилище
// до вызова Build; Build проверяет источник и возвращает записи.
type Creation struct {
	Incident Incident
	AlertID  string
	ReopenOf string
	Build    func(inc *Incident, src Source) (Change, error)
}

// Change — записи одного действия: добавляются той же транзакцией, что и
// изменение инцидента.
type Change struct {
	Timeline []TimelineEntry
	Comment  *Comment
	// Stage — отмеченный этап.
	Stage *Stage
	// Events — новые ссылки на события (сверх MaxEvents не пишутся).
	Events []EventRef
	// CloseAlerts — закрыть незакрытые оповещения инцидента.
	CloseAlerts *CloseAlerts
	Audit       []audit.Entry
}

// CloseAlerts — закрытие связанных оповещений вместе с инцидентом.
type CloseAlerts struct {
	By      alerting.By
	Comment string
}

// Related — инцидент и связанные записи для карточки и выгрузки (один снимок).
type Related struct {
	Incident Incident
	Timeline []TimelineEntry
	Comments []Comment
	Events   []EventRef
	Alerts   []alerting.Alert
}

// Store — хранилище инцидентов: PGStore (рабочее) и Memory (тесты). Оно же
// создаёт инциденты по оповещениям в приёме событий (IncidentOpener).
type Store interface {
	alerting.IncidentOpener
	Incidents(ctx context.Context, orgID string, q Query) ([]Incident, error)
	Incident(ctx context.Context, orgID, id string) (Incident, error)
	Related(ctx context.Context, orgID, id string) (Related, error)
	// Create создаёт инцидент; existing = true — оповещение уже связано с
	// инцидентом или закрытый уже открыт заново: возвращается тот инцидент,
	// записей нет.
	Create(ctx context.Context, c Creation) (inc Incident, existing bool, err error)
	// Update меняет инцидент под блокировкой строки.
	Update(ctx context.Context, orgID, id string, fn func(*Incident, Counts) (Change, error)) (Incident, error)
	// LinkAlert связывает оповещение с инцидентом: сначала блокируется
	// оповещение, потом инцидент. Уже связанное с ним — existing = true.
	LinkAlert(ctx context.Context, orgID, id, alertID string,
		fn func(*Incident, alerting.Alert, []EventRef, Counts) (Change, error)) (inc Incident, existing bool, err error)
	Instructions(ctx context.Context, orgID string) (map[string]Instruction, error)
	SetInstructions(ctx context.Context, orgID, category string, fn func(cur Instruction) (Instruction, audit.Entry, error)) (Instruction, error)
	// Record — запись аудита вне изменения (выгрузка карточки).
	Record(ctx context.Context, e audit.Entry) error
}

// Options — зависимости сервиса.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	// Alerts — оповещения: значения по умолчанию для инцидента из оповещения.
	Alerts *alerting.Service
	OrgID  string
	Clock  func() time.Time
	// UserCheck — ответственный существует, активен и видит инциденты;
	// иначе — ErrUserInactive, прочие ошибки — сбой. nil — не проверяется.
	UserCheck func(ctx context.Context, id string) error
}

// Service — инциденты для API консоли.
type Service struct {
	store     Store
	alerts    *alerting.Service
	orgID     string
	clock     func() time.Time
	ids       *ids.Generator
	userCheck func(ctx context.Context, id string) error
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Provider == nil || o.Alerts == nil {
		return nil, errors.New("инциденты: нет хранилища, криптопрофиля или оповещений")
	}
	r, err := o.Provider.Random()
	if err != nil {
		return nil, err
	}
	if o.OrgID == "" {
		o.OrgID = audit.DefaultOrgID
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return &Service{store: o.Store, alerts: o.Alerts, orgID: o.OrgID, clock: o.Clock, ids: ids.NewGenerator(r),
		userCheck: o.UserCheck}, nil
}

// By — субъект действия.
type By struct {
	Actor audit.Actor
	IP    netip.Addr
	// UserID — пользователь субъекта (у токена — его владелец).
	UserID string
}

// ref — субъект в полях created_by, хронологии и комментариях.
func (b By) ref() string {
	s := string(b.Actor.Type) + ":" + b.Actor.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

// name — имя автора для показа.
func (b By) name() string {
	n := b.Actor.Name
	if n == "" {
		n = b.Actor.ID
	}
	if utf8.RuneCountInString(n) > 128 {
		n = string([]rune(n)[:128])
	}
	return n
}

func (b By) entry(action, objID string, details map[string]any) audit.Entry {
	return audit.Entry{Actor: b.Actor, SourceIP: b.IP, Action: action, Object: audit.Object{Type: "incident", ID: objID},
		Result: audit.ResultSuccess, Details: details}
}

func (b By) alertBy() alerting.By { return alerting.By{Actor: b.Actor, IP: b.IP, UserID: b.UserID} }

// systemBy — субъект автоматических действий сервера.
var systemBy = By{Actor: audit.Actor{Type: audit.ActorSystem, ID: "aisec-server", Name: "Сервер управления"}}

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

func (s *Service) newID() (string, error) { return newID(s.ids) }

func newID(g *ids.Generator) (string, error) {
	id, err := g.New()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// entryAt — запись хронологии с новым ID.
func entryAt(g *ids.Generator, incidentID string, at time.Time, actor, kind string, details map[string]any) (TimelineEntry, error) {
	id, err := newID(g)
	if err != nil {
		return TimelineEntry{}, err
	}
	if details == nil {
		details = map[string]any{}
	}
	return TimelineEntry{ID: id, IncidentID: incidentID, At: at, Actor: actor, Kind: kind, Details: details}, nil
}

// List — страница инцидентов от новых к старым.
func (s *Service) List(ctx context.Context, q Query) ([]Incident, error) {
	return s.store.Incidents(ctx, s.orgID, q)
}

// Card — инцидент со связанными записями и инструкцией категории.
type Card struct {
	Incident    Incident
	Related     Related
	Instruction Instruction
}

// Card — карточка инцидента.
func (s *Service) Card(ctx context.Context, id string) (Card, error) {
	rel, err := s.store.Related(ctx, s.orgID, id)
	if err != nil {
		return Card{}, err
	}
	inc := rel.Incident
	ins, err := s.instruction(ctx, inc.Category)
	if err != nil {
		return Card{}, err
	}
	return Card{Incident: inc, Related: rel, Instruction: ins}, nil
}

// newIncident — инцидент с полями по умолчанию: статус «новый», этапы по
// шаблону, срок реакции по серьёзности.
func newIncident(id, orgID string, now time.Time, by string, title, severity, category, source string) Incident {
	return Incident{ID: id, OrgID: orgID, Title: title, Severity: severity, Category: category, Status: StatusNew,
		Source: source, ReactionDueAt: now.Add(ReactionTime(severity)), CreatedAt: now, CreatedBy: by, UpdatedAt: now,
		UpdatedBy: by, Version: 1, Stages: newStages()}
}

func createDetails(inc *Incident) map[string]any {
	d := map[string]any{"number": inc.Number, "title": inc.Title, "severity": inc.Severity, "category": inc.Category,
		"source": inc.Source, "reaction_due_at": inc.ReactionDueAt}
	if inc.ReopenedFrom != "" {
		d["reopened_from"] = inc.ReopenedFrom
	}
	return d
}

// Create создаёт инцидент вручную, из оповещения (AlertID; повтор — тот же
// инцидент, created = false) или повторным открытием закрытого (ReopenOf).
func (s *Service) Create(ctx context.Context, by By, in CreateInput) (inc Incident, created bool, err error) {
	if err := parseCreate(in); err != nil {
		return Incident{}, false, err
	}
	title, severity, category, source := in.Title, in.Severity, in.Category, SourceManual
	switch {
	case in.AlertID != "":
		source = SourceAlert
		card, err := s.alerts.Alert(ctx, in.AlertID)
		if errors.Is(err, alerting.ErrNotFound) {
			return Incident{}, false, ErrAlertNotFound
		}
		if err != nil {
			return Incident{}, false, err
		}
		a := card.Alert
		if title == "" {
			title = a.Title
		}
		if severity == "" {
			severity = a.Severity
		}
		if category == "" {
			rule, err := s.alerts.Rule(ctx, a.RuleID)
			if err != nil {
				return Incident{}, false, err
			}
			category = CategoryOfAlert(rule)
		}
	case in.ReopenOf != "":
		source = SourceReopen
		prev, err := s.store.Incident(ctx, s.orgID, in.ReopenOf)
		if err != nil {
			return Incident{}, false, err
		}
		if title == "" {
			title = prev.Title
		}
		if severity == "" {
			severity = prev.Severity
		}
		if category == "" {
			category = prev.Category
		}
	}
	id, err := s.newID()
	if err != nil {
		return Incident{}, false, err
	}
	now := s.now()
	n := newIncident(id, s.orgID, now, by.ref(), title, severity, category, source)
	if source == SourceReopen {
		n.ReopenedFrom = in.ReopenOf
	}
	got, existing, err := s.store.Create(ctx, Creation{Incident: n, AlertID: in.AlertID, ReopenOf: in.ReopenOf,
		Build: func(inc *Incident, src Source) (Change, error) {
			var ch Change
			details := map[string]any{"source": inc.Source}
			if src.Previous != nil {
				if src.Previous.Status != StatusClosed {
					return Change{}, ErrNotClosed
				}
				details["reopened_from"] = src.Previous.ID
				details["reopened_from_number"] = src.Previous.Number
				e, err := entryAt(s.ids, src.Previous.ID, now, by.ref(), KindReopened,
					map[string]any{"incident_id": inc.ID, "number": inc.Number})
				if err != nil {
					return Change{}, err
				}
				ch.Timeline = append(ch.Timeline, e)
			}
			e, err := entryAt(s.ids, inc.ID, now, by.ref(), KindCreated, details)
			if err != nil {
				return Change{}, err
			}
			ch.Timeline = append([]TimelineEntry{e}, ch.Timeline...)
			if src.Alert != nil {
				e, err := entryAt(s.ids, inc.ID, now, by.ref(), KindAlertLinked, alertDetails(src.Alert, len(src.Refs)))
				if err != nil {
					return Change{}, err
				}
				ch.Timeline = append(ch.Timeline, e)
			}
			ch.Events = src.Refs
			d := createDetails(inc)
			if src.Alert != nil {
				d["alert_id"] = src.Alert.ID
			}
			ch.Audit = append(ch.Audit, by.entry("incident.create", inc.ID, d))
			return ch, nil
		}})
	if err != nil {
		return Incident{}, false, err
	}
	return got, !existing, nil
}

func alertDetails(a *alerting.Alert, refs int) map[string]any {
	return map[string]any{"alert_id": a.ID, "rule_id": a.RuleID, "rule_name": a.RuleName, "severity": a.Severity,
		"title": a.Title, "count": a.Count, "events": refs}
}

// SetStatus переводит инцидент по автомату; закрытие — с резолюцией и
// закрытием связанных оповещений.
func (s *Service) SetStatus(ctx context.Context, by By, id string, in StatusInput) (Incident, error) {
	if err := ParseStatusInput(in); err != nil {
		return Incident{}, err
	}
	return s.store.Update(ctx, s.orgID, id, func(inc *Incident, c Counts) (Change, error) {
		from := inc.Status
		if from == StatusClosed {
			return Change{}, ErrClosed
		}
		if !transitionAllowed(from, in.Status) {
			return Change{}, ErrTransition
		}
		if c.Timeline >= MaxTimeline {
			return Change{}, ErrLimit
		}
		now := s.now()
		inc.Status = in.Status
		if from == StatusNew {
			inc.ReactedAt = now
			if inc.AssigneeID == "" && by.UserID != "" {
				inc.AssigneeID = by.UserID
			}
		}
		var ch Change
		switch in.Status {
		case StatusContained:
			inc.ContainedAt = now
		case StatusClosed:
			inc.Resolution, inc.ResolutionComment = in.Resolution, in.Comment
			inc.ClosedAt, inc.ClosedBy = now, by.ref()
			ch.CloseAlerts = &CloseAlerts{By: by.alertBy(), Comment: fmt.Sprintf("Закрыто вместе с инцидентом № %d", inc.Number)}
		}
		inc.UpdatedAt, inc.UpdatedBy = now, by.ref()
		details := map[string]any{"from": from, "to": in.Status}
		if in.Resolution != "" {
			details["resolution"] = in.Resolution
		}
		if in.Comment != "" {
			details["comment"] = in.Comment
		}
		e, err := entryAt(s.ids, inc.ID, now, by.ref(), KindStatusChanged, details)
		if err != nil {
			return Change{}, err
		}
		ch.Timeline = []TimelineEntry{e}
		ch.Audit = []audit.Entry{by.entry("incident.status_changed", inc.ID, map[string]any{"number": inc.Number,
			"from": from, "to": in.Status, "resolution": in.Resolution, "comment": in.Comment != ""})}
		return ch, nil
	})
}

// Assign назначает ответственного; пустой userID снимает назначение.
func (s *Service) Assign(ctx context.Context, by By, id string, in AssignInput) (Incident, error) {
	if err := parseAssign(in); err != nil {
		return Incident{}, err
	}
	to := *in.UserID
	if to != "" && s.userCheck != nil {
		if err := s.userCheck(ctx, to); err != nil {
			return Incident{}, err
		}
	}
	inc, err := s.store.Update(ctx, s.orgID, id, func(inc *Incident, c Counts) (Change, error) {
		if inc.Status == StatusClosed {
			return Change{}, ErrClosed
		}
		if inc.AssigneeID == to {
			return Change{}, errUnchanged
		}
		if c.Timeline >= MaxTimeline {
			return Change{}, ErrLimit
		}
		from := inc.AssigneeID
		now := s.now()
		inc.AssigneeID, inc.UpdatedAt, inc.UpdatedBy = to, now, by.ref()
		e, err := entryAt(s.ids, inc.ID, now, by.ref(), KindAssigned, map[string]any{"from": from, "to": to})
		if err != nil {
			return Change{}, err
		}
		return Change{Timeline: []TimelineEntry{e}, Audit: []audit.Entry{by.entry("incident.assigned", inc.ID,
			map[string]any{"number": inc.Number, "from": from, "to": to})}}, nil
	})
	if errors.Is(err, errUnchanged) {
		return s.store.Incident(ctx, s.orgID, id)
	}
	return inc, err
}

// errUnchanged — действие ничего не меняет: записи нет.
var errUnchanged = errors.New("без изменений")

// AddComment добавляет комментарий; Replaces — правка своего комментария
// новой записью (у записи не больше одной следующей версии).
func (s *Service) AddComment(ctx context.Context, by By, id string, in CommentInput) (Comment, error) {
	if err := parseComment(in); err != nil {
		return Comment{}, err
	}
	cid, err := s.newID()
	if err != nil {
		return Comment{}, err
	}
	var out Comment
	_, err = s.store.Update(ctx, s.orgID, id, func(inc *Incident, c Counts) (Change, error) {
		if inc.Status == StatusClosed {
			return Change{}, ErrClosed
		}
		if c.Comments >= MaxComments || c.Timeline >= MaxTimeline {
			return Change{}, ErrLimit
		}
		now := s.now()
		inc.UpdatedAt, inc.UpdatedBy = now, by.ref()
		out = Comment{ID: cid, IncidentID: inc.ID, At: now, Author: by.ref(), AuthorName: by.name(), Body: in.Body,
			Replaces: in.Replaces}
		details := map[string]any{"comment_id": cid}
		if in.Replaces != "" {
			details["replaces"] = in.Replaces
		}
		e, err := entryAt(s.ids, inc.ID, now, by.ref(), KindCommentAdded, details)
		if err != nil {
			return Change{}, err
		}
		return Change{Comment: &out, Timeline: []TimelineEntry{e}, Audit: []audit.Entry{by.entry("incident.comment_added",
			inc.ID, map[string]any{"number": inc.Number, "comment_id": cid, "replaces": in.Replaces,
				"length": utf8.RuneCountInString(in.Body)})}}, nil
	})
	if err != nil {
		return Comment{}, err
	}
	return out, nil
}

// CompleteStage отмечает этап реагирования; отмеченный не снимается.
func (s *Service) CompleteStage(ctx context.Context, by By, id, key string, in StageInput) (Incident, error) {
	if err := parseStage(key, in); err != nil {
		return Incident{}, err
	}
	return s.store.Update(ctx, s.orgID, id, func(inc *Incident, c Counts) (Change, error) {
		if inc.Status == StatusClosed {
			return Change{}, ErrClosed
		}
		i := slices.IndexFunc(inc.Stages, func(st Stage) bool { return st.Key == key })
		if i < 0 {
			return Change{}, &InputError{Errs: []error{errors.New("stage: этапа нет в инциденте")}}
		}
		if !inc.Stages[i].DoneAt.IsZero() {
			return Change{}, ErrStageDone
		}
		if c.Timeline >= MaxTimeline {
			return Change{}, ErrLimit
		}
		now := s.now()
		inc.Stages[i].DoneAt, inc.Stages[i].DoneBy, inc.Stages[i].Note = now, by.ref(), in.Note
		inc.UpdatedAt, inc.UpdatedBy = now, by.ref()
		st := inc.Stages[i]
		e, err := entryAt(s.ids, inc.ID, now, by.ref(), KindStageCompleted, map[string]any{"stage": key, "note": in.Note != ""})
		if err != nil {
			return Change{}, err
		}
		return Change{Stage: &st, Timeline: []TimelineEntry{e}, Audit: []audit.Entry{by.entry("incident.stage_completed",
			inc.ID, map[string]any{"number": inc.Number, "stage": key})}}, nil
	})
}

// LinkAlert добавляет оповещение в существующий инцидент (ТЗ 6.3, п. 5);
// повтор — без изменений.
func (s *Service) LinkAlert(ctx context.Context, by By, id string, in LinkInput) (Incident, bool, error) {
	if err := parseLink(in); err != nil {
		return Incident{}, false, err
	}
	inc, existing, err := s.store.LinkAlert(ctx, s.orgID, id, in.AlertID,
		func(inc *Incident, a alerting.Alert, refs []EventRef, c Counts) (Change, error) {
			if inc.Status == StatusClosed {
				return Change{}, ErrClosed
			}
			if c.Alerts >= alerting.MaxIncidentAlerts || c.Timeline >= MaxTimeline {
				return Change{}, ErrLimit
			}
			now := s.now()
			inc.UpdatedAt, inc.UpdatedBy = now, by.ref()
			e, err := entryAt(s.ids, inc.ID, now, by.ref(), KindAlertLinked, alertDetails(&a, len(refs)))
			if err != nil {
				return Change{}, err
			}
			return Change{Timeline: []TimelineEntry{e}, Events: refs, Audit: []audit.Entry{by.entry("incident.alert_linked",
				inc.ID, map[string]any{"number": inc.Number, "alert_id": a.ID, "rule_id": a.RuleID})}}, nil
		})
	return inc, !existing, err
}

// CategoryInfo — категория с действующей инструкцией.
type CategoryInfo struct {
	Category    Category
	Instruction Instruction
}

func (s *Service) instruction(ctx context.Context, category string) (Instruction, error) {
	all, err := s.store.Instructions(ctx, s.orgID)
	if err != nil {
		return Instruction{}, err
	}
	return effective(all, category), nil
}

// effective — инструкция категории: последняя версия или текст по умолчанию.
func effective(all map[string]Instruction, category string) Instruction {
	if ins, ok := all[category]; ok {
		return ins
	}
	c, _ := LookupCategory(category)
	return Instruction{Category: category, Body: c.Instructions, Version: 1}
}

// Categories — справочник категорий с инструкциями.
func (s *Service) Categories(ctx context.Context) ([]CategoryInfo, error) {
	all, err := s.store.Instructions(ctx, s.orgID)
	if err != nil {
		return nil, err
	}
	out := make([]CategoryInfo, 0, len(categories))
	for _, c := range Categories() {
		out = append(out, CategoryInfo{Category: c, Instruction: effective(all, c.ID)})
	}
	return out, nil
}

// SetInstructions сохраняет новую версию инструкции категории (право
// incident_categories.manage); прежняя версия хранится.
func (s *Service) SetInstructions(ctx context.Context, by By, category string, in InstructionsInput) (Instruction, error) {
	if _, ok := LookupCategory(category); !ok {
		return Instruction{}, ErrNotFound
	}
	if err := parseInstructions(in); err != nil {
		return Instruction{}, err
	}
	ins, err := s.store.SetInstructions(ctx, s.orgID, category, func(cur Instruction) (Instruction, audit.Entry, error) {
		if cur.Version == 0 {
			cur = effective(nil, category)
		}
		if in.Version != cur.Version {
			return Instruction{}, audit.Entry{}, ErrVersionConflict
		}
		if in.Body == cur.Body {
			return Instruction{}, audit.Entry{}, errUnchanged
		}
		next := Instruction{Category: category, Body: in.Body, Version: cur.Version + 1, UpdatedAt: s.now(), UpdatedBy: by.ref()}
		rec := audit.Entry{Actor: by.Actor, SourceIP: by.IP, Action: "incident_category.update",
			Object: audit.Object{Type: "incident_category", ID: category}, Result: audit.ResultSuccess,
			Details: map[string]any{"category": category, "before_version": cur.Version, "after_version": next.Version,
				"before_default": cur.Default(), "length": utf8.RuneCountInString(in.Body)}}
		return next, rec, nil
	})
	if errors.Is(err, errUnchanged) {
		return s.instruction(ctx, category)
	}
	return ins, err
}

// Export — карточка в JSON без содержимого событий (ТЗ 5.7); запись
// data.export пишется до выдачи данных.
func (s *Service) Export(ctx context.Context, by By, id string) (Document, error) {
	c, err := s.Card(ctx, id)
	if err != nil {
		return Document{}, err
	}
	now := s.now()
	doc := NewDocument(c, now)
	if err := s.store.Record(ctx, audit.Entry{Actor: by.Actor, SourceIP: by.IP, Action: "data.export",
		Object: audit.Object{Type: "incident", ID: id}, Result: audit.ResultSuccess,
		Details: map[string]any{"format": "json", "number": c.Incident.Number, "timeline": len(doc.Timeline),
			"comments": len(doc.Comments), "events": len(doc.Events), "alerts": len(doc.Alerts), "snapshot": now}}); err != nil {
		return Document{}, err
	}
	return doc, nil
}

// autoIncident — инцидент по оповещению правила с признаком «инцидент»
// (хранилище, транзакция приёма событий). Номер присваивает хранилище.
func autoIncident(g *ids.Generator, orgID string, now time.Time, a *alerting.Alert, refs []EventRef, category string) (Incident, func(*Incident) (Change, error), error) {
	id, err := newID(g)
	if err != nil {
		return Incident{}, nil, err
	}
	if _, ok := LookupCategory(category); !ok {
		category = CategoryOther
	}
	title := a.Title
	if utf8.RuneCountInString(title) > MaxTitle {
		title = string([]rune(title)[:MaxTitle])
	}
	inc := newIncident(id, orgID, now, systemBy.ref(), title, a.Severity, category, SourceAuto)
	build := func(inc *Incident) (Change, error) {
		e1, err := entryAt(g, inc.ID, now, systemBy.ref(), KindCreated, map[string]any{"source": SourceAuto, "rule_id": a.RuleID})
		if err != nil {
			return Change{}, err
		}
		e2, err := entryAt(g, inc.ID, now, systemBy.ref(), KindAlertLinked, alertDetails(a, len(refs)))
		if err != nil {
			return Change{}, err
		}
		d := createDetails(inc)
		d["alert_id"], d["rule_id"] = a.ID, a.RuleID
		return Change{Timeline: []TimelineEntry{e1, e2}, Events: refs,
			Audit: []audit.Entry{systemBy.entry("incident.create", inc.ID, d)}}, nil
	}
	return inc, build, nil
}

// triggeredEntry — запись хронологии о новых срабатываниях связанного оповещения.
func triggeredEntry(g *ids.Generator, incidentID string, now time.Time, a *alerting.Alert, refs int) (TimelineEntry, error) {
	return entryAt(g, incidentID, now, systemBy.ref(), KindAlertTriggered,
		map[string]any{"alert_id": a.ID, "events": refs, "count": a.Count})
}
