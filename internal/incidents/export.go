package incidents

import (
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
)

// Представления инцидента в JSON: карточка API и выгрузка (ТЗ 5.7).
// Содержимого запросов и ответов нет: только ссылки на события.

// View — инцидент.
type View struct {
	ID                string     `json:"id"`
	Number            int64      `json:"number"`
	Title             string     `json:"title"`
	Severity          string     `json:"severity"`
	Category          string     `json:"category"`
	Status            string     `json:"status"`
	Resolution        string     `json:"resolution,omitempty"`
	ResolutionComment string     `json:"resolution_comment,omitempty"`
	Source            string     `json:"source"`
	ReopenedFrom      string     `json:"reopened_from,omitempty"`
	AssigneeID        string     `json:"assignee_id,omitempty"`
	ReactionDueAt     time.Time  `json:"reaction_due_at"`
	Overdue           bool       `json:"overdue"`
	ReactedAt         *time.Time `json:"reacted_at,omitempty"`
	ContainedAt       *time.Time `json:"contained_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	CreatedBy         string     `json:"created_by"`
	UpdatedAt         time.Time  `json:"updated_at"`
	UpdatedBy         string     `json:"updated_by"`
	ClosedAt          *time.Time `json:"closed_at,omitempty"`
	ClosedBy          string     `json:"closed_by,omitempty"`
	Version           int        `json:"version"`
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// ViewOf — представление инцидента на момент now.
func ViewOf(i *Incident, now time.Time) View {
	return View{ID: i.ID, Number: i.Number, Title: i.Title, Severity: i.Severity, Category: i.Category, Status: i.Status,
		Resolution: i.Resolution, ResolutionComment: i.ResolutionComment, Source: i.Source, ReopenedFrom: i.ReopenedFrom,
		AssigneeID: i.AssigneeID, ReactionDueAt: i.ReactionDueAt.UTC(), Overdue: i.Overdue(now), ReactedAt: optTime(i.ReactedAt),
		ContainedAt: optTime(i.ContainedAt), CreatedAt: i.CreatedAt.UTC(), CreatedBy: i.CreatedBy, UpdatedAt: i.UpdatedAt.UTC(),
		UpdatedBy: i.UpdatedBy, ClosedAt: optTime(i.ClosedAt), ClosedBy: i.ClosedBy, Version: i.Version}
}

// StageView — этап реагирования.
type StageView struct {
	Key    string     `json:"key"`
	Title  string     `json:"title"`
	DoneAt *time.Time `json:"done_at,omitempty"`
	DoneBy string     `json:"done_by,omitempty"`
	Note   string     `json:"note,omitempty"`
}

// TimelineView — запись хронологии.
type TimelineView struct {
	At      time.Time      `json:"at"`
	Actor   string         `json:"actor"`
	Kind    string         `json:"kind"`
	Details map[string]any `json:"details"`
}

// CommentView — комментарий; Superseded — есть следующая версия.
type CommentView struct {
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	Author     string    `json:"author"`
	AuthorName string    `json:"author_name"`
	Body       string    `json:"body"`
	Replaces   string    `json:"replaces,omitempty"`
	Superseded bool      `json:"superseded"`
}

// AlertRefView — связанное оповещение.
type AlertRefView struct {
	ID        string    `json:"id"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	Count     int64     `json:"count"`
	CreatedAt time.Time `json:"created_at"`
}

// EventView — ссылка на событие; карточка — GET /api/v1/events/{id}.
type EventView struct {
	ID string    `json:"id"`
	TS time.Time `json:"ts"`
}

// InstructionView — инструкция реагирования.
type InstructionView struct {
	Category  string     `json:"category"`
	Body      string     `json:"body"`
	Version   int        `json:"version"`
	Default   bool       `json:"default"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// InstructionViewOf — представление инструкции.
func InstructionViewOf(i Instruction) InstructionView {
	return InstructionView{Category: i.Category, Body: i.Body, Version: i.Version, Default: i.Default(),
		UpdatedAt: optTime(i.UpdatedAt), UpdatedBy: i.UpdatedBy}
}

// CardView — карточка инцидента.
type CardView struct {
	View
	CategoryTitle string         `json:"category_title"`
	Stages        []StageView    `json:"stages"`
	Timeline      []TimelineView `json:"timeline"`
	Comments      []CommentView  `json:"comments"`
	Alerts        []AlertRefView `json:"alerts"`
	Events        []EventView    `json:"events"`
	// EventsTruncated — ссылок столько, сколько допускает предел MaxEvents.
	EventsTruncated bool            `json:"events_truncated"`
	Instruction     InstructionView `json:"instruction"`
}

// CardViewOf — представление карточки на момент now.
func CardViewOf(c Card, now time.Time) CardView {
	cat, _ := LookupCategory(c.Incident.Category)
	v := CardView{View: ViewOf(&c.Incident, now), CategoryTitle: cat.Title, Stages: make([]StageView, 0, len(c.Incident.Stages)),
		Timeline: make([]TimelineView, 0, len(c.Related.Timeline)), Comments: make([]CommentView, 0, len(c.Related.Comments)),
		Alerts: make([]AlertRefView, 0, len(c.Related.Alerts)), Events: make([]EventView, 0, len(c.Related.Events)),
		EventsTruncated: len(c.Related.Events) >= MaxEvents, Instruction: InstructionViewOf(c.Instruction)}
	for _, s := range c.Incident.Stages {
		v.Stages = append(v.Stages, StageView{Key: s.Key, Title: StageTitle(s.Key), DoneAt: optTime(s.DoneAt), DoneBy: s.DoneBy, Note: s.Note})
	}
	for _, t := range c.Related.Timeline {
		d := t.Details
		if d == nil {
			d = map[string]any{}
		}
		v.Timeline = append(v.Timeline, TimelineView{At: t.At.UTC(), Actor: t.Actor, Kind: t.Kind, Details: d})
	}
	replaced := map[string]bool{}
	for _, cm := range c.Related.Comments {
		if cm.Replaces != "" {
			replaced[cm.Replaces] = true
		}
	}
	for _, cm := range c.Related.Comments {
		v.Comments = append(v.Comments, CommentView{ID: cm.ID, At: cm.At.UTC(), Author: cm.Author, AuthorName: cm.AuthorName,
			Body: cm.Body, Replaces: cm.Replaces, Superseded: replaced[cm.ID]})
	}
	for _, a := range c.Related.Alerts {
		v.Alerts = append(v.Alerts, alertRef(a))
	}
	for _, e := range c.Related.Events {
		v.Events = append(v.Events, EventView{ID: e.ID, TS: e.TS.UTC()})
	}
	return v
}

func alertRef(a alerting.Alert) AlertRefView {
	return AlertRefView{ID: a.ID, RuleID: a.RuleID, RuleName: a.RuleName, Title: a.Title, Severity: a.Severity,
		Status: a.Status, Count: a.Count, CreatedAt: a.CreatedAt.UTC()}
}

// DocumentFormat — формат выгрузки карточки.
const DocumentFormat = "aisec-incident/1"

// Document — выгрузка карточки в JSON (ТЗ 5.7): для передачи в SIEM/IRP
// заказчика. Содержимого событий нет.
type Document struct {
	Format     string    `json:"format"`
	ExportedAt time.Time `json:"exported_at"`
	CardView
}

// NewDocument — выгрузка карточки на момент now.
func NewDocument(c Card, now time.Time) Document {
	return Document{Format: DocumentFormat, ExportedAt: now.UTC(), CardView: CardViewOf(c, now)}
}
