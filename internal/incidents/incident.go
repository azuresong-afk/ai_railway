package incidents

import (
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
)

// Статусы инцидента (ТЗ 5.7).
const (
	StatusNew        = "new"
	StatusInProgress = "in_progress"
	StatusContained  = "contained"
	StatusClosed     = "closed"
)

// Statuses — все статусы по порядку автомата.
func Statuses() []string { return []string{StatusNew, StatusInProgress, StatusContained, StatusClosed} }

// Резолюции закрытия (ТЗ 5.7).
const (
	ResolutionResolved      = "resolved"
	ResolutionFalsePositive = "false_positive"
	ResolutionRiskAccepted  = "risk_accepted"
)

// Resolutions — допустимые резолюции.
func Resolutions() []string {
	return []string{ResolutionResolved, ResolutionFalsePositive, ResolutionRiskAccepted}
}

// Источники инцидента.
const (
	SourceManual = "manual" // вручную
	SourceAlert  = "alert"  // из оповещения
	SourceAuto   = "auto"   // правилом с признаком «инцидент» в приёме событий
	SourceReopen = "reopen" // повторное открытие закрытого
)

// transitionAllowed — допустимый переход статуса. Назад автомат не ходит;
// закрытый инцидент не открывается (повторное открытие — новый инцидент).
func transitionAllowed(from, to string) bool {
	switch from {
	case StatusNew:
		return to == StatusInProgress || to == StatusClosed
	case StatusInProgress:
		return to == StatusContained || to == StatusClosed
	case StatusContained:
		return to == StatusClosed
	}
	return false
}

// Пределы ввода и объёма.
const (
	MaxTitle             = 300
	MaxComment           = 4000
	MaxResolutionComment = 2000
	MaxStageNote         = 2000
	MaxInstructions      = 8000
	// MaxComments — комментариев (с правками) в инциденте.
	MaxComments = 500
	// MaxTimeline — записей хронологии: ручные действия сверх предела
	// отклоняются, кроме закрытия — оно проходит всегда и даёт не больше
	// одной записи сверх предела (3В18 ревью 3.r2).
	MaxTimeline = 2000
	// MaxAutoTimeline — предел для автоматических записей о новых
	// срабатываниях (приём событий): сверх него они не пишутся, а у
	// разбора остаётся запас на ручные действия (3В18 ревью 3.r2).
	MaxAutoTimeline = MaxTimeline - 100
	// MaxEvents — ссылок на события; дальше ссылки не добавляются.
	MaxEvents = 1000
	// Пределы тел — с запасом на экранирование \uXXXX: символ вне BMP
	// занимает в JSON 12 байт.
	// MaxBody — тело запроса инцидента, кроме комментария и инструкции.
	MaxBody = 32 << 10
	// MaxCommentBody — тело запроса комментария.
	MaxCommentBody = 64 << 10
	// MaxInstructionsBody — тело запроса инструкции.
	MaxInstructionsBody = 128 << 10
	// MaxListLimit — записей на странице списка.
	MaxListLimit = 200
)

// reactionBySeverity — срок реакции по серьёзности: время до перехода из
// статуса «новый» (умолчания, настройка — следующие задачи).
var reactionBySeverity = map[string]time.Duration{
	"critical": time.Hour,
	"high":     4 * time.Hour,
	"medium":   24 * time.Hour,
	"low":      72 * time.Hour,
	"info":     7 * 24 * time.Hour,
}

// ReactionTime — срок реакции для серьёзности.
func ReactionTime(severity string) time.Duration { return reactionBySeverity[severity] }

// StageDef — этап реагирования шаблона.
type StageDef struct {
	Key   string
	Title string
}

// stageTemplate — этапы по умолчанию (ТЗ 5.7; по смыслу совместимы с
// приказом ФСБ России № 554, п. 19).
var stageTemplate = []StageDef{
	{Key: "intake", Title: "Приём сообщения"},
	{Key: "triage", Title: "Сбор первичных сведений"},
	{Key: "containment", Title: "Локализация"},
	{Key: "investigation", Title: "Сбор сведений для расследования"},
}

// StageTemplate — этапы реагирования по умолчанию.
func StageTemplate() []StageDef { return slices.Clone(stageTemplate) }

// StageTitle — название этапа по ключу.
func StageTitle(key string) string {
	for _, s := range stageTemplate {
		if s.Key == key {
			return s.Title
		}
	}
	return key
}

// Incident — инцидент.
type Incident struct {
	ID                string
	OrgID             string
	Number            int64
	Title             string
	Severity          string
	Category          string
	Status            string
	Resolution        string
	ResolutionComment string
	Source            string
	ReopenedFrom      string
	AssigneeID        string
	ReactionDueAt     time.Time
	ReactedAt         time.Time
	ContainedAt       time.Time
	CreatedAt         time.Time
	CreatedBy         string
	UpdatedAt         time.Time
	UpdatedBy         string
	ClosedAt          time.Time
	ClosedBy          string
	Version           int
	Stages            []Stage
}

func (i *Incident) clone() Incident {
	c := *i
	c.Stages = slices.Clone(i.Stages)
	return c
}

// Overdue — срок реакции истёк, а инцидент всё ещё новый.
func (i *Incident) Overdue(now time.Time) bool {
	return i.Status == StatusNew && now.After(i.ReactionDueAt)
}

// Stage — этап реагирования инцидента.
type Stage struct {
	Key      string
	Position int
	DoneAt   time.Time
	DoneBy   string
	Note     string
}

// newStages — этапы нового инцидента по шаблону.
func newStages() []Stage {
	out := make([]Stage, len(stageTemplate))
	for i, s := range stageTemplate {
		out[i] = Stage{Key: s.Key, Position: i + 1}
	}
	return out
}

// Виды записей хронологии.
const (
	KindCreated        = "created"
	KindStatusChanged  = "status_changed"
	KindAssigned       = "assigned"
	KindCommentAdded   = "comment_added"
	KindStageCompleted = "stage_completed"
	KindAlertLinked    = "alert_linked"
	KindAlertTriggered = "alert_triggered"
	KindReopened       = "reopened"
)

// TimelineEntry — запись хронологии.
type TimelineEntry struct {
	ID         string
	IncidentID string
	At         time.Time
	Actor      string
	Kind       string
	// Details — подробности без содержимого запросов (ID, статусы, счётчики).
	Details map[string]any
}

// Comment — комментарий; правка — новая запись с Replaces.
type Comment struct {
	ID         string
	IncidentID string
	At         time.Time
	Author     string
	AuthorName string
	Body       string
	Replaces   string
}

// EventRef — ссылка на событие (ID и ключ секции).
type EventRef = alerting.EventRef

// Counts — объём связанных записей инцидента (проверка пределов).
type Counts struct {
	Timeline int
	Comments int
	Events   int
	Alerts   int
}

// Query — выборка инцидентов от новых к старым.
type Query struct {
	// Status — статус; StatusOpen — все, кроме закрытых.
	Status     string
	Severity   string
	Category   string
	AssigneeID string
	Source     string
	After      *Position
	Limit      int
}

// StatusOpen — фильтр «все незакрытые».
const StatusOpen = "open"

// Position — место в выборке: (время создания, ID).
type Position struct {
	CreatedAt time.Time
	ID        string
}

func (q *Query) match(i *Incident) bool {
	st := q.Status == "" || i.Status == q.Status || q.Status == StatusOpen && i.Status != StatusClosed
	return st && (q.Severity == "" || i.Severity == q.Severity) && (q.Category == "" || i.Category == q.Category) &&
		(q.AssigneeID == "" || i.AssigneeID == q.AssigneeID) && (q.Source == "" || i.Source == q.Source) &&
		(q.After == nil || i.CreatedAt.Before(q.After.CreatedAt) || i.CreatedAt.Equal(q.After.CreatedAt) && i.ID < q.After.ID)
}

// Instruction — инструкция реагирования категории.
type Instruction struct {
	Category string
	Body     string
	// Version — 1 у текста по умолчанию, каждая правка — следующая.
	Version   int
	UpdatedAt time.Time
	UpdatedBy string
}

// Default — действует текст по умолчанию из кода.
func (i Instruction) Default() bool { return i.Version <= 1 }
