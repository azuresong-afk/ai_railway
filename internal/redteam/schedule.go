package redteam

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/reports"
)

// Расписания запусков (ТЗ 5.13; задача 5.33 этапа 5, ADR-0031, дополнение
// 5.33). Календарь — как у расписаний отчётов (internal/reports): ежедневно,
// еженедельно, ежемесячно; время — в часовом поясе установки. Чаще раза в
// сутки расписание не бывает: частоту ограничивает и сам запуск (одна цель —
// один запуск, предел частоты запросов цели). Секретов расписание не
// хранит: цель с секретным заголовком по расписанию не запускается — её
// запускает CI с токеном и значением заголовка.

// Коды аудита расписаний.
const (
	ActionScheduleCreated = "redteam.schedule_created"
	ActionScheduleUpdated = "redteam.schedule_updated"
	ActionScheduleDeleted = "redteam.schedule_deleted"
	// ActionScheduleSkipped — запуск по расписанию не начат (причина — в
	// записи): занята цель, пропущен срок, нет базы, цель требует секрет.
	ActionScheduleSkipped = "redteam.schedule_skipped"
	objectSchedule        = "redteam_schedule"
)

// Периодичность — как у расписаний отчётов.
const (
	FreqDaily   = reports.FreqDaily
	FreqWeekly  = reports.FreqWeekly
	FreqMonthly = reports.FreqMonthly
)

// Пределы расписаний.
const (
	// MaxSchedules — расписаний в установке.
	MaxSchedules = 20
	// MaxScheduleName — длина названия, символов.
	MaxScheduleName = 100
	// TickInterval — период опроса сроков расписаний.
	TickInterval = time.Minute
	// MissedGrace — на сколько позже срока ещё можно начать запуск: после
	// простоя сервера атаки не стартуют в непредусмотренное время, срок
	// считается пропущенным.
	MissedGrace = time.Hour
	// BusyRetry и MaxBusyRetries — повтор запуска, который застал занятую
	// цель или сервер (очереди нет, ADR-0031, раздел 1): каждые 5 минут, не
	// дольше часа.
	BusyRetry      = 5 * time.Minute
	MaxBusyRetries = 12
	// scheduleBatch — расписаний за один опрос.
	scheduleBatch = 10
)

// Итог последней попытки расписания.
const (
	ScheduleStarted       = "started"
	ScheduleBusy          = "busy"
	ScheduleMissed        = "missed"
	ScheduleNoScenarios   = "no_scenarios"
	ScheduleNoGateway     = "gateway_not_configured"
	ScheduleNeedsSecret   = "needs_secret"
	ScheduleTargetInvalid = "target_invalid"
	ScheduleError         = "error"
)

var atRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// ErrTooManySchedules — достигнут предел расписаний.
var ErrTooManySchedules = errors.New("достигнут предел числа расписаний")

// ErrVersionConflict — расписание изменили после того, как его прочитал
// администратор.
var ErrVersionConflict = errors.New("расписание изменено другим пользователем: обновите страницу")

// Schedule — расписание запусков одной цели.
type Schedule struct {
	ID       string
	OrgID    string
	Name     string
	TargetID string
	// Frequency, Weekday (1–7, ISO 8601), Day (1–28), At («ЧЧ:ММ»).
	Frequency string
	Weekday   int
	Day       int
	At        string
	// Threats и Lang — отбор сценариев запуска; пусто — все сценарии базы.
	Threats []string
	Lang    string
	Enabled bool
	// NextRunAt — ближайший срок; LastRunAt — плановое время последней
	// попытки; LastRunID — запуск, начатый ею; LastStatus — итог попытки;
	// Retries — повторы из-за занятой цели.
	NextRunAt  time.Time
	LastRunAt  *time.Time
	LastRunID  string
	LastStatus string
	Retries    int
	Version    int
	CreatedAt  time.Time
	CreatedBy  string
	UpdatedAt  time.Time
	UpdatedBy  string
}

// timing — календарь расписания.
func (s Schedule) timing() reports.Schedule {
	return reports.Schedule{Frequency: s.Frequency, Weekday: s.Weekday, Day: s.Day, At: s.At}
}

// ScheduleInput — расписание из запроса API (создание и полная замена).
type ScheduleInput struct {
	Name      string   `json:"name"`
	TargetID  string   `json:"target_id"`
	Frequency string   `json:"frequency"`
	Weekday   int      `json:"weekday,omitempty"`
	Day       int      `json:"day,omitempty"`
	At        string   `json:"at"`
	Threats   []string `json:"threats,omitempty"`
	Lang      string   `json:"lang,omitempty"`
	Enabled   *bool    `json:"enabled,omitempty"`
	// Version — для изменения: версия, которую видел администратор.
	Version int `json:"version,omitempty"`
}

// Schedule проверяет ввод и возвращает расписание без служебных полей.
func (in ScheduleInput) Schedule() (Schedule, error) {
	var l errList
	s := Schedule{Name: strings.TrimSpace(in.Name), TargetID: in.TargetID, Frequency: in.Frequency, Weekday: in.Weekday, Day: in.Day,
		At: in.At, Lang: in.Lang, Enabled: in.Enabled == nil || *in.Enabled, Threats: []string{}}
	if !shortText(s.Name, 1, MaxScheduleName) {
		l.add("name — от 1 до %d знаков, обычный текст", MaxScheduleName)
	}
	if !uuidRe.MatchString(in.TargetID) {
		l.add("target_id — ID цели")
	}
	switch in.Frequency {
	case FreqDaily:
		if in.Weekday != 0 || in.Day != 0 {
			l.add("frequency — для ежедневного запуска день недели и день месяца не задаются")
		}
	case FreqWeekly:
		if in.Weekday < 1 || in.Weekday > 7 || in.Day != 0 {
			l.add("weekday — день недели от 1 (понедельник) до 7 (воскресенье)")
		}
	case FreqMonthly:
		if in.Day < 1 || in.Day > reports.MaxMonthDay || in.Weekday != 0 {
			l.add("day — день месяца от 1 до %d", reports.MaxMonthDay)
		}
	default:
		l.add("frequency — daily, weekly или monthly (чаще раза в сутки запуски не расписываются)")
	}
	if !atRe.MatchString(in.At) {
		l.add("at — время ЧЧ:ММ, например 03:30")
	}
	if len(in.Threats) > MaxRunFilter {
		l.add("threats — не больше %d строк", MaxRunFilter)
	}
	seen := map[string]bool{}
	for i, th := range in.Threats {
		switch {
		case !threatRe.MatchString(th):
			l.add("threats[%d] — строка матрицы DM-NN", i)
		case seen[th]:
			l.add("threats[%d] — строка %s повторяется", i, th)
		default:
			seen[th] = true
			s.Threats = append(s.Threats, th)
		}
	}
	if in.Lang != "" && in.Lang != LangRU && in.Lang != LangEN {
		l.add("lang — ru или en")
	}
	if err := l.err(); err != nil {
		return Schedule{}, err
	}
	return s, nil
}

// scheduleAudit — поля расписания для аудита.
func scheduleAudit(s Schedule) map[string]any {
	d := map[string]any{"name": s.Name, "target_id": s.TargetID, "frequency": s.Frequency, "at": s.At, "enabled": s.Enabled}
	if s.Weekday != 0 {
		d["weekday"] = s.Weekday
	}
	if s.Day != 0 {
		d["day"] = s.Day
	}
	if len(s.Threats) > 0 {
		d["threats"] = s.Threats
	}
	if s.Lang != "" {
		d["lang"] = s.Lang
	}
	return d
}

// scheduleActor — субъект запусков по расписанию в журнале аудита.
func scheduleActor(id string) audit.Actor {
	return audit.Actor{Type: audit.ActorSystem, ID: "redteam-schedule:" + id, Name: "Расписание тестирования устойчивости"}
}

// location — часовой пояс установки (UTC, если не задан).
func (s *Service) location(ctx context.Context) (*time.Location, error) {
	if s.o.Location == nil {
		return time.UTC, nil
	}
	return s.o.Location(ctx)
}

// checkScheduleTarget — цель расписания есть и запускается без значения
// секретного заголовка.
func (s *Service) checkScheduleTarget(ctx context.Context, targetID string) error {
	t, err := s.Target(ctx, targetID)
	if errors.Is(err, ErrNotFound) {
		return invalidf("target_id — цель не найдена")
	}
	if err != nil {
		return err
	}
	if t.AuthHeader != "" {
		return invalidf("target_id — у цели секретный заголовок %s: значение в продукте не хранится, по расписанию такая цель не запускается; запускайте её из CI", t.AuthHeader)
	}
	return nil
}

// Schedules — расписания организации.
func (s *Service) Schedules(ctx context.Context) ([]Schedule, error) {
	return s.o.Store.Schedules(ctx, s.o.OrgID)
}

// Schedule — расписание по ID.
func (s *Service) Schedule(ctx context.Context, id string) (Schedule, error) {
	if !uuidRe.MatchString(id) {
		return Schedule{}, ErrNotFound
	}
	return s.o.Store.Schedule(ctx, s.o.OrgID, id)
}

// CreateSchedule добавляет расписание; первый срок — ближайший после «сейчас».
func (s *Service) CreateSchedule(ctx context.Context, by By, in ScheduleInput) (Schedule, error) {
	sc, err := in.Schedule()
	if err != nil {
		return Schedule{}, err
	}
	if err := s.checkScheduleTarget(ctx, sc.TargetID); err != nil {
		return Schedule{}, err
	}
	loc, err := s.location(ctx)
	if err != nil {
		return Schedule{}, err
	}
	u, err := s.ids.New()
	if err != nil {
		return Schedule{}, err
	}
	now := s.o.Clock().UTC().Truncate(time.Microsecond)
	if sc.NextRunAt, err = sc.timing().Next(now, loc); err != nil {
		return Schedule{}, err
	}
	sc.ID, sc.OrgID, sc.Version = u.String(), s.o.OrgID, 1
	sc.CreatedAt, sc.CreatedBy, sc.UpdatedAt, sc.UpdatedBy = now, by.name(), now, by.name()
	if err := s.o.Store.CreateSchedule(ctx, sc, by.entry(ActionScheduleCreated, objectSchedule, sc.ID, scheduleAudit(sc))); err != nil {
		return Schedule{}, err
	}
	return sc, nil
}

// UpdateSchedule заменяет расписание целиком; срок пересчитывается от
// «сейчас», счётчик повторов обнуляется.
func (s *Service) UpdateSchedule(ctx context.Context, by By, id string, in ScheduleInput) (Schedule, error) {
	before, err := s.Schedule(ctx, id)
	if err != nil {
		return Schedule{}, err
	}
	sc, err := in.Schedule()
	if err != nil {
		return Schedule{}, err
	}
	if in.Version != before.Version {
		return Schedule{}, ErrVersionConflict
	}
	if err := s.checkScheduleTarget(ctx, sc.TargetID); err != nil {
		return Schedule{}, err
	}
	loc, err := s.location(ctx)
	if err != nil {
		return Schedule{}, err
	}
	now := s.o.Clock().UTC().Truncate(time.Microsecond)
	if sc.NextRunAt, err = sc.timing().Next(now, loc); err != nil {
		return Schedule{}, err
	}
	sc.ID, sc.OrgID, sc.Version = before.ID, before.OrgID, before.Version+1
	sc.LastRunAt, sc.LastRunID, sc.LastStatus = before.LastRunAt, before.LastRunID, before.LastStatus
	sc.CreatedAt, sc.CreatedBy, sc.UpdatedAt, sc.UpdatedBy = before.CreatedAt, before.CreatedBy, now, by.name()
	rec := by.entry(ActionScheduleUpdated, objectSchedule, sc.ID, map[string]any{"before": scheduleAudit(before), "after": scheduleAudit(sc)})
	if err := s.o.Store.UpdateSchedule(ctx, sc, before.Version, rec); err != nil {
		return Schedule{}, err
	}
	return sc, nil
}

// DeleteSchedule удаляет расписание; начатый им запуск продолжается.
func (s *Service) DeleteSchedule(ctx context.Context, by By, id string) error {
	sc, err := s.Schedule(ctx, id)
	if err != nil {
		return err
	}
	return s.o.Store.DeleteSchedule(ctx, s.o.OrgID, id, by.entry(ActionScheduleDeleted, objectSchedule, id, scheduleAudit(sc)))
}

// ScheduleProgress — итог попытки запуска по расписанию.
type ScheduleProgress struct {
	NextRunAt  time.Time
	LastRunAt  *time.Time
	LastRunID  string
	LastStatus string
	Retries    int
}

func (s *Service) scheduleSkipped(sc Schedule, due time.Time, status string, retries int) audit.Entry {
	return audit.Entry{Actor: scheduleActor(sc.ID), Action: ActionScheduleSkipped, Object: audit.Object{Type: objectSchedule, ID: sc.ID},
		Result: audit.ResultFailure, Details: map[string]any{"name": sc.Name, "target_id": sc.TargetID, "status": status,
			"due": due.UTC().Format(time.RFC3339), "retries": retries}}
}

// TickSchedules начинает запуски расписаний, срок которых наступил. Срок
// занимается раньше запуска: сбой между занятием и запуском теряет запуск, но
// не дублирует его — атаки дважды не отправляются. Пропущенные после простоя
// сроки сводятся к одному, и тот начинается, только если опоздание не больше
// MissedGrace.
func (s *Service) TickSchedules(ctx context.Context) error {
	loc, err := s.location(ctx)
	if err != nil {
		return err
	}
	now := s.o.Clock().UTC().Truncate(time.Microsecond)
	due, err := s.o.Store.DueSchedules(ctx, s.o.OrgID, now, scheduleBatch)
	if err != nil {
		return err
	}
	for _, sc := range due {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.runScheduled(ctx, sc, now, loc); err != nil {
			s.o.Logger.Error("тестирование устойчивости: расписание не выполнено", "schedule", sc.ID, "error", err)
		}
	}
	return nil
}

func (s *Service) runScheduled(ctx context.Context, sc Schedule, now time.Time, loc *time.Location) error {
	plan, err := sc.timing().Latest(sc.NextRunAt, now, loc)
	if err != nil {
		return err
	}
	next, err := sc.timing().Next(now, loc)
	if err != nil {
		return err
	}
	// Занять срок: расписание изменили или другой опрос взял его раньше —
	// запуска нет.
	claimed, err := s.o.Store.ClaimSchedule(ctx, s.o.OrgID, sc.ID, sc.NextRunAt, next)
	if err != nil || !claimed {
		return err
	}
	finish := func(p ScheduleProgress, rec *audit.Entry) error {
		p.LastRunAt = &plan
		return s.o.Store.FinishSchedule(ctx, s.o.OrgID, sc.ID, p, rec)
	}
	if sc.Retries == 0 && now.Sub(plan) > MissedGrace {
		rec := s.scheduleSkipped(sc, plan, ScheduleMissed, 0)
		return finish(ScheduleProgress{NextRunAt: next, LastStatus: ScheduleMissed}, &rec)
	}
	// Цель могли удалить или добавить ей секретный заголовок после расписания.
	if t, err := s.Target(ctx, sc.TargetID); err != nil || t.AuthHeader != "" {
		status := ScheduleTargetInvalid
		if err == nil {
			status = ScheduleNeedsSecret
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		rec := s.scheduleSkipped(sc, plan, status, sc.Retries)
		return finish(ScheduleProgress{NextRunAt: next, LastStatus: status}, &rec)
	}
	by := By{Actor: scheduleActor(sc.ID)}
	run, err := s.StartRun(ctx, by, StartInput{TargetID: sc.TargetID, Threats: sc.Threats, Lang: sc.Lang})
	switch {
	case err == nil:
		return finish(ScheduleProgress{NextRunAt: next, LastRunID: run.ID, LastStatus: ScheduleStarted}, nil)
	case errors.Is(err, ErrBusy):
		if sc.Retries < MaxBusyRetries {
			// Повтор через BusyRetry, но не позже обычного срока.
			retry := now.Add(BusyRetry)
			if retry.After(next) {
				retry = next
			}
			return finish(ScheduleProgress{NextRunAt: retry, LastStatus: ScheduleBusy, Retries: sc.Retries + 1}, nil)
		}
		rec := s.scheduleSkipped(sc, plan, ScheduleBusy, sc.Retries)
		return finish(ScheduleProgress{NextRunAt: next, LastStatus: ScheduleBusy}, &rec)
	}
	status := ScheduleError
	switch {
	case errors.Is(err, ErrNoScenarios):
		status = ScheduleNoScenarios
	case errors.Is(err, ErrGatewayNotConfigured):
		status = ScheduleNoGateway
	}
	rec := s.scheduleSkipped(sc, plan, status, sc.Retries)
	if status == ScheduleError {
		s.o.Logger.Error("тестирование устойчивости: запуск по расписанию не начат", "schedule", sc.ID, "error", err)
	}
	return finish(ScheduleProgress{NextRunAt: next, LastStatus: status}, &rec)
}

func (s *Service) scheduleLoop(ctx context.Context) {
	t := time.NewTicker(TickInterval)
	defer t.Stop()
	for {
		if err := s.TickSchedules(ctx); err != nil && ctx.Err() == nil {
			s.o.Logger.Error("тестирование устойчивости: сбой опроса расписаний", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ScheduleStatusText — итог попытки для людей.
func ScheduleStatusText(status string) string {
	switch status {
	case ScheduleStarted:
		return "запуск начат"
	case ScheduleBusy:
		return "цель или сервер заняты"
	case ScheduleMissed:
		return "срок пропущен (сервер был выключен)"
	case ScheduleNoScenarios:
		return "нет сценариев"
	case ScheduleNoGateway:
		return "адрес шлюза не задан"
	case ScheduleNeedsSecret:
		return "цели нужен секретный заголовок"
	case ScheduleTargetInvalid:
		return "цель не найдена или изменена"
	case ScheduleError:
		return "ошибка (см. журнал сервера)"
	}
	return status
}
