package reports

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/notify"
)

// Ошибки сервиса.
var (
	ErrNotFound = errors.New("отчёты: расписание не найдено")
	// ErrRecipientNotFound — справочник не знает пользователя.
	ErrRecipientNotFound = errors.New("отчёты: получатель не найден")
	ErrVersionConflict   = errors.New("отчёты: расписание изменено другим пользователем")
	ErrTooMany           = errors.New("отчёты: достигнут предел числа расписаний")
	ErrChannel           = errors.New("отчёты: канал не найден, не почтовый или отключён")
	ErrNoRecipients      = errors.New("отчёты: у почтового канала нет получателей")
)

// Статусы запуска рассылки.
const (
	RunPending = "pending"
	RunSent    = "sent"
	RunFailed  = "failed"
)

// Коды ошибок запуска (без текстов получателей и адресов).
const (
	ErrCodeBuild    = "build_failed"
	ErrCodeRender   = "render_failed"
	ErrCodeDisabled = "schedule_disabled"
	ErrCodeChannel  = "channel_unavailable"
	ErrCodePeriod   = "bad_period"
	// ErrCodeAudit — запись data.export не сделана: письмо не отправлено.
	ErrCodeAudit = "audit_failed"
	// ErrCodeExhausted — попытки израсходованы прерванными отправками.
	ErrCodeExhausted = "attempts_exhausted"
)

// Параметры планировщика.
const (
	// MaxAttempts — попыток отправки одного запуска (задержки — notify.Backoff).
	MaxAttempts = 5
	// TickInterval — период опроса расписаний и очереди.
	TickInterval = 30 * time.Second
	// runLease — срок, на который запуск откладывается при выборке: больше
	// предела построения и отправки; повтор — если сервер остановился.
	runLease = 10 * time.Minute
	// enqueueBatch — расписаний за один опрос.
	enqueueBatch = 20
	// MaxRunsPage — запусков в журнале расписания.
	MaxRunsPage = 100
	// buildTimeout — предел построения отчёта.
	buildTimeout = 2 * time.Minute
	// RunRetention — срок хранения завершённых запусков журнала рассылки
	// (3Н47 ревью 3.r4): как у закрытых оповещений по умолчанию. Факт
	// выгрузки остаётся в журнале аудита (data.export).
	RunRetention = 365 * 24 * time.Hour
	// pruneEvery — как часто опрос удаляет запуски старше RunRetention.
	pruneEvery = time.Hour
)

// Run — запуск рассылки: строка журнала доставки и очередь повторов.
type Run struct {
	ID         string
	OrgID      string
	ScheduleID string
	// DueAt — запуск расписания, который породил рассылку.
	DueAt time.Time
	// PeriodFirst и PeriodLast — дни отчёта, YYYY-MM-DD.
	PeriodFirst, PeriodLast string
	Status                  string
	Attempts                int
	NextAt                  time.Time
	Error                   string
	CreatedAt               time.Time
	UpdatedAt               time.Time
	SentAt                  time.Time
	// SkippedNoEmail — сколько получателей-пользователей пропущено в последней
	// попытке: нет адреса, учётная запись деактивирована или без права
	// reports.read, либо сервер SMTP отклонил адрес. Адреса в журнал
	// доставки не пишутся.
	SkippedNoEmail int
}

// Store — хранилище расписаний и журнала рассылки.
type Store interface {
	Schedules(ctx context.Context) ([]Schedule, error)
	Schedule(ctx context.Context, id string) (Schedule, error)
	// CreateSchedule сохраняет расписание и запись аудита одной транзакцией.
	CreateSchedule(ctx context.Context, s Schedule, rec audit.Entry) error
	// UpdateSchedule меняет расписание под блокировкой строки: fn получает
	// прежнее и возвращает новое и запись аудита той же транзакции.
	UpdateSchedule(ctx context.Context, id string, fn func(old Schedule) (Schedule, audit.Entry, error)) (Schedule, error)
	// DeleteSchedule удаляет расписание и его журнал; rec строит запись
	// аудита по удаляемому расписанию.
	DeleteSchedule(ctx context.Context, id string, rec func(old Schedule) audit.Entry) error
	// Runs — журнал рассылки расписания, новые сначала.
	Runs(ctx context.Context, scheduleID string, limit int) ([]Run, error)
	// EnqueueDue ставит в очередь рассылки включённых расписаний со сроком
	// next_run_at <= now: для каждого вызывает plan; он возвращает запуск
	// и новое next_run_at. Возвращает число поставленных.
	EnqueueDue(ctx context.Context, now time.Time, limit int, plan func(Schedule) (Run, time.Time, error)) (int, error)
	// ClaimRun берёт запуск, срок которого наступил, откладывает его на lease
	// и засчитывает попытку (3В32 ревью 3.r4: падение сервера во время
	// отправки тоже расходует попытку, повторы конечны).
	// Record пишет запись аудита отдельной транзакцией.
	ClaimRun(ctx context.Context, now time.Time, lease time.Duration) (Run, Schedule, bool, error)
	// FinishRun сохраняет итог попытки; rec — запись аудита той же транзакции.
	FinishRun(ctx context.Context, r Run, rec *audit.Entry) error
	Record(ctx context.Context, rec audit.Entry) error
	// PruneRuns удаляет завершённые (sent, failed) запуски, обновлённые
	// раньше before; возвращает число удалённых.
	PruneRuns(ctx context.Context, before time.Time) (int64, error)
}

// Mailer — отправка письма с отчётом (*notify.Service).
type Mailer interface {
	SendReport(ctx context.Context, channelID string, m notify.ReportMail) error
}

// Recipient — пользователь консоли как получатель отчётов.
type Recipient struct {
	// Email — адрес из учётной записи; пусто — адреса нет.
	Email string
	// Active — учётная запись активна; CanRead — у роли есть reports.read на все объекты.
	Active, CanRead bool
	// Scope — разделы отчёта, которые роль вправе читать (как у вызывающего
	// GET /reports/{kind}): получатель не получает больше, чем может прочитать.
	Scope Scope
}

// Eligible — получателю можно слать отчёт расписания sc: учётная запись
// активна, есть reports.read, а права на разделы покрывают разделы расписания.
func (r Recipient) Eligible(sc Scope) bool {
	return r.Active && r.CanRead && (!sc.Incidents || r.Scope.Incidents) && (!sc.Alerts || r.Scope.Alerts) && (!sc.Budgets || r.Scope.Budgets) &&
		(!sc.Compliance || r.Scope.Compliance)
}

// Directory — справочник пользователей (*auth.Service через api): адрес и
// право на отчёты проверяются при сохранении расписания и при каждой отправке.
// Неизвестный пользователь — ErrRecipientNotFound.
type Directory interface {
	Recipient(ctx context.Context, userID string) (Recipient, error)
}

// ChannelReader — чтение каналов уведомлений (*notify.Service).
type ChannelReader interface {
	Channel(ctx context.Context, id string) (notify.Channel, error)
	Channels(ctx context.Context) ([]notify.Channel, error)
}

// ChannelRef — почтовый канал для выбора в расписании: без адресов и
// настроек сервера (3Н46 ревью 3.r4).
type ChannelRef struct {
	ID   string
	Name string
}

// MailChannels — включённые почтовые каналы с получателями, к которым можно
// привязать расписание.
func (s *Service) MailChannels(ctx context.Context) ([]ChannelRef, error) {
	out := []ChannelRef{}
	if s.o.Channels == nil {
		return out, nil
	}
	list, err := s.o.Channels.Channels(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range list {
		if c.Type == notify.TypeEmail && c.Enabled && len(c.Settings.To) > 0 {
			out = append(out, ChannelRef{ID: c.ID, Name: c.Name})
		}
	}
	return out, nil
}

// Options — зависимости сервиса.
type Options struct {
	Store    Store
	Builder  *Builder
	Mailer   Mailer
	Channels ChannelReader
	// Directory — справочник получателей-пользователей; без него расписания
	// с получателями-пользователями не сохраняются.
	Directory Directory
	// Location — часовой пояс установки (install_settings).
	Location func(ctx context.Context) (*time.Location, error)
	IDs      *ids.Generator
	OrgID    string
	Logger   *slog.Logger
	Now      func() time.Time
}

// Service — построение отчётов и расписания рассылки.
type Service struct {
	o Options
	// prunedAt — последняя очистка журнала рассылки (только из Tick).
	mu       sync.Mutex
	prunedAt time.Time
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Builder == nil || o.Location == nil || o.IDs == nil {
		return nil, errors.New("отчёты: нет хранилища, сборщика, часового пояса или источника идентификаторов")
	}
	if o.OrgID == "" {
		o.OrgID = audit.DefaultOrgID
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Service{o: o}, nil
}

func (s *Service) now() time.Time { return s.o.Now().UTC().Truncate(time.Microsecond) }

// Location — часовой пояс установки.
func (s *Service) Location(ctx context.Context) (*time.Location, error) { return s.o.Location(ctx) }

// Build строит отчёт.
func (s *Service) Build(ctx context.Context, p Params, sc Scope) (Doc, error) {
	return s.o.Builder.Build(ctx, p, sc)
}

// Render пишет документ в формате format.
func Render(w *bytes.Buffer, d Doc, format string, delim rune) error {
	switch format {
	case FormatCSV:
		return WriteCSV(w, d, delim)
	case FormatXLSX:
		return WriteXLSX(w, d)
	case FormatHTML:
		return WriteHTML(w, d)
	}
	return errors.New("отчёты: формат")
}

// By — субъект изменения.
type By struct {
	Actor audit.Actor
	IP    netip.Addr
	// Scope — права субъекта на разделы отчёта; расписание получает их снимок.
	Scope Scope
}

func (b By) ref() string {
	r := string(b.Actor.Type) + ":" + b.Actor.ID
	if len(r) > 128 {
		r = r[:128]
	}
	return r
}

func (s *Service) entry(b By, action, id string, details any) audit.Entry {
	return audit.Entry{OrgID: s.o.OrgID, Actor: b.Actor, SourceIP: b.IP, Action: action,
		Object: audit.Object{Type: "report_schedule", ID: id}, Result: audit.ResultSuccess, Details: details}
}

// scheduleScope — разделы, которые сохраняются в расписании отчёта kind:
// «Соответствие» целиком зависит от одного права, а в прочих видах раздела
// соответствия нет — получатели проверяются только по тому, что в отчёте.
func scheduleScope(kind string, by Scope) Scope {
	if kind == KindCompliance {
		return Scope{Compliance: by.Compliance}
	}
	by.Compliance = false
	return by
}

func view(sc Schedule) map[string]any {
	return map[string]any{"name": sc.Name, "report": sc.Report, "frequency": sc.Frequency, "weekday": sc.Weekday, "day": sc.Day,
		"at": sc.At, "format": sc.Format, "applies": sc.Applies, "channel_id": sc.ChannelID, "enabled": sc.Enabled,
		"recipient_user_ids": sc.RecipientUserIDs,
		"scope": map[string]bool{"incidents": sc.Scope.Incidents, "alerts": sc.Scope.Alerts, "budgets": sc.Scope.Budgets,
			"compliance": sc.Scope.Compliance}}
}

// Schedules — все расписания.
func (s *Service) Schedules(ctx context.Context) ([]Schedule, error) { return s.o.Store.Schedules(ctx) }

// Schedule — расписание по ID.
func (s *Service) Schedule(ctx context.Context, id string) (Schedule, error) {
	return s.o.Store.Schedule(ctx, id)
}

// Runs — журнал рассылки расписания.
func (s *Service) Runs(ctx context.Context, id string, limit int) ([]Run, error) {
	if _, err := s.o.Store.Schedule(ctx, id); err != nil {
		return nil, err
	}
	return s.o.Store.Runs(ctx, id, min(max(limit, 1), MaxRunsPage))
}

// checkChannel проверяет, что канал почтовый, включён и имеет получателей.
func (s *Service) checkChannel(ctx context.Context, id string) error {
	if s.o.Channels == nil {
		return ErrChannel
	}
	c, err := s.o.Channels.Channel(ctx, id)
	if err != nil {
		if errors.Is(err, notify.ErrNotFound) {
			return ErrChannel
		}
		return err
	}
	if c.Type != notify.TypeEmail || !c.Enabled {
		return ErrChannel
	}
	if len(c.Settings.To) == 0 {
		return ErrNoRecipients
	}
	return nil
}

// checkRecipients проверяет получателей-пользователей: учётная запись есть,
// активна и может читать отчёты. Отсутствие адреса не ошибка: такой
// получатель пропускается при отправке, консоль подсказывает об этом.
func (s *Service) checkRecipients(ctx context.Context, ids []string, sc Scope) error {
	if len(ids) == 0 {
		return nil
	}
	if s.o.Directory == nil {
		return &InputError{Fields: map[string]string{"recipient_user_ids": "Получатели-пользователи недоступны."}}
	}
	for _, id := range ids {
		r, err := s.o.Directory.Recipient(ctx, id)
		if errors.Is(err, ErrRecipientNotFound) || (err == nil && !r.Eligible(sc)) {
			return &InputError{Fields: map[string]string{"recipient_user_ids": "Получатель не найден, деактивирован или не имеет права на отчёты."}}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateSchedule создаёт расписание (право reports.schedules.manage).
func (s *Service) CreateSchedule(ctx context.Context, by By, in ScheduleInput) (Schedule, error) {
	sc, err := in.Validate()
	if err != nil {
		return Schedule{}, err
	}
	if !by.Scope.Allows(sc.Report) {
		return Schedule{}, ErrScope
	}
	sc.Scope = scheduleScope(sc.Report, by.Scope)
	if err := s.checkChannel(ctx, sc.ChannelID); err != nil {
		return Schedule{}, err
	}
	if err := s.checkRecipients(ctx, sc.RecipientUserIDs, sc.Scope); err != nil {
		return Schedule{}, err
	}
	loc, err := s.o.Location(ctx)
	if err != nil {
		return Schedule{}, err
	}
	id, err := s.o.IDs.New()
	if err != nil {
		return Schedule{}, err
	}
	now := s.now()
	sc.ID, sc.OrgID, sc.Version = id.String(), s.o.OrgID, 1
	sc.CreatedAt, sc.CreatedBy, sc.UpdatedAt, sc.UpdatedBy = now, by.ref(), now, by.ref()
	if sc.NextRunAt, err = sc.Next(now, loc); err != nil {
		return Schedule{}, err
	}
	if err := s.o.Store.CreateSchedule(ctx, sc, s.entry(by, "report_schedule.create", sc.ID, view(sc))); err != nil {
		return Schedule{}, err
	}
	return sc, nil
}

// UpdateSchedule заменяет настройки расписания; ближайший запуск пересчитывается.
func (s *Service) UpdateSchedule(ctx context.Context, by By, id string, in ScheduleInput) (Schedule, error) {
	sc, err := in.Validate()
	if err != nil {
		return Schedule{}, err
	}
	if !by.Scope.Allows(sc.Report) {
		return Schedule{}, ErrScope
	}
	scope := scheduleScope(sc.Report, by.Scope)
	if err := s.checkChannel(ctx, sc.ChannelID); err != nil {
		return Schedule{}, err
	}
	if err := s.checkRecipients(ctx, sc.RecipientUserIDs, scope); err != nil {
		return Schedule{}, err
	}
	loc, err := s.o.Location(ctx)
	if err != nil {
		return Schedule{}, err
	}
	return s.o.Store.UpdateSchedule(ctx, id, func(old Schedule) (Schedule, audit.Entry, error) {
		if in.Version != old.Version {
			return Schedule{}, audit.Entry{}, ErrVersionConflict
		}
		n := old
		n.Name, n.Report, n.Frequency, n.Weekday, n.Day, n.At = sc.Name, sc.Report, sc.Frequency, sc.Weekday, sc.Day, sc.At
		n.Format, n.Applies, n.ChannelID, n.Enabled, n.Scope = sc.Format, sc.Applies, sc.ChannelID, sc.Enabled, scope
		n.RecipientUserIDs = sc.RecipientUserIDs
		n.Version, n.UpdatedAt, n.UpdatedBy = old.Version+1, s.now(), by.ref()
		next, err := n.Next(s.now(), loc)
		if err != nil {
			return Schedule{}, audit.Entry{}, err
		}
		n.NextRunAt = next
		return n, s.entry(by, "report_schedule.update", id, map[string]any{"before": view(old), "after": view(n)}), nil
	})
}

// DeleteSchedule удаляет расписание вместе с журналом рассылки.
func (s *Service) DeleteSchedule(ctx context.Context, by By, id string) error {
	return s.o.Store.DeleteSchedule(ctx, id, func(old Schedule) audit.Entry {
		return s.entry(by, "report_schedule.delete", id, view(old))
	})
}

// systemActor — субъект записей рассылки: свой на каждое расписание, чтобы
// правило DM-41 считало выгрузки по расписаниям отдельно.
func systemActor(scheduleID string) audit.Actor {
	return audit.Actor{Type: audit.ActorSystem, ID: "report-schedule:" + scheduleID, Name: "report-schedule"}
}

// Tick ставит в очередь рассылки расписаний, срок которых наступил, и
// выполняет запуски, срок которых наступил. Пропущенные после простоя
// запуски сводятся к одному догоняющему.
func (s *Service) Tick(ctx context.Context) error {
	loc, err := s.o.Location(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	if _, err := s.o.Store.EnqueueDue(ctx, now, enqueueBatch, func(sc Schedule) (Run, time.Time, error) {
		due, err := sc.Latest(sc.NextRunAt, now, loc)
		if err != nil {
			return Run{}, time.Time{}, err
		}
		next, err := sc.Next(now, loc)
		if err != nil {
			return Run{}, time.Time{}, err
		}
		id, err := s.o.IDs.New()
		if err != nil {
			return Run{}, time.Time{}, err
		}
		first, last := sc.PeriodDays(due, loc)
		return Run{ID: id.String(), OrgID: s.o.OrgID, ScheduleID: sc.ID, DueAt: due, PeriodFirst: first, PeriodLast: last,
			Status: RunPending, NextAt: now, CreatedAt: now, UpdatedAt: now}, next, nil
	}); err != nil {
		return err
	}
	if err := s.prune(ctx, now); err != nil {
		return err
	}
	for n := 0; n < enqueueBatch; n++ {
		r, sc, ok, err := s.o.Store.ClaimRun(ctx, s.now(), runLease)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if err := s.deliver(ctx, r, sc, loc); err != nil {
			return err
		}
	}
	return nil
}

// prune раз в pruneEvery удаляет завершённые запуски старше RunRetention
// (3Н47 ревью 3.r4: журнал рассылки не растёт бесконечно).
func (s *Service) prune(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	due := now.Sub(s.prunedAt) >= pruneEvery
	if due {
		s.prunedAt = now
	}
	s.mu.Unlock()
	if !due {
		return nil
	}
	_, err := s.o.Store.PruneRuns(ctx, now.Add(-RunRetention))
	return err
}

// Run выполняет Tick каждые interval до отмены ctx.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = TickInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			s.o.Logger.Error("рассылка отчётов: сбой опроса", "class", "reports", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) deliver(ctx context.Context, r Run, sc Schedule, loc *time.Location) error {
	if !sc.Enabled {
		r.Status, r.Error, r.UpdatedAt = RunFailed, ErrCodeDisabled, s.now()
		return s.o.Store.FinishRun(ctx, r, nil)
	}
	actor := systemActor(sc.ID)
	code := ""
	if r.Error == ErrCodeExhausted {
		// Попытки израсходованы прерванными отправками (падение сервера).
		code = ErrCodeExhausted
	} else {
		code = s.send(ctx, &r, sc, loc)
		if ctx.Err() != nil {
			// Остановка сервера: повтор после lease, попытка уже засчитана.
			return ctx.Err()
		}
	}
	now := s.now()
	r.UpdatedAt = now
	if code == "" {
		r.Status, r.Error, r.SentAt = RunSent, "", now
		return s.o.Store.FinishRun(ctx, r, nil)
	}
	r.Error = code
	if r.Attempts < MaxAttempts && code != ErrCodePeriod && code != ErrCodeRender {
		r.NextAt = now.Add(notify.Backoff(r.Attempts))
		return s.o.Store.FinishRun(ctx, r, nil)
	}
	r.Status = RunFailed
	rec := audit.Entry{OrgID: s.o.OrgID, Actor: actor, Action: "report.delivery_failed", Object: audit.Object{Type: "report_schedule", ID: sc.ID},
		Result: audit.ResultFailure, Details: map[string]any{"schedule_name": sc.Name, "report": sc.Report, "channel_id": sc.ChannelID,
			"run_id": r.ID, "attempts": r.Attempts, "error": code}}
	return s.o.Store.FinishRun(ctx, r, &rec)
}

// userRecipients возвращает адреса получателей-пользователей расписания и
// идентификаторы пропущенных: без адреса, деактивированных и без права на
// отчёты (роль могла измениться после сохранения расписания). Адреса в
// журналы не попадают: возвращаются только отправке письма.
func (s *Service) userRecipients(ctx context.Context, sc Schedule) (emails, skipped []string, err error) {
	skipped = []string{}
	if len(sc.RecipientUserIDs) == 0 {
		return nil, skipped, nil
	}
	if s.o.Directory == nil {
		return nil, append(skipped, sc.RecipientUserIDs...), nil
	}
	for _, id := range sc.RecipientUserIDs {
		r, err := s.o.Directory.Recipient(ctx, id)
		switch {
		case errors.Is(err, ErrRecipientNotFound):
			skipped = append(skipped, id)
		case err != nil:
			return nil, nil, err
		case !r.Eligible(sc.Scope) || r.Email == "":
			skipped = append(skipped, id)
		default:
			emails = append(emails, r.Email)
		}
	}
	return emails, skipped, nil
}

// send строит отчёт, пишет data.export и отправляет письмо; возвращает код
// ошибки (пусто — отправлено). Запись аудита — до отправки и отдельной
// транзакцией (3В32 ревью 3.r4): без записи письмо не уходит, как и
// выгрузка по запросу. Адреса получателей в записи — те, по которым уходит
// именно это письмо (3Н47 ревью 3.r4): запись делается из ReportMail.Before.
func (s *Service) send(ctx context.Context, r *Run, sc Schedule, loc *time.Location) string {
	per, err := NewPeriod(r.PeriodFirst, r.PeriodLast, loc, s.now())
	if err != nil {
		return ErrCodePeriod
	}
	bctx, cancel := context.WithTimeout(ctx, buildTimeout)
	defer cancel()
	doc, err := s.o.Builder.Build(bctx, Params{Kind: sc.Report, Format: sc.Format, Period: per, Applies: sc.Applies}, sc.Scope)
	if err != nil {
		s.o.Logger.Error("рассылка отчётов: отчёт не построен", "class", "reports", "schedule", sc.ID, "error", err)
		return ErrCodeBuild
	}
	var buf bytes.Buffer
	if err := Render(&buf, doc, sc.Format, events.DelimSemicolon); err != nil || buf.Len() > notify.MaxReportAttachment {
		return ErrCodeRender
	}
	if s.o.Mailer == nil {
		return ErrCodeChannel
	}
	extra, skipped, err := s.userRecipients(ctx, sc)
	if err != nil {
		s.o.Logger.Error("рассылка отчётов: справочник получателей недоступен", "class", "reports", "schedule", sc.ID, "error", err)
		return notify.ErrCodeInternal
	}
	r.SkippedNoEmail = len(skipped)
	details := map[string]any{"report": sc.Report, "format": sc.Format, "from": r.PeriodFirst,
		"to": r.PeriodLast, "rows": doc.Rows(), "channel_id": sc.ChannelID, "run_id": r.ID, "attempt": r.Attempts, "scheduled": true,
		"user_recipients": len(extra), "skipped_users": skipped}
	if sc.Report == KindCompliance {
		details["applies"] = sc.Applies // 5Н8 ревью 5.r1: от неё зависят состав и процент
	}
	rec := audit.Entry{OrgID: s.o.OrgID, Actor: systemActor(sc.ID), Action: "data.export", Object: audit.Object{Type: "report_schedule", ID: sc.ID},
		Result: audit.ResultSuccess, Details: details}
	var auditErr error
	mail := notify.ReportMail{ID: r.ID, Subject: "[AISec] " + Title(sc.Report) + ": " + per.Label(),
		Body: fmt.Sprintf("%s за период %s.\n\nОтчёт во вложении. Расписание: %s.\nСформирован платформой AISec; содержимого запросов и ответов в отчёте нет.",
			Title(sc.Report), per.Label(), sc.Name),
		Filename: fmt.Sprintf("aisec-%s-%s_%s.%s", sc.Report, per.First, per.Last, sc.Format), ContentType: ContentType(sc.Format), Data: buf.Bytes(),
		ExtraTo: extra,
		Before: func(to []string) error {
			details["recipients"] = to
			auditErr = s.o.Store.Record(ctx, rec)
			return auditErr
		},
		// Адрес пользователя, отклонённый сервером SMTP, не срывает
		// рассылку остальным и считается пропущенным (ревью 4.r1, 4В13).
		Rejected: func(n int) { r.SkippedNoEmail += n }}
	if err := s.o.Mailer.SendReport(ctx, sc.ChannelID, mail); err != nil {
		if auditErr != nil {
			s.o.Logger.Error("рассылка отчётов: выгрузка не записана в журнал аудита, письмо не отправлено", "class", "reports",
				"schedule", sc.ID, "error", auditErr)
			return ErrCodeAudit
		}
		if errors.Is(err, notify.ErrNotFound) {
			return ErrCodeChannel
		}
		code := notify.ErrorCode(err)
		if len(code) > 40 || code == "" {
			code = notify.ErrCodeInternal
		}
		return code
	}
	return ""
}
