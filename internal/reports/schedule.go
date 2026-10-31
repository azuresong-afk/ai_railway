package reports

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Расписания (Р6): ежедневно, еженедельно, ежемесячно; время — в часовом
// поясе установки. Cron-выражений нет: меньше разбора недоверенного ввода.

// Периодичность.
const (
	FreqDaily   = "daily"
	FreqWeekly  = "weekly"
	FreqMonthly = "monthly"
)

// Пределы расписаний.
const (
	MaxScheduleName = 200
	// MaxSchedules — расписаний в установке.
	MaxSchedules = 50
	// MaxMonthDay — наибольший день месяца: 29–31 есть не в каждом месяце.
	MaxMonthDay = 28
	// MaxUserRecipients — получателей-пользователей у одного расписания.
	MaxUserRecipients = 20
)

// Schedule — расписание рассылки отчёта.
type Schedule struct {
	ID        string
	OrgID     string
	Name      string
	Report    string // вид отчёта
	Frequency string
	// Weekday — день недели для FreqWeekly: 1 — понедельник … 7 — воскресенье (ISO 8601).
	Weekday int
	// Day — день месяца для FreqMonthly, 1..MaxMonthDay.
	Day int
	// At — время суток «ЧЧ:ММ» в часовом поясе установки.
	At     string
	Format string // html или xlsx
	// Applies — применимость требований для отчёта соответствия (задача
	// 5.12 этапа 5); пусто — все пункты базы. У других видов всегда пусто.
	Applies string
	// ChannelID — почтовый канал: сервер SMTP и получатели.
	ChannelID string
	Enabled   bool
	// NextRunAt — ближайший запуск; LastRunAt — запуск, на который
	// поставлена последняя рассылка (пусто, если ещё не было).
	NextRunAt time.Time
	LastRunAt time.Time
	Version   int
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
	// Scope — разделы отчёта по правам автора последнего изменения (3В31
	// ревью 3.r4): получатели канала — адреса, а не пользователи с правами,
	// поэтому рассылка не шире прав того, кто её настроил.
	Scope Scope
	// RecipientUserIDs — получатели-пользователи консоли: адрес берётся из
	// учётной записи при отправке, в дополнение к адресам канала (задача 4.6).
	RecipientUserIDs []string
}

// ScheduleInput — расписание из запроса API (создание и полная замена).
type ScheduleInput struct {
	Name      string `json:"name"`
	Report    string `json:"report"`
	Frequency string `json:"frequency"`
	Weekday   int    `json:"weekday"`
	Day       int    `json:"day"`
	At        string `json:"at"`
	Format    string `json:"format"`
	// Applies — применимость для отчёта соответствия: gis, kii, ispdn,
	// commercial; пусто — все пункты.
	Applies   string `json:"applies"`
	ChannelID string `json:"channel_id"`
	Enabled   *bool  `json:"enabled"`
	// RecipientUserIDs — пользователи консоли, которым уходит отчёт
	// (необязательно, до MaxUserRecipients).
	RecipientUserIDs []string `json:"recipient_user_ids"`
	// Version — для изменения: версия, которую видел администратор.
	Version int `json:"version"`
}

// InputError — ошибки полей ввода.
type InputError struct{ Fields map[string]string }

func (e *InputError) Error() string {
	return "отчёты: ввод расписания неверен"
}

// Validate проверяет ввод и возвращает нормализованное расписание без
// служебных полей; имя канала проверяет сервис.
func (in ScheduleInput) Validate() (Schedule, error) {
	bad := map[string]string{}
	name := strings.TrimSpace(in.Name)
	switch {
	case name == "" || utf8.RuneCountInString(name) > MaxScheduleName:
		bad["name"] = fmt.Sprintf("Название — от 1 до %d знаков.", MaxScheduleName)
	case !plain(name):
		bad["name"] = "Название — обычный текст без управляющих знаков."
	}
	if !ValidKind(in.Report) {
		bad["report"] = "Одно из значений: summary, incidents, pilot."
	}
	switch {
	case !ValidApplies(in.Applies):
		bad["applies"] = "Одно из значений: gis, kii, ispdn, commercial — или пусто."
	case in.Applies != "" && in.Report != KindCompliance:
		bad["applies"] = "Применимость задаётся только для отчёта соответствия."
	}
	s := Schedule{Name: name, Report: in.Report, Frequency: in.Frequency, At: in.At, Format: in.Format, Applies: in.Applies, ChannelID: in.ChannelID}
	switch in.Frequency {
	case FreqDaily:
		if in.Weekday != 0 || in.Day != 0 {
			bad["frequency"] = "Для ежедневной рассылки день недели и день месяца не задаются."
		}
	case FreqWeekly:
		if in.Weekday < 1 || in.Weekday > 7 || in.Day != 0 {
			bad["weekday"] = "День недели — от 1 (понедельник) до 7 (воскресенье)."
		}
		s.Weekday = in.Weekday
	case FreqMonthly:
		if in.Day < 1 || in.Day > MaxMonthDay || in.Weekday != 0 {
			bad["day"] = fmt.Sprintf("День месяца — от 1 до %d.", MaxMonthDay)
		}
		s.Day = in.Day
	default:
		bad["frequency"] = "Одно из значений: daily, weekly, monthly."
	}
	if _, _, err := parseAt(in.At); err != nil {
		bad["at"] = "Время — ЧЧ:ММ, например 08:30."
	}
	if in.Format != FormatHTML && in.Format != FormatXLSX {
		bad["format"] = "Вложение — html или xlsx."
	}
	if !validUUID(in.ChannelID) {
		bad["channel_id"] = "Укажите почтовый канал."
	}
	s.Enabled = in.Enabled == nil || *in.Enabled
	if len(in.RecipientUserIDs) > MaxUserRecipients {
		bad["recipient_user_ids"] = fmt.Sprintf("Получателей-пользователей не больше %d.", MaxUserRecipients)
	} else {
		seen := map[string]bool{}
		s.RecipientUserIDs = []string{}
		for _, id := range in.RecipientUserIDs {
			switch {
			case !validUUID(id):
				bad["recipient_user_ids"] = "Получатель — идентификатор пользователя (UUID)."
			case seen[id]:
				bad["recipient_user_ids"] = "Получатели не должны повторяться."
			default:
				seen[id] = true
				s.RecipientUserIDs = append(s.RecipientUserIDs, id)
			}
		}
	}
	if len(bad) > 0 {
		return s, &InputError{Fields: bad}
	}
	return s, nil
}

func plain(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || r == 0xFFFD {
			return false
		}
	}
	return true
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

func parseAt(s string) (h, m int, err error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, errors.New("время")
	}
	for _, i := range []int{0, 1, 3, 4} {
		if s[i] < '0' || s[i] > '9' {
			return 0, 0, errors.New("время")
		}
	}
	h, m = int(s[0]-'0')*10+int(s[1]-'0'), int(s[3]-'0')*10+int(s[4]-'0')
	if h > 23 || m > 59 {
		return 0, 0, errors.New("время")
	}
	return h, m, nil
}

// isoWeekday — день недели по ISO 8601: понедельник 1 … воскресенье 7.
func isoWeekday(t time.Time) int {
	if w := int(t.Weekday()); w != 0 {
		return w
	}
	return 7
}

// Next — первый запуск расписания строго после after. Календарь — в поясе
// loc: сутки в день перевода часов не дублируются и не пропускаются. Время,
// которого в день перевода вперёд нет, сдвигается на час вперёд; в день
// перевода назад берётся первое вхождение.
func (s Schedule) Next(after time.Time, loc *time.Location) (time.Time, error) {
	h, m, err := parseAt(s.At)
	if err != nil {
		return time.Time{}, err
	}
	if loc == nil {
		loc = time.UTC
	}
	local := after.In(loc)
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC)
	for i := 0; i < 400; i++ {
		d := day.AddDate(0, 0, i)
		switch s.Frequency {
		case FreqDaily:
		case FreqWeekly:
			if isoWeekday(d) != s.Weekday {
				continue
			}
		case FreqMonthly:
			if d.Day() != s.Day {
				continue
			}
		default:
			return time.Time{}, errors.New("отчёты: периодичность")
		}
		t := time.Date(d.Year(), d.Month(), d.Day(), h, m, 0, 0, loc).UTC()
		if t.After(after) {
			return t, nil
		}
	}
	return time.Time{}, errors.New("отчёты: ближайший запуск не найден")
}

// Latest — последний запуск расписания, не позже now, начиная с from
// (запуск, срок которого наступил). Пропущенные после простоя запуски
// сводятся к одному — последнему (один догоняющий, не пачка).
func (s Schedule) Latest(from, now time.Time, loc *time.Location) (time.Time, error) {
	cur := from
	for i := 0; i < 1000; i++ {
		n, err := s.Next(cur, loc)
		if err != nil {
			return time.Time{}, err
		}
		if n.After(now) {
			return cur, nil
		}
		cur = n
	}
	return cur, nil
}

// PeriodDays — период отчёта запуска due: полные сутки (ежедневно), прошлая
// неделя с понедельника по воскресенье (еженедельно) или прошлый календарный
// месяц (ежемесячно); границы — в часовом поясе установки.
func (s Schedule) PeriodDays(due time.Time, loc *time.Location) (first, last string) {
	if loc == nil {
		loc = time.UTC
	}
	l := due.In(loc)
	d := time.Date(l.Year(), l.Month(), l.Day(), 0, 0, 0, 0, time.UTC)
	switch s.Frequency {
	case FreqWeekly:
		monday := d.AddDate(0, 0, 1-isoWeekday(d))
		return monday.AddDate(0, 0, -7).Format(dateLayout), monday.AddDate(0, 0, -1).Format(dateLayout)
	case FreqMonthly:
		first := time.Date(d.Year(), d.Month()-1, 1, 0, 0, 0, 0, time.UTC)
		return first.Format(dateLayout), time.Date(d.Year(), d.Month(), 0, 0, 0, 0, 0, time.UTC).Format(dateLayout)
	}
	y := d.AddDate(0, 0, -1).Format(dateLayout)
	return y, y
}
