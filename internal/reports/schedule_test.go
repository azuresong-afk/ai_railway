package reports

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func utc(y int, m time.Month, d, h, mi int) time.Time {
	return time.Date(y, m, d, h, mi, 0, 0, time.UTC)
}

func TestScheduleNextDailyAndWeekly(t *testing.T) {
	msk := mustLoc(t, "Europe/Moscow")
	daily := Schedule{Frequency: FreqDaily, At: "08:30"}
	// 08:30 МСК = 05:30 UTC. После запуска — завтра.
	n, err := daily.Next(utc(2026, 10, 25, 4, 0), msk)
	if err != nil || !n.Equal(utc(2026, 10, 25, 5, 30)) {
		t.Fatalf("сегодня: %v %v", n, err)
	}
	if n, _ = daily.Next(utc(2026, 10, 25, 5, 30), msk); !n.Equal(utc(2026, 10, 26, 5, 30)) { //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
		t.Errorf("строго после: %v", n)
	}
	// Еженедельно, понедельник; 25.10.2026 — воскресенье.
	weekly := Schedule{Frequency: FreqWeekly, Weekday: 1, At: "00:00"}
	if n, _ = weekly.Next(utc(2026, 10, 25, 5, 0), msk); !n.Equal(utc(2026, 10, 25, 21, 0)) { //nolint:gosec // G104: ошибка проверена выше или не важна для проверки (26.10 00:00 МСК)
		t.Errorf("понедельник: %v", n)
	}
	sunday := Schedule{Frequency: FreqWeekly, Weekday: 7, At: "23:59"}
	if n, _ = sunday.Next(utc(2026, 10, 25, 5, 0), msk); !n.Equal(utc(2026, 10, 25, 20, 59)) { //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
		t.Errorf("воскресенье: %v", n)
	}
}

// Переход месяца и года: день 28 и последний день года.
func TestScheduleNextMonthly(t *testing.T) {
	msk := mustLoc(t, "Europe/Moscow")
	m := Schedule{Frequency: FreqMonthly, Day: 1, At: "03:00"}
	if n, _ := m.Next(utc(2026, 12, 31, 23, 0), msk); !n.Equal(utc(2027, 1, 1, 0, 0)) { //nolint:gosec // G104: ошибка проверена выше или не важна для проверки (01.01 03:00 МСК)
		t.Errorf("через год: %v", n)
	}
	m28 := Schedule{Frequency: FreqMonthly, Day: 28, At: "12:00"}
	n, _ := m28.Next(utc(2026, 2, 28, 10, 0), msk) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки (28.02 13:00 МСК уже прошло? 10:00 UTC = 13:00 МСК > 12:00)
	if !n.Equal(utc(2026, 3, 28, 9, 0)) {
		t.Errorf("февраль: %v", n)
	}
	// Периоды: ежемесячно в январе — прошлый декабрь; через границу года.
	first, last := m.PeriodDays(utc(2027, 1, 1, 0, 0), msk)
	if first != "2026-12-01" || last != "2026-12-31" {
		t.Errorf("прошлый месяц: %s %s", first, last)
	}
	if f, l := m28.PeriodDays(utc(2026, 3, 28, 9, 0), msk); f != "2026-02-01" || l != "2026-02-28" {
		t.Errorf("февраль: %s %s", f, l)
	}
}

func TestSchedulePeriodDays(t *testing.T) {
	msk := mustLoc(t, "Europe/Moscow")
	d := Schedule{Frequency: FreqDaily}
	// Запуск 01.03 00:30 МСК — отчёт за 28.02 (пояс установки, не UTC).
	if f, l := d.PeriodDays(utc(2026, 2, 28, 21, 30), msk); f != "2026-02-28" || l != "2026-02-28" {
		t.Errorf("сутки: %s %s", f, l)
	}
	w := Schedule{Frequency: FreqWeekly}
	// Запуск в среду 21.10.2026 — прошлая неделя 12–18.10; в понедельник 26.10 — 19–25.10.
	if f, l := w.PeriodDays(utc(2026, 10, 21, 5, 0), msk); f != "2026-10-12" || l != "2026-10-18" {
		t.Errorf("неделя (среда): %s %s", f, l)
	}
	if f, l := w.PeriodDays(utc(2026, 10, 26, 5, 0), msk); f != "2026-10-19" || l != "2026-10-25" {
		t.Errorf("неделя (понедельник): %s %s", f, l)
	}
	// Воскресенье относится к той же неделе, что и понедельник перед ним.
	if f, l := w.PeriodDays(utc(2026, 10, 25, 5, 0), msk); f != "2026-10-12" || l != "2026-10-18" {
		t.Errorf("неделя (воскресенье): %s %s", f, l)
	}
}

// Перевод часов: запуск ровно один раз в сутки, без пропуска и дубля.
func TestScheduleDST(t *testing.T) {
	ber := mustLoc(t, "Europe/Berlin")
	s := Schedule{Frequency: FreqDaily, At: "02:30"}
	// Весна: 02:30 29.03.2026 не существует — запуск в тот же день на час позже по часам (03:30).
	n, err := s.Next(utc(2026, 3, 28, 12, 0), ber)
	if err != nil || n.In(ber).Format("2006-01-02") != "2026-03-29" {
		t.Fatalf("весна: %v %v", n, err)
	}
	n2, _ := s.Next(n, ber) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	if n2.In(ber).Format("2006-01-02 15:04") != "2026-03-30 02:30" {
		t.Errorf("после весны: %v", n2.In(ber))
	}
	// Осень: 02:30 встречается дважды — берётся первое, второе не запускает.
	a, _ := s.Next(utc(2026, 10, 24, 12, 0), ber) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	if a.In(ber).Format("2006-01-02") != "2026-10-25" {
		t.Fatalf("осень: %v", a.In(ber))
	}
	b, _ := s.Next(a, ber) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
	if b.In(ber).Format("2006-01-02 15:04") != "2026-10-26 02:30" {
		t.Errorf("после осени: %v", b.In(ber))
	}
	if cnt := 0; true {
		cur := utc(2026, 10, 20, 0, 0)
		for {
			cur, _ = s.Next(cur, ber) //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
			if !cur.Before(utc(2026, 11, 3, 0, 0)) {
				break
			}
			cnt++
		}
		if cnt != 14 {
			t.Errorf("запусков за 14 суток с переходом: %d", cnt)
		}
	}
}

// Простой: пропущенные запуски сводятся к одному — последнему, а период —
// к периоду этого запуска.
func TestScheduleLatestCatchUp(t *testing.T) {
	msk := mustLoc(t, "Europe/Moscow")
	s := Schedule{Frequency: FreqDaily, At: "08:00"}
	next := utc(2026, 10, 10, 5, 0)
	now := utc(2026, 10, 25, 9, 0)
	due, err := s.Latest(next, now, msk)
	if err != nil || !due.Equal(utc(2026, 10, 25, 5, 0)) {
		t.Fatalf("догоняющий запуск: %v %v", due, err)
	}
	if f, l := s.PeriodDays(due, msk); f != "2026-10-24" || l != "2026-10-24" {
		t.Errorf("период догоняющего: %s %s", f, l)
	}
	// Срок только наступил: запуск — сам next.
	if due, _ = s.Latest(utc(2026, 10, 25, 5, 0), utc(2026, 10, 25, 5, 0), msk); !due.Equal(utc(2026, 10, 25, 5, 0)) { //nolint:gosec // G104: ошибка проверена выше или не важна для проверки
		t.Errorf("наступивший срок: %v", due)
	}
}

func TestScheduleValidate(t *testing.T) {
	ch := "01900000-0000-7000-8000-0000000000aa"
	ok := ScheduleInput{Name: " Еженедельный ", Report: KindSummary, Frequency: FreqWeekly, Weekday: 1, At: "08:30", Format: FormatXLSX, ChannelID: ch}
	s, err := ok.Validate()
	if err != nil || s.Name != "Еженедельный" || !s.Enabled || s.Weekday != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	cases := map[string]func(*ScheduleInput){
		"name":       func(i *ScheduleInput) { i.Name = "" },
		"report":     func(i *ScheduleInput) { i.Report = "all" },
		"frequency":  func(i *ScheduleInput) { i.Frequency = "hourly" },
		"weekday":    func(i *ScheduleInput) { i.Weekday = 8 },
		"at":         func(i *ScheduleInput) { i.At = "24:00" },
		"format":     func(i *ScheduleInput) { i.Format = FormatCSV },
		"channel_id": func(i *ScheduleInput) { i.ChannelID = "x" },
		// Применимость — только у отчёта соответствия и из набора (5.12).
		"applies": func(i *ScheduleInput) { i.Applies = "gis" },
	}
	for field, mut := range cases {
		in := ok
		mut(&in)
		_, err := in.Validate()
		var ie *InputError
		if !errors.As(err, &ie) || ie.Fields[field] == "" {
			t.Errorf("%s: %v", field, err)
		}
	}
	// 5Н8 ревью 5.r1: в тексте ошибки — все виды отчётов, и compliance.
	in := ok
	in.Report = "all"
	if _, err := in.Validate(); !strings.Contains(fieldsOf(err)["report"], KindCompliance) {
		t.Errorf("текст ошибки вида отчёта: %v", err)
	}
	in = ok
	in.Report, in.Applies = KindCompliance, "commercial"
	if s, err := in.Validate(); err != nil || s.Applies != "commercial" {
		t.Fatalf("применимость отчёта соответствия: %+v %v", s, err)
	}
	in.Applies = "private"
	if _, err := in.Validate(); err == nil {
		t.Error("неизвестная применимость принята")
	}
	// День месяца только 1–28; лишние поля чужой периодичности отклоняются.
	for _, in := range []ScheduleInput{
		{Name: "a", Report: KindPilot, Frequency: FreqMonthly, Day: 29, At: "08:00", Format: FormatHTML, ChannelID: ch},
		{Name: "a", Report: KindPilot, Frequency: FreqMonthly, Day: 3, Weekday: 2, At: "08:00", Format: FormatHTML, ChannelID: ch},
		{Name: "a", Report: KindPilot, Frequency: FreqDaily, Day: 3, At: "08:00", Format: FormatHTML, ChannelID: ch},
		{Name: "a\nb", Report: KindPilot, Frequency: FreqDaily, At: "08:00", Format: FormatHTML, ChannelID: ch},
		{Name: strings.Repeat("я", 201), Report: KindPilot, Frequency: FreqDaily, At: "08:00", Format: FormatHTML, ChannelID: ch},
	} {
		if _, err := in.Validate(); err == nil {
			t.Errorf("принято %+v", in)
		}
	}
}

func FuzzScheduleNext(f *testing.F) {
	f.Add("08:30", 1, 0, int64(1_800_000_000))
	f.Add("99:99", 9, 40, int64(0))
	f.Fuzz(func(t *testing.T, at string, wd, day int, sec int64) {
		for _, fr := range []string{FreqDaily, FreqWeekly, FreqMonthly} {
			in := ScheduleInput{Name: "n", Report: KindPilot, Frequency: fr, Weekday: wd, Day: day, At: at, Format: FormatHTML,
				ChannelID: "01900000-0000-7000-8000-0000000000aa"}
			s, err := in.Validate()
			if err != nil {
				continue
			}
			after := time.Unix(sec%4_000_000_000, 0).UTC()
			for _, loc := range []*time.Location{time.UTC, time.FixedZone("x", 3*3600)} {
				n, err := s.Next(after, loc)
				if err != nil || !n.After(after) || n.Sub(after) > 32*24*time.Hour+2*time.Hour {
					t.Fatalf("%+v после %v: %v %v", s, after, n, err)
				}
			}
		}
	})
}

// fieldsOf — поля ошибки проверки (*InputError).
func fieldsOf(err error) map[string]string {
	var ie *InputError
	if errors.As(err, &ie) {
		return ie.Fields
	}
	return nil
}
