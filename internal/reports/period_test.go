package reports

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func mustLoc(t testing.TB, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

var now2026 = time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)

func TestNewPeriod(t *testing.T) {
	msk := mustLoc(t, "Europe/Moscow")
	p, err := NewPeriod("2026-10-01", "2026-10-31", msk, now2026)
	if err != nil {
		t.Fatal(err)
	}
	// Конец позже сегодняшнего дня урезается до сегодняшнего (25.10 по Москве).
	if p.Last != "2026-10-25" || p.Days != 25 {
		t.Errorf("конец %s, суток %d", p.Last, p.Days)
	}
	if !p.From.Equal(time.Date(2026, 9, 30, 21, 0, 0, 0, time.UTC)) || !p.To.Equal(time.Date(2026, 10, 25, 21, 0, 0, 0, time.UTC)) {
		t.Errorf("границы UTC: %v — %v", p.From, p.To)
	}
	if p.Label() != "01.10.2026 — 25.10.2026" {
		t.Errorf("подпись %q", p.Label())
	}
	one, err := NewPeriod("2026-10-20", "2026-10-20", msk, now2026)
	if err != nil || one.Label() != "20.10.2026" || one.To.Sub(one.From) != 24*time.Hour {
		t.Errorf("один день: %+v %v", one, err)
	}
}

func TestNewPeriodLimits(t *testing.T) {
	msk := mustLoc(t, "Europe/Moscow")
	// 366 суток — можно, 367 — нет.
	if _, err := NewPeriod("2025-10-25", "2026-10-25", msk, now2026); err != nil {
		t.Errorf("366 суток: %v", err)
	}
	for _, c := range [][2]string{
		{"2025-10-24", "2026-10-25"}, // 367
		{"2026-10-26", "2026-10-27"}, // начало в будущем
		{"2026-10-10", "2026-10-09"}, // конец раньше начала
		{"2026-1-1", "2026-10-09"}, {"2026-13-01", "2026-12-01"}, {"2026-02-30", "2026-03-01"}, {"", ""},
		{"2026-10-01 ", "2026-10-02"}, {"２０２６-10-01", "2026-10-02"}, {"2026/10/01", "2026-10-02"},
	} {
		if _, err := NewPeriod(c[0], c[1], msk, now2026); !errors.Is(err, ErrPeriod) {
			t.Errorf("%v: %v", c, err)
		}
	}
}

// Сутки в день перевода часов: 23 и 25 часов, границы — по календарю пояса.
func TestPeriodDST(t *testing.T) {
	ber := mustLoc(t, "Europe/Berlin")
	now := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	spring, err := NewPeriod("2026-03-29", "2026-03-29", ber, now)
	if err != nil || spring.To.Sub(spring.From) != 23*time.Hour {
		t.Errorf("весна: %v %v", spring.To.Sub(spring.From), err)
	}
	fall, err := NewPeriod("2026-10-25", "2026-10-25", ber, now)
	if err != nil || fall.To.Sub(fall.From) != 25*time.Hour {
		t.Errorf("осень: %v %v", fall.To.Sub(fall.From), err)
	}
	// Год с переходом осенью и 366 днями не превышает предел часов дашбордов: отказ.
	if _, err := NewPeriod("2025-11-20", "2026-11-20", ber, now); err != nil && !errors.Is(err, ErrPeriod) {
		t.Errorf("год: %v", err)
	}
}

func TestParseParams(t *testing.T) {
	msk := mustLoc(t, "Europe/Moscow")
	q := func(s string) map[string][]string {
		v, err := url.ParseQuery(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	p, err := ParseParams(KindPilot, q("from=2026-10-01&to=2026-10-10&format=xlsx&app=crm-bot"), msk, now2026)
	if err != nil || p.Format != FormatXLSX || p.App != "crm-bot" || p.Kind != KindPilot {
		t.Fatalf("%+v %v", p, err)
	}
	if p, err = ParseParams(KindSummary, q("from=2026-10-01&to=2026-10-10"), msk, now2026); err != nil || p.Format != FormatHTML {
		t.Fatalf("формат по умолчанию: %+v %v", p, err)
	}
	for _, bad := range []string{
		"", "from=2026-10-01", "to=2026-10-01", "from=2026-10-01&to=2026-10-02&format=pdf", "from=2026-10-01&to=2026-10-02&x=1",
		"from=2026-10-01&from=2026-10-02&to=2026-10-03", "from=2026-10-01&to=2026-10-02&app=CRM", "from=2026-10-01&to=2026-10-02&app=" + strings.Repeat("a", 65),
		"from=2026-10-01&to=2026-10-02&app=a/b", "from=2026-10-01&to=2026-10-02&format=" + strings.Repeat("x", 200),
	} {
		if _, err := ParseParams(KindSummary, q(bad), msk, now2026); err == nil {
			t.Errorf("принято %q", bad)
		}
	}
	if _, err := ParseParams("other", q("from=2026-10-01&to=2026-10-02"), msk, now2026); err == nil {
		t.Error("неизвестный вид отчёта принят")
	}
}

func FuzzParseParams(f *testing.F) {
	f.Add("summary", "from", "2026-10-01", "to", "2026-10-31", "html")
	f.Add("pilot", "app", "x", "format", "\x00", "csv")
	f.Fuzz(func(t *testing.T, kind, k1, v1, k2, v2, format string) {
		loc := time.UTC
		q := map[string][]string{k1: {v1}, k2: {v2}, "format": {format}}
		p, err := ParseParams(kind, q, loc, now2026)
		if err != nil {
			return
		}
		if !ValidKind(p.Kind) || !ValidFormat(p.Format) {
			t.Fatalf("принят %+v", p)
		}
		if !p.Period.From.Before(p.Period.To) || p.Period.Days < 1 || p.Period.Days > MaxPeriodDays || p.Period.To.After(now2026.Add(25*time.Hour)) {
			t.Fatalf("период %+v", p.Period)
		}
		if p.App != "" && !ValidSlug(p.App) {
			t.Fatalf("приложение %q", p.App)
		}
	})
}

func FuzzParseDay(f *testing.F) {
	f.Add("2026-10-01")
	f.Add("0000-00-00")
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDay(s)
		if err == nil && d.Format(dateLayout) != s {
			t.Fatalf("%q → %v", s, d)
		}
	})
}
