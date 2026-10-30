package sysstatus_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/license"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
)

// DM-44, ТЗ 5.15 (задача 4.26, ADR-0026, п. 8): условия лицензии по стадиям
// срока на поддельных часах — за 30 и 7 суток, льготный период, запрет
// изменений; недействительная лицензия и отставшие часы — свои условия;
// сбой чтения не меняет состояние; новая лицензия снимает условия.
//
// Покрывает: DM-44 (лицензия)
func TestDM44_LicenseConditions(t *testing.T) {
	e := newEnv()
	o := e.opts()
	until := t0.Add(40 * 24 * time.Hour)
	signed := &license.Signed{License: &license.License{Number: 5, IssuedAt: t0.Add(-24 * time.Hour), ValidFrom: t0.Add(-24 * time.Hour),
		ValidUntil: until}}
	var (
		cur       = signed
		number    = uint64(5)
		highWater time.Time
		readErr   error
	)
	o.License = func(context.Context) (license.State, error) {
		return license.Evaluate(cur, number, e.clock, highWater), readErr
	}
	s, err := sysstatus.New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	states := func() []string {
		var out []string
		for _, r := range e.mem.Records {
			d := r.Details.(map[string]any)
			out = append(out, d["condition"].(string)+"="+d["state"].(string))
		}
		return out
	}
	step := func(at time.Time, want ...string) {
		t.Helper()
		e.clock = at
		before := len(states())
		for range 2 {
			if err := s.Evaluate(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if got := states()[before:]; !slices.Equal(got, want) {
			t.Fatalf("%s: %v, ожидалось %v", at.Format(time.DateOnly), got, want)
		}
	}
	step(t0)
	step(until.Add(-29*24*time.Hour), "license_expiry=raised")
	if n := notif(s.Status(ctx), sysstatus.ConditionLicenseExpiry); !n.Active || n.Requirement != "ЗИ.2" {
		t.Fatalf("строка состояния: %+v", n)
	}
	if d := e.mem.Records[0].Details.(map[string]any); d["days_left"] != 29 || d["number"] != uint64(5) || d["valid_until"] == nil ||
		d["license_state"] != license.PhaseExpiring {
		t.Fatalf("подробности: %v", d)
	}
	step(until.Add(-6*24*time.Hour), "license_expiry:critical=raised")
	step(until.Add(time.Hour), "license_expiry=cleared", "license_expiry:critical=cleared", "license_grace=raised")
	step(until.Add(31*24*time.Hour), "license_grace=cleared", "license_restricted=raised")

	// Сбой чтения — состояние не меняется.
	readErr = errors.New("нет связи с БД")
	step(until.Add(32 * 24 * time.Hour))
	readErr = nil

	// Часы сервера отстали от отметки: условие времени, стадия — по отметке.
	highWater = until.Add(32 * 24 * time.Hour)
	step(until.Add(-60*24*time.Hour), "license_clock=raised")

	// Лицензия не прошла повторную проверку.
	cur = nil
	step(highWater, "license_clock=cleared", "license_invalid=raised", "license_restricted=cleared")

	// Новая лицензия снимает условия.
	next := *signed.License
	next.Number, next.ValidUntil = 6, highWater.Add(365*24*time.Hour)
	cur, number = &license.Signed{License: &next}, 6
	step(highWater, "license_invalid=cleared")
	for _, r := range e.mem.Records {
		if err := validateEntry(r); err != nil {
			t.Error(err)
		}
	}
}
