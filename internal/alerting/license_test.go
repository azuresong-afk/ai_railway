package alerting

import (
	"context"
	"errors"
	"testing"
)

// DM-44 (оповещение, этап 4), ТЗ 5.15: условия лицензии «Состояния
// системы» поднимают системное правило system.license_expiry; за 30 и за 7
// суток — отдельные оповещения, стадия — в заголовке; правило не
// отключается; снятие условия оповещение не закрывает.
func TestDM44_LicenseExpiry(t *testing.T) {
	e := newEnv(t)
	r := e.rule(t, BuiltinLicenseExpiry)
	if !Locked(r.Kind) || !r.Enabled || r.Severity != "high" {
		t.Fatalf("правило: %+v", r)
	}
	off := false
	if _, err := e.svc.UpdateRule(context.Background(), e.admin, r.ID, RuleInput{Enabled: &off, Version: r.Version,
		Recipients: Recipients{Roles: []string{}, Users: []string{}}}); !errors.Is(err, ErrLocked) {
		t.Fatalf("отключение: %v", err)
	}

	e.systemAlert(t, "license_expiry", "raised", map[string]any{"requirement": "ЗИ.2", "number": 7, "days_left": 29})
	e.systemAlert(t, "license_expiry:critical", "raised", map[string]any{"requirement": "ЗИ.2", "number": 7, "days_left": 6})
	// Повтор того же условия — то же оповещение.
	e.systemAlert(t, "license_expiry", "cleared", nil)
	e.systemAlert(t, "license_expiry", "raised", map[string]any{"requirement": "ЗИ.2", "number": 7, "days_left": 29})
	got := e.alerts(t, BuiltinLicenseExpiry)
	titles := map[string]bool{}
	for _, a := range got {
		titles[a.Title] = true
		if a.Kind != KindSystem || a.Status != StatusNew {
			t.Fatalf("оповещение: %+v", a)
		}
	}
	if len(got) != 2 || !titles["Лицензия — осталось 29 сут."] || !titles["Лицензия — осталось 6 сут."] {
		t.Fatalf("за 30 и 7 суток: %+v", got)
	}

	for code, title := range map[string]string{
		"license_grace":      "Лицензия — льготный период",
		"license_restricted": "Лицензия — изменения конфигурации запрещены",
		"license_invalid":    "Лицензия — подпись не прошла проверку",
		"license_clock":      "Лицензия — часы сервера отстают",
	} {
		e.systemAlert(t, code, "raised", map[string]any{"requirement": "ЗИ.2"})
		found := false
		for _, a := range e.alerts(t, BuiltinLicenseExpiry) {
			if a.Title == title && a.Details["condition"] == code {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: %+v", code, e.alerts(t, BuiltinLicenseExpiry))
		}
	}
	if got := e.alerts(t, BuiltinLicenseExpiry); len(got) != 6 {
		t.Fatalf("оповещений: %d", len(got))
	}
}
