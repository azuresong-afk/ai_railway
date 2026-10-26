package api

import (
	"context"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/incidents"
)

// Сроки хранения в памяти: значение и записи аудита изменений.
type memIncidentRetention struct {
	days int
	recs []audit.Entry
}

func (m *memIncidentRetention) RetentionDays(context.Context, string) (int, error) {
	return m.days, nil
}

func (m *memIncidentRetention) SetRetentionDays(_ context.Context, _ string, days int, fn func(int) (audit.Entry, error)) (int, error) {
	rec, err := fn(m.days)
	if err != nil {
		return 0, err
	}
	old := m.days
	m.days, m.recs = days, append(m.recs, rec)
	return old, nil
}

func (m *memIncidentRetention) PurgeExpired(context.Context, string) (int, error) { return 0, nil }

type memAlertRetention struct {
	days int
	recs []audit.Entry
}

func (m *memAlertRetention) RetentionDays(context.Context) (int, error) { return m.days, nil }

func (m *memAlertRetention) SetRetentionDays(_ context.Context, days int, fn func(int) (audit.Entry, error)) (int, error) {
	rec, err := fn(m.days)
	if err != nil {
		return 0, err
	}
	old := m.days
	m.days, m.recs = days, append(m.recs, rec)
	return old, nil
}

func (m *memAlertRetention) PurgeExpired(context.Context) (int, error) { return 0, nil }

// 3Н37 ревью 3.r2: срок хранения закрытых инцидентов (3 года по умолчанию)
// читают с incidents.read, меняет incident_categories.manage; сокращение —
// с текущим паролем (без него — 400 с полем password, как ждёт консоль),
// неверный — 403 reauthentication_failed; в аудите — weakening (DM-40).
func TestIncidentSettingsViaAPI(t *testing.T) {
	e := newIncidentsEnv(t)
	admin := e.mustLogin(t, "admin")
	analyst := e.mustLogin(t, "analyst")
	auditor := e.mustLogin(t, "auditor")
	owner := e.mustLogin(t, "owner")
	sys := e.mustLogin(t, "sysadm")
	const path = "/api/v1/incident-settings"

	for _, s := range []session{owner, sys} {
		mustProblem(t, e.call(s, "GET", path, "", false), 403, CodeForbidden)
	}
	for _, s := range []session{analyst, auditor, owner, sys} {
		mustProblem(t, e.call(s, "PUT", path, `{"retention_days":1500}`, true), 403, CodeForbidden)
	}
	w := e.call(auditor, "GET", path, "", false)
	if got := decode[incidents.RetentionSettings](t, w.Body.Bytes()); w.Code != 200 || got.RetentionDays != 1095 {
		t.Fatalf("срок по умолчанию: %d %s", w.Code, w.Body)
	}
	for _, b := range []string{`{"retention_days":364}`, `{"retention_days":1826}`, `{"retention_days":"x"}`, `{"retention_days":1500,"x":1}`} {
		mustProblem(t, e.call(admin, "PUT", path, b, true), 400, CodeInvalidRequest)
	}
	// Увеличение — без повторной проверки.
	if w := e.call(admin, "PUT", path, `{"retention_days":1500}`, true); w.Code != 200 {
		t.Fatalf("увеличение: %d %s", w.Code, w.Body)
	}
	// Сокращение без пароля — 400 с полем password; неверный пароль — 403.
	w = e.call(admin, "PUT", path, `{"retention_days":400}`, true)
	mustProblem(t, w, 400, CodeInvalidRequest)
	if p := decode[Problem](t, w.Body.Bytes()); len(p.Errors) != 1 || p.Errors[0].Field != "password" {
		t.Fatalf("поле ошибки: %s", w.Body)
	}
	mustProblem(t, e.call(admin, "PUT", path, `{"retention_days":400,"password":"не тот пароль"}`, true), 403, CodeReauthFailed)
	if e.incRetention.days != 1500 {
		t.Fatalf("срок сокращён без проверки: %d", e.incRetention.days)
	}
	if w := e.call(admin, "PUT", path, `{"retention_days":400,"password":"`+tPhrase+`"}`, true); w.Code != 200 {
		t.Fatalf("сокращение: %d %s", w.Code, w.Body)
	}
	recs := e.incRetention.recs
	if len(recs) != 2 || recs[1].Action != "incident.settings_changed" || recs[1].Details.(map[string]any)["weakening"] != true ||
		recs[0].Details.(map[string]any)["weakening"] != false {
		t.Fatalf("аудит: %+v", recs)
	}
}

// 3Н37 ревью 3.r2: сокращение срока хранения оповещений без пароля — 400 с
// полем password (так обещает openapi.yaml и ждёт консоль), не 403.
func TestAlertSettingsReduceWithoutPassword(t *testing.T) {
	e := newIncidentsEnv(t)
	admin := e.mustLogin(t, "admin")
	const path = "/api/v1/alert-settings"
	w := e.call(admin, "PUT", path, `{"retention_days":120}`, true)
	mustProblem(t, w, 400, CodeInvalidRequest)
	if p := decode[Problem](t, w.Body.Bytes()); len(p.Errors) != 1 || p.Errors[0].Field != "password" {
		t.Fatalf("поле ошибки: %s", w.Body)
	}
	if e.alertRetention.days != 365 || len(e.alertRetention.recs) != 0 {
		t.Fatalf("срок сокращён без проверки: %d", e.alertRetention.days)
	}
	if w := e.call(admin, "PUT", path, `{"retention_days":120,"password":"`+tPhrase+`"}`, true); w.Code != 200 || e.alertRetention.days != 120 {
		t.Fatalf("сокращение: %d %s", w.Code, w.Body)
	}
}
