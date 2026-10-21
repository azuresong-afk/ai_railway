package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
)

type fakeStatus struct{ st sysstatus.Status }

func (f fakeStatus) Status(context.Context) sysstatus.Status { return f.st }

func TestSystemStatus(t *testing.T) {
	at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	svc, err := sysstatus.New(sysstatus.Options{
		Version: "1.2.3", StartedAt: at, Clock: func() time.Time { return at },
		Sync: func() sysstatus.ClockState { return sysstatus.ClockState{Sync: sysstatus.SyncSynchronized} },
	})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := newHandler(t, Options{Status: svc, Authorizer: allowPerm{auth.PermSystemRead: true}})
	w := do(h, http.MethodGet, "/api/v1/system/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var got sysstatus.Status
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Server.Version != "1.2.3" || got.Time.Sync != sysstatus.SyncSynchronized || len(got.Notifications) != 6 {
		t.Fatalf("%+v", got)
	}
	// Пустые списки — массивы, не null: клиент консоли не проверяет на null.
	for _, f := range []string{`"gateways":[]`, `"unavailable":[]`, `"integrity":[]`} {
		if !strings.Contains(w.Body.String(), f) {
			t.Errorf("нет %s в %s", f, w.Body.String())
		}
	}
}

// Отказ в доступе: без права system.read — 403, без сессии — 401; без
// подключённого сбора — 503 (после проверки прав).
func TestSystemStatusDenied(t *testing.T) {
	st := fakeStatus{}
	h, _ := newHandler(t, Options{Status: st, Authorizer: allowPerm{}})
	mustProblem(t, do(h, http.MethodGet, "/api/v1/system/status", ""), http.StatusForbidden, CodeForbidden)
	h, _ = newHandler(t, Options{Status: st, Authorizer: DenyAll{}})
	mustProblem(t, do(h, http.MethodGet, "/api/v1/system/status", ""), http.StatusUnauthorized, CodeUnauthorized)
	h, _ = newHandler(t, Options{Authorizer: allowPerm{auth.PermSystemRead: true}})
	mustProblem(t, do(h, http.MethodGet, "/api/v1/system/status", ""), http.StatusServiceUnavailable, CodeUnavailable)
}

// Heartbeat с итогами самотеста и целостности шлюза (задача 2.20): итоги
// доходят до реестра; неверные — 400 Problem Details.
func TestHeartbeatReports(t *testing.T) {
	svc, gw := newGatewayEnv(t)
	h, _, err := NewInternal(InternalOptions{Logger: quiet(), Hasher: testHasher(t), Gateways: svc, Authorizer: asGateway(gw.ID),
		RateLimit: RateConfig{Rules: []RateRule{{Prefix: "/", Max: 0}}}})
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/internal/v1/heartbeat", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, bad := range []string{
		`{"version":"1","selftest":{"ok":true,"checked_at":"` + now + `","failed":5}}`,
		`{"version":"1","integrity":{"ok":false,"checked_at":"` + now + `","reason":"zzz","failed":1}}`,
		`{"version":"1","selftest":{"ok":true,"failed":0}}`,
		`{"version":"1","selftest":{"ok":true,"checked_at":"` + now + `","failed":0,"extra":1}}`,
		`{"version":"1","selftest":{"ok":true,"checked_at":"2999-01-01T00:00:00Z","failed":0}}`,
	} {
		mustProblem(t, post(bad), http.StatusBadRequest, CodeInvalidRequest)
	}
	good := `{"version":"1","selftest":{"ok":true,"checked_at":"` + now + `","failed":0},` +
		`"integrity":{"ok":false,"checked_at":"` + now + `","reason":"files_mismatch","failed":2}}`
	if w := post(good); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	list, err := svc.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	g := list[0]
	if g.Selftest == nil || !g.Selftest.OK || g.Integrity == nil || g.Integrity.Reason != "files_mismatch" || g.Integrity.Failed != 2 {
		t.Fatalf("%+v %+v", g.Selftest, g.Integrity)
	}
	// Совместимость: heartbeat прежнего шлюза без итогов принимается.
	if w := post(`{"version":"1"}`); w.Code != http.StatusOK && w.Code != http.StatusTooManyRequests {
		t.Fatalf("%d", w.Code)
	}
}
