package gateway_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/gateway"
)

// Heartbeat несёт итоги самотеста и целостности (задача 2.20); без итогов
// поля не отправляются — формат совместим с серверами и шлюзами прежних версий.
func TestHeartbeatSendsReports(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16)) //nolint:gosec // G104: тестовый сервер
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Errorf("тело heartbeat: %v", err)
		}
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"server_time": time.Now(), "interval_seconds": 30}) //nolint:gosec // G104: ответ тестового сервера
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	reports := &gateway.Reports{}
	ctx := context.Background()
	beats := 0
	gateway.RunHeartbeat(ctx, gateway.HeartbeatConfig{
		Client: srv.Client(), Server: u, Version: "1", Logger: quiet(), Reports: reports,
		Sleep: func(_ context.Context, _ time.Duration) bool {
			beats++
			switch beats {
			case 1: // после первого heartbeat итоги появляются
				at := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
				reports.SetSelftest(false, at, 2)
				reports.SetIntegrity(true, at, "ok", 0, gateway.Manifest{Version: "1.2.0", Created: at.Add(-time.Hour), TestSigned: true})
				reports.SetBundleKeys([]string{"0123456789abcdef"})
				return true
			}
			return false
		},
	})
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("heartbeat: %d", len(bodies))
	}
	if _, ok := bodies[0]["selftest"]; ok {
		t.Errorf("итог отправлен до его появления: %v", bodies[0])
	}
	st, _ := bodies[1]["selftest"].(map[string]any)
	in, _ := bodies[1]["integrity"].(map[string]any)
	if st["ok"] != false || st["failed"] != float64(2) || st["checked_at"] != "2026-10-21T10:00:00Z" ||
		in["ok"] != true || in["reason"] != "ok" || in["failed"] != float64(0) {
		t.Fatalf("итоги: %v", bodies[1])
	}
	// В20, Н34, В19 ревью 2.r4: манифест, тестовый ключ и ключи пакетов.
	keys, _ := bodies[1]["bundle_keys"].([]any)
	if in["manifest_version"] != "1.2.0" || in["manifest_created"] != "2026-10-21T09:00:00Z" || in["test_signed"] != true ||
		len(keys) != 1 || keys[0] != "0123456789abcdef" {
		t.Fatalf("манифест и ключи: %v", bodies[1])
	}
}
