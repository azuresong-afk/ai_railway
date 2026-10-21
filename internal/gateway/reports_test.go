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
				reports.SetIntegrity(true, at, "ok", 0)
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
}
