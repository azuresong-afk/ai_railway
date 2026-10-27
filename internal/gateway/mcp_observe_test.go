package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// Отправка увиденных описаний на сервер: не чаще ObserveInterval на
// MCP-сервер, отправленные хеши не повторяются, 429 возвращает описания в
// очередь, прочие отказы — отбрасывают.
func TestToolObserverBatching(t *testing.T) {
	var mu sync.Mutex
	var got []observeBody
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/agents/tools:observe" {
			http.NotFound(w, r)
			return
		}
		var b observeBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Errorf("тело: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		got = append(got, b)
		w.Header().Set("Content-Type", "application/json")
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "30")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	o := NewToolObserver(srv.Client(), u, quiet())
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	o.now = func() time.Time { return now }
	ctx := context.Background()
	tool := func(h string) ObservedTool {
		return ObservedTool{Descriptor: []byte(`{"name":"` + h + `"}`), Hash: h}
	}

	o.Observe("files", []ObservedTool{tool("a"), tool("b"), tool("a")})
	o.flush(ctx)
	if len(got) != 1 || got[0].Server != "files" || len(got[0].Tools) != 2 {
		t.Fatalf("первое сообщение: %+v", got)
	}
	// Отправленные хеши не повторяются; новый ждёт срока.
	o.Observe("files", []ObservedTool{tool("a"), tool("c")})
	o.flush(ctx)
	if len(got) != 1 {
		t.Fatalf("раньше срока: %d", len(got))
	}
	now = now.Add(ObserveInterval)
	o.flush(ctx)
	if len(got) != 2 || len(got[1].Tools) != 1 || string(got[1].Tools[0].Descriptor) != `{"name":"c"}` {
		t.Fatalf("второе сообщение: %+v", got)
	}
	// 429 — повтор после Retry-After.
	status = http.StatusTooManyRequests
	now = now.Add(ObserveInterval)
	o.Observe("files", []ObservedTool{tool("d")})
	o.flush(ctx)
	status = http.StatusOK
	now = now.Add(ObserveInterval)
	o.flush(ctx)
	if len(got) != 3 {
		t.Fatalf("повтор раньше Retry-After: %d", len(got))
	}
	now = now.Add(30 * time.Second)
	o.flush(ctx)
	if len(got) != 4 || got[3].Tools[0].Descriptor == nil {
		t.Fatalf("повтор после 429: %+v", got)
	}
	// Отказ 400 — описания отбрасываются.
	status = http.StatusBadRequest
	now = now.Add(ObserveInterval)
	o.Observe("files", []ObservedTool{tool("e")})
	o.flush(ctx)
	status = http.StatusOK
	now = now.Add(time.Hour)
	o.flush(ctx)
	if len(got) != 5 {
		t.Fatalf("после отказа 400: %d", len(got))
	}
	// Без сервера управления — ничего не происходит.
	var none *ToolObserver
	none.Observe("files", []ObservedTool{tool("x")})
	none.Run(ctx)
}

// Предел ждущих описаний на сервер — MaxObserveBatch.
func TestToolObserverPendingLimit(t *testing.T) {
	u, _ := url.Parse("https://127.0.0.1:1")
	o := NewToolObserver(http.DefaultClient, u, quiet())
	tools := make([]ObservedTool, MaxObserveBatch+10)
	for i := range tools {
		tools[i] = ObservedTool{Descriptor: []byte(`{}`), Hash: string(rune('a'+i%26)) + time.Duration(i).String()}
	}
	o.Observe("files", tools)
	if n := len(o.pending["files"]); n != MaxObserveBatch {
		t.Fatalf("ждущих: %d", n)
	}
}
