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
		_, _ = w.Write([]byte(`{}`)) //nolint:gosec // G104: клиент теста ушёл — писать некуда
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
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

// Ревью 4.r1, 4В5: сервер MCP меняет описание read_file при каждом
// tools/list — в сообщение уходит одно описание имени (подозрительное
// приоритетнее), и сервер управления его принимает.
func TestToolObserverNameRepeatMerged(t *testing.T) {
	var got []observeBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b observeBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			t.Errorf("тело: %v", err)
		}
		got = append(got, b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`)) //nolint:gosec // G104: клиент теста ушёл — писать некуда
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	o := NewToolObserver(srv.Client(), u, quiet())
	desc := func(h string, bad bool) ObservedTool {
		return ObservedTool{Name: "read_file", Descriptor: []byte(`{"name":"read_file","description":"` + h + `"}`), Hash: h,
			Suspicious: bad}
	}
	o.Observe("files", []ObservedTool{desc("v1", false)})
	o.Observe("files", []ObservedTool{desc("v2", true)})
	o.Observe("files", []ObservedTool{desc("v3", false), {Name: "write_file", Descriptor: []byte(`{"name":"write_file"}`), Hash: "w"}})
	o.flush(context.Background())
	if len(got) != 1 || len(got[0].Tools) != 2 {
		t.Fatalf("сообщения: %+v", got)
	}
	if d := got[0].Tools[0]; string(d.Descriptor) != `{"name":"read_file","description":"v2"}` || !d.Suspicious {
		t.Fatalf("описание read_file: %s %v", d.Descriptor, d.Suspicious)
	}
	// Повтор имени в остатке после 429 тоже сливается перед отправкой.
	uniq := []ObservedTool{desc("v4", false), desc("v5", false)}
	o.mu.Lock()
	o.pending["files"] = uniq
	o.mu.Unlock()
	o.now = func() time.Time { return time.Now().Add(time.Hour) }
	o.flush(context.Background())
	if len(got) != 2 || len(got[1].Tools) != 1 {
		t.Fatalf("остаток с повтором имени: %+v", got)
	}
}

// Предел ждущих описаний на сервер — MaxObserveBatch.
func TestToolObserverPendingLimit(t *testing.T) {
	u, err := url.Parse("https://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
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
