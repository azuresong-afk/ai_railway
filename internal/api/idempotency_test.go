package api

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseIdempotencyKey(t *testing.T) {
	if _, present, p := ParseIdempotencyKey(nil); present || p != nil {
		t.Fatal("отсутствие заголовка — не ошибка")
	}
	if k, present, p := ParseIdempotencyKey([]string{"abc-1.2_X"}); k != "abc-1.2_X" || !present || p != nil {
		t.Fatal("верный ключ отвергнут")
	}
	for _, bad := range [][]string{{""}, {"a b"}, {"a/b"}, {strings.Repeat("a", 65)}, {"a", "b"}, {"ключ"}, {"a\r\nX: y"}} {
		if _, present, p := ParseIdempotencyKey(bad); !present || p == nil {
			t.Errorf("принят %q", bad)
		}
	}
}

func FuzzIdempotencyKey(f *testing.F) {
	f.Add("abc")
	f.Add("")
	f.Add("a b\x00")
	f.Fuzz(func(t *testing.T, s string) {
		k, present, p := ParseIdempotencyKey([]string{s})
		if !present {
			t.Fatal("значение есть, present=false")
		}
		if p == nil && (k != s || !validIdempotencyKey(s) || len(s) > maxIdempotencyKey) {
			t.Fatalf("принят %q", s)
		}
	})
}

func idemRoutes(calls *atomic.Int32) []Route {
	return []Route{{Method: http.MethodPost, Path: "/api/v1/things", Permission: "things.write", Idempotent: true,
		Handler: func(w http.ResponseWriter, r *http.Request) {
			n := calls.Add(1)
			var in struct{ Name string }
			if p := DecodeJSON(w, r, &in, 1024); p != nil {
				WriteProblem(w, p)
				return
			}
			w.Header().Set("Location", "/api/v1/things/"+in.Name)
			WriteJSON(w, http.StatusCreated, map[string]any{"name": in.Name, "n": n})
		}}}
}

func TestIdempotencyReplayAndMismatch(t *testing.T) {
	var calls atomic.Int32
	h, _ := newHandler(t, Options{Authorizer: allowPerm{"things.write": true}, Extra: idemRoutes(&calls)})
	post := func(key, body string) (int, string, string) {
		hdr := []string{"Content-Type", "application/json"}
		if key != "" {
			hdr = append(hdr, "Idempotency-Key", key)
		}
		w := do(h, "POST", "/api/v1/things", body, hdr...)
		return w.Code, w.Body.String(), w.Header().Get("Idempotent-Replayed")
	}
	c1, b1, r1 := post("k1", `{"Name":"a"}`)
	c2, b2, r2 := post("k1", `{"Name":"a"}`)
	if c1 != 201 || c2 != 201 || b1 != b2 || r1 != "" || r2 != "true" || calls.Load() != 1 {
		t.Fatalf("повтор: %d %d %q %q calls=%d", c1, c2, r1, r2, calls.Load())
	}
	if c, _, _ := post("k1", `{"Name":"b"}`); c != 422 {
		t.Fatalf("другое тело с тем же ключом: %d", c)
	}
	post("", `{"Name":"a"}`)
	post("", `{"Name":"a"}`)
	if calls.Load() != 3 {
		t.Fatalf("без ключа каждый запрос выполняется: calls=%d", calls.Load())
	}
	if c, _, _ := post("плохой ключ", `{}`); c != 400 {
		t.Fatalf("неверный ключ: %d", c)
	}
}

func TestIdempotencyErrorsNotStored(t *testing.T) {
	var calls atomic.Int32
	h, _ := newHandler(t, Options{Authorizer: allowPerm{"things.write": true}, Extra: []Route{{
		Method: http.MethodPost, Path: "/api/v1/boom", Permission: "things.write", Idempotent: true,
		Handler: func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				WriteProblem(w, errInternal())
				return
			}
			WriteJSON(w, http.StatusCreated, map[string]string{"ok": "1"})
		}}}})
	for i, want := range []int{500, 201} {
		if w := do(h, "POST", "/api/v1/boom", `{}`, "Idempotency-Key", "k"); w.Code != want {
			t.Fatalf("попытка %d: %d", i, w.Code)
		}
	}
}

func TestMemoryIdempotencyBoundsAndTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	m := NewMemoryIdempotency(time.Minute, 2, func() time.Time { return now })
	ctx := t.Context()
	begin := func(scope, key string) IdemState {
		t.Helper()
		st, _, err := m.Begin(ctx, scope, key, "f")
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	for _, k := range []string{"a", "b"} {
		if s := begin("s", k); s != IdemNew {
			t.Fatal(k)
		}
	}
	if s := begin("s", "c"); s != IdemFull {
		t.Fatalf("ожидалось переполнение: %v", s)
	}
	if s := begin("s", "a"); s != IdemBusy {
		t.Fatalf("тот же запрос выполняется: %v", s)
	}
	now = now.Add(2 * time.Minute)
	if s := begin("s", "c"); s != IdemNew {
		t.Fatalf("после срока место освобождается: %v", s)
	}
	// Ключи разных субъектов не пересекаются.
	if s := begin("other", "c"); s != IdemNew {
		t.Fatalf("другая область: %v", s)
	}
}
