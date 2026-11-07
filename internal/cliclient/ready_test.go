package cliclient

import (
	"context"
	"net/http"
	"testing"
)

// Проверка готовности при обновлении: только https и /readyz, доверие —
// только своему корню, перенаправления не выполняются, готов — только 200.
func TestReady(t *testing.T) {
	status := http.StatusOK
	s := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		if status == http.StatusFound {
			http.Redirect(w, r, "https://example.invalid/", status)
			return
		}
		w.WriteHeader(status)
	}))
	p := profile(t)
	ctx := context.Background()
	if err := Ready(ctx, p, s.url+"/readyz", s.ca); err != nil {
		t.Fatal(err)
	}
	if err := Ready(ctx, p, s.url+"/readyz", s.ca2); err == nil {
		t.Fatal("принят сертификат чужого корня")
	}
	for _, st := range []int{http.StatusServiceUnavailable, http.StatusFound} {
		status = st
		if err := Ready(ctx, p, s.url+"/readyz", s.ca); err == nil {
			t.Fatalf("ответ %d принят как готовность", st)
		}
	}
	for _, bad := range []string{"http://127.0.0.1/readyz", s.url + "/other", s.url + "/readyz?x=1", "https://u:p@127.0.0.1/readyz", "https:///readyz"} {
		if err := Ready(ctx, p, bad, s.ca); err == nil {
			t.Fatalf("принят адрес %s", bad)
		}
	}
	if err := Ready(ctx, nil, s.url+"/readyz", s.ca); err == nil {
		t.Fatal("без криптопрофиля")
	}
}
