package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func testDist() fstest.MapFS {
	return fstest.MapFS{
		"index.html":      {Data: []byte("<!doctype html>консоль")},
		"assets/app-1.js": {Data: []byte("js")},
		".gitkeep":        {Data: nil},
		"assets/.hidden":  {Data: []byte("x")},
	}
}

func get(h http.Handler, method, url string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, url, nil))
	return rec
}

func TestStaticFallback(t *testing.T) {
	h := staticFallback(testDist())
	cases := []struct {
		method, url string
		code        int
	}{
		{"GET", "/", 200},
		{"HEAD", "/", 200},
		{"GET", "/index.html", 200},
		{"GET", "/assets/app-1.js", 200},
		{"GET", "/assets/", 404},         // каталоги не перечисляются
		{"GET", "/assets", 404},          // каталог без слэша
		{"GET", "/.gitkeep", 404},        // скрытые файлы не отдаются
		{"GET", "/assets/.hidden", 404},  // и в подкаталогах
		{"GET", "/nope", 404},            // нет подмены на index.html
		{"GET", "/../etc/passwd", 404},   // выход за каталог
		{"GET", "/assets/%2e%2e/x", 404}, // кодированный выход
		{"POST", "/", 405},
	}
	for _, c := range cases {
		if got := get(h, c.method, c.url).Code; got != c.code {
			t.Errorf("%s %s: код %d, ожидался %d", c.method, c.url, got, c.code)
		}
	}
	if cc := get(h, "GET", "/").Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("index.html: Cache-Control %q", cc)
	}
	if cc := get(h, "GET", "/assets/app-1.js").Header().Get("Cache-Control"); cc == "" {
		t.Error("assets: нет Cache-Control")
	}
}

func TestConsoleFS(t *testing.T) {
	if _, err := consoleFS(fstest.MapFS{".gitkeep": {}}); !errors.Is(err, errNoConsole) {
		t.Fatalf("без index.html ожидался errNoConsole, получено %v", err)
	}
	if _, err := consoleFS(testDist()); err != nil {
		t.Fatalf("с index.html: %v", err)
	}
}

// Любой путь запроса: без паники, отдаётся только файл из сборки, не каталог.
func FuzzStaticFallbackPath(f *testing.F) {
	for _, s := range []string{"/", "/assets/app-1.js", "/..", "/a/../../x", "//", "/%00", "/.gitkeep"} {
		f.Add(s)
	}
	h := staticFallback(testDist())
	f.Fuzz(func(t *testing.T, p string) {
		req, err := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
		if err != nil {
			t.Skip()
		}
		req.URL.Path = p
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 && rec.Code != 404 && rec.Code != 304 {
			t.Fatalf("путь %q: код %d", p, rec.Code)
		}
		if rec.Code == 200 {
			if b := rec.Body.String(); b != "<!doctype html>консоль" && b != "js" {
				t.Fatalf("путь %q отдал постороннее содержимое %q", p, b)
			}
		}
	})
}
