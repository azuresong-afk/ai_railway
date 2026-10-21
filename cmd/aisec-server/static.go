package main

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// staticFallback — обработчик статики веб-консоли (web/dist, встроена в бинарник) для путей
// вне /api и /internal. Только GET и HEAD; маршрутизация консоли хеш-адресная, поэтому
// отдаются сам index.html по «/» и файлы сборки по точному пути. Каталоги не перечисляются,
// скрытые файлы не отдаются, остальное — 404 без подмены на index.html.
func staticFallback(dist fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Метод не поддерживается.", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		if !fs.ValidPath(name) || strings.Contains(name, "/.") || strings.HasPrefix(name, ".") {
			http.NotFound(w, r)
			return
		}
		f, err := dist.Open(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer func() { _ = f.Close() }() //nolint:gosec // закрытие файла только для чтения
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
		rs, ok := f.(io.ReadSeeker)
		if !ok {
			http.Error(w, "Внутренняя ошибка.", http.StatusInternalServerError)
			return
		}
		if name == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		} else if strings.HasPrefix(name, "assets/") {
			// Имена файлов сборки содержат хеш содержимого.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeContent(w, r, name, time.Time{}, rs)
	})
}

// errNoConsole — сборки консоли нет (в web/dist только .gitkeep): сервер работает как API.
var errNoConsole = errors.New("веб-консоль не собрана")

// consoleFS возвращает сборку консоли или errNoConsole, если index.html нет.
func consoleFS(dist fs.FS) (fs.FS, error) {
	if _, err := fs.Stat(dist, "index.html"); err != nil {
		return nil, errNoConsole
	}
	return dist, nil
}
