package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"rsc.io/qr"
)

// Отрисовка корпуса: HTML-страница → headless Chromium из окружения
// (AISEC_CHROMIUM) → PNG. JPEG получается вторым проходом в том же
// Chromium: PNG рисуется на canvas и кодируется toDataURL("image/jpeg"),
// результат читается из DOM (--dump-dom). Так генератору не нужны
// кодировщики изображений (depguard media-decoders) и новые библиотеки.
// Шрифты — только локальные из web/src/assets/fonts (OFL), встраиваются
// в страницу data:-адресами; сеть у Chromium выключена.

const renderTimeout = 90 * time.Second

type renderer struct {
	chromium string
	fontCSS  string
	work     string
}

// fontFaces — @font-face для Onest и JetBrains Mono: кириллица и латиница
// лежат в разных файлах, поэтому у каждого — свой unicode-range.
func fontFaces(dir string) (string, error) {
	const (
		cyr = "U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116"
		lat = "U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD"
	)
	faces := []struct{ family, file, rng string }{
		{"Onest", "onest-cyrillic-wght-normal.woff2", cyr},
		{"Onest", "onest-latin-wght-normal.woff2", lat},
		{"JetBrains Mono", "jetbrains-mono-cyrillic-wght-normal.woff2", cyr},
		{"JetBrains Mono", "jetbrains-mono-latin-wght-normal.woff2", lat},
	}
	var b strings.Builder
	for _, f := range faces {
		data, err := os.ReadFile(filepath.Join(dir, f.file)) //nolint:gosec // G304: путь из флага -fonts утилиты разработчика
		if err != nil {
			return "", fmt.Errorf("шрифт: %w", err)
		}
		fmt.Fprintf(&b, "@font-face{font-family:%q;font-weight:100 900;font-display:block;unicode-range:%s;src:url(data:font/woff2;base64,%s) format(\"woff2\")}\n",
			f.family, f.rng, base64.StdEncoding.EncodeToString(data))
	}
	return b.String(), nil
}

// chromiumArgs — общие флаги: без сети, расширений и фоновых служб; масштаб 1, чтобы размеры файла совпадали с окном.
func (r *renderer) chromiumArgs(extra ...string) []string {
	args := []string{
		"--headless", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
		"--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-sync",
		"--disable-background-networking", "--disable-component-update", "--disable-default-apps",
		"--host-resolver-rules=MAP * ~NOTFOUND", "--proxy-server=127.0.0.1:9", "--proxy-bypass-list=<-loopback>",
		"--font-render-hinting=none", "--virtual-time-budget=3000",
	}
	// От root Chromium без --no-sandbox не запускается (облачная среда);
	// у обычного пользователя песочница остаётся.
	if os.Geteuid() == 0 {
		args = append(args, "--no-sandbox")
	}
	return append(args, extra...)
}

func (r *renderer) run(args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), renderTimeout)
	defer cancel()
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, r.chromium, args...) //nolint:gosec // G204: путь к Chromium задаёт разработчик (-chromium, AISEC_CHROMIUM), аргументы — свои
	cmd.Stdout, cmd.Stderr = &out, &errb
	// Профиль — во временном каталоге (HOME и XDG_*), а не у пользователя:
	// с --user-data-dir headless Chromium этой сборки не завершается.
	home := filepath.Join(r.work, "home")
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home, "XDG_CACHE_HOME="+home)
	if err := cmd.Run(); err != nil {
		tail := errb.String()
		if len(tail) > 2000 {
			tail = tail[len(tail)-2000:]
		}
		return nil, fmt.Errorf("chromium: %w: %s", err, tail)
	}
	return out.Bytes(), nil
}

// page — полная HTML-страница образца.
func (r *renderer) page(s *sample) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><style>")
	b.WriteString(r.fontCSS)
	fmt.Fprintf(&b, "html,body{margin:0;width:%dpx;height:%dpx;overflow:hidden;background:%s}", s.Width, s.Height, s.bg())
	b.WriteString("body{font-family:Onest,sans-serif;color:#1d2433;font-size:22px;line-height:1.45}")
	b.WriteString(".mono{font-family:'JetBrains Mono',monospace}.l{white-space:pre}")
	b.WriteString(s.CSS)
	b.WriteString("</style></head><body>")
	b.WriteString(s.body())
	b.WriteString("</body></html>")
	return b.String()
}

// renderPNG отрисовывает образец в PNG размером Width×Height.
func (r *renderer) renderPNG(s *sample) ([]byte, error) {
	pagePath := filepath.Join(r.work, s.ID+".html")
	if err := os.WriteFile(pagePath, []byte(r.page(s)), 0o600); err != nil {
		return nil, err
	}
	out := filepath.Join(r.work, s.ID+".png")
	if _, err := r.run(r.chromiumArgs(fmt.Sprintf("--window-size=%d,%d", s.Width, s.Height),
		"--screenshot="+out, "file://"+pagePath)); err != nil {
		return nil, err
	}
	return os.ReadFile(out) //nolint:gosec // G304: свой временный каталог
}

const jpegMark = "data:image/jpeg;base64,"

// toJPEG перекодирует PNG в JPEG с качеством q (0–1) через canvas.
func (r *renderer) toJPEG(id string, png []byte, q float64) ([]byte, error) {
	page := fmt.Sprintf(`<!doctype html><html><body><img id="i" src="data:image/png;base64,%s"><pre id="o"></pre><script>
window.addEventListener("load",function(){var i=document.getElementById("i"),c=document.createElement("canvas");
c.width=i.naturalWidth;c.height=i.naturalHeight;c.getContext("2d").drawImage(i,0,0);
document.getElementById("o").textContent=c.toDataURL("image/jpeg",%.2f);i.remove();});
</script></body></html>`, base64.StdEncoding.EncodeToString(png), q)
	pagePath := filepath.Join(r.work, id+"-jpeg.html")
	if err := os.WriteFile(pagePath, []byte(page), 0o600); err != nil {
		return nil, err
	}
	dom, err := r.run(r.chromiumArgs("--dump-dom", "file://"+pagePath))
	if err != nil {
		return nil, err
	}
	i := bytes.Index(dom, []byte(jpegMark))
	if i < 0 {
		return nil, errors.New("chromium: в DOM нет JPEG")
	}
	enc := dom[i+len(jpegMark):]
	if j := bytes.IndexByte(enc, '<'); j >= 0 {
		enc = enc[:j]
	}
	return base64.StdEncoding.DecodeString(string(bytes.TrimSpace(enc)))
}

// qrSVG — QR-код как SVG из прямоугольников (как в консоли, internal/auth/qr.go):
// модуль module пикселей, поле 4 модуля.
func qrSVG(text string, module int) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	n := c.Size + 8
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/>`,
		n*module, n*module, n, n, n, n)
	for y := range c.Size {
		for x := range c.Size {
			if c.Black(x, y) {
				fmt.Fprintf(&b, `<rect x="%d" y="%d" width="1" height="1"/>`, x+4, y+4)
			}
		}
	}
	b.WriteString("</svg>")
	return b.String(), nil
}

// esc — экранирование текста для HTML.
func esc(s string) string { return html.EscapeString(s) }
