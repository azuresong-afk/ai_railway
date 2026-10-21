package gateway_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
)

// Пакеты конфигурации на шлюзе (Р7, ОЦЛ.3, DM-42; задача 2.13): опрос,
// проверка, применение, файл состояния и отказы.

// bundleServer — внутренний API сервера: отдаёт body с ETag, учитывает
// If-None-Match и запоминает отчёты.
type bundleServer struct {
	mu      sync.Mutex
	body    []byte
	etag    string
	inm     []string
	keys    []string
	reports []map[string]any
}

func (s *bundleServer) set(body []byte, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.etag = body, `"`+version+`"`
}

func (s *bundleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/internal/v1/policies/bundle":
		s.inm = append(s.inm, r.Header.Get("If-None-Match"))
		s.keys = append(s.keys, r.Header.Get(gateway.BundleKeyHeader))
		if s.body == nil {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("ETag", s.etag)
		for _, v := range strings.Split(r.Header.Get("If-None-Match"), ",") {
			if strings.TrimSpace(v) == s.etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		_, _ = w.Write(s.body) //nolint:gosec // G104: тестовый сервер
	case "/internal/v1/policies/bundle/status":
		var m map[string]any
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.reports = append(s.reports, m)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *bundleServer) lastReport() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reports) == 0 {
		return nil
	}
	return s.reports[len(s.reports)-1]
}

func (s *bundleServer) reportCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reports)
}

type bundleEnv struct {
	fx      *bundletest.Fixture
	srv     *bundleServer
	url     *url.URL
	dir     string
	applied []int64
	fail    error
	log     *bytes.Buffer
}

func newBundleEnv(t *testing.T) *bundleEnv {
	t.Helper()
	e := &bundleEnv{fx: bundletest.New(t), srv: &bundleServer{}, dir: stateDir(t), log: &bytes.Buffer{}}
	ts := httptest.NewServer(e.srv)
	t.Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	e.url = u
	return e
}

// stateDir — каталог состояния 0700.
func stateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// client — новый шлюз над тем же каталогом состояния (как после перезапуска).
func (e *bundleEnv) client(t *testing.T) *gateway.BundleClient {
	t.Helper()
	rnd, err := e.fx.Provider.Random()
	if err != nil {
		t.Fatal(err)
	}
	st, err := gateway.OpenBundleState(e.dir, rnd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	c, err := gateway.NewBundleClient(gateway.BundleConfig{Client: http.DefaultClient, Server: e.url, Opener: e.fx.Opener(t),
		RecipientKey: e.fx.Recipient.PublicKey(), State: st,
		Apply: func(b *bundle.Bundle) error {
			if b.Secrets["llm"] != bundletest.Credential {
				return errors.New("секрет не расшифрован")
			}
			if e.fail != nil {
				return e.fail
			}
			e.applied = append(e.applied, b.Header.Version)
			return nil
		},
		Logger: slog.New(slog.NewJSONHandler(e.log, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *bundleEnv) poll(t *testing.T, c *gateway.BundleClient) {
	t.Helper()
	if err := c.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (e *bundleEnv) saved(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, gateway.BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wantReport(t *testing.T, got map[string]any, result string, version float64, reason string) {
	t.Helper()
	if got == nil || got["result"] != result || got["version"] != version || (reason != "" && got["reason"] != reason) {
		t.Fatalf("отчёт серверу: %v, ждали %s %v %s", got, result, version, reason)
	}
}

func TestBundleClientApplyAndSave(t *testing.T) {
	e := newBundleEnv(t)
	c := e.client(t)
	// Пакета на сервере нет — 503, шлюз не готов.
	if err := c.Poll(context.Background()); err == nil || c.Ready() {
		t.Fatalf("без пакета: %v", err)
	}
	v1 := e.fx.Seal(t, e.fx.Content(t), 100)
	e.srv.set(v1, "100")
	e.poll(t, c)
	if !c.Ready() || c.ETag() != `"100"` || len(e.applied) != 1 {
		t.Fatalf("не применён: %q %v", c.ETag(), e.applied)
	}
	wantReport(t, e.srv.lastReport(), "applied", 100, "")
	if !bytes.Equal(e.saved(t), v1) {
		t.Fatal("на диске не тот пакет")
	}
	info, err := os.Stat(filepath.Join(e.dir, gateway.BundleFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("права файла пакета: %v %v", info.Mode(), err)
	}
	if k := e.srv.keys[len(e.srv.keys)-1]; k != base64.RawURLEncoding.EncodeToString(e.fx.Recipient.PublicKey()) {
		t.Fatalf("ключ получателя в заголовке: %q", k)
	}
	// Повторный опрос — If-None-Match, 304, без применения и отчёта.
	e.poll(t, c)
	if len(e.applied) != 1 || e.srv.inm[len(e.srv.inm)-1] != `"100"` || e.srv.reportCount() != 1 {
		t.Fatalf("повторный опрос: %v %v %d", e.applied, e.srv.inm, e.srv.reportCount())
	}
	// Временных файлов не осталось.
	ents, err := os.ReadDir(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range ents {
		if de.Name() != gateway.BundleFile && de.Name() != gateway.BundleKeyFile {
			t.Fatalf("лишний файл в каталоге состояния: %s", de.Name())
		}
	}
	if strings.Contains(e.log.String(), bundletest.Credential) {
		t.Fatal("учётные данные провайдера в техническом журнале")
	}
}

// TestDM42_GatewayKeepsBundleOnTamper: подменённый пакет отклоняется до
// разбора, шлюз работает на прежнем, сервер получает отчёт об отказе, а
// отклонённая версия больше не скачивается.
func TestDM42_GatewayKeepsBundleOnTamper(t *testing.T) {
	e := newBundleEnv(t)
	c := e.client(t)
	v1 := e.fx.Seal(t, e.fx.Content(t), 100)
	e.srv.set(v1, "100")
	e.poll(t, c)
	var env map[string]string
	if err := json.Unmarshal(e.fx.Seal(t, e.fx.Content(t), 200), &env); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(env["signature"])
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 1
	env["signature"] = base64.StdEncoding.EncodeToString(sig)
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.set(tampered, "200")
	e.poll(t, c)
	if c.ETag() != `"100"` || len(e.applied) != 1 || !bytes.Equal(e.saved(t), v1) {
		t.Fatalf("подмена применена: %q %v", c.ETag(), e.applied)
	}
	wantReport(t, e.srv.lastReport(), "rejected", 200, bundle.ReasonSignature)
	if !strings.Contains(e.log.String(), "DM-42") {
		t.Fatal("отказ не записан в технический журнал")
	}
	e.poll(t, c)
	if inm := e.srv.inm[len(e.srv.inm)-1]; inm != `"100", "200"` || e.srv.reportCount() != 2 {
		t.Fatalf("отклонённый пакет запрошен снова: %q, отчётов %d", inm, e.srv.reportCount())
	}
}

func TestBundleClientRollbackRejected(t *testing.T) {
	e := newBundleEnv(t)
	c := e.client(t)
	e.srv.set(e.fx.Seal(t, e.fx.Content(t), 500), "500")
	e.poll(t, c)
	e.srv.set(e.fx.Seal(t, e.fx.Content(t), 300), "300")
	e.poll(t, c)
	if c.ETag() != `"500"` || len(e.applied) != 1 {
		t.Fatalf("откат применён: %q", c.ETag())
	}
	wantReport(t, e.srv.lastReport(), "rejected", 300, bundle.ReasonRollback)
}

// Пакет с верной подписью, который не собирается в обработчик (например,
// политика ссылается на словарь, которого нет у приложения), — отказ
// invalid_content, действует прежний.
func TestBundleClientApplyFailureKeepsOld(t *testing.T) {
	e := newBundleEnv(t)
	c := e.client(t)
	v1 := e.fx.Seal(t, e.fx.Content(t), 100)
	e.srv.set(v1, "100")
	e.poll(t, c)
	e.fail = errors.New("политика corp: нет словаря lists.codename (проект зенит)")
	e.srv.set(e.fx.Seal(t, e.fx.Content(t), 200), "200")
	e.poll(t, c)
	if c.ETag() != `"100"` || !bytes.Equal(e.saved(t), v1) {
		t.Fatalf("неприменимый пакет заменил прежний: %q", c.ETag())
	}
	wantReport(t, e.srv.lastReport(), "rejected", 200, bundle.ReasonInvalidContent)
	if strings.Contains(e.log.String(), "зенит") {
		t.Fatal("фрагмент содержимого пакета в техническом журнале")
	}
}

func TestBundleClientTooLarge(t *testing.T) {
	e := newBundleEnv(t)
	c := e.client(t)
	e.srv.set(bytes.Repeat([]byte(" "), bundle.MaxSize+1), "7")
	e.poll(t, c)
	if c.Ready() {
		t.Fatal("слишком большой пакет принят")
	}
	wantReport(t, e.srv.lastReport(), "rejected", 7, bundle.ReasonTooLarge)
}

// После перезапуска шлюз берёт сохранённый пакет, проверяя его заново:
// подмена файла на диске — отказ, шлюз ждёт пакет с сервера.
func TestBundleClientLoadSaved(t *testing.T) {
	e := newBundleEnv(t)
	c := e.client(t)
	if c.LoadSaved() {
		t.Fatal("пустой каталог: пакет загружен")
	}
	v1 := e.fx.Seal(t, e.fx.Content(t), 100)
	e.srv.set(v1, "100")
	e.poll(t, c)

	c2 := e.client(t)
	if !c2.LoadSaved() || c2.ETag() != `"100"` {
		t.Fatalf("сохранённый пакет не загружен: %q", c2.ETag())
	}
	// Тот же пакет на сервере — 304; отчёт о применении из файла не шлётся.
	e.poll(t, c2)
	if e.srv.reportCount() != 1 || e.srv.inm[len(e.srv.inm)-1] != `"100"` {
		t.Fatalf("после перезапуска: отчётов %d, If-None-Match %q", e.srv.reportCount(), e.srv.inm[len(e.srv.inm)-1])
	}

	path := filepath.Join(e.dir, gateway.BundleFile)
	damaged := append(append([]byte{}, v1[:len(v1)/2]...), 'x')
	if err := os.WriteFile(path, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	c3 := e.client(t)
	if c3.LoadSaved() || c3.Ready() {
		t.Fatal("повреждённый файл принят")
	}
	e.srv.set(nil, "")
	_ = c3.Poll(context.Background()) //nolint:gosec // G104: сервер отвечает 503, важен отчёт
	wantReport(t, e.srv.lastReport(), "rejected", 0, bundle.ReasonFormat)

	if err := os.WriteFile(path, v1, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if e.client(t).LoadSaved() {
		t.Fatal("файл пакета, доступный остальным, принят")
	}
}

func TestBundleStateRecipientAndPerms(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	dir := stateDir(t)
	st, err := gateway.OpenBundleState(dir, rnd)
	if err != nil {
		t.Fatal(err)
	}
	r1, err := st.Recipient(p)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, gateway.BundleKeyFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("ключ получателя: %v %v", info.Mode(), err)
	}
	r2, err := st.Recipient(p)
	if err != nil || !bytes.Equal(r1.PublicKey(), r2.PublicKey()) {
		t.Fatalf("ключ при повторном запуске другой: %v", err)
	}
	for range 3 {
		if err := st.Save([]byte(`{"x":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := st.Load(); err != nil || string(b) != `{"x":1}` {
		t.Fatalf("%q %v", b, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// Ссылка на чужой файл вместо пакета не читается за пределами каталога.
	outside := filepath.Join(t.TempDir(), "other.json")
	if err := os.WriteFile(outside, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := stateDir(t)
	if err := os.Symlink(outside, filepath.Join(link, gateway.BundleFile)); err != nil {
		t.Fatal(err)
	}
	st2, err := gateway.OpenBundleState(link, rnd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st2.Load(); err == nil {
		t.Fatal("символическая ссылка за пределы каталога прочитана")
	}
	_ = st2.Close() //nolint:gosec // G104: каталог только читался
	open := t.TempDir()
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.OpenBundleState(open, rnd); err == nil {
		t.Fatal("каталог 0755 принят")
	}
}

func TestUnavailableUntilFirstBundle(t *testing.T) {
	sw := gateway.NewSwitch(gateway.NewUnavailable(quiet()))
	for _, rq := range [][2]string{{http.MethodPost, "/v1/chat/completions"}, {http.MethodPost, "/v1/embeddings"},
		{http.MethodPost, "/guard/v1/check"}, {http.MethodGet, "/v1/models"}, {http.MethodGet, "/readyz"}} {
		w := httptest.NewRecorder()
		sw.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), rq[0], rq[1], nil))
		body, err := io.ReadAll(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(string(body), "config_unavailable") || w.Header().Get("Retry-After") == "" {
			t.Errorf("%s %s: %d %s", rq[0], rq[1], w.Code, body)
		}
	}
	w := httptest.NewRecorder()
	sw.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: %d", w.Code)
	}
	sw.Store(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	w = httptest.NewRecorder()
	sw.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusTeapot {
		t.Fatalf("после пакета: %d", w.Code)
	}
}
