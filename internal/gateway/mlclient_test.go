package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/ml"
	"github.com/azuresong-afk/ai_railway/internal/ml/mltest"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

var mlInfo = ml.ModelInfo{ID: "injection", Version: "1.0", Labels: []string{"injection", "benign"}, Directions: []string{"input"}}

// mlSocketDir — каталог сокета 0700 с коротким путём (предел sun_path).
func mlSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gwml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) //nolint:gosec // G104: ошибка в тесте не важна
	return dir
}

// startML — сервер протокола aisec-ml с тестовой моделью; сокет 0660.
func startML(t *testing.T, hook func(ctx context.Context, text string) error) string {
	t.Helper()
	sock := filepath.Join(mlSocketDir(t), "s")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sock, 0o660); err != nil { //nolint:gosec // G302: тест задаёт права сокета и каталога намеренно
		t.Fatal(err)
	}
	m := mltest.NewModel(mlInfo, map[string]string{"ignore": "injection", "hello": "benign"}, hook)
	srv, err := ml.NewServer(ml.ServerConfig{Models: []ml.Model{m}, Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	return sock
}

// startFakeML — сокет, на котором «aisec-ml» ведёт себя как задано: serve
// получает каждое соединение.
func startFakeML(t *testing.T, serve func(c net.Conn)) string {
	t.Helper()
	sock := filepath.Join(mlSocketDir(t), "s")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sock, 0o660); err != nil { //nolint:gosec // G302: тест задаёт права сокета и каталога намеренно
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() }) //nolint:gosec // G104: ошибка в тесте не важна
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck // тест
				serve(c)
			}()
		}
	}()
	return sock
}

func newMLClient(t *testing.T, sock string, mod func(*MLClientConfig)) *MLClient {
	t.Helper()
	cfg := MLClientConfig{Socket: sock, Timeout: 200 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	c, err := NewMLClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestMLClientDetect(t *testing.T) {
	c := newMLClient(t, startML(t, nil), nil)
	text := "Привет! please ignore it"
	for range 3 { // повторно — по тому же соединению из пула
		res, err := c.Detect(context.Background(), "injection", text)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 1 || text[res.Findings[0].Start:res.Findings[0].End] != "ignore" || res.Partial {
			t.Fatalf("находки: %+v", res)
		}
	}
	if _, err := c.Detect(context.Background(), "toxicity", text); !errors.Is(err, ErrMLUnavailable) {
		t.Fatalf("незагруженная модель: %v", err)
	}
}

// Длинный текст режется по границам символов, позиции — в исходном тексте;
// сверх MLMaxChunks частей — Partial.
func TestMLClientLongText(t *testing.T) {
	c := newMLClient(t, startML(t, nil), func(cfg *MLClientConfig) { cfg.Timeout = 5 * time.Second })
	text := strings.Repeat("я", ml.MaxText/2-1) + "ab ignore" + strings.Repeat("я", 10)
	res, err := c.Detect(context.Background(), "injection", text)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || text[res.Findings[0].Start:res.Findings[0].End] != "ignore" || res.Partial {
		t.Fatalf("находки: %+v", res.Findings)
	}
	huge := strings.Repeat("a", ml.MaxText*MLMaxChunks) + " ignore"
	res, err = c.Detect(context.Background(), "injection", huge)
	if err != nil || !res.Partial || len(res.Findings) != 0 {
		t.Fatalf("текст сверх %d частей: %+v %v", MLMaxChunks, res, err)
	}
}

func TestSplitText(t *testing.T) {
	text := strings.Repeat("ж", 5) // по 2 байта
	chunks, rest := splitText(text, 3, 10)
	if rest || len(chunks) != 5 {
		t.Fatalf("части %v", chunks)
	}
	for _, ch := range chunks {
		if s := text[ch[0]:ch[1]]; s != "ж" {
			t.Fatalf("часть %q разрезала символ", s)
		}
	}
	if chunks, rest := splitText(text, 4, 2); !rest || len(chunks) != 2 {
		t.Fatalf("предел частей: %v %v", chunks, rest)
	}
	if chunks, _ := splitText("", 4, 2); len(chunks) != 1 {
		t.Fatalf("пустой текст: %v", chunks)
	}
}

// Сокет или каталог с чужими правами — отказ подключения.
func TestMLClientRefusesForeignPermissions(t *testing.T) {
	sock := startML(t, nil)
	if err := os.Chmod(sock, 0o666); err != nil { //nolint:gosec // G302: тест задаёт права сокета и каталога намеренно
		t.Fatal(err)
	}
	c := newMLClient(t, sock, nil)
	if _, err := c.Detect(context.Background(), "injection", "x"); !errors.Is(err, ErrMLUnavailable) || !strings.Contains(err.Error(), "права сокета") {
		t.Fatalf("сокет 0666: %v", err)
	}
	if err := os.Chmod(sock, 0o660); err != nil { //nolint:gosec // G302: тест задаёт права сокета и каталога намеренно
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(sock), 0o777); err != nil { //nolint:gosec // G302: тест задаёт права сокета и каталога намеренно
		t.Fatal(err)
	}
	c = newMLClient(t, sock, nil)
	if _, err := c.Detect(context.Background(), "injection", "x"); !errors.Is(err, ErrMLUnavailable) || !strings.Contains(err.Error(), "каталог") {
		t.Fatalf("каталог 0777: %v", err)
	}
	// Обычный файл на месте сокета.
	file := filepath.Join(mlSocketDir(t), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c = newMLClient(t, file, nil)
	if _, err := c.Detect(context.Background(), "injection", "x"); !errors.Is(err, ErrMLUnavailable) {
		t.Fatalf("файл вместо сокета: %v", err)
	}
}

// После сбоя — отсрочка: вызовы сразу получают ErrMLUnavailable, не
// подключаясь; после отсрочки — снова попытка.
func TestMLClientBackoff(t *testing.T) {
	sock := filepath.Join(mlSocketDir(t), "s")
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	c := newMLClient(t, sock, func(cfg *MLClientConfig) {
		cfg.MinBackoff, cfg.MaxBackoff = time.Second, 4*time.Second
		cfg.now = func() time.Time { return now }
	})
	if _, err := c.Detect(context.Background(), "injection", "x"); !errors.Is(err, ErrMLUnavailable) {
		t.Fatalf("нет сокета: %v", err)
	}
	// Сокет появился, но отсрочка ещё идёт.
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })           //nolint:gosec // G104: ошибка в тесте не важна
	if err := os.Chmod(sock, 0o660); err != nil { //nolint:gosec // G302: тест задаёт права сокета и каталога намеренно
		t.Fatal(err)
	}
	if _, err := c.Detect(context.Background(), "injection", "x"); err == nil || !strings.Contains(err.Error(), "отсрочка") {
		t.Fatalf("в отсрочке: %v", err)
	}
	_ = l.Close() //nolint:gosec // G104: ошибка в тесте не важна
	now = now.Add(1100 * time.Millisecond)
	if _, err := c.Detect(context.Background(), "injection", "x"); err == nil || strings.Contains(err.Error(), "отсрочка") {
		t.Fatalf("после отсрочки должна быть новая попытка: %v", err)
	}
	if c.backoff != 2*time.Second {
		t.Fatalf("отсрочка не удвоилась: %v", c.backoff)
	}
}

// Предел одновременных вызовов: сверх него — сразу ErrMLUnavailable.
func TestMLClientInflightLimit(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	sock := startML(t, func(ctx context.Context, text string) error {
		if text == "block" {
			started <- struct{}{}
			<-release
		}
		return nil
	})
	c := newMLClient(t, sock, func(cfg *MLClientConfig) { cfg.MaxInflight, cfg.Timeout = 1, 5*time.Second })
	done := make(chan error, 1)
	go func() {
		_, err := c.Detect(context.Background(), "injection", "block")
		done <- err
	}()
	<-started
	begin := time.Now()
	if _, err := c.Detect(context.Background(), "injection", "x"); err == nil || !strings.Contains(err.Error(), "предел") {
		t.Fatalf("сверх предела: %v", err)
	}
	if time.Since(begin) > 100*time.Millisecond {
		t.Fatal("вызов сверх предела ждал очереди")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Зависший aisec-ml: вызов завершается по своему сроку.
func TestMLClientHungServer(t *testing.T) {
	sock := startFakeML(t, func(c net.Conn) { time.Sleep(2 * time.Second) })
	c := newMLClient(t, sock, func(cfg *MLClientConfig) { cfg.Timeout = 50 * time.Millisecond })
	begin := time.Now()
	if _, err := c.Detect(context.Background(), "injection", "x"); !errors.Is(err, ErrMLUnavailable) {
		t.Fatalf("зависание: %v", err)
	}
	if d := time.Since(begin); d > time.Second {
		t.Fatalf("вызов ждал %v", d)
	}
}

// Ответ с чужим номером, не тем типом или неверным телом — сбой протокола.
func TestMLClientProtocolViolations(t *testing.T) {
	for name, reply := range map[string]func(c net.Conn, h ml.Header){
		"чужой номер": func(c net.Conn, h ml.Header) {
			_ = ml.WriteFrame(c, ml.Header{Type: ml.TypeError, ID: h.ID + 1}, []byte(`{"code":"internal"}`)) //nolint:gosec // G104: ошибка в тесте не важна
		},
		"сверх предела": func(c net.Conn, h ml.Header) {
			_, _ = c.Write(ml.AppendHeader(nil, ml.Header{Type: ml.TypeResult, ID: h.ID, Length: ml.MaxResultBody + 1})) //nolint:gosec // G104: ошибка в тесте не важна
		},
		"мусор": func(c net.Conn, _ ml.Header) { _, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")) }, //nolint:gosec // G104: ошибка в тесте не важна
		"чужая метка": func(c net.Conn, h ml.Header) {
			_ = ml.WriteFrame(c, ml.Header{Type: ml.TypeResult, ID: h.ID}, //nolint:gosec // G104: ошибка в тесте не важна
				[]byte(`{"model":"injection","version":"1.0","findings":[{"label":"other","score":1,"start":0,"end":1}]}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			sock := startFakeML(t, func(c net.Conn) {
				hello, _ := ml.MarshalBody(ml.HelloOK{Protocol: ml.ProtocolVersion, Models: []ml.ModelInfo{mlInfo}}) //nolint:gosec // G104: ошибка в тесте не важна
				for {
					h, _, err := readServerFrame(c)
					if err != nil {
						return
					}
					if h.Type == ml.TypeHello {
						_ = ml.WriteFrame(c, ml.Header{Type: ml.TypeHelloOK, ID: h.ID}, hello) //nolint:gosec // G104: ошибка в тесте не важна
						continue
					}
					reply(c, h)
				}
			})
			c := newMLClient(t, sock, nil)
			if _, err := c.Detect(context.Background(), "injection", "x"); !errors.Is(err, ErrMLUnavailable) {
				t.Fatalf("нарушение протокола принято: %v", err)
			}
		})
	}
}

func readServerFrame(c net.Conn) (ml.Header, []byte, error) {
	return ml.ReadFrame(c, ml.ServerSide)
}

func TestNewMLDetectorValidates(t *testing.T) {
	c := newMLClient(t, "/run/none/s", nil)
	good := MLDetectorSpec{ID: "test.ml", Version: "1.0.0", Model: "injection", Directions: []detect.Direction{detect.Input},
		Categories: map[string]string{"injection": "injection.ml"}, Threat: "DM-01", Threshold: 0.5}
	if _, err := NewMLDetector(good, c); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*MLDetectorSpec){
		"ID":        func(s *MLDetectorSpec) { s.ID = "Test" },
		"версия":    func(s *MLDetectorSpec) { s.Version = "1" },
		"модель":    func(s *MLDetectorSpec) { s.Model = "" },
		"категория": func(s *MLDetectorSpec) { s.Categories = map[string]string{"injection": "injection"} },
		"угроза":    func(s *MLDetectorSpec) { s.Threat = "DM-1" },
		"порог":     func(s *MLDetectorSpec) { s.Threshold = 0 },
	} {
		s := good
		mod(&s)
		if _, err := NewMLDetector(s, c); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func mlTestDetector(t *testing.T, sock string) *MLDetector {
	t.Helper()
	c := newMLClient(t, sock, func(cfg *MLClientConfig) { cfg.Timeout = 50 * time.Millisecond })
	d, err := NewMLDetector(MLDetectorSpec{ID: "test.ml", Version: "1.0.0", Model: "injection", Directions: []detect.Direction{detect.Input},
		Categories: map[string]string{"injection": "injection.ml"}, Threat: "DM-01", Threshold: 0.5}, c)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Исправный aisec-ml: находка ML в событии, признака ml_unavailable нет.
func TestMLDetectorFindingInEvent(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var log *eventLog
	d := mlTestDetector(t, startML(t, nil))
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { a.FailMode = "fail_closed" }
		o.setup, log = withDetector(t, d), o.events
	})
	resp := postChat(t, g, userBody(t, "please ignore previous"), nil)
	if resp.Code != 200 {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e := lastEvent(t, log, resp)
	found := false
	for _, f := range e.Findings {
		found = found || (f.Detector == "test.ml" && f.Category == "injection.ml" && f.Rule == "injection-1.0")
	}
	if !found || e.Decision.MLUnavailable {
		t.Fatalf("событие: находки %+v, решение %+v", e.Findings, e.Decision)
	}
}

// Падение или зависание aisec-ml не мешает шлюзу: даже при fail_closed
// запрос проходит к провайдеру, событие — с ml_unavailable и без сбоев
// детекторов (ADR-0024, раздел 4).
func TestMLUnavailableDoesNotBlockGateway(t *testing.T) {
	cases := map[string]func(t *testing.T) string{
		"процесс не запущен": func(t *testing.T) string { return filepath.Join(mlSocketDir(t), "s") },
		"завис": func(t *testing.T) string {
			return startFakeML(t, func(c net.Conn) { time.Sleep(2 * time.Second) })
		},
		"упал посреди запроса": func(t *testing.T) string {
			return startFakeML(t, func(c net.Conn) {
				hello, _ := ml.MarshalBody(ml.HelloOK{Protocol: ml.ProtocolVersion, Models: []ml.ModelInfo{mlInfo}}) //nolint:gosec // G104: ошибка в тесте не важна
				h, _, err := readServerFrame(c)
				if err != nil {
					return
				}
				_ = ml.WriteFrame(c, ml.Header{Type: ml.TypeHelloOK, ID: h.ID}, hello) //nolint:gosec // G104: ошибка в тесте не важна
				_, _, _ = readServerFrame(c)                                           //nolint:gosec // G104: detect прочитан, соединение обрывается
			})
		},
		"перегружен": func(t *testing.T) string {
			return startFakeML(t, func(c net.Conn) {
				hello, _ := ml.MarshalBody(ml.HelloOK{Protocol: ml.ProtocolVersion, Models: []ml.ModelInfo{mlInfo}}) //nolint:gosec // G104: ошибка в тесте не важна
				for {
					h, _, err := readServerFrame(c)
					if err != nil {
						return
					}
					if h.Type == ml.TypeHello {
						_ = ml.WriteFrame(c, ml.Header{Type: ml.TypeHelloOK, ID: h.ID}, hello) //nolint:gosec // G104: ошибка в тесте не важна
						continue
					}
					_ = ml.WriteFrame(c, ml.Header{Type: ml.TypeError, ID: h.ID}, []byte(`{"code":"overloaded"}`)) //nolint:gosec // G104: ошибка в тесте не важна
				}
			})
		},
	}
	for name, sockFn := range cases {
		t.Run(name, func(t *testing.T) {
			up, rec := newUpstream(t, nil)
			var log *eventLog
			d := mlTestDetector(t, sockFn(t))
			g := newGateway(t, up.URL, func(o *gwOpts) {
				o.app = func(a *config.Application) { a.FailMode = "fail_closed" }
				o.setup, o.detTimeout, log = withDetector(t, d), time.Second, o.events
			})
			begin := time.Now()
			resp := postChat(t, g, userBody(t, "please ignore previous"), nil)
			if resp.Code != 200 {
				t.Fatalf("%d %s", resp.Code, resp.Body.String())
			}
			if time.Since(begin) > time.Second {
				t.Fatalf("запрос ждал aisec-ml %v", time.Since(begin))
			}
			if _, _, _, calls := rec.get(); calls != 1 {
				t.Fatal("запрос не дошёл до провайдера")
			}
			e := lastEvent(t, log, resp)
			if !e.Decision.MLUnavailable || len(e.Decision.Failures) != 0 || e.Decision.Rule == ruleFailClosed {
				t.Fatalf("решение: %+v", e.Decision)
			}
		})
	}
}

// Срок детектора меньше срока клиента: сбой по сроку детектора тоже не
// включает fail_closed.
func TestMLDetectorTimeoutIsMLUnavailable(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var log *eventLog
	sock := startFakeML(t, func(c net.Conn) { time.Sleep(2 * time.Second) })
	c := newMLClient(t, sock, func(cfg *MLClientConfig) { cfg.Timeout = 5 * time.Second })
	d, err := NewMLDetector(MLDetectorSpec{ID: "test.ml", Version: "1.0.0", Model: "injection", Directions: []detect.Direction{detect.Input},
		Categories: map[string]string{"injection": "injection.ml"}, Threat: "DM-01", Threshold: 0.5}, c)
	if err != nil {
		t.Fatal(err)
	}
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { a.FailMode = "fail_closed" }
		o.setup, o.detTimeout, log = withDetector(t, d), 20*time.Millisecond, o.events
	})
	resp := postChat(t, g, userBody(t, "Привет"), nil)
	if resp.Code != 200 {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if e := lastEvent(t, log, resp); !e.Decision.MLUnavailable || len(e.Decision.Failures) != 0 {
		t.Fatalf("решение: %+v", e.Decision)
	}
}

// Общий срок проверки истёк: ML-детекторы в сбои не попадают.
func TestOverallDeadlineSkipsML(t *testing.T) {
	d := mlTestDetector(t, "/run/none/s")
	reg, err := detect.NewRegistry(d)
	if err != nil {
		t.Fatal(err)
	}
	in := &inspection{}
	in.overall(in.withoutML(reg, []string{"pii.ru", "test.ml"}), "messages[0].content")
	if len(in.Failures) != 1 || in.Failures[0].Detector != "pii.ru" || !in.MLUnavailable {
		t.Fatalf("сбои: %+v, ml_unavailable %v", in.Failures, in.MLUnavailable)
	}
}

// helloThen — «aisec-ml», который отвечает на hello и передаёт кадры detect
// в reply; reply возвращает false — соединение закрывается.
func helloThen(reply func(c net.Conn, h ml.Header) bool) func(c net.Conn) {
	return func(c net.Conn) {
		hello, _ := ml.MarshalBody(ml.HelloOK{Protocol: ml.ProtocolVersion, Models: []ml.ModelInfo{mlInfo}}) //nolint:gosec // G104: ошибка в тесте не важна
		for {
			h, _, err := readServerFrame(c)
			if err != nil {
				return
			}
			if h.Type == ml.TypeHello {
				_ = ml.WriteFrame(c, ml.Header{Type: ml.TypeHelloOK, ID: h.ID}, hello) //nolint:gosec // G104: ошибка в тесте не важна
				continue
			}
			if !reply(c, h) {
				return
			}
		}
	}
}

var emptyResult = []byte(`{"model":"injection","version":"1.0","findings":[]}`)

// Свободное соединение закрыто aisec-ml (простой, перезапуск): вызов
// повторяется на новом соединении, отсрочки нет.
func TestMLClientRetriesClosedIdleConn(t *testing.T) {
	var dials atomic.Int32
	sock := startFakeML(t, func(c net.Conn) {
		dials.Add(1)
		// Одно соединение — один ответ, затем aisec-ml его закрывает.
		helloThen(func(c net.Conn, h ml.Header) bool {
			_ = ml.WriteFrame(c, ml.Header{Type: ml.TypeResult, ID: h.ID}, emptyResult) //nolint:gosec // G104: ошибка в тесте не важна
			return false
		})(c)
	})
	c := newMLClient(t, sock, nil)
	for i := range 3 {
		if _, err := c.Detect(context.Background(), "injection", "x"); err != nil {
			t.Fatalf("вызов %d: %v", i, err)
		}
	}
	if c.isDown() || dials.Load() != 3 {
		t.Fatalf("отсрочка %v, подключений %d", c.isDown(), dials.Load())
	}
}

// Свободное соединение старше mlIdleMax не берётся: aisec-ml мог его
// закрыть по простою.
func TestMLClientDropsStaleIdleConn(t *testing.T) {
	var dials atomic.Int32
	sock := startFakeML(t, func(c net.Conn) {
		dials.Add(1)
		helloThen(func(c net.Conn, h ml.Header) bool {
			return ml.WriteFrame(c, ml.Header{Type: ml.TypeResult, ID: h.ID}, emptyResult) == nil
		})(c)
	})
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	c := newMLClient(t, sock, func(cfg *MLClientConfig) { cfg.now = func() time.Time { return now } })
	for _, step := range []time.Duration{0, time.Second, mlIdleMax} {
		now = now.Add(step)
		if _, err := c.Detect(context.Background(), "injection", "x"); err != nil {
			t.Fatal(err)
		}
	}
	if dials.Load() != 2 {
		t.Fatalf("подключений %d, нужно 2", dials.Load())
	}
}

// Одиночный вызов, не уложившийся в срок, и отменённый запрос не включают
// отсрочку; mlTimeoutsToFail подряд — включают.
func TestMLClientTimeoutsAndBackoff(t *testing.T) {
	sock := startFakeML(t, helloThen(func(net.Conn, ml.Header) bool { time.Sleep(time.Second); return true }))
	c := newMLClient(t, sock, func(cfg *MLClientConfig) { cfg.Timeout = 20 * time.Millisecond })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Detect(ctx, "injection", "x"); !errors.Is(err, ErrMLUnavailable) || c.isDown() {
		t.Fatalf("отмена запроса: %v, отсрочка %v", err, c.isDown())
	}
	for i := 1; i <= mlTimeoutsToFail; i++ {
		if _, err := c.Detect(context.Background(), "injection", "x"); !errors.Is(err, ErrMLUnavailable) {
			t.Fatalf("вызов %d: %v", i, err)
		}
		if c.isDown() != (i == mlTimeoutsToFail) {
			t.Fatalf("вызов %d: отсрочка %v", i, c.isDown())
		}
	}
	// Во время отсрочки отсрочка не растёт.
	backoff := c.backoff
	c.fail(errors.New("сбой"))
	if c.backoff != backoff {
		t.Fatalf("отсрочка выросла во время отсрочки: %v → %v", backoff, c.backoff)
	}
}

// После Close вызовы получают ErrMLUnavailable и соединения в пул не
// возвращаются.
func TestMLClientClosed(t *testing.T) {
	c := newMLClient(t, startML(t, nil), nil)
	if _, err := c.Detect(context.Background(), "injection", "x"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := c.Detect(context.Background(), "injection", "x"); !errors.Is(err, ErrMLUnavailable) {
		t.Fatalf("закрытый клиент: %v", err)
	}
	if len(c.idle) != 0 {
		t.Fatal("соединение вернулось в пул закрытого клиента")
	}
}

// Модель из пакета не подходит детектору (нет метки, другое направление) —
// ml_unavailable, а не молчаливое отсутствие находок.
func TestMLDetectorChecksModel(t *testing.T) {
	sock := startML(t, nil)
	c := newMLClient(t, sock, nil)
	d, err := NewMLDetector(MLDetectorSpec{ID: "test.ml", Version: "1.0.0", Model: "injection",
		Directions: []detect.Direction{detect.Input, detect.Output},
		Categories: map[string]string{"toxic": "toxicity.ml"}, Threat: "DM-01", Threshold: 0.5}, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Detect(context.Background(), detect.Text{Text: "ignore", Direction: detect.Input}); !errors.Is(err, ErrMLUnavailable) ||
		!strings.Contains(err.Error(), "метки") {
		t.Fatalf("нет метки: %v", err)
	}
	if _, err := mlTestDetector(t, sock).Detect(context.Background(), detect.Text{Text: "ignore", Direction: detect.Output}); !errors.Is(err, ErrMLUnavailable) ||
		!strings.Contains(err.Error(), "направление") {
		t.Fatalf("чужое направление: %v", err)
	}
}

// Сбой ML вместе со сбоем обычного детектора при fail_closed: решение
// принимается по обычному детектору — 503, в сбоях только он.
func TestMLUnavailableWithOtherFailureFailsClosed(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var log *eventLog
	d := mlTestDetector(t, filepath.Join(mlSocketDir(t), "s"))
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { a.FailMode = "fail_closed" }
		o.setup = func(a *App) {
			reg, err := detect.NewRegistry(append(builtin.All(), d, broken)...)
			if err != nil {
				t.Fatal(err)
			}
			p, err := policy.Compile(&policy.Spec{ID: "t", Name: "t", Version: 1, Mode: policy.Monitor, Rules: []policy.RuleSpec{
				{ID: "ml", Detector: d.ID(), Action: policy.Log, Severity: policy.Low},
				{ID: "broken", Detector: broken.ID(), Action: policy.Log, Severity: policy.Low},
			}}, reg)
			if err != nil {
				t.Fatal(err)
			}
			a.Detectors, a.Policy = reg, p
		}
		log = o.events
	})
	resp := postChat(t, g, userBody(t, "Привет"), nil)
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	e := lastEvent(t, log, resp)
	if !e.Decision.MLUnavailable || e.Decision.Rule != ruleFailClosed || len(e.Decision.Failures) != 1 || e.Decision.Failures[0].Detector != broken.ID() {
		t.Fatalf("решение: %+v", e.Decision)
	}
}
