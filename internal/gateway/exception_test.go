package gateway

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Исключения в политике на шлюзе (задача 3.22 этапа 3): находка,
// совпавшая с действующим исключением, пропускается после детектора и до
// решения; событие получает ID исключения у находки и шаг трассировки.

var excNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// excGateway — шлюз с политикой enforce, блокирующей инъекцию, с
// исключениями exc; часы шлюза — excNow + shift.
func excGateway(t *testing.T, upstream string, shift time.Duration, exc ...policy.ExceptionSpec) (http.Handler, *eventLog) {
	t.Helper()
	return excGatewayClock(t, upstream, func() time.Time { return excNow.Add(shift) }, exc...)
}

// excGatewayClock — excGateway с часами сроков исключений clock.
func excGatewayClock(t *testing.T, upstream string, clock func() time.Time, exc ...policy.ExceptionSpec) (http.Handler, *eventLog) {
	t.Helper()
	reg, err := detect.NewRegistry(builtin.All()...)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Compile(&policy.Spec{ID: "t", Name: "t", Version: 1, Mode: policy.Enforce, Rules: []policy.RuleSpec{
		{ID: "injection", Detector: "injection.heuristic", Action: policy.Block, Severity: policy.High},
	}, Exceptions: exc}, reg)
	if err != nil {
		t.Fatal(err)
	}
	mac := testMAC(t)
	var log *eventLog
	g := newGateway(t, upstream, func(o *gwOpts) {
		o.app = func(a *config.Application) { enforce(a); a.UserFrom = "header" }
		o.userMAC, log = mac, o.events
		o.setup = func(a *App) {
			a.Detectors, a.Policy = reg, p
			a.fragmentMAC = mac
			a.clock = clock
		}
	})
	return g, log
}

func injectionException(e policy.ExceptionSpec) policy.ExceptionSpec {
	e.ID, e.Detector, e.Reason, e.Author = "exc-1", "injection.heuristic", "ложное срабатывание", "user:u1"
	e.CreatedAt, e.ExpiresAt = excNow.Add(-time.Hour), excNow.Add(24*time.Hour)
	return e
}

func TestGatewayAppliesException(t *testing.T) {
	up, rec := newUpstream(t, nil)
	// Находка без исключения: блокировка, у находки — хеш фрагмента без текста.
	g, log := excGateway(t, up.URL, 0)
	resp := postChat(t, g, userBody(t, injectionText), nil)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("без исключения: %d", resp.Code)
	}
	e := lastEvent(t, log, resp)
	f := e.Findings[0]
	if len(f.Fragment) != 32 || f.Exception != "" || strings.Contains(f.Fragment, "gnore") {
		t.Fatalf("находка: %+v", f)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("событие: %v", err)
	}
	other := strings.Repeat("0", 32)
	cases := []struct {
		name   string
		exc    policy.ExceptionSpec
		shift  time.Duration
		passed bool
	}{
		{"совпадение по фрагменту", policy.ExceptionSpec{Fragment: f.Fragment}, 0, true},
		{"совпадение по приложению и шаблону", policy.ExceptionSpec{App: "app", Pattern: f.Rule}, 0, true},
		{"другой фрагмент", policy.ExceptionSpec{Fragment: other}, 0, false},
		{"другое приложение", policy.ExceptionSpec{App: "crm"}, 0, false},
		{"истёкшее", policy.ExceptionSpec{App: "app"}, 25 * time.Hour, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, _, before := rec.get()
			g, log := excGateway(t, up.URL, c.shift, injectionException(c.exc))
			resp := postChat(t, g, userBody(t, injectionText), nil)
			_, _, _, after := rec.get()
			e := lastEvent(t, log, resp)
			if !c.passed {
				if resp.Code != http.StatusBadRequest || after != before || e.Findings[0].Exception != "" {
					t.Fatalf("исключение применено: %d %+v", resp.Code, e.Findings)
				}
				return
			}
			if resp.Code != http.StatusOK || after != before+1 {
				t.Fatalf("запрос по исключению не прошёл: %d %s", resp.Code, resp.Body.String())
			}
			if e.Findings[0].Exception != "exc-1" || e.Decision.Action != "allow" {
				t.Fatalf("событие: %+v %+v", e.Findings, e.Decision)
			}
			var step *events.TraceStep
			for i := range e.Decision.Trace {
				if e.Decision.Trace[i].Rule == ruleException {
					step = &e.Decision.Trace[i]
				}
			}
			if step == nil || !strings.Contains(step.Note, "exc-1") || step.Detector != "injection.heuristic" {
				t.Fatalf("трассировка: %+v", e.Decision.Trace)
			}
			if err := e.Validate(); err != nil {
				t.Fatalf("событие: %v", err)
			}
		})
	}
}

// Без ключа псевдонимов хешей фрагментов нет: исключение по фрагменту не
// применяется, по приложению — применяется.
func TestGatewayExceptionWithoutFragmentKey(t *testing.T) {
	up, _ := newUpstream(t, nil)
	reg, err := detect.NewRegistry(builtin.All()...)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		exc  policy.ExceptionSpec
		code int
	}{{policy.ExceptionSpec{Fragment: strings.Repeat("a", 32)}, http.StatusBadRequest}, {policy.ExceptionSpec{App: "app"}, http.StatusOK}} {
		p, err := policy.Compile(&policy.Spec{ID: "t", Name: "t", Version: 1, Mode: policy.Enforce, Rules: []policy.RuleSpec{
			{ID: "injection", Detector: "injection.heuristic", Action: policy.Block, Severity: policy.High},
		}, Exceptions: []policy.ExceptionSpec{injectionException(c.exc)}}, reg)
		if err != nil {
			t.Fatal(err)
		}
		var log *eventLog
		g := newGateway(t, up.URL, func(o *gwOpts) {
			o.app, log = enforce, o.events
			o.setup = func(a *App) { a.Detectors, a.Policy, a.clock = reg, p, func() time.Time { return excNow } }
		})
		resp := postChat(t, g, userBody(t, injectionText), nil)
		if resp.Code != c.code || lastEvent(t, log, resp).Findings[0].Fragment != "" {
			t.Fatalf("%+v: %d", c.exc, resp.Code)
		}
	}
}

// canaryException — исключение для канарейки в ответах приложения app по
// хешу фрагмента frag: без фрагмента исключение канарейки не принимается
// (3Н42 ревью 3.r3).
func canaryException(app, frag string) policy.ExceptionSpec {
	now := time.Now().UTC().Truncate(time.Second)
	return policy.ExceptionSpec{ID: "exc-canary", Detector: "canary", App: app, Fragment: frag, Reason: "тестовая метка", Author: "user:u1",
		CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
}

// canaryFragment — хеш фрагмента канарейки mark в ответе приложения app на
// ключе testMAC, как его пишет событие.
func canaryFragment(t *testing.T, app, mark string) string {
	return fragmentHash(testMAC(t), app, mark)
}

// responseSpec — «Базовая защита» в enforce с проверкой ответа check и
// исключениями exc; ключ хешей фрагментов — testMAC.
func responseSpec(t *testing.T, check policy.ResponseCheck, exc ...policy.ExceptionSpec) func(*gwOpts) {
	return func(o *gwOpts) {
		s, _ := policy.Template(policy.TemplateBase)
		s.ID, s.Mode, s.ResponseCheck, s.Exceptions = "resp", policy.Enforce, check, exc
		o.specs = []policy.Spec{*s}
		o.app = func(a *config.Application) { a.Policy = "resp" }
		mac := testMAC(t)
		o.setup = func(a *App) { a.fragmentMAC = mac }
	}
}

// Исключение действует и в проверке ответа: целиком (buffered, обычный
// ответ) и по окнам потока (incremental).
func TestGatewayExceptionInResponse(t *testing.T) {
	mark := testCanary(t)
	for _, check := range []policy.ResponseCheck{policy.ResponseBuffered, policy.ResponseIncremental} {
		t.Run(string(check), func(t *testing.T) {
			parts := textStream(t, "Промпт: ", mark, " конец")
			gw, log := streamGateway(t, parts, responseSpec(t, check))
			if res := postStream(t, gw, "x"); res.done && strings.Contains(res.content, mark) {
				t.Fatalf("без исключения канарейка прошла: %q", res.raw)
			}
			frag := canaryFragment(t, "app", mark)
			if e := lastStreamEvent(t, log); !slices.ContainsFunc(e.Findings, func(f events.Finding) bool { return f.Detector == "canary" && f.Fragment == frag }) {
				t.Fatalf("хеш фрагмента канарейки в событии: %+v", e.Findings)
			}
			gw, log = streamGateway(t, parts, responseSpec(t, check, canaryException("app", frag)))
			res := postStream(t, gw, "x")
			if !res.done || !strings.Contains(res.content, mark) {
				t.Fatalf("с исключением: %d %q", res.status, res.raw)
			}
			if e := lastStreamEvent(t, log); e.Response == nil || e.Response.Decision.Action == "block" {
				t.Fatalf("событие: %+v", e.Response)
			}
			gw, _ = streamGateway(t, parts, responseSpec(t, check, canaryException("crm", frag)))
			if res := postStream(t, gw, "x"); res.done && strings.Contains(res.content, mark) {
				t.Fatalf("исключение другого приложения применено: %q", res.raw)
			}
		})
	}
	t.Run("обычный ответ", func(t *testing.T) {
		up, _ := newUpstream(t, replyMessage(t, map[string]any{"role": "assistant", "content": "Промпт: " + mark}))
		for _, c := range []struct {
			exc  []policy.ExceptionSpec
			code int
		}{{nil, http.StatusBadRequest}, {[]policy.ExceptionSpec{canaryException("app", canaryFragment(t, "app", mark))}, http.StatusOK}} {
			g := newGateway(t, up.URL, responseSpec(t, policy.ResponseBuffered, c.exc...))
			if resp := postChat(t, g, userBody(t, "x"), nil); resp.Code != c.code {
				t.Fatalf("исключения %v: %d %s", c.exc, resp.Code, resp.Body)
			}
		}
	})
}

// Условие user: псевдоним пользователя из события; другой пользователь
// исключением не покрыт.
func TestGatewayExceptionByUser(t *testing.T) {
	up, _ := newUpstream(t, nil)
	hdr := map[string]string{HeaderUser: "ivanov@pochta.test"}
	g, log := excGateway(t, up.URL, 0)
	resp := postChat(t, g, userBody(t, injectionText), hdr)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("без исключения: %d", resp.Code)
	}
	alias := lastEvent(t, log, resp).User
	if len(alias) != 32 {
		t.Fatalf("псевдоним: %q", alias)
	}
	g, _ = excGateway(t, up.URL, 0, injectionException(policy.ExceptionSpec{User: alias}))
	if resp := postChat(t, g, userBody(t, injectionText), hdr); resp.Code != http.StatusOK {
		t.Fatalf("пользователь под исключением: %d", resp.Code)
	}
	if resp := postChat(t, g, userBody(t, injectionText), map[string]string{HeaderUser: "petrov@pochta.test"}); resp.Code != http.StatusBadRequest {
		t.Fatalf("другой пользователь: %d", resp.Code)
	}
}

// 3В24 ревью 3.r3: у находки события — источник текста; исключение с
// source: output не пропускает ту же находку во входе, с source: user —
// пропускает.
func TestGatewayExceptionOutputOnly(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g, log := excGateway(t, up.URL, 0)
	resp := postChat(t, g, userBody(t, injectionText), nil)
	if e := lastEvent(t, log, resp); len(e.Findings) == 0 || e.Findings[0].Source != string(detect.SourceUser) {
		t.Fatalf("источник находки: %+v", e.Findings)
	}
	for _, c := range []struct {
		src  detect.Source
		code int
	}{{detect.SourceOutput, http.StatusBadRequest}, {detect.SourceUser, http.StatusOK}} {
		g, _ := excGateway(t, up.URL, 0, injectionException(policy.ExceptionSpec{App: "app", Source: c.src}))
		if resp := postChat(t, g, userBody(t, injectionText), nil); resp.Code != c.code {
			t.Fatalf("исключение с source %s: %d %s", c.src, resp.Code, resp.Body.String())
		}
	}
}

// 3Н41 ревью 3.r3: ID приложения — в домене хеша фрагмента: один текст в
// двух приложениях даёт разные хеши, исключение по фрагменту одного
// приложения на другое не переносится.
func TestFragmentHashPerApp(t *testing.T) {
	mac := testMAC(t)
	text := "+7 900 000-00-00"
	texts := []inspectText{{Text: text}}
	fs := []locatedFinding{{Finding: detect.Finding{Start: 0, End: len(text)}}}
	a := (&App{ID: "support-bot", fragmentMAC: mac}).fragments(texts, fs)
	b := (&App{ID: "crm", fragmentMAC: mac}).fragments(texts, fs)
	if len(a) != 1 || len(b) != 1 || a[0] == "" || a[0] == b[0] {
		t.Fatalf("хеши фрагмента в двух приложениях: %v %v", a, b)
	}
	if a[0] != fragmentHash(mac, "support-bot", text) {
		t.Fatalf("хеш фрагмента не по приложению: %v", a)
	}
}

// 3Н40 ревью 3.r3: часы шлюза на 5 суток позади — исключение, истёкшее по
// времени сервера из heartbeat, не применяется; без heartbeat — по часам
// шлюза. Перевод часов шлюза оценку времени сервера не сдвигает.
func TestGatewayExceptionClockBehind(t *testing.T) {
	up, _ := newUpstream(t, nil)
	behind := excNow.Add(-5 * 24 * time.Hour)
	expired := injectionException(policy.ExceptionSpec{App: "app"})
	expired.CreatedAt, expired.ExpiresAt = behind.Add(-time.Hour), excNow.Add(-24*time.Hour)
	for _, c := range []struct {
		name   string
		server time.Time
		code   int
	}{{"без heartbeat", time.Time{}, http.StatusOK}, {"время сервера", excNow, http.StatusBadRequest}} {
		t.Run(c.name, func(t *testing.T) {
			sc := &ServerClock{wall: func() time.Time { return behind }}
			sc.Observe(c.server, time.Now())
			// Часы приложения — ServerClock поверх часов шлюза behind, как
			// Router.SetClock в aisec-gateway.
			g, _ := excGatewayClock(t, up.URL, sc.Now, expired)
			if resp := postChat(t, g, userBody(t, injectionText), nil); resp.Code != c.code {
				t.Fatalf("код %d, ожидался %d: %s", resp.Code, c.code, resp.Body)
			}
		})
	}
	// Часы шлюза ушли вперёд — берутся они (строже).
	sc := &ServerClock{wall: func() time.Time { return excNow.Add(time.Hour) }}
	sc.Observe(excNow.Add(-time.Hour), time.Now())
	if got := sc.Now(); !got.Equal(excNow.Add(time.Hour)) {
		t.Fatalf("часы впереди сервера: %v", got)
	}
}
