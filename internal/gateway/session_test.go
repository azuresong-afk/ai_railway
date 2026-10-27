package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/session"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
}

func testProvider(t testing.TB) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testHasher(t testing.TB) aisecCrypto.Hasher {
	t.Helper()
	h, err := testProvider(t).Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// testSessions — сессии на ключе testMAC с часами clock (nil — time.Now).
func testSessions(t *testing.T, maxSessions int, clock *fakeClock) *Sessions {
	t.Helper()
	cfg := SessionConfig{Provider: testProvider(t), MAC: testMAC(t), MaxSessions: maxSessions}
	if clock != nil {
		cfg.Now = clock.now
	}
	s, err := NewSessions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// sessionPolicy — базовая политика в enforce, где инъекция только
// журналируется (решает session.risk), с правилами rules в конце.
func sessionPolicy(t *testing.T, s *Sessions, rules ...policy.RuleSpec) func(*gwOpts) {
	return func(o *gwOpts) {
		spec, _ := policy.Template(policy.TemplateBase)
		spec.ID, spec.Mode = "sess", policy.Enforce
		for i := range spec.Rules {
			if spec.Rules[i].Detector == "injection.heuristic" {
				spec.Rules[i].Action = policy.Log
			}
		}
		spec.Rules = append(spec.Rules, rules...)
		o.specs = []policy.Spec{*spec}
		o.app = func(a *config.Application) { a.Policy = "sess" }
		o.sessions = s
	}
}

func riskRule(action policy.Action, th float64) policy.RuleSpec {
	return policy.RuleSpec{ID: "session-risk", Detector: session.RiskID, Directions: []detect.Direction{detect.Input},
		Threshold: &th, Action: action, Severity: policy.High}
}

func historyRule() policy.RuleSpec {
	return policy.RuleSpec{ID: "history", Detector: session.HistoryID, Directions: []detect.Direction{detect.Input},
		Action: policy.Log, Severity: policy.High}
}

// dialog — тело запроса чата из пар «роль, текст».
func dialog(t *testing.T, msgs ...string) string {
	t.Helper()
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	req := struct {
		Model    string `json:"model"`
		Messages []msg  `json:"messages"`
	}{Model: "m"}
	for i := 0; i+1 < len(msgs); i += 2 {
		req.Messages = append(req.Messages, msg{msgs[i], msgs[i+1]})
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func hasFinding(e events.Event, detector string) (events.Finding, bool) {
	for _, f := range e.Findings {
		if f.Detector == detector {
			return f, true
		}
	}
	return events.Finding{}, false
}

// Покрывает: DM-06
// Серия инъекций в одной сессии: каждая по отдельности только
// журналируется, накопленная оценка доходит до порога правила session.risk
// и блокирует ход. В событии — псевдоним сессии, а не значение заголовка.
func TestDM06_SessionRiskEscalatesToBlock(t *testing.T) {
	clock := newFakeClock()
	s := testSessions(t, 0, clock)
	up, rec := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		sessionPolicy(t, s, riskRule(policy.Block, 0.8))(o)
		log = o.events
	})
	hdr := map[string]string{HeaderSession: "chat-42"}
	var codes []int
	for i := 0; i < 3; i++ {
		clock.advance(time.Minute)
		resp := postChat(t, g, dialog(t, "user", injectionText), hdr)
		codes = append(codes, resp.Code)
		e := lastEvent(t, log, nil)
		if e.Session == nil || e.Session.Source != events.SessionHeader || len(e.Session.ID) != 32 {
			t.Fatalf("ход %d: сессия в событии %+v", i, e.Session)
		}
		if strings.Contains(e.Session.ID, "chat-42") {
			t.Fatal("в событии исходный идентификатор сессии")
		}
		if e.Session.Turns != i+1 || e.Session.Risk <= 0 {
			t.Fatalf("ход %d: risk %v, turns %d", i, e.Session.Risk, e.Session.Turns)
		}
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK || codes[2] != http.StatusBadRequest {
		t.Fatalf("коды ответов %v: первая инъекция проходит, серия блокируется", codes)
	}
	e := lastEvent(t, log, nil)
	f, ok := hasFinding(e, session.RiskID)
	if !ok || f.Threat != "DM-06" || f.Category != session.CatEscalation || f.Location != riskLocation {
		t.Fatalf("находка session.risk: %+v", e.Findings)
	}
	if e.Decision.Rule != "session-risk" {
		t.Fatalf("решение по правилу %q", e.Decision.Rule)
	}
	if _, _, _, calls := rec.get(); calls != 2 {
		t.Fatalf("провайдер получил %d запросов, заблокированный не должен дойти", calls)
	}
	// Другая сессия того же приложения начинает с нуля.
	if resp := postChat(t, g, dialog(t, "user", injectionText), map[string]string{HeaderSession: "chat-43"}); resp.Code != http.StatusOK {
		t.Fatalf("другая сессия: %d", resp.Code)
	}
}

// Покрывает: DM-06
// Прошлые ходы в истории запроса оценку не повторяют: вклад дают только
// сообщения после последнего ответа модели.
func TestDM06_HistoryNotCountedAgain(t *testing.T) {
	clock := newFakeClock()
	s := testSessions(t, 0, clock)
	up, _ := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		sessionPolicy(t, s, riskRule(policy.Block, 0.8))(o)
		log = o.events
	})
	hdr := map[string]string{HeaderSession: "s1"}
	if resp := postChat(t, g, dialog(t, "user", injectionText), hdr); resp.Code != http.StatusOK {
		t.Fatalf("первый ход: %d", resp.Code)
	}
	first := lastEvent(t, log, nil).Session.Risk
	msgs := []string{"user", injectionText}
	for i := 0; i < 5; i++ {
		msgs = append(msgs, "assistant", "ответ", "user", "спасибо, а какая погода?")
		if resp := postChat(t, g, dialog(t, msgs...), hdr); resp.Code != http.StatusOK {
			t.Fatalf("ход %d с инъекцией только в истории: %d", i, resp.Code)
		}
	}
	if risk := lastEvent(t, log, nil).Session.Risk; risk > first {
		t.Fatalf("оценка выросла от истории: %v > %v", risk, first)
	}
}

// Покрывает: DM-06
// Затухание до нуля: за много периодов полураспада оценка уходит в ноль,
// а сессия старше TTL начинается заново.
func TestDM06_RiskDecaysToZero(t *testing.T) {
	clock := newFakeClock()
	s := testSessions(t, 0, clock)
	key := "app\x00k"
	r1, _ := s.observe(key, 1)
	clock.advance(DefaultRiskHalfLife)
	r2, _ := s.observe(key, 0)
	if r1 <= 0 || r2 > r1/2+1e-9 || r2 < r1/2-1e-9 {
		t.Fatalf("за полураспад: %v → %v", r1, r2)
	}
	clock.advance(40 * DefaultRiskHalfLife)
	if r, _ := s.observe(key, 0); r != 0 {
		t.Fatalf("после 40 полураспадов оценка %v, ожидался 0", r)
	}
	clock.advance(DefaultSessionTTL + time.Second)
	if r, turns := s.observe(key, 0.6); turns != 1 || math.Abs(r-0.6/riskSaturation) > 1e-9 {
		t.Fatalf("после TTL сессия не началась заново: risk %v, turns %d", r, turns)
	}
	// Сессия без находок состояния не заводит.
	if _, turns := s.observe("app\x00clean", 0); turns != 0 || s.Len() != 1 {
		t.Fatalf("сессия без находок: turns %d, сессий %d", turns, s.Len())
	}
}

// Покрывает: DM-06
// Переполнение: сессий не больше предела, вытесняется та, что дольше всех
// не обновлялась; устаревшие по TTL забываются первыми.
func TestDM06_SessionLimitEvictsOldest(t *testing.T) {
	clock := newFakeClock()
	s := testSessions(t, 3, clock)
	for i := 0; i < 3; i++ {
		clock.advance(time.Second)
		s.observe(fmt.Sprint("k", i), 1)
	}
	clock.advance(time.Second)
	s.observe("k0", 1) // k0 обновлена — самая старая теперь k1
	for i := 3; i < 10; i++ {
		clock.advance(time.Second)
		s.observe(fmt.Sprint("k", i), 1)
		if s.Len() > 3 {
			t.Fatalf("сессий %d при пределе 3", s.Len())
		}
	}
	if _, ok := s.byKey["k1"]; ok {
		t.Fatal("не вытеснена самая старая сессия")
	}
	if _, turns := s.observe("k9", 1); turns != 2 {
		t.Fatalf("свежая сессия вытеснена: turns %d", turns)
	}
	clock.advance(DefaultSessionTTL + time.Hour)
	s.observe("fresh", 1)
	if s.Len() != 1 {
		t.Fatalf("устаревшие сессии не забыты: %d", s.Len())
	}
}

// Сессия запроса: заголовок — 1–128 байт из [A-Za-z0-9._:-], один; неверный
// — 400 invalid_session без эха значения, и запрос до провайдера не доходит.
// Заголовок проверяется и у шлюза без сессий.
func TestSessionHeaderValidation(t *testing.T) {
	up, rec := newUpstream(t, nil)
	for _, withSessions := range []bool{true, false} {
		g := newGateway(t, up.URL, func(o *gwOpts) {
			if withSessions {
				o.sessions = testSessions(t, 0, nil)
			}
		})
		for _, bad := range []string{"", strings.Repeat("a", MaxSessionIDLength+1), "сессия", "a b", "a/b", "секрет-<script>"} {
			req := postChatReq(t, g, chatBody, http.Header{HeaderSession: {bad}})
			if req.Code != http.StatusBadRequest || errCode(t, req) != "invalid_session" {
				t.Fatalf("%q: %d %s", bad, req.Code, req.Body.String())
			}
			if bad != "" && strings.Contains(req.Body.String(), bad) {
				t.Fatalf("значение заголовка в ответе: %s", req.Body.String())
			}
		}
		if resp := postChatReq(t, g, chatBody, http.Header{HeaderSession: {"a", "b"}}); resp.Code != http.StatusBadRequest {
			t.Fatalf("два заголовка: %d", resp.Code)
		}
		for _, good := range []string{"a", strings.Repeat("Z", MaxSessionIDLength), "conv_1:part-2.x"} {
			if resp := postChat(t, g, chatBody, map[string]string{HeaderSession: good}); resp.Code != http.StatusOK {
				t.Fatalf("%q: %d", good, resp.Code)
			}
		}
	}
	if _, _, _, calls := rec.get(); calls != 6 {
		t.Fatalf("до провайдера дошло %d запросов, ожидалось 6", calls)
	}
}

// postChatReq — запрос чата с заголовками, в том числе повторяющимися.
func postChatReq(t *testing.T, h http.Handler, body string, hdr http.Header) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Отпечаток без заголовка: тот же диалог — та же сессия, другой
// пользователь, приложение или начало диалога — другая.
func TestSessionFingerprint(t *testing.T) {
	s := testSessions(t, 0, nil)
	parse := func(body string) *chat.Request {
		req, err := chat.Parse([]byte(body), chat.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	start := dialog(t, "system", "Ты помощник", "user", "привет")
	cont := dialog(t, "system", "Ты помощник", "user", "привет", "assistant", "здравствуйте", "user", "дальше")
	id := func(app, user, body string) string {
		rs, err := s.identify(app, user, nil, parse(body))
		if err != nil {
			t.Fatal(err)
		}
		if rs.ev.Source != events.SessionFingerprint {
			t.Fatalf("источник %q", rs.ev.Source)
		}
		return rs.ev.ID
	}
	a := id("app", "u1", start)
	if b := id("app", "u1", cont); a != b {
		t.Fatal("продолжение диалога — другая сессия")
	}
	for name, other := range map[string]string{
		"пользователь": id("app", "u2", start),
		"приложение":   id("app2", "u1", start),
		"начало":       id("app", "u1", dialog(t, "system", "Ты помощник", "user", "добрый день")),
	} {
		if other == a {
			t.Fatalf("%s другой, сессия та же", name)
		}
	}
	// Заголовок и отпечаток не пересекаются, в разных приложениях — разные.
	rs, err := s.identify("app", "u1", []string{"x"}, parse(start))
	if err != nil {
		t.Fatal(err)
	}
	rs2, err := s.identify("app2", "u1", []string{"x"}, parse(start))
	if err != nil {
		t.Fatal(err)
	}
	if rs.ev.ID == a || rs.ev.ID == rs2.ev.ID || rs.ev.Source != events.SessionHeader {
		t.Fatal("псевдонимы заголовка и отпечатка совпадают")
	}
	// Пробелы в начале диалога сессию не меняют (ревью B2, п. 2).
	if b := id("app", "u1", dialog(t, "system", " Ты\n помощник ", "user", "привет  ")); b != a {
		t.Fatal("лишние пробелы начали новую сессию")
	}
	// Отпечаток без пользователя и заголовка — общий (shared), с заголовком — нет.
	shared, err := s.identify("app", "", nil, parse(start))
	if err != nil {
		t.Fatal(err)
	}
	if !shared.shared || rs.shared {
		t.Fatalf("shared: без пользователя %v, с заголовком %v", shared.shared, rs.shared)
	}
}

// Новый ход — после ответа модели перед последней репликой пользователя:
// дописанный в конец ответ ассистента (prefill) ход не обрывает (ревью B2,
// п. 5).
func TestNewTurnFrom(t *testing.T) {
	for name, tc := range map[string]struct {
		msgs []string
		want int
	}{
		"первый ход":  {[]string{"system", "с", "user", "в"}, 0},
		"продолжение": {[]string{"user", "в", "assistant", "о", "user", "в2"}, 2},
		"prefill":     {[]string{"user", "в", "assistant", "о", "user", "в2", "assistant", "Конечно,"}, 2},
		"без user":    {[]string{"system", "с", "assistant", "о"}, 0},
	} {
		req, err := chat.Parse([]byte(dialog(t, tc.msgs...)), chat.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if got := newTurnFrom(req); got != tc.want {
			t.Errorf("%s: %d, нужно %d", name, got, tc.want)
		}
	}
}

// Покрывает: DM-06
// Отпечаток без пользователя и заголовка общий для разных пользователей
// с одинаковым началом диалога: оценка не копится, блокировки нет (ревью
// B2, п. 4). Prefill в конце запроса инъекцию из подсчёта не выводит.
func TestDM06_SharedFingerprintAndPrefill(t *testing.T) {
	clock := newFakeClock()
	s := testSessions(t, 0, clock)
	up, _ := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		sessionPolicy(t, s, riskRule(policy.Block, 0.2))(o)
		log = o.events
	})
	for i := 0; i < 3; i++ {
		clock.advance(time.Minute)
		if resp := postChat(t, g, dialog(t, "user", injectionText), nil); resp.Code != http.StatusOK {
			t.Fatalf("ход %d без заголовка и пользователя: %d", i, resp.Code)
		}
		if e := lastEvent(t, log, nil); e.Session == nil || e.Session.Risk != 0 || e.Session.Source != events.SessionFingerprint {
			t.Fatalf("ход %d: сессия %+v", i, e.Session)
		}
	}
	hdr := map[string]string{HeaderSession: "prefill"}
	clock.advance(time.Minute)
	postChat(t, g, dialog(t, "user", "привет", "assistant", "здравствуйте", "user", injectionText, "assistant", "Конечно,"), hdr)
	if e := lastEvent(t, log, nil); e.Session == nil || e.Session.Risk == 0 {
		t.Fatalf("инъекция перед prefill не учтена: %+v", e.Session)
	}
}

// Покрывает: DM-03
// Шлюз отдаёт хеши реплик истории (если в политике есть правило
// history.integrity) и выданных ответов — в обычном ответе и в потоке.
// Хеш не зависит от пробелов и не совпадает с хешем другой реплики.
func TestDM03_GatewayReportsReplyHashes(t *testing.T) {
	s := testSessions(t, 0, nil)
	up, _ := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		sessionPolicy(t, s, historyRule())(o)
		log = o.events
	})
	hdr := map[string]string{HeaderSession: "h1"}
	if resp := postChat(t, g, dialog(t, "user", "привет"), hdr); resp.Code != http.StatusOK {
		t.Fatalf("%d", resp.Code)
	}
	e := lastEvent(t, log, nil)
	issued := s.replyHash("ответ")
	if len(e.Session.History) != 0 || len(e.Session.Issued) != 1 || e.Session.Issued[0] != issued {
		t.Fatalf("первый ход: %+v", e.Session)
	}
	body := dialog(t, "user", "привет", "assistant", "  ответ\n", "user", "ещё", "assistant", "другое", "user", "x")
	if resp := postChat(t, g, body, hdr); resp.Code != http.StatusOK {
		t.Fatalf("%d", resp.Code)
	}
	e = lastEvent(t, log, nil)
	h := e.Session.History
	if len(h) != 2 || h[0].Message != 1 || h[0].Hash != issued || h[1].Message != 3 || h[1].Hash == issued {
		t.Fatalf("история: %+v", h)
	}
	if e.Session.HistoryRule != "history" || e.Session.HistoryAction != "log" || e.Session.HistorySeverity != "high" {
		t.Fatalf("правило истории: %+v", e.Session)
	}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}

	// Поток: хеш собранной реплики, как её получило приложение.
	sup := sseUpstream(t, []string{chunk("от"), chunk("вет") + "data: [DONE]\n\n"}, nil)
	var slog *eventLog
	sg := newGateway(t, sup.URL, func(o *gwOpts) {
		sessionPolicy(t, s, historyRule())(o)
		slog = o.events
	})
	if resp := postChat(t, sg, `{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}`, hdr); resp.Code != http.StatusOK {
		t.Fatalf("поток: %d", resp.Code)
	}
	if e := lastEvent(t, slog, nil); len(e.Session.Issued) != 1 || e.Session.Issued[0] != issued {
		t.Fatalf("поток: выдано %+v", e.Session)
	}
}

// Покрывает: DM-03
// Без правила history.integrity в политике хешей истории в событии нет,
// пустая история — тоже без хешей.
func TestDM03_NoHistoryWithoutRule(t *testing.T) {
	s := testSessions(t, 0, nil)
	up, _ := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		sessionPolicy(t, s)(o)
		log = o.events
	})
	body := dialog(t, "user", "привет", "assistant", "ответ", "user", "x")
	if resp := postChat(t, g, body, nil); resp.Code != http.StatusOK {
		t.Fatalf("%d", resp.Code)
	}
	if e := lastEvent(t, log, nil); len(e.Session.History) != 0 || len(e.Session.Issued) != 0 || e.Session.HistoryRule != "" {
		t.Fatalf("история без правила: %+v", e.Session)
	}
	if got := s.history(&chat.Request{}); got != nil {
		t.Fatalf("пустая история: %+v", got)
	}
}

func FuzzSessionHeader(f *testing.F) {
	for _, s := range []string{"", "a", "conv_1:part-2.x", strings.Repeat("a", 129), "сессия", "a\x00b", "a b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		id, err := parseSessionHeader([]string{v})
		if err != nil {
			// Ошибка — постоянный текст: значение заголовка в ответ не попадает.
			if !errors.Is(err, errSessionHeader) {
				t.Fatalf("ошибка %v", err)
			}
			return
		}
		if id != v || len(v) == 0 || len(v) > MaxSessionIDLength {
			t.Fatalf("принято %q", v)
		}
		for _, c := range []byte(v) {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", rune(c)) {
				t.Fatalf("принят символ %q", c)
			}
		}
	})
}
