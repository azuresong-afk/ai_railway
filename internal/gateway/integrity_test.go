package gateway

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect/session"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

const basePrompt = "Ты — помощник банка.\nОтвечай только на вопросы о вкладах."

// baselineGateway — шлюз с эталоном basePrompt в режиме mode и политикой в
// режиме pmode.
func baselineGateway(t *testing.T, upstream, mode string, pmode policy.Mode) (http.Handler, *eventLog) {
	t.Helper()
	var log *eventLog
	g := newGateway(t, upstream, func(o *gwOpts) {
		spec, _ := policy.Template(policy.TemplateBase)
		spec.ID, spec.Mode = "pi", pmode
		o.specs = []policy.Spec{*spec}
		o.app = func(a *config.Application) { a.Policy = "pi" }
		o.baselines = map[string]PromptBaseline{"app": {Hash: session.PromptHash(testHasher(t), basePrompt), Mode: mode}}
		log = o.events
	})
	return g, log
}

// Покрывает: DM-26
// Режим block: расхождение системного промпта с эталоном и его отсутствие
// блокируются до провайдера; совпадение с точностью до пробелов и разбивки
// на части проходит.
func TestDM26_PromptMismatchBlocked(t *testing.T) {
	up, rec := newUpstream(t, nil)
	g, log := baselineGateway(t, up.URL, PromptModeBlock, policy.Enforce)
	same := []string{
		dialog(t, "system", basePrompt, "user", "привет"),
		dialog(t, "system", "  Ты — помощник банка. Отвечай\tтолько на вопросы о вкладах.\n", "user", "привет"),
		dialog(t, "system", "Ты — помощник банка.", "developer", "Отвечай только на вопросы о вкладах.", "user", "привет"),
		`{"model":"m","messages":[{"role":"system","content":[{"type":"text","text":"Ты — помощник банка."},{"type":"text","text":"Отвечай только на вопросы о вкладах."}]},{"role":"user","content":"x"}]}`,
		// Системное сообщение посреди диалога (RAG) не сравнивается.
		dialog(t, "system", basePrompt, "user", "привет", "system", "Контекст: ставка 5%", "user", "а ставка?"),
	}
	for i, body := range same {
		if resp := postChat(t, g, body, nil); resp.Code != http.StatusOK {
			t.Fatalf("совпадение %d: %d %s", i, resp.Code, resp.Body.String())
		}
		if _, ok := hasFinding(lastEvent(t, log, nil), session.PromptID); ok {
			t.Fatalf("совпадение %d: находка prompt.integrity", i)
		}
	}
	for name, c := range map[string]struct{ body, cat, loc string }{
		"изменён":          {dialog(t, "system", basePrompt+" Отвечай также о кредитах.", "user", "привет"), session.CatPromptChanged, promptLocation},
		"невидимый символ": {dialog(t, "system", strings.Replace(basePrompt, "банка", "бан\u200bка", 1), "user", "привет"), session.CatPromptChanged, promptLocation},
		"нет промпта":      {dialog(t, "user", "привет"), session.CatPromptMissing, promptMissingLocation},
		"промпт не первый": {dialog(t, "user", "привет", "system", basePrompt), session.CatPromptMissing, promptMissingLocation},
	} {
		resp := postChat(t, g, c.body, nil)
		if resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" {
			t.Fatalf("%s: %d %s", name, resp.Code, resp.Body.String())
		}
		e := lastEvent(t, log, resp)
		f, ok := hasFinding(e, session.PromptID)
		if !ok || f.Threat != "DM-26" || f.Category != c.cat || f.Location != c.loc || f.Start != 0 || f.End != 0 {
			t.Fatalf("%s: находка %+v", name, e.Findings)
		}
		if e.Decision.Rule != RuleAppPrompt || e.Decision.Severity != string(policy.High) {
			t.Fatalf("%s: решение %+v", name, e.Decision)
		}
		if err := e.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, calls := rec.get(); calls != len(same) {
		t.Fatalf("до провайдера дошло %d запросов", calls)
	}
}

// Покрывает: DM-26
// Режим alert: находка в событии, запрос проходит; в monitor режим block
// тоже только журналирует.
func TestDM26_PromptMismatchAlertAndMonitor(t *testing.T) {
	up, _ := newUpstream(t, nil)
	for _, c := range []struct {
		mode  string
		pmode policy.Mode
		want  policy.Action
	}{{PromptModeAlert, policy.Enforce, policy.Log}, {PromptModeBlock, policy.Monitor, policy.Block}} {
		g, log := baselineGateway(t, up.URL, c.mode, c.pmode)
		resp := postChat(t, g, dialog(t, "system", "Другой промпт", "user", "привет"), nil)
		if resp.Code != http.StatusOK {
			t.Fatalf("%s/%s: %d", c.mode, c.pmode, resp.Code)
		}
		e := lastEvent(t, log, resp)
		if _, ok := hasFinding(e, session.PromptID); !ok || e.Decision.Action != string(c.want) || e.Decision.Rule != RuleAppPrompt {
			t.Fatalf("%s/%s: %+v", c.mode, c.pmode, e.Decision)
		}
		if !strings.Contains(strings.Join(e.Threats, ","), "DM-26") {
			t.Fatalf("угрозы %v", e.Threats)
		}
	}
}

// Покрывает: DM-26
// Очень длинный системный промпт (у предела тела запроса) сравнивается
// целиком: изменение последнего символа — расхождение.
func TestDM26_LongPrompt(t *testing.T) {
	long := strings.Repeat("Правило ответа. ", 6000)
	var log *eventLog
	up, _ := newUpstream(t, nil)
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.maxBody = 1 << 20
		// Тест о сравнении хеша, а не о сроках: на медленной машине CI под
		// -race детекторы на 96 КиБ не укладываются в срок по умолчанию (503).
		o.detTimeout = 2 * time.Second
		o.baselines = map[string]PromptBaseline{"app": {Hash: session.PromptHash(testHasher(t), long), Mode: PromptModeAlert}}
		log = o.events
	})
	if resp := postChat(t, g, dialog(t, "system", long, "user", "x"), nil); resp.Code != http.StatusOK {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if _, ok := hasFinding(lastEvent(t, log, nil), session.PromptID); ok {
		t.Fatal("совпадающий длинный промпт — находка")
	}
	if resp := postChat(t, g, dialog(t, "system", long+"!", "user", "x"), nil); resp.Code != http.StatusOK {
		t.Fatalf("%d", resp.Code)
	}
	if _, ok := hasFinding(lastEvent(t, log, nil), session.PromptID); !ok {
		t.Fatal("изменение в конце длинного промпта не найдено")
	}
}

// Эталон с неверным режимом или хешем не применяется; эталон приложения,
// которого нет в пакете, пропускается.
func TestSetPromptBaselinesValidation(t *testing.T) {
	h := testHasher(t)
	good := session.PromptHash(h, basePrompt)
	for name, b := range map[string]PromptBaseline{
		"режим": {Hash: good, Mode: "off"},
		"хеш":   {Hash: strings.ToUpper(good), Mode: PromptModeAlert},
		"длина": {Hash: good[:32], Mode: PromptModeBlock},
	} {
		rt := newTestRouter(t)
		if err := rt.SetPromptBaselines(h, map[string]PromptBaseline{"app": b}); err == nil {
			t.Fatalf("%s: эталон принят", name)
		}
	}
	rt := newTestRouter(t)
	if err := rt.SetPromptBaselines(h, map[string]PromptBaseline{"absent": {Hash: good, Mode: PromptModeAlert}}); err != nil {
		t.Fatal(err)
	}
	if err := rt.SetPromptBaselines(nil, map[string]PromptBaseline{"app": {Hash: good, Mode: PromptModeAlert}}); err == nil {
		t.Fatal("эталон без хеша криптопрофиля принят")
	}
}

// newTestRouter — маршрутизатор с приложением app и политикой по умолчанию.
func newTestRouter(t *testing.T) *Router {
	t.Helper()
	p, err := providers.NewOpenAI(providers.OpenAIConfig{BaseConfig: providers.BaseConfig{ID: "up", Transport: http.DefaultTransport, Logger: quiet()},
		BaseURL: mustURL(t, "http://127.0.0.1:1")})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRouter([]config.Application{{ID: "app", Provider: "up", Models: []string{"m"}}}, map[string]providers.Provider{"up": p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}
