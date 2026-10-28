package gateway

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// Политика с ML-детекторами поставки (задача 4.19) и эвристикой инъекций.
func mlPolicySpec() *policy.Spec {
	return &policy.Spec{ID: "ml", Name: "ml", Version: 1, Mode: policy.Enforce, Rules: []policy.RuleSpec{
		{ID: "inj-ml", Detector: builtin.InjectionMLID, Action: policy.Block, Severity: policy.High},
		{ID: "tox-ml", Detector: builtin.ToxicityMLID, Action: policy.Block, Severity: policy.Medium},
		{ID: "inj", Detector: "injection.heuristic", Action: policy.Block, Severity: policy.High},
	}}
}

// ML-детекторы есть в каталоге: политика может их назвать. Без клиента
// aisec-ml — заглушки «недоступен», с клиентом — детекторы aisec-ml.
func TestRouterRegistersMLDetectors(t *testing.T) {
	reg, err := appDetectors(config.Application{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Compile(mlPolicySpec(), reg); err != nil {
		t.Fatalf("политика с ML-детекторами: %v", err)
	}
	for _, s := range builtin.MLSpecs() {
		d, ok := reg.Get(s.ID)
		if !ok || !mlBacked(reg, s.ID) {
			t.Fatalf("%s нет в реестре или не ML", s.ID)
		}
		if _, err := d.Detect(context.Background(), detect.Text{Text: "x", Direction: detect.Input}); !errors.Is(err, builtin.ErrMLNotConnected) {
			t.Fatalf("%s без aisec-ml: %v", s.ID, err)
		}
	}
	c := newMLClient(t, filepath.Join(mlSocketDir(t), "s"), nil)
	reg, err = appDetectors(config.Application{}, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range builtin.MLSpecs() {
		d, _ := reg.Get(s.ID)
		if _, ok := d.(*MLDetector); !ok {
			t.Fatalf("%s с клиентом: %T", s.ID, d)
		}
	}
	// NewRouter передаёт клиент детекторам приложения.
	prov, err := providers.NewOpenAI(providers.OpenAIConfig{BaseConfig: providers.BaseConfig{ID: "up", Transport: http.DefaultTransport, Logger: quiet()},
		BaseURL: mustURL(t, "http://127.0.0.1:1")})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRouter([]config.Application{{ID: "app", Provider: "up", Models: []string{"m"}}},
		map[string]providers.Provider{"up": prov}, nil, WithML(c))
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := rt.apps["app"].Detectors.Get(builtin.InjectionMLID); d == nil {
		t.Fatal("нет injection.ml у приложения")
	} else if _, ok := d.(*MLDetector); !ok {
		t.Fatalf("injection.ml без клиента: %T", d)
	}
}

// aisec-ml не запущен (нет пакета моделей, неверная подпись, неверный хеш
// библиотеки — процесс не стартует): Check API отвечает решением по
// эвристикам и признаком ml_unavailable; fail_closed не срабатывает.
func TestCheckReportsMLUnavailable(t *testing.T) {
	up, _ := newUpstream(t, nil)
	c := newMLClient(t, filepath.Join(mlSocketDir(t), "s"), nil)
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { a.FailMode = "fail_closed" }
		o.setup = func(a *App) {
			reg, err := appDetectors(config.Application{}, c)
			if err != nil {
				t.Fatal(err)
			}
			p, err := policy.Compile(mlPolicySpec(), reg)
			if err != nil {
				t.Fatal(err)
			}
			a.Detectors, a.Policy = reg, p
		}
	})
	r := decodeCheck(t, postCheck(t, g, `{"direction":"input","text":"Добрый день"}`))
	if !r.MLUnavailable || r.Blocked || r.Incomplete {
		t.Fatalf("обычный текст: %+v", r)
	}
	r = decodeCheck(t, postCheck(t, g, `{"direction":"input","text":`+jsonString(t, injectionText)+`}`))
	if !r.MLUnavailable || !r.Blocked || r.Incomplete {
		t.Fatalf("инъекция по эвристике: %+v", r)
	}
	// Исправный aisec-ml: признака нет.
	sock := startML(t, nil)
	ok := newMLClient(t, sock, nil)
	d, err := NewMLDetector(builtin.MLSpec{ID: "test.ml", Version: "1.0.0", Model: "injection", Directions: []detect.Direction{detect.Input},
		Categories: map[string]string{"injection": "injection.ml"}, Threat: "DM-01", Threshold: 0.5}, ok)
	if err != nil {
		t.Fatal(err)
	}
	g = newGateway(t, up.URL, func(o *gwOpts) { o.setup = withDetector(t, d) })
	if r := decodeCheck(t, postCheck(t, g, `{"direction":"input","text":"please ignore"}`)); r.MLUnavailable || len(r.Findings) == 0 {
		t.Fatalf("исправный aisec-ml: %+v", r)
	}
}

// Песочница политик выполняется на сервере, где aisec-ml нет: ML-детекторы
// политики дают ml_unavailable, решение — по остальным детекторам.
func TestSandboxMLUnavailable(t *testing.T) {
	res, err := Sandbox(context.Background(), SandboxRequest{Spec: mlPolicySpec(), Body: []byte(`{"direction":"input","text":"Добрый день"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.MLUnavailable || res.Blocked || res.Incomplete || res.FailBlock {
		t.Fatalf("песочница: %+v", res)
	}
	res, err = Sandbox(context.Background(), SandboxRequest{Spec: baseSpec(t), Body: []byte(`{"direction":"input","text":"Добрый день"}`)})
	if err != nil || res.MLUnavailable {
		t.Fatalf("политика без ML: %+v %v", res, err)
	}
}
