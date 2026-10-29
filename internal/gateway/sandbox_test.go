package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

func baseSpec(t *testing.T) *policy.Spec {
	t.Helper()
	reg, err := appDetectors(config.Application{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := policy.TemplateFor(policy.TemplateBase, reg)
	if !ok {
		t.Fatal("нет шаблона base")
	}
	if len(builtin.All()) == 0 {
		t.Fatal("нет встроенных детекторов")
	}
	return s
}

// Песочница даёт те же решение, находки и преобразованный текст, что Check
// API шлюза на том же тексте и той же политике, и не пишет событий.
func TestSandboxMatchesCheckAPI(t *testing.T) {
	bodies := []string{
		`{"direction":"input","text":` + jsonString(t, "Документ. "+injectionText) + `}`,
		`{"direction":"input","messages":[{"role":"user","content":` + jsonString(t, "Напишите на "+piiEmail) + `},{"role":"tool","content":"ok"}]}`,
		`{"direction":"output","text":"Обычный ответ без находок."}`,
	}
	blocked, changed := 0, 0
	for _, mode := range []string{"enforce", "monitor"} {
		for _, body := range bodies {
			up, upRec := newUpstream(t, nil)
			var log *eventLog
			g := newGateway(t, up.URL, func(o *gwOpts) {
				o.maxBody = 1 << 16
				o.app = func(a *config.Application) { a.PolicyMode = mode }
				log = o.events
			})
			resp := postCheck(t, g, body)
			if resp.Code != http.StatusOK {
				t.Fatalf("%s: Check API %d %s", mode, resp.Code, resp.Body.String())
			}
			want := decodeCheck(t, resp)
			before := len(log.all())

			res, err := Sandbox(context.Background(), SandboxRequest{Spec: baseSpec(t), App: config.Application{PolicyMode: mode},
				External: true, Body: []byte(body)})
			if err != nil {
				t.Fatal(err)
			}
			if res.Decision != want.Decision || string(res.Action) != want.Action || res.Blocked != want.Blocked ||
				res.Message != want.Message || res.Unchecked != want.Unchecked || res.Incomplete != want.Incomplete {
				t.Fatalf("%s %s: песочница %+v, Check API %+v", mode, body, res, want)
			}
			if len(res.Findings) != len(want.Findings) {
				t.Fatalf("%s %s: находок %d, в Check API %d", mode, body, len(res.Findings), len(want.Findings))
			}
			for i, f := range res.Findings {
				w := want.Findings[i]
				if f.Detector != w.Detector || f.Category != w.Category || f.Start != w.Start || f.End != w.End || f.Location != w.Location {
					t.Fatalf("находка %d: %+v, в Check API %+v", i, f, w)
				}
				if f.Rule == "" || f.Action == "" {
					t.Fatalf("у находки нет правила: %+v", f)
				}
			}
			switch {
			case want.Text != nil:
				if len(res.Texts) != 1 || res.Texts[0].Text != *want.Text || res.Texts[0].Role != "" {
					t.Fatalf("текст: %+v, в Check API %q", res.Texts, *want.Text)
				}
			case want.Messages != nil:
				for i, m := range want.Messages {
					if res.Texts[i].Text != m.Content || res.Texts[i].Role != m.Role {
						t.Fatalf("сообщение %d: %+v, в Check API %+v", i, res.Texts[i], m)
					}
				}
			default:
				if res.Texts != nil {
					t.Fatalf("при блокировке текст возвращён: %+v", res.Texts)
				}
			}
			if len(log.all()) != before || upCalls(upRec) != 0 {
				t.Fatal("песочница записала событие или обратилась к провайдеру")
			}
			if res.Blocked {
				blocked++
			}
			if len(res.Texts) > 0 && res.Texts[0].Changed {
				changed++
			}
		}
	}
	if blocked != 1 || changed != 2 {
		t.Fatalf("блокировок %d, изменённых текстов %d: проверка не задела политику", blocked, changed)
	}
}

func TestSandboxErrors(t *testing.T) {
	spec := baseSpec(t)
	var se *SandboxError
	for _, body := range []string{``, `[]`, `{"direction":"sideways","text":"x"}`, `{"direction":"input"}`,
		`{"direction":"input","text":"x","extra":1}`, `{"direction":"input","text":"a"} {}`} {
		if _, err := Sandbox(context.Background(), SandboxRequest{Spec: spec, Body: []byte(body)}); !errors.As(err, &se) {
			t.Errorf("%q: %v", body, err)
		}
	}
	// Предел сообщений приложения действует и в песочнице.
	msgs := `{"direction":"input","messages":[{"role":"user","content":"a"},{"role":"user","content":"b"}]}`
	if _, err := Sandbox(context.Background(), SandboxRequest{Spec: spec, App: config.Application{Quotas: config.Quotas{MaxMessages: 1}},
		Body: []byte(msgs)}); !errors.As(err, &se) || se.Code == "" {
		t.Fatalf("предел сообщений: %v", err)
	}
	// Правило на категорию словаря, которого у приложения нет, — ошибка политики.
	bad := *spec
	bad.Rules = append(bad.Rules[:len(bad.Rules):len(bad.Rules)], policy.RuleSpec{ID: "list", Detector: lists.ID,
		Categories: []string{"lists.custom"}, Action: policy.Block, Severity: policy.High})
	if _, err := Sandbox(context.Background(), SandboxRequest{Spec: &bad, Body: []byte(`{"direction":"input","text":"x"}`)}); !errors.Is(err, ErrSandboxPolicy) {
		t.Fatalf("неверная политика: %v", err)
	}
	if _, err := Sandbox(context.Background(), SandboxRequest{Body: []byte(`{"direction":"input","text":"x"}`)}); err == nil {
		t.Fatal("без политики")
	}
}

// Словари приложения попадают в детектор lists песочницы.
func TestSandboxAppLists(t *testing.T) {
	spec := baseSpec(t)
	spec.Rules = append(spec.Rules, policy.RuleSpec{ID: "codename", Detector: lists.ID, Categories: []string{"lists.codename"},
		Action: policy.Block, Severity: policy.High})
	app := config.Application{PolicyMode: "enforce", Lists: []lists.Spec{{ID: "codename", Category: "codename", Words: []string{"Северное сияние"}}}}
	res, err := Sandbox(context.Background(), SandboxRequest{Spec: spec, App: app, Body: []byte(`{"direction":"input","text":"Проект Северное сияние"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Blocked || res.Rule != "codename" || len(res.Findings) != 1 || res.Findings[0].Rule != "codename" {
		b, err := json.Marshal(res)
		t.Fatalf("словарь приложения: %s %v", b, err)
	}
}

func upCalls(u *upstreamRecord) int {
	_, _, _, n := u.get()
	return n
}
