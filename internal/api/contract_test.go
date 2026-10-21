package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Контрактные тесты: маршруты сервера и спецификация api/openapi.yaml
// сверяются в обе стороны, ответы — со схемой Problem.

type spec struct {
	Paths      map[string]map[string]operation `yaml:"paths"`
	Components struct {
		Schemas map[string]struct {
			Required   []string                  `yaml:"required"`
			Properties map[string]map[string]any `yaml:"properties"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

type operation struct {
	Security   []map[string]any          `yaml:"security"`
	Permission string                    `yaml:"x-permission"`
	Parameters []map[string]any          `yaml:"parameters"`
	Responses  map[string]map[string]any `yaml:"responses"`
}

func loadSpec(t *testing.T) spec {
	t.Helper()
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var s spec
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// serverOwned — пути спецификации, которые обслуживает aisec-server.
func serverOwned(p string) bool {
	return p == "/healthz" || p == "/readyz" || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/internal/")
}

func TestRoutesMatchSpec(t *testing.T) {
	s := loadSpec(t)
	_, rt := newHandler(t, Options{})
	registered := map[string]Route{}
	for _, r := range rt.Routes() {
		registered[strings.ToLower(r.Method)+" "+r.Path] = r
		op, ok := s.Paths[r.Path][strings.ToLower(r.Method)]
		if !ok {
			t.Errorf("маршрут %s %s не описан в openapi.yaml", r.Method, r.Path)
			continue
		}
		if _, ok := op.Responses["429"]; !ok {
			t.Errorf("%s %s: не описан ответ 429 (ЗИ.6)", r.Method, r.Path)
		}
		if !r.Public {
			for _, code := range []string{"401", "403"} {
				if _, ok := op.Responses[code]; !ok {
					t.Errorf("%s %s: не описан ответ %s", r.Method, r.Path, code)
				}
			}
			// Разрешение в спецификации совпадает с разрешением маршрута (УПД.3).
			if op.Permission != r.Permission {
				t.Errorf("%s %s: x-permission %q, а у маршрута %q", r.Method, r.Path, op.Permission, r.Permission)
			}
			if _, ok := auth.LookupPermission(r.Permission); !ok && r.Permission != auth.PermSelf && r.Permission != auth.PermSession {
				t.Errorf("%s %s: разрешения %q нет в каталоге", r.Method, r.Path, r.Permission)
			}
			// Токен API указан в security ровно у операций, доступных токену (ИАФ.9).
			bearer := slices.ContainsFunc(op.Security, func(m map[string]any) bool { _, ok := m["bearerToken"]; return ok })
			if bearer != auth.TokenGrantable(r.Permission) {
				t.Errorf("%s %s: bearerToken в security — %v, а токену разрешение %q доступно — %v",
					r.Method, r.Path, bearer, r.Permission, auth.TokenGrantable(r.Permission))
			}
		} else if op.Security == nil || len(op.Security) != 0 || op.Permission != "" {
			t.Errorf("%s %s: открытый маршрут должен иметь security: [] и не иметь x-permission", r.Method, r.Path)
		}
		if r.Idempotent && !slices.ContainsFunc(op.Parameters, func(p map[string]any) bool {
			ref, _ := p["$ref"].(string)
			return strings.HasSuffix(ref, "/parameters/IdempotencyKey")
		}) {
			t.Errorf("%s %s: не описан параметр Idempotency-Key", r.Method, r.Path)
		}
	}
	for path, ops := range s.Paths {
		if !serverOwned(path) {
			continue
		}
		for method := range ops {
			if _, ok := registered[method+" "+path]; !ok {
				t.Errorf("в openapi.yaml есть %s %s, а обработчика нет", strings.ToUpper(method), path)
			}
		}
	}
}

// Ответы с ошибкой соответствуют схеме Problem, а код ответа описан в спецификации.
func TestProblemResponsesMatchSpec(t *testing.T) {
	s := loadSpec(t)
	problem := s.Components.Schemas["Problem"]
	if len(problem.Required) == 0 {
		t.Fatal("в спецификации нет схемы Problem")
	}
	h, rt := newHandler(t, Options{Ready: func(_ context.Context) error { return errTest }})
	for _, r := range rt.Routes() {
		w := do(h, r.Method, strings.ReplaceAll(r.Path, "{id}", "x"), "")
		if w.Code < 400 {
			continue
		}
		op := s.Paths[r.Path][strings.ToLower(r.Method)]
		if _, ok := op.Responses[strconv.Itoa(w.Code)]; !ok {
			t.Errorf("%s %s: ответ %d не описан в спецификации", r.Method, r.Path, w.Code)
		}
		checkProblemBody(t, problem.Required, problem.Properties, w.Body.Bytes())
	}
	// Ошибки маршрутизатора и ограничителя.
	for _, w := range []*httptest.ResponseRecorder{
		do(h, "GET", "/api/v1/nope", ""), do(h, "DELETE", "/healthz", ""),
	} {
		checkProblemBody(t, problem.Required, problem.Properties, w.Body.Bytes())
	}
}

func checkProblemBody(t *testing.T, required []string, props map[string]map[string]any, body []byte) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("тело ошибки не JSON: %v", err)
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			t.Errorf("в ошибке нет обязательного поля %s: %s", k, body)
		}
	}
	for k := range m {
		if _, ok := props[k]; !ok {
			t.Errorf("поле %s не описано в схеме Problem", k)
		}
	}
	// Коды ошибок из кода и из спецификации совпадают.
	enum, _ := props["code"]["enum"].([]any)
	code, _ := m["code"].(string)
	found := false
	for _, e := range enum {
		found = found || e == code
	}
	if !found {
		t.Errorf("код %q не входит в enum схемы Problem", code)
	}
	if m["type"] != problemTypeBase+code {
		t.Errorf("type %v не соответствует коду %s", m["type"], code)
	}
}

func TestAllProblemCodesDocumented(t *testing.T) {
	s := loadSpec(t)
	enum, _ := s.Components.Schemas["Problem"].Properties["code"]["enum"].([]any)
	for code := range problemTitles {
		found := false
		for _, e := range enum {
			found = found || e == code
		}
		if !found {
			t.Errorf("код %s не описан в openapi.yaml", code)
		}
	}
	if len(enum) != len(problemTitles) {
		t.Errorf("в спецификации %d кодов, в коде %d", len(enum), len(problemTitles))
	}
}
