package events

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func request() *Event {
	return &Event{
		ID: "0192f1a0-7b3c-7d4e-8f00-000000000000", Time: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
		Type: TypeGatewayRequest, App: "app", PolicyMode: ModeMonitor, Storage: StorageMasked,
		Decision: &Decision{Action: "block", Applied: []string{"pseudonymize"}},
		Threats:  []string{"DM-01", "DM-31"},
		Findings: []Finding{{Detector: "pii.ru", Threat: "DM-31", Score: 1}},
		Content:  &Content{Request: "Позвоните [[PHONE_1]]"},
	}
}

func TestValidateOK(t *testing.T) {
	if err := request().Validate(); err != nil {
		t.Fatal(err)
	}
	af := &Event{ID: "x", Time: time.Now(), Type: TypeAuthFailure, AuthFailure: &AuthFailure{RemoteAddr: "10.0.0.1", KeyPrefix: "aisec_abcd1234", Reason: "revoked"}}
	if err := af.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := map[string]func(*Event){
		"нет ID":            func(e *Event) { e.ID = "" },
		"тип":               func(e *Event) { e.Type = "other" },
		"нет решения":       func(e *Event) { e.Decision = nil },
		"режим политики":    func(e *Event) { e.PolicyMode = "audit" },
		"full":              func(e *Event) { e.Storage = StorageFull },
		"none с содержимым": func(e *Event) { e.Storage = StorageNone },
		"режим хранения":    func(e *Event) { e.Storage = "all" },
		"категория":         func(e *Event) { e.Threats = []string{"LLM01"} },
		"категория находки": func(e *Event) { e.Findings[0].Threat = "Б1" },
		"auth без причины":  func(e *Event) { e.Type = TypeAuthFailure; e.AuthFailure = &AuthFailure{} },
		"auth с содержимым": func(e *Event) { e.Type = TypeAuthFailure; e.AuthFailure = &AuthFailure{Reason: "r"} },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			e := request()
			edit(e)
			if err := e.Validate(); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
}

func TestJSONFieldNames(t *testing.T) {
	b, err := json.Marshal(request())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{`"policy_mode":"monitor"`, `"applied":["pseudonymize"]`, `"threats":["DM-01","DM-31"]`} {
		if !strings.Contains(string(b), f) {
			t.Errorf("нет %s в %s", f, b)
		}
	}
}
