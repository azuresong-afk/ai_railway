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
		Decision: &Decision{Action: "block", Applied: []string{"pseudonymize"}, Policy: "base", PolicyVersion: 1, Rule: "injection",
			FailMode: "fail_open", Failures: []DetectorFailure{{Detector: "lists", Location: "messages[0].content", Reason: FailureTimeout}}},
		Threats:    []string{"DM-01", "DM-31"},
		Findings:   []Finding{{Detector: "pii.ru", Threat: "DM-31", Score: 1}},
		Content:    &Content{Request: "Позвоните [[PHONE_1]]"},
		Response:   &Response{Mode: ResponseIncremental, Cut: true, Decision: &Decision{Action: "block", Applied: []string{"block"}, Rule: "canary"}},
		Pseudonyms: &Pseudonyms{Issued: 1, Pseudonymized: 1, Restored: 1},
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
		"нет ID":             func(e *Event) { e.ID = "" },
		"тип":                func(e *Event) { e.Type = "other" },
		"нет решения":        func(e *Event) { e.Decision = nil },
		"нет действия":       func(e *Event) { e.Decision.Action = "" },
		"причина сбоя":       func(e *Event) { e.Decision.Failures = []DetectorFailure{{Detector: "pii.ru", Reason: "boom"}} },
		"режим политики":     func(e *Event) { e.PolicyMode = "audit" },
		"режим ответа":       func(e *Event) { e.Response.Mode = "async" },
		"ответ без действия": func(e *Event) { e.Response.Decision.Action = "" },
		"сбой на ответе": func(e *Event) {
			e.Response.Decision.Failures = []DetectorFailure{{Detector: "canary", Reason: "boom"}}
		},
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
	for _, f := range []string{`"policy_mode":"monitor"`, `"applied":["pseudonymize"]`, `"threats":["DM-01","DM-31"]`,
		`"failures":[{"detector":"lists","location":"messages[0].content","reason":"timeout"}]`,
		`"response":{"mode":"incremental","decision":{"action":"block","applied":["block"],"rule":"canary"},"cut":true}`,
		`"pseudonyms":{"issued":1,"pseudonymized":1,"redacted":0,"restored":1,"failed":0}`} {
		if !strings.Contains(string(b), f) {
			t.Errorf("нет %s в %s", f, b)
		}
	}
}
