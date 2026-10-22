package incidents

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// controlFree — в тексте нет управляющих символов, кроме перевода строки и
// табуляции в многострочных полях.
func controlFree(s string, multiline bool) bool {
	for _, r := range s {
		allowed := multiline && (r == '\n' || r == '\t' || r == '\r')
		if r < 0x20 && !allowed || r == 0x7f {
			return false
		}
	}
	return utf8.ValidString(s)
}

// Разбор тел создания, комментария и инструкции: принятое тело укладывается
// в пределы полей и не содержит управляющих символов; разбор не паникует.
func FuzzIncidentInputs(f *testing.F) {
	for _, s := range []string{`{"title":"Утечка","severity":"high","category":"pii_leak"}`,
		`{"alert_id":"01900000-0000-7000-8000-0000000000a1"}`, `{"reopen_of":"x","alert_id":"y"}`,
		`{"body":"Смотрю журнал\nшлюза","replaces":"01900000-0000-7000-8000-0000000000c1"}`, `{"body":"   "}`,
		`{"body":"Сменить канарейку","version":1}`, `{"title":"\u0000","severity":"urgent"}`, `{"version":-1}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var c CreateInput
		if json.Unmarshal(raw, &c) == nil && parseCreate(c) == nil {
			if utf8.RuneCountInString(c.Title) > MaxTitle || !controlFree(c.Title, false) {
				t.Fatalf("название %q", c.Title)
			}
			if c.AlertID != "" && c.ReopenOf != "" || c.AlertID != "" && !validID(c.AlertID) {
				t.Fatalf("источник %+v", c)
			}
			if c.AlertID == "" && c.ReopenOf == "" && (c.Title == "" || !validSeverity(c.Severity)) {
				t.Fatalf("ручное создание %+v", c)
			}
		}
		var m CommentInput
		if json.Unmarshal(raw, &m) == nil && parseComment(m) == nil {
			if strings.TrimSpace(m.Body) == "" || utf8.RuneCountInString(m.Body) > MaxComment || !controlFree(m.Body, true) {
				t.Fatalf("комментарий %q", m.Body)
			}
		}
		var in InstructionsInput
		if json.Unmarshal(raw, &in) == nil && parseInstructions(in) == nil {
			if in.Version < 1 || utf8.RuneCountInString(in.Body) > MaxInstructions || !controlFree(in.Body, true) {
				t.Fatalf("инструкция %+v", in)
			}
		}
	})
}
