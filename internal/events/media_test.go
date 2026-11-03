package events

import (
	"encoding/json"
	"strings"
	"testing"
)

// Проверка изображений в событии (задача 5.39, ADR-0032, раздел 8).

func withMedia() *Event {
	e := request()
	e.Media = []MediaCheck{
		{Location: "messages[0].content[1]", Mode: MediaModeSync, Checked: true, Format: "png", Width: 640, Height: 480, Frames: 1, Texts: 2, LatencyMS: 40},
		{Location: "messages[0].content[2]", Mode: MediaModeSync, Reason: MediaReasonURL},
	}
	e.Decision.MediaUnchecked = true
	e.Findings = append(e.Findings, Finding{Detector: "injection.heuristic", Threat: "DM-45", Score: 1, Source: SourceImage,
		Location: "messages[0].content[1]", Box: &Box{X: 10, Y: 20, W: 300, H: 24}})
	return e
}

func TestValidateMediaOK(t *testing.T) {
	if err := withMedia().Validate(); err != nil {
		t.Fatal(err)
	}
	e := withMedia()
	e.Type = TypeCheck
	if err := e.Validate(); err != nil {
		t.Fatalf("Check API: %v", err)
	}
}

func TestValidateMediaErrors(t *testing.T) {
	cases := map[string]func(*Event){
		"тип события":                            func(e *Event) { e.Type = TypeAuthFailure; e.AuthFailure = &AuthFailure{Reason: "revoked"} },
		"нет места":                              func(e *Event) { e.Media[0].Location = "" },
		"длинное место":                          func(e *Event) { e.Media[0].Location = strings.Repeat("m", maxShort+1) },
		"режим":                                  func(e *Event) { e.Media[0].Mode = "later" },
		"проверено с причиной":                   func(e *Event) { e.Media[0].Reason = MediaReasonTimeout },
		"не проверено без причины":               func(e *Event) { e.Media[1].Reason = "" },
		"неизвестная причина":                    func(e *Event) { e.Media[1].Reason = "boom" },
		"проверено при off":                      func(e *Event) { e.Media[0].Mode = MediaModeOff },
		"формат":                                 func(e *Event) { e.Media[0].Format = "svg" },
		"отрицательная ширина":                   func(e *Event) { e.Media[0].Width = -1 },
		"огромная высота":                        func(e *Event) { e.Media[0].Height = maxBoxCoord + 1 },
		"рамка не у image":                       func(e *Event) { e.Findings[1].Source = "input" },
		"рамка нулевая":                          func(e *Event) { e.Findings[1].Box.W = 0 },
		"рамка отрицательная":                    func(e *Event) { e.Findings[1].Box.X = -5 },
		"media_unchecked без media":              func(e *Event) { e.Media = nil },
		"media_unavailable без сбоя анализатора": func(e *Event) { e.Decision.MediaUnavailable = true },
		"media_unavailable без media_unchecked": func(e *Event) {
			e.Media[1].Reason, e.Decision.MediaUnavailable, e.Decision.MediaUnchecked = MediaReasonOverloaded, true, false
		},
		"слишком много записей": func(e *Event) {
			for len(e.Media) <= MaxMedia {
				e.Media = append(e.Media, e.Media[1])
			}
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			e := withMedia()
			edit(e)
			if err := e.Validate(); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
}

// Имена полей в JSON — контракт с сервером и api/openapi.yaml.
func TestMediaJSONFieldNames(t *testing.T) {
	b, err := json.Marshal(withMedia())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{`"media":[`, `"media_unchecked":true`, `"box":{"x":10,"y":20,"w":300,"h":24}`,
		`"checked":true`, `"reason":"url"`, `"texts":2`} {
		if !strings.Contains(string(b), f) {
			t.Fatalf("нет %s в %s", f, b)
		}
	}
}

// media_unavailable (задача 5.44): допустим вместе с media_unchecked и
// изображением, не проверенным из-за сбоя анализатора; фильтр событий
// находит его по признаку решения.
func TestMediaUnavailableFlag(t *testing.T) {
	for _, reason := range mediaFailureReasons {
		e := withMedia()
		e.Media[1].Reason, e.Decision.MediaUnavailable = reason, true
		if err := e.Validate(); err != nil {
			t.Fatalf("%s: %v", reason, err)
		}
	}
	f, err := ParseFilter(`media_unavailable = true`)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(&Record{Details: &Details{Decision: &Decision{MediaUnavailable: true}}}) || f.Match(&Record{Details: &Details{Decision: &Decision{MediaUnchecked: true}}}) || f.Match(&Record{}) {
		t.Fatal("Match media_unavailable")
	}
	var b strings.Builder
	a := &sqlArgs{}
	f.appendSQL(&b, a)
	if b.String() != ` AND COALESCE((e.details->'decision'->>'media_unavailable')::boolean, false) = $1` || a.args[0] != true {
		t.Fatalf("SQL %q, параметры %v", b.String(), a.args)
	}
	for _, bad := range []string{`media_unavailable != true`, `media_unavailable = "yes"`} {
		if _, err := ParseFilter(bad); err == nil {
			t.Errorf("%s: принят", bad)
		}
	}
}
