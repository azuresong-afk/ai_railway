package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// Параметр media_check и проверенные анализатором изображения (задача 5.39,
// ADR-0032, раздел 8).

func TestMediaCheckSpec(t *testing.T) {
	ok := []Spec{
		{MediaCheck: ""}, {MediaCheck: MediaCheckOff}, {MediaCheck: MediaCheckAsync},
		{MediaCheck: MediaCheckSync, MediaTimeoutMS: MinMediaTimeoutMS}, {MediaCheck: MediaCheckSync, MediaTimeoutMS: MaxMediaTimeoutMS},
	}
	for i, s := range ok {
		s.ID, s.Name, s.Version, s.Mode = "p", "П", 1, Enforce
		if err := s.Validate(); err != nil {
			t.Fatalf("случай %d: %v", i, err)
		}
	}
	bad := []Spec{
		{MediaCheck: "always"}, {MediaCheck: "SYNC"},
		{MediaCheck: MediaCheckSync, MediaTimeoutMS: MinMediaTimeoutMS - 1},
		{MediaCheck: MediaCheckSync, MediaTimeoutMS: MaxMediaTimeoutMS + 1},
		{MediaTimeoutMS: -1},
	}
	for i, s := range bad {
		s.ID, s.Name, s.Version, s.Mode = "p", "П", 1, Enforce
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "media_check") {
			t.Fatalf("случай %d: ожидалась ошибка media_check, получено %v", i, err)
		}
	}
}

func TestMediaCheckCompileDefaults(t *testing.T) {
	p := compile(t, &Spec{ID: "p", Name: "П", Version: 1, Mode: Enforce})
	if p.MediaCheck != MediaCheckOff || p.MediaTimeout != DefaultMediaTimeout {
		t.Fatalf("умолчания: %q %v", p.MediaCheck, p.MediaTimeout)
	}
	p = compile(t, &Spec{ID: "p", Name: "П", Version: 1, Mode: Enforce, MediaCheck: MediaCheckSync, MediaTimeoutMS: 750})
	if p.MediaCheck != MediaCheckSync || p.MediaTimeout != 750*time.Millisecond {
		t.Fatalf("заданные значения: %q %v", p.MediaCheck, p.MediaTimeout)
	}
}

// Покрывает: DM-14
// Проверенная aisec-media часть под non_text не попадает: block и
// allow_inline её не блокируют, отметка «не проверено» — только за
// непроверенными частями.
func TestDM14_CheckedMediaSkipsNonText(t *testing.T) {
	checked := MediaPart{Kind: "image", Checked: true}
	unchecked := MediaPart{Kind: "image"}
	url := MediaPart{Kind: "image", URL: true}
	cases := []struct {
		nonText   NonText
		media     []MediaPart
		block     bool
		unchecked bool
	}{
		{NonTextBlock, []MediaPart{checked}, false, false},
		{NonTextBlock, []MediaPart{checked, unchecked}, true, false},
		{NonTextAllowUnchecked, []MediaPart{checked}, false, false},
		{NonTextAllowUnchecked, []MediaPart{checked, unchecked}, false, true},
		{NonTextAllowInline, []MediaPart{checked, url}, true, false},
		{NonTextAllowInline, []MediaPart{{Kind: "image", URL: true, Checked: true}}, false, false},
	}
	for i, c := range cases {
		p := compile(t, &Spec{ID: "p", Name: "П", Version: 1, Mode: Enforce, NonText: c.nonText})
		d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Media: c.media})
		if d.Block != c.block || d.NonTextUnchecked != c.unchecked {
			t.Fatalf("случай %d: %+v", i, d)
		}
	}
}

// Покрывает: DM-46 (часть)
// Текст на изображении не замаскировать: правило redact или pseudonymize по
// находке с источником image даёт block (Р9 этапа 5), в monitor — только
// журнал, защита данных не применяется ни в одном режиме.
func TestImageSourceProtectBlocks(t *testing.T) {
	spec := &Spec{ID: "p", Name: "П", Version: 1, Mode: Enforce, Rules: []RuleSpec{
		{ID: "pii", Detector: detPII, Directions: []detect.Direction{detect.Input}, Action: Pseudonymize, Severity: Medium},
		{ID: "secrets", Detector: detSecrets, Directions: []detect.Direction{detect.Input}, Action: Redact, Severity: High},
	}}
	p := compile(t, spec)
	img := hit(detPII, "pii.card", 0.97, SourceImage)
	d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, External: true, Hits: []Hit{img}})
	if !d.Block || d.Action != Block || d.Rule != "pii" || len(d.Matches) != 1 || d.Matches[0].Apply != "" || d.Matches[0].Protect != "" {
		t.Fatalf("enforce: %+v", d)
	}
	sec := hit(detSecrets, "secret.api_key", 0.95, SourceImage)
	d = p.Evaluate(Request{Endpoint: EndpointCheck, Direction: detect.Input, Hits: []Hit{sec}})
	if !d.Block || d.Rule != "secrets" {
		t.Fatalf("Check API: %+v", d)
	}
	spec.Mode = Monitor
	p = compile(t, spec)
	d = p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, External: true, Hits: []Hit{img}})
	if d.Block || d.Action != Block || d.Matches[0].Apply != "" || len(d.Applied()) != 0 {
		t.Fatalf("monitor: %+v", d)
	}
	// Тот же текст в сообщении маскируется, как прежде.
	d = p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, External: true, Hits: []Hit{pii}})
	if d.Action != Pseudonymize || d.Matches[0].Apply != Pseudonymize {
		t.Fatalf("текст сообщения: %+v", d)
	}
}

// Правило может ограничиться источником image.
func TestImageSourceInRules(t *testing.T) {
	p := compile(t, &Spec{ID: "p", Name: "П", Version: 1, Mode: Enforce, Rules: []RuleSpec{
		{ID: "inj-image", Detector: detInjection, Sources: []detect.Source{SourceImage}, Action: Block, Severity: High},
	}})
	if d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Hits: []Hit{inj}}); d.Action != Allow {
		t.Fatalf("источник user: %+v", d)
	}
	img := hit(detInjection, "injection.override", 0.9, SourceImage)
	if d := p.Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, Hits: []Hit{img}}); !d.Block {
		t.Fatalf("источник image: %+v", d)
	}
}

func TestTemplatesMediaCheck(t *testing.T) {
	for _, id := range TemplateIDs() {
		s, _ := Template(id)
		want := MediaCheckAsync
		if s.NonText == NonTextBlock {
			want = MediaCheckSync
		}
		if s.MediaCheck != want {
			t.Fatalf("шаблон %s: media_check %q, ожидалось %q", id, s.MediaCheck, want)
		}
	}
}
