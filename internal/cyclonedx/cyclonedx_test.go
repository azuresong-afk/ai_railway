package cyclonedx

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func hasher(t testing.TB) aisecCrypto.Hasher {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

var uuidRe = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestSerialForDeterministic(t *testing.T) {
	h := hasher(t)
	bom := &BOM{Metadata: Metadata{Timestamp: "2026-10-31T00:00:00Z", Component: Component{Version: "1"}},
		Components: []Component{{BOMRef: "a", Version: "1", Hashes: []Hash{{Alg: "SHA-256", Content: "00"}}}}}
	a, b := SerialFor(bom, h), SerialFor(bom, h)
	if a != b || !uuidRe.MatchString(a) {
		t.Fatalf("серийный номер %q / %q", a, b)
	}
	bom.Components[0].Version = "2"
	if SerialFor(bom, h) == a {
		t.Fatal("другой состав — тот же номер")
	}
}

func TestEmptyFieldsOmitted(t *testing.T) {
	data, err := json.Marshal(BOM{Components: []Component{{Type: "library", Name: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"services", "publisher", `"components":[{"type":"library","name":"x","components"`} {
		if strings.Contains(string(data), f) {
			t.Errorf("пустое поле %s в выводе: %s", f, data)
		}
	}
}

func TestParseLimit(t *testing.T) {
	if _, err := Parse([]byte(`{"bomFormat":"CycloneDX"}`), 8); err == nil {
		t.Fatal("документ больше предела принят")
	}
	bom, err := Parse([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","x":1}`), 1<<10)
	if err != nil || bom.SpecVersion != SpecVersion {
		t.Fatalf("разбор: %+v, %v", bom, err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"file","name":"a"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data, 1<<16)
	})
}
