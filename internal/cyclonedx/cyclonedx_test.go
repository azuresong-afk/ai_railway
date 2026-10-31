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

func TestValidate(t *testing.T) {
	h := hasher(t)
	good := func() *BOM {
		b := &BOM{BOMFormat: BOMFormat, SpecVersion: SpecVersion, Version: 1,
			Metadata: Metadata{Timestamp: "2026-10-31T00:00:00Z", Component: Component{Type: "application", BOMRef: "aisec", Name: "AISec"}},
			Components: []Component{{Type: "machine-learning-model", BOMRef: "m", Name: "m",
				Components: []Component{{Type: "file", BOMRef: "m/f", Name: "f", Hashes: []Hash{{Alg: "SHA-256", Content: strings.Repeat("ab", 32)}}}}}},
			Services:     []Service{{BOMRef: "p", Name: "p", TrustZone: "external"}},
			Dependencies: []Dependency{{Ref: "aisec", DependsOn: []string{"m"}}, {Ref: "m", DependsOn: []string{"p"}}}}
		b.SerialNumber = SerialFor(b, h)
		return b
	}
	if err := Validate(good()); err != nil {
		t.Fatalf("правильный документ: %v", err)
	}
	for name, mut := range map[string]func(*BOM){
		"версия":              func(b *BOM) { b.SpecVersion = "1.5" },
		"серийный номер":      func(b *BOM) { b.SerialNumber = "x" },
		"время":               func(b *BOM) { b.Metadata.Timestamp = "вчера" },
		"тип компонента":      func(b *BOM) { b.Components[0].Type = "model" },
		"алгоритм хеша":       func(b *BOM) { b.Components[0].Components[0].Hashes[0].Alg = "GOST" },
		"вид хеша":            func(b *BOM) { b.Components[0].Components[0].Hashes[0].Content = "xyz" },
		"повтор bom-ref":      func(b *BOM) { b.Services[0].BOMRef = "m/f" },
		"ссылка связи":        func(b *BOM) { b.Dependencies[1].DependsOn = []string{"нет"} },
		"зона доверия":        func(b *BOM) { b.Services[0].TrustZone = "dmz" },
		"повтор связи":        func(b *BOM) { b.Dependencies = append(b.Dependencies, Dependency{Ref: "m"}) },
		"компонент без имени": func(b *BOM) { b.Components[0].Name = "" },
	} {
		b := good()
		mut(b)
		if Validate(b) == nil {
			t.Errorf("%s: ошибка не найдена", name)
		}
	}
}
