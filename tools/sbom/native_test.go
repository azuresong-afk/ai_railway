package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/tools/internal/components"
)

const nativeDoc = `
  - name: onnxruntime
    version: 1.31.0 (402979ac1bef89dcd55add41eaa7277c407599eb)
    type: native-library
    scope: product
    purpose: p
    license: MIT
    repository: https://github.com/microsoft/onnxruntime
    attack_surface: true
    security_function: false
    provided_by: Microsoft
    justification: j
    decision: d
    decided: 2026-10-28
  - name: mp11
    version: boost-1.82.0
    type: native-library
    scope: product
    purpose: p
    license: BSL-1.0
    license_decision: ADR-0024
    repository: https://github.com/boostorg/mp11
    attack_surface: false
    security_function: false
    provided_by: Boost
    justification: j
    decision: d
    decided: 2026-10-28
`

// ADR-0024: SBOM образа aisec-ml перечисляет ONNX Runtime и встроенные в неё
// библиотеки из реестра.
func TestAddNative(t *testing.T) {
	_, h := fixtures(t)
	reg, err := components.Parse(strings.NewReader(registryDoc + nativeDoc))
	if err != nil {
		t.Fatal(err)
	}
	bom, err := Build(reg, bins()[:1], "1.0.0", ts, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddNative(bom, reg); err != nil {
		t.Fatal(err)
	}
	if err := AsImage(bom, "aisec-test/aisec-ml:1.0.0-test", []ImageFile{{Name: "libonnxruntime.so.1.31.0", SHA256: "ee"}}, h); err != nil {
		t.Fatal(err)
	}
	var ort *Component
	for i, c := range bom.Components {
		if c.Name == "onnxruntime" {
			ort = &bom.Components[i]
		}
	}
	if ort == nil || ort.Version != "1.31.0" || ort.PURL != "pkg:generic/onnxruntime@1.31.0" || ort.Licenses[0].Expression != "MIT" ||
		!slices.Contains(ort.Properties, Property{Name: propNativeSource, Value: "1.31.0 (402979ac1bef89dcd55add41eaa7277c407599eb)"}) {
		t.Fatalf("onnxruntime: %+v", ort)
	}
	root := bom.Dependencies[0]
	for _, ref := range []string{"pkg:generic/onnxruntime@1.31.0", "pkg:generic/mp11@boost-1.82.0", "file:libonnxruntime.so.1.31.0"} {
		if !slices.Contains(root.DependsOn, ref) {
			t.Errorf("нет %s в корне: %v", ref, root.DependsOn)
		}
	}
	if err := Check(bom); err != nil {
		t.Fatal(err)
	}
	// Реестр без native-library — ошибка: образ aisec-ml без ORT в SBOM не собирается.
	plain, _ := fixtures(t)
	bom, err = Build(plain, bins()[:1], "1.0.0", ts, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddNative(bom, plain); err == nil {
		t.Fatal("SBOM без библиотек принят")
	}
}
