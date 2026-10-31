package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAsImage(t *testing.T) {
	reg, h := fixtures(t)
	bom, err := Build(reg, bins()[:1], "1.0.0", ts, h)
	if err != nil {
		t.Fatal(err)
	}
	product := bom.SerialNumber
	files := []ImageFile{{Name: "aisec-manifest.json", SHA256: "cc"}, {Name: "aisec-manifest.json.sig", SHA256: "dd"}}
	if err := AsImage(bom, "aisec-test/aisec-gateway:1.0.0-test", files, h); err != nil {
		t.Fatal(err)
	}
	m := bom.Metadata.Component
	if m.Type != "container" || m.Name != "aisec-test/aisec-gateway" || m.Version != "1.0.0-test" || m.BOMRef != imageRef {
		t.Fatalf("предмет документа: %+v", m)
	}
	if len(m.Properties) != 1 || m.Properties[0] != (Property{Name: propImageBase, Value: "scratch"}) {
		t.Errorf("свойства образа: %+v", m.Properties)
	}
	root := bom.Dependencies[0]
	want := []string{"file:aisec-gateway", "file:aisec-manifest.json", "file:aisec-manifest.json.sig"}
	if root.Ref != imageRef || !slices.Equal(root.DependsOn, want) {
		t.Errorf("корень зависимостей: %+v", root)
	}
	if bom.SerialNumber == product {
		t.Error("серийный номер не пересчитан")
	}
	if err := Check(bom); err != nil {
		t.Fatal(err)
	}
}

func TestAsImageRejects(t *testing.T) {
	reg, h := fixtures(t)
	for name, tc := range map[string]struct {
		image string
		files []ImageFile
	}{
		"без тега":             {"aisec/aisec-server", nil},
		"с digest":             {"aisec/aisec-server@sha256:00", nil},
		"заглавные":            {"AISec/aisec-server:1", nil},
		"пустое":               {"", nil},
		"файл дважды":          {"aisec/aisec-server:1", []ImageFile{{"m", "1"}, {"m", "2"}}},
		"файл как бинарник":    {"aisec/aisec-server:1", []ImageFile{{"aisec-gateway", "1"}}},
		"длинный тег":          {"aisec/aisec-server:" + strings.Repeat("a", 129), nil},
		"перевод строки":       {"aisec/aisec-server:1\n", nil},
		"пробел в репозитории": {"aisec /x:1", nil},
	} {
		t.Run(name, func(t *testing.T) {
			bom, err := Build(reg, bins()[:1], "1.0.0", ts, h)
			if err != nil {
				t.Fatal(err)
			}
			if err := AsImage(bom, tc.image, tc.files, h); err == nil {
				t.Fatalf("образ %q принят", tc.image)
			}
		})
	}
}

func TestRunImageFlags(t *testing.T) {
	dir := t.TempDir()
	if err := run("docs/cert/components.yaml", "go.sum", "", filepath.Join(dir, "o.json"), "1", "", []string{"x"},
		imageSpec{Files: []string{"m"}}); err == nil || !strings.Contains(err.Error(), "-image") {
		t.Errorf("-file без -image: %v", err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, maxImageFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, h := fixtures(t)
	if _, err := readImageFile(big, h); err == nil {
		t.Error("файл больше предела принят")
	}
	small := filepath.Join(dir, "small")
	if err := os.WriteFile(small, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := readImageFile(small, h)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name != "small" || f.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("файл: %+v", f)
	}
}
