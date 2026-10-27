package ml_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ml"
	"github.com/azuresong-afk/ai_railway/internal/ml/mltest"
)

var testSpec = mltest.Spec{ID: "injection", Version: "1.0", Directions: []string{"input"}, Words: map[string]string{"ignore": "injection"}}

func provider(t *testing.T) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// writePackage — подписанный пакет и ключ проверки «производителя».
func writePackage(t *testing.T, specs ...mltest.Spec) (string, aisecCrypto.Provider, aisecCrypto.Verifier) {
	t.Helper()
	p := provider(t)
	s, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.NewVerifier(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := mltest.WritePackage(dir, p, s, specs...); err != nil {
		t.Fatal(err)
	}
	return dir, p, v
}

func TestLoadModelsOK(t *testing.T) {
	dir, p, v := writePackage(t, testSpec, mltest.Spec{ID: "toxicity", Version: "0.1", Directions: []string{"input", "output"}, Words: map[string]string{"дурак": "toxic"}})
	models, m, err := ml.LoadModels(dir, ml.LoadOptions{Provider: p, Verifier: v})
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 || m.Models[0].ID != "injection" || string(models[0].Model) != "test-onnx:injection" || len(models[1].Tokenizer) == 0 {
		t.Fatalf("загружено: %+v", m)
	}
	// Модель из пакета работает в тестовом исполнителе.
	if _, err := (mltest.Executor{}).Load(models[0]); err != nil {
		t.Fatal(err)
	}
}

func TestLoadModelsRejectsForeignSignature(t *testing.T) {
	dir, p, _ := writePackage(t, testSpec)
	other, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.NewVerifier(other.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ml.LoadModels(dir, ml.LoadOptions{Provider: p, Verifier: v}); !errors.Is(err, ml.ErrModelsSignature) {
		t.Fatalf("чужой ключ: %v", err)
	}
}

func TestLoadModelsRejectsTamperedManifest(t *testing.T) {
	dir, p, v := writePackage(t, testSpec)
	mp := filepath.Join(dir, ml.ModelsManifestFile)
	data, err := os.ReadFile(mp) //nolint:gosec // G304: путь — временный каталог теста
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mp, []byte(strings.Replace(string(data), `"1.0"`, `"1.1"`, 1)), 0o600); err != nil { //nolint:gosec // G703: путь — временный каталог теста
		t.Fatal(err)
	}
	if _, _, err := ml.LoadModels(dir, ml.LoadOptions{Provider: p, Verifier: v}); !errors.Is(err, ml.ErrModelsSignature) {
		t.Fatalf("изменённый манифест: %v", err)
	}
}

// Подмена весов модели: хеш не совпадает — отказ загрузки всего пакета.
func TestLoadModelsRejectsTamperedWeights(t *testing.T) {
	for name, tamper := range map[string]func(p string) error{
		"хеш": func(p string) error { return os.WriteFile(p, []byte("test-onnx:injectioX"), 0o600) },
		"размер": func(p string) error {
			return os.WriteFile(p, []byte("test-onnx:injection-longer"), 0o600)
		},
		"ссылка": func(p string) error {
			if err := os.Rename(p, p+".orig"); err != nil {
				return err
			}
			return os.Symlink(p+".orig", p)
		},
		"нет файла": os.Remove,
	} {
		t.Run(name, func(t *testing.T) {
			dir, p, v := writePackage(t, testSpec)
			if err := tamper(filepath.Join(dir, "injection", "model.onnx")); err != nil {
				t.Fatal(err)
			}
			models, _, err := ml.LoadModels(dir, ml.LoadOptions{Provider: p, Verifier: v})
			if !errors.Is(err, ml.ErrModelFile) || models != nil {
				t.Fatalf("подмена принята: %v", err)
			}
		})
	}
}

func TestLoadModelsLimits(t *testing.T) {
	dir, p, v := writePackage(t, testSpec)
	if _, _, err := ml.LoadModels(dir, ml.LoadOptions{Provider: p, Verifier: v, MaxTotal: 10}); err == nil {
		t.Fatal("пакет сверх предела памяти принят")
	}
	if _, _, err := ml.LoadModels(filepath.Join(dir, "нет"), ml.LoadOptions{Provider: p, Verifier: v}); err == nil {
		t.Fatal("нет каталога — без ошибки")
	}
	if err := os.Remove(filepath.Join(dir, ml.ModelsSignatureFile)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ml.LoadModels(dir, ml.LoadOptions{Provider: p, Verifier: v}); err == nil {
		t.Fatal("пакет без подписи принят")
	}
}

func TestLoadModelsRejectsOtherProfile(t *testing.T) {
	dir, _, v := writePackage(t, testSpec)
	gost, err := aisecCrypto.New(aisecCrypto.ProfileGOST)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ml.LoadModels(dir, ml.LoadOptions{Provider: gost, Verifier: v}); err == nil {
		t.Fatal("пакет профиля standard принят в профиле gost")
	}
}

func TestCheckMLBOM(t *testing.T) {
	spec := ml.ModelSpec{ID: "injection", Version: "1.0"}
	ok := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"machine-learning-model","name":"injection","version":"1.0","modelCard":{}}]}`
	if err := ml.CheckMLBOM([]byte(ok), spec); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]string{
		"не CycloneDX":  `{"bomFormat":"SPDX","specVersion":"1.6","components":[]}`,
		"версия":        `{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"type":"machine-learning-model","name":"injection","version":"1.0"}]}`,
		"нет модели":    `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"injection","version":"1.0"}]}`,
		"другая версия": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"machine-learning-model","name":"injection","version":"2.0"}]}`,
		"не JSON":       `{`,
	} {
		if err := ml.CheckMLBOM([]byte(b), spec); !errors.Is(err, ml.ErrMLBOM) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseModelsManifestRejects(t *testing.T) {
	dir, _, _ := writePackage(t, testSpec)
	good, err := os.ReadFile(filepath.Join(dir, ml.ModelsManifestFile)) //nolint:gosec // G304: путь — временный каталог теста
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ml.ParseModelsManifest(good); err != nil {
		t.Fatal(err)
	}
	for name, repl := range map[string][2]string{
		"выход из каталога": {`"injection/model.onnx"`, `"injection/../x"`},
		"чужой каталог":     {`"injection/model.onnx"`, `"toxicity/model.onnx"`},
		"роль":              {`"role": "model"`, `"role": "weights"`},
		"повтор роли":       {`"role": "tokenizer"`, `"role": "model"`},
		"формат":            {ml.ModelsFormatV1, "aisec-ml-models-v2"},
		"задача":            {`"classification"`, `"generation"`},
		"окно":              {`"max_tokens": 512`, `"max_tokens": 4096`},
		"хеш":               {`"hash": "`, `"hash": "ZZ`},
		"лишнее поле":       {`"format"`, `"x": 1, "format"`},
	} {
		bad := strings.Replace(string(good), repl[0], repl[1], 1)
		if bad == string(good) {
			t.Fatalf("%s: замена не применилась", name)
		}
		if _, err := ml.ParseModelsManifest([]byte(bad)); !errors.Is(err, ml.ErrModelsManifest) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// FuzzParseModelsManifest — манифест пакета моделей (каталог мог быть
// подменён): без паники; принятый манифест кодируется и разбирается
// обратно, пути файлов — внутри каталога своей модели.
func FuzzParseModelsManifest(f *testing.F) {
	dir := f.TempDir()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		f.Fatal(err)
	}
	s, err := p.GenerateSigner()
	if err != nil {
		f.Fatal(err)
	}
	if _, err := mltest.WritePackage(dir, p, s, testSpec); err != nil {
		f.Fatal(err)
	}
	good, err := os.ReadFile(filepath.Join(dir, ml.ModelsManifestFile)) //nolint:gosec // G304: путь — временный каталог теста
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ml.ParseModelsManifest(data)
		if err != nil {
			return
		}
		for _, spec := range m.Models {
			for _, file := range spec.Files {
				if !strings.HasPrefix(file.Path, spec.ID+"/") || strings.Contains(file.Path, "..") {
					t.Fatalf("принят путь %q", file.Path)
				}
			}
		}
		out, err := ml.MarshalModelsManifest(m)
		if err != nil {
			t.Fatalf("принятый манифест не кодируется: %v", err)
		}
		if _, err := ml.ParseModelsManifest(out); err != nil {
			t.Fatalf("закодированный манифест не разбирается: %v", err)
		}
	})
}
