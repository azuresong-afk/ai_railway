package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/ml"
)

// modelsDir — каталог пакета с одной моделью и файл её описания.
func modelsDir(t *testing.T, bomVersion string) (dir, spec string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "toxicity-ru"), 0o750); err != nil {
		t.Fatal(err)
	}
	bom, err := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"components": []map[string]any{{"type": "machine-learning-model", "name": "toxicity-ru", "version": bomVersion}}})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		ml.ModelFileName: []byte("onnx"), ml.TokenizerFileName: []byte(`{"model":{}}`), ml.MLBOMFileName: bom,
	} {
		if err := os.WriteFile(filepath.Join(dir, "toxicity-ru", name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	spec = filepath.Join(t.TempDir(), "models.json")
	if err := os.WriteFile(spec, []byte(`{"models":[{"id":"toxicity-ru","version":"1.0.0","task":"classification",
		"labels":["insult","non-toxic"],"directions":["input","output"],"max_tokens":512}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, spec
}

func signModelsArgs(dir, spec string, extra ...string) []string {
	return append([]string{"sign-models", "-dir", dir, "-spec", spec, "-version", "2026.10.1", "-created", "2026-10-28T00:00:00Z"}, extra...)
}

// ADR-0024, раздел 5: пакет, подписанный sign-models, принимает проверка
// aisec-ml со встроенным ключом.
func TestSignModelsTestKey(t *testing.T) {
	dir, spec := modelsDir(t, "1.0.0")
	var stdout, stderr strings.Builder
	if err := run(signModelsArgs(dir, spec, "-test-key", "../../testdata/integrity/manifest-test.signkey"), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "НЕ ДЛЯ ПОСТАВКИ") || !strings.Contains(stdout.String(), "моделей: 1") {
		t.Fatalf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	v, _, err := integrity.EmbeddedVerifier(p)
	if err != nil {
		t.Fatal(err)
	}
	loaded, m, err := ml.LoadModels(dir, ml.LoadOptions{Provider: p, Verifier: v})
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "2026.10.1" || len(loaded) != 1 || string(loaded[0].Model) != "onnx" || len(loaded[0].Spec.Files) != 3 {
		t.Fatalf("пакет: %+v", m)
	}
	// Повторная подпись не перезаписывает готовый пакет.
	if err := run(signModelsArgs(dir, spec, "-test-key", "../../testdata/integrity/manifest-test.signkey"), io.Discard, io.Discard); err == nil {
		t.Fatal("готовый пакет перезаписан")
	}
}

// Ключ производителя — только без сети (ADR-0022); пакет проверяется его
// открытым ключом.
func TestSignModelsVendorKeyOffline(t *testing.T) {
	offline(t)
	key, pub := vendorKey(t)
	dir, spec := modelsDir(t, "1.0.0")
	offlineIfs := netInterfaces
	netInterfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "eth0", Flags: net.FlagUp | net.FlagRunning}}, nil
	}
	if err := run(signModelsArgs(dir, spec, "-key", key), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "без сети") {
		t.Fatalf("ключ производителя при работающей сети: %v", err)
	}
	netInterfaces = offlineIfs
	if err := run(signModelsArgs(dir, spec, "-key", key), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	v, err := aisecCrypto.LoadVerifierFile(p, pub, aisecCrypto.KeyKindManifestSigningPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ml.LoadModels(dir, ml.LoadOptions{Provider: p, Verifier: v}); err != nil {
		t.Fatal(err)
	}
	// Тестовый ключ пакет производителя не принимает.
	tv, _, err := integrity.EmbeddedVerifier(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ml.LoadModels(dir, ml.LoadOptions{Provider: p, Verifier: tv}); err == nil {
		t.Fatal("пакет производителя принят тестовым ключом")
	}
}

func TestSignModelsRejects(t *testing.T) {
	testKey := "../../testdata/integrity/manifest-test.signkey"
	cases := map[string]func(t *testing.T) []string{
		"ML-BOM другой версии": func(t *testing.T) []string {
			dir, spec := modelsDir(t, "0.9.0")
			return signModelsArgs(dir, spec, "-test-key", testKey)
		},
		"нет файла модели": func(t *testing.T) []string {
			dir, spec := modelsDir(t, "1.0.0")
			if err := os.Remove(filepath.Join(dir, "toxicity-ru", ml.ModelFileName)); err != nil {
				t.Fatal(err)
			}
			return signModelsArgs(dir, spec, "-test-key", testKey)
		},
		"ссылка вместо файла": func(t *testing.T) []string {
			dir, spec := modelsDir(t, "1.0.0")
			f := filepath.Join(dir, "toxicity-ru", ml.TokenizerFileName)
			if err := os.Remove(f); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(spec, f); err != nil {
				t.Fatal(err)
			}
			return signModelsArgs(dir, spec, "-test-key", testKey)
		},
		"файлы в описании": func(t *testing.T) []string {
			dir, _ := modelsDir(t, "1.0.0")
			spec := filepath.Join(t.TempDir(), "models.json")
			if err := os.WriteFile(spec, []byte(`{"models":[{"id":"toxicity-ru","version":"1.0.0","task":"classification",
				"labels":["insult"],"directions":["input"],"max_tokens":512,"files":[{"path":"toxicity-ru/x","role":"model","size":1,"hash":"00"}]}]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			return signModelsArgs(dir, spec, "-test-key", testKey)
		},
		"неизвестное поле описания": func(t *testing.T) []string {
			dir, _ := modelsDir(t, "1.0.0")
			spec := filepath.Join(t.TempDir(), "models.json")
			if err := os.WriteFile(spec, []byte(`{"models":[],"extra":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
			return signModelsArgs(dir, spec, "-test-key", testKey)
		},
		"оба ключа": func(t *testing.T) []string {
			dir, spec := modelsDir(t, "1.0.0")
			return signModelsArgs(dir, spec, "-test-key", testKey, "-key", testKey)
		},
		"без ключа": func(t *testing.T) []string {
			dir, spec := modelsDir(t, "1.0.0")
			return signModelsArgs(dir, spec)
		},
		"ключ из репозитория как ключ производителя": func(t *testing.T) []string {
			offline(t)
			dir, spec := modelsDir(t, "1.0.0")
			data, err := os.ReadFile("../../testdata/integrity/manifest-test.signkey")
			if err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(t.TempDir(), "repo.signkey")
			if err := os.WriteFile(key, data, 0o400); err != nil { //nolint:gosec // G703: путь во временном каталоге теста
				t.Fatal(err)
			}
			return signModelsArgs(dir, spec, "-key", key)
		},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			a := args(t)
			if err := run(a, io.Discard, io.Discard); err == nil {
				t.Fatal("принято")
			}
			// Неудачная подпись не оставляет манифест пакета.
			if _, err := os.Stat(filepath.Join(a[2], ml.ModelsSignatureFile)); err == nil {
				t.Fatal("подпись записана")
			}
		})
	}
}

// Виды library и model в манифесте выпуска (ADR-0024, раздел 8).
func TestBuildLibraryAndModels(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string]string{
		"bin/aisec-ml": "ml", "dist/index.html": "<!doctype html>",
		"lib/libonnxruntime.so.1.31.0": "ort", "models/toxicity-ru/model.onnx": "onnx", "models/aisec-models.json": "{}",
	} {
		f := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(f), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "out", "aisec-manifest.json")
	if err := run([]string{"build", "-test-key", "../../testdata/integrity/manifest-test.signkey", "-out", out, "-version", "1",
		"-created", "2026-10-28T00:00:00Z", "-bin", filepath.Join(dir, "bin"), "-cmds", "aisec-ml", "-static", filepath.Join(dir, "dist"),
		"-migrations", "../../migrations", "-lib", filepath.Join(dir, "lib"), "-models", filepath.Join(dir, "models")}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out) //nolint:gosec // G304: файл теста
	if err != nil {
		t.Fatal(err)
	}
	m, err := integrity.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]integrity.Kind{}
	for _, e := range m.Files {
		kinds[e.Path] = e.Kind
	}
	if kinds["lib/libonnxruntime.so.1.31.0"] != integrity.KindLibrary || kinds["models/toxicity-ru/model.onnx"] != integrity.KindModel ||
		kinds["models/aisec-models.json"] != integrity.KindModel {
		t.Fatalf("виды: %v", kinds)
	}
	// Выпуск aisec-ml — без консоли и миграций; основному выпуску они обязательны.
	mlOut := filepath.Join(dir, "ml", "aisec-manifest.json")
	if err := run([]string{"build", "-test-key", "../../testdata/integrity/manifest-test.signkey", "-out", mlOut, "-version", "1",
		"-created", "2026-10-28T00:00:00Z", "-bin", filepath.Join(dir, "bin"), "-cmds", "aisec-ml", "-lib", filepath.Join(dir, "lib")}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"build", "-test-key", "../../testdata/integrity/manifest-test.signkey", "-out", filepath.Join(dir, "x.json"), "-version", "1",
		"-created", "2026-10-28T00:00:00Z", "-bin", filepath.Join(dir, "bin"), "-cmds", "aisec-ml", "-models", filepath.Join(dir, "models")}, io.Discard, io.Discard); err == nil {
		t.Fatal("основной выпуск без -static и -migrations принят")
	}
}
