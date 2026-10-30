package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/ml"
	"github.com/azuresong-afk/ai_railway/tools/internal/components"
)

// maxModelsSpec — предел файла описания моделей пакета.
const maxModelsSpec = 256 << 10

// modelsSpec — описание моделей пакета без файлов: ID, версия, задача,
// метки, направления, окно. Файлы, их размеры и хеши sign-models считает сам.
type modelsSpec struct {
	Models []ml.ModelSpec `json:"models"`
}

// signModels собирает манифест пакета моделей aisec-ml и подписывает его
// ключом производителя (ADR-0024, раздел 5): каталог моделей — <id>/
// model.onnx, tokenizer.json, mlbom.cdx.json. Как у sign: ключ
// производителя — только на машине без сети, тестовый ключ — только для
// тестовых пакетов. Существующие манифест и подпись не перезаписываются;
// готовый пакет проверяется тем же кодом, что и в aisec-ml при запуске.
func signModels(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sign-models", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "закрытый ключ производителя (AISEC MANIFEST SIGNING KEY, права 0400) на отдельном носителе")
	testKey := fs.String("test-key", "", "тестовый ключ из репозитория — НЕ ДЛЯ ПОСТАВКИ")
	dir := fs.String("dir", "", "каталог пакета моделей: <id>/model.onnx, tokenizer.json, mlbom.cdx.json")
	specFile := fs.String("spec", "", "описание моделей, JSON: {\"models\": [{id, version, task, labels, directions, max_tokens}]}")
	version := fs.String("version", "", "версия пакета моделей")
	created := fs.String("created", "", "время сборки пакета, RFC 3339")
	registry := fs.String("components", components.DefaultPath, "реестр компонентов: с -key каждая модель — запись type: ml-model с решением владельца")
	expect := fs.String("expect-sha256", "", "хеш манифеста пакета, напечатанный -dry-run на сборочной машине (рекомендуется с -key)")
	dryRun := fs.Bool("dry-run", false, "только собрать манифест и напечатать его SHA-256: без ключа и без записи файлов")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *dir == "" || *specFile == "" || *version == "" || *created == "" {
		return errors.New("обязательны -dir, -spec, -version и -created")
	}
	if *dryRun != (*keyFile == "" && *testKey == "") || !*dryRun && *keyFile != "" && *testKey != "" {
		return errors.New("нужен ровно один из -key, -test-key и -dry-run")
	}
	ts, err := time.Parse(time.RFC3339, *created)
	if err != nil {
		return errors.New("-created: ожидается время RFC 3339")
	}
	var signer aisecCrypto.Signer
	switch {
	case *dryRun:
		// Ключ не нужен: печатается только хеш манифеста.
	case *keyFile != "":
		if err := checkOffline(); err != nil {
			return err
		}
		if signer, err = loadVendorSigner(p, *keyFile); err != nil {
			return err
		}
	default:
		if signer, err = loadTestSigner(p, *testKey); err != nil {
			return err
		}
	}
	raw, err := readLimited(*specFile, maxModelsSpec)
	if err != nil {
		return err
	}
	var spec modelsSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return fmt.Errorf("%s: %w", *specFile, err)
	}
	if dec.More() {
		return fmt.Errorf("%s: данные после объекта", *specFile)
	}
	// Ключ производителя подписывает только модели с решением владельца в
	// реестре (4В32): иначе модель без согласия ушла бы заказчику подписанной.
	if *keyFile != "" {
		ids := make([]string, 0, len(spec.Models))
		for _, m := range spec.Models {
			ids = append(ids, m.ID)
		}
		if err := checkApprovedModels(*registry, ids); err != nil {
			return err
		}
	}
	m, err := ml.BuildModelsManifest(p, *dir, *version, ts, spec.Models)
	if err != nil {
		return err
	}
	data, err := ml.MarshalModelsManifest(m)
	if err != nil {
		return err
	}
	// Манифест собирается заново из файлов каталога: хеш со сборочной
	// машины (-dry-run) подтверждает, что на машину подписи перенесены те же
	// файлы с тем же описанием (как -expect-sha256 у sign, ревью 4.r3).
	sum, err := manifestSum(p, data)
	if err != nil {
		return err
	}
	if *dryRun {
		_, err = fmt.Fprintf(stdout, "SHA-256 манифеста пакета: %s\nПодпишите на машине без сети: sign-models … -expect-sha256 %s\n", sum, sum)
		return err
	}
	if *expect != "" && !strings.EqualFold(strings.TrimSpace(*expect), sum) {
		return fmt.Errorf("хеш манифеста пакета %s не совпадает с -expect-sha256: файлы или описание изменены после сборки", sum)
	}
	sig, err := ml.SignModels(signer, data)
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(*dir, ml.ModelsManifestFile)
	if err := writeNew(manifestPath, data, 0o644); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(*dir, ml.ModelsSignatureFile), sig, 0o644); err != nil {
		return err
	}
	// Проверка готового пакета открытым ключом подписавшего — так же, как
	// aisec-ml при запуске (подпись, разбор, файлы, ML-BOM).
	v, err := p.NewVerifier(signer.PublicKey())
	if err != nil {
		return err
	}
	if _, _, err := ml.LoadModels(*dir, ml.LoadOptions{Provider: p, Verifier: v, MaxTotal: 16 << 30}); err != nil {
		return fmt.Errorf("проверка готового пакета: %w", err)
	}
	fp, err := integrity.Fingerprint(p, signer.PublicKey())
	if err != nil {
		return err
	}
	if *keyFile != "" && *expect == "" {
		if _, err := fmt.Fprintln(stderr, "manifest: хеш не сверен (-expect-sha256): сравните SHA-256 ниже с напечатанным -dry-run на сборочной машине"); err != nil {
			return err
		}
	}
	if *testKey != "" {
		if _, err := fmt.Fprintln(stderr, "manifest: ВНИМАНИЕ: пакет моделей подписан тестовым ключом — НЕ ДЛЯ ПОСТАВКИ"); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(stdout, "Подписан пакет моделей %s: версия %s, моделей: %d\nSHA-256 манифеста пакета: %s\nОтпечаток ключа: %s\n",
		*dir, m.Version, len(m.Models), sum, fp)
	return err
}

// checkApprovedModels — у каждой модели ids есть запись type: ml-model,
// scope: product в реестре компонентов (с решением владельца — его
// требует схема реестра). Иначе — отказ со списком моделей.
func checkApprovedModels(registry string, ids []string) error {
	f, err := os.Open(registry) //nolint:gosec // G304: путь к реестру задаёт make
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // файл только читается
	reg, err := components.Parse(f)
	if err != nil {
		return fmt.Errorf("%s: %w", registry, err)
	}
	var missing []string
	for _, id := range ids {
		if !reg.ApprovedModel(id) {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("модели без решения владельца в %s (запись type: ml-model, scope: product): %v — в поставку не подписываются", registry, missing)
	}
	return nil
}

// checkModels — команда check-models: у моделей готового пакета (манифест
// aisec-models.json в -dir) есть решение владельца в реестре; make
// ml-release-dir RELEASE=1 вызывает её до сборки выпуска (4В32).
func checkModels(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check-models", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "каталог подписанного пакета моделей")
	registry := fs.String("components", components.DefaultPath, "реестр компонентов")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *dir == "" {
		return errors.New("обязателен -dir")
	}
	raw, err := readLimited(filepath.Join(*dir, ml.ModelsManifestFile), maxModelsSpec)
	if err != nil {
		return err
	}
	m, err := ml.ParseModelsManifest(raw)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(m.Models))
	for _, s := range m.Models {
		ids = append(ids, s.ID)
	}
	if err := checkApprovedModels(*registry, ids); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Модели пакета с решением владельца: %v\n", ids)
	return err
}
