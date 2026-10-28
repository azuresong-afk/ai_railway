package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/ml"
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *dir == "" || *specFile == "" || *version == "" || *created == "" {
		return errors.New("обязательны -dir, -spec, -version и -created")
	}
	if (*keyFile == "") == (*testKey == "") {
		return errors.New("нужен ровно один из -key и -test-key")
	}
	ts, err := time.Parse(time.RFC3339, *created)
	if err != nil {
		return errors.New("-created: ожидается время RFC 3339")
	}
	var signer aisecCrypto.Signer
	if *keyFile != "" {
		if err := checkOffline(); err != nil {
			return err
		}
		if signer, err = loadVendorSigner(p, *keyFile); err != nil {
			return err
		}
	} else if signer, err = loadTestSigner(p, *testKey); err != nil {
		return err
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
	m, err := ml.BuildModelsManifest(p, *dir, *version, ts, spec.Models)
	if err != nil {
		return err
	}
	data, err := ml.MarshalModelsManifest(m)
	if err != nil {
		return err
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
	sum, err := manifestSum(p, data)
	if err != nil {
		return err
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
