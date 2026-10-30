package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/ml"
)

// Привязка пакета моделей к выпуску (4В23, ADR-0024, раздел 5): aisec-ml
// загружает только пакет из каталога models/ своего выпуска, и байты его
// манифеста aisec-models.json должны совпасть с записью подписанного
// манифеста выпуска. Старый подписанный пакет из другого каталога или с
// подменой файлов в models/ не загружается, хотя его подпись верна.

// maxSigFile — предел файла подписи манифеста выпуска.
const maxSigFile = 1 << 10

// manifestPath — манифест целостности выпуска: из конфигурации или над
// каталогом bin/ бинарника.
func manifestPath(cfg *config) string {
	if cfg.Manifest != "" {
		return cfg.Manifest
	}
	exe, err := os.Executable()
	if err != nil {
		return "" // releaseModels отвергнет пустой путь
	}
	return integrity.DefaultManifestPath(exe)
}

// releaseModels проверяет, что каталог моделей — models/ выпуска с
// манифестом manifest, и возвращает хеш aisec-models.json из подписанного
// манифеста выпуска.
func releaseModels(manifest, models string, p aisecCrypto.Provider, v aisecCrypto.Verifier) ([]byte, error) {
	if manifest == "" || !filepath.IsAbs(manifest) {
		return nil, errors.New("манифест выпуска: нужен абсолютный путь")
	}
	if want := filepath.Join(filepath.Dir(manifest), "models"); filepath.Clean(models) != want {
		return nil, fmt.Errorf("каталог моделей %s не входит в выпуск: ожидается %s", models, want)
	}
	data, err := readLimited(manifest, integrity.MaxManifestSize)
	if err != nil {
		return nil, fmt.Errorf("манифест выпуска: %w", err)
	}
	sig, err := readLimited(manifest+".sig", maxSigFile)
	if err != nil {
		return nil, fmt.Errorf("подпись манифеста выпуска: %w", err)
	}
	if err := integrity.VerifySignature(v, data, sig); err != nil {
		return nil, fmt.Errorf("манифест выпуска: %w", err)
	}
	m, err := integrity.Parse(data)
	if err != nil {
		return nil, err
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	if m.Profile != p.Name() || m.HashAlg != h.Name() {
		return nil, fmt.Errorf("манифест выпуска в профиле %s, а aisec-ml — в %s", m.Profile, p.Name())
	}
	name := path.Join("models", ml.ModelsManifestFile)
	for _, e := range m.Files {
		if e.Path == name && e.Kind == integrity.KindModel {
			return hex.DecodeString(e.Hash)
		}
	}
	return nil, fmt.Errorf("в манифесте выпуска нет %s: пакет моделей не входит в выпуск", name)
}

// readLimited читает файл не длиннее limit байт.
func readLimited(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name) //nolint:gosec // G304: путь — манифест выпуска из конфигурации администратора
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // файл только читается
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("файл больше %d байт", limit)
	}
	return b, nil
}
