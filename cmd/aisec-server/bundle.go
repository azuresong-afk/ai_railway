package main

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/azuresong-afk/ai_railway/internal/api"
	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// bundleSigningKeyFile — ключ подписи пакетов конфигурации в каталоге
// ключей aisec-cli init (ADR-0007, п. 3).
const bundleSigningKeyFile = "bundle-signing.key"

// loadBundleSigner читает ключ подписи пакетов (0400) и проверяет профиль.
func loadBundleSigner(p aisecCrypto.Provider, keysDir string) (aisecCrypto.Signer, error) {
	path := filepath.Join(keysDir, bundleSigningKeyFile)
	data, err := aisecCrypto.ReadKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("ключ подписи пакетов конфигурации: %w", err)
	}
	defer clear(data)
	profile, seed, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindSigning)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if profile != p.Name() {
		return nil, fmt.Errorf("%s: ключ профиля %s, а установка — %s", path, profile, p.Name())
	}
	return p.NewSigner(seed)
}

// newBundleRoutes — сборка и выдача пакетов конфигурации шлюзам (задача
// 2.13): маршруты внутреннего порта.
func newBundleRoutes(cfg *serverConfig, p aisecCrypto.Provider, db *store.DB, auditLog *audit.Log,
	appsSvc *apps.Service, policiesSvc *versions.Service, logger *slog.Logger) ([]api.Route, error) {
	signer, err := loadBundleSigner(p, cfg.KeysDir)
	if err != nil {
		return nil, err
	}
	sealer, err := bundle.NewSealer(p, signer)
	if err != nil {
		return nil, err
	}
	st, err := build.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return nil, err
	}
	svc, err := build.New(build.Options{Apps: appsSvc, Policies: policiesSvc, Store: st, Audit: auditLog,
		Sealer: sealer, Provider: p, Logger: logger})
	if err != nil {
		return nil, err
	}
	logger.Info("пакеты конфигурации шлюзов подписываются ключом", "key_id", sealer.KeyID())
	return api.BundleRoutes(svc, logger.With("listener", "internal")), nil
}
