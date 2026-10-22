package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/api"
	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
)

// Ключи подписи пакетов конфигурации в каталоге ключей aisec-cli init
// (ADR-0007, п. 3). bundleSigningNextFile — необязательный второй открытый
// ключ на время ротации: шлюз с ним не считается подменённым (В19 ревью 2.r4).
const (
	bundleSigningKeyFile  = "bundle-signing.key"
	bundleSigningPubFile  = "bundle-signing.pub"
	bundleSigningNextFile = "bundle-signing.next.pub"
)

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

// bundleKeys — ключи подписи пакетов для сверки с ключами шлюзов в
// heartbeat (В19 ревью 2.r4): действующий и второй на время ротации.
func bundleKeys(p aisecCrypto.Provider, keysDir, current string) (gwregistry.BundleKeys, error) {
	keys := gwregistry.BundleKeys{Current: current}
	path := filepath.Join(keysDir, bundleSigningNextFile)
	data, err := aisecCrypto.ReadPEMFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return keys, nil
	}
	if err != nil {
		return keys, fmt.Errorf("второй ключ подписи пакетов: %w", err)
	}
	v, err := aisecCrypto.ParseVerifierPEM(p, path, data, aisecCrypto.KeyKindSigningPublic)
	if err != nil {
		return keys, fmt.Errorf("второй ключ подписи пакетов: %w", err)
	}
	h, err := p.Hasher()
	if err != nil {
		return keys, err
	}
	keys.Next = bundle.KeyID(h, v.PublicKey())
	return keys, nil
}

// bundleReuse — сколько секунд опросы шлюзов получают уже собранный
// результат без новой выборки данных (Н26 ревью 2.r3b).
const bundleReuse = 5 * time.Second

// newBundleRoutes — сборка и выдача пакетов конфигурации шлюзам (задача
// 2.13): маршруты внутреннего порта. Изменения приложений и политик
// проверяются сборкой при сохранении (В16 ревью 2.r3b).
func newBundleRoutes(cfg *serverConfig, p aisecCrypto.Provider, db *store.DB, auditLog *audit.Log,
	appsSvc *apps.Service, policiesSvc *versions.Service, gateways *gwregistry.Service, logger *slog.Logger) ([]api.Route, *build.Service, error) {
	signer, err := loadBundleSigner(p, cfg.KeysDir)
	if err != nil {
		return nil, nil, err
	}
	sealer, err := bundle.NewSealer(p, signer)
	if err != nil {
		return nil, nil, err
	}
	keys, err := bundleKeys(p, cfg.KeysDir, sealer.KeyID())
	if err != nil {
		return nil, nil, err
	}
	gateways.SetBundleKeys(keys)
	st, err := build.NewPGStore(db.Pool(), auditLog)
	if err != nil {
		return nil, nil, err
	}
	svc, err := build.New(build.Options{Apps: appsSvc, Policies: policiesSvc, Store: st, Audit: auditLog,
		Sealer: sealer, Provider: p, Logger: logger, Reuse: bundleReuse})
	if err != nil {
		return nil, nil, err
	}
	appsSvc.SetBundleCheck(svc.CheckApplication)
	policiesSvc.SetBundleCheck(svc.CheckPolicy)
	logger.Info("пакеты конфигурации шлюзов подписываются ключом", "key_id", sealer.KeyID())
	return api.BundleRoutes(svc, logger.With("listener", "internal")), svc, nil
}

// bundleHealth — итог сборки для «Состояния системы»: nil, пока сборка не
// создана (сервер без внутреннего порта).
func bundleHealth(ref *atomic.Pointer[build.Service]) func(ctx context.Context) (*sysstatus.BundleHealth, error) {
	return func(ctx context.Context) (*sysstatus.BundleHealth, error) {
		svc := ref.Load()
		if svc == nil {
			return nil, nil
		}
		h, err := svc.Health(ctx)
		if err != nil {
			return nil, err
		}
		out := &sysstatus.BundleHealth{Version: h.Version, BuiltAt: h.BuiltAt, Failed: h.Failed, Reason: h.Reason}
		if h.Version > 0 {
			out.ETag = bundle.ETag(h.Version)
		}
		for _, x := range h.Excluded {
			out.Excluded = append(out.Excluded, sysstatus.ExcludedApp{Application: x.Application, Reason: x.Reason})
		}
		return out, nil
	}
}
