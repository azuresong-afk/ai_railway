package main

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// newBundleClient — режим с сервером (задача 2.13): ключи проверки пакетов,
// каталог состояния с ключом получателя и применение пакета заменой
// обработчика в sw.
func newBundleClient(cfg *config.Gateway, p aisecCrypto.Provider, tp aisecCrypto.TLSProvider, rnd aisecCrypto.Random,
	gatewayID string, control *http.Client, hb *handlerBuilder, sw *gateway.Switch, logger *slog.Logger) (*gateway.BundleClient, error) {
	var verifiers []aisecCrypto.Verifier
	for _, path := range cfg.BundlePubFiles {
		v, err := aisecCrypto.LoadVerifierFile(p, path, aisecCrypto.KeyKindSigningPublic)
		if err != nil {
			return nil, fmt.Errorf("ключ проверки пакетов конфигурации: %w", err)
		}
		verifiers = append(verifiers, v)
	}
	state, err := gateway.OpenBundleState(cfg.StateDir, rnd)
	if err != nil {
		return nil, err
	}
	// Каталог открыт до остановки процесса: os.Root держит дескриптор.
	recipient, err := state.Recipient(p)
	if err != nil {
		return nil, err
	}
	opener, err := bundle.NewOpener(p, verifiers, recipient, gatewayID)
	if err != nil {
		return nil, err
	}
	apply := func(b *bundle.Bundle) error {
		h, err := buildFromBundle(b, tp, rnd, hb, logger)
		if err != nil {
			return err
		}
		sw.Store(h)
		return nil
	}
	return gateway.NewBundleClient(gateway.BundleConfig{Client: control, Server: cfg.Server, Opener: opener,
		RecipientKey: recipient.PublicKey(), State: state, Apply: apply, Logger: logger})
}

// buildFromBundle собирает обработчик по проверенному пакету: провайдеры с
// корневыми сертификатами и учётными данными из пакета, политики,
// приложения со словарями и ключи. Политика со ссылкой на словарь, которого
// нет у приложения, — ошибка сборки, и пакет отклоняется.
func buildFromBundle(b *bundle.Bundle, tp aisecCrypto.TLSProvider, rnd aisecCrypto.Random, hb *handlerBuilder,
	logger *slog.Logger) (http.Handler, error) {
	provs := map[string]providers.Provider{}
	for i, pc := range b.Content.GatewayProviders() {
		prov, err := newProvider(pc, []byte(b.Content.Providers[i].CAPEM), b.Secrets[pc.ID], tp, rnd, logger)
		if err != nil {
			return nil, err
		}
		provs[pc.ID] = prov
	}
	specs, err := b.Content.Specs()
	if err != nil {
		return nil, err
	}
	recs, err := b.Content.KeyRecords()
	if err != nil {
		return nil, err
	}
	return hb.build(b.Content.GatewayApplications(), provs, specs, recs, b.Content.UnavailableIDs())
}
