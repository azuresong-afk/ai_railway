package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/providers"
)

// newBundleClient — режим с сервером (задача 2.13): ключи проверки пакетов
// (pubs — содержимое файлов -bundle-pub, прочитанное при запуске), каталог
// состояния с ключом получателя и применение пакета заменой обработчика в
// sw. Возвращает и KeyID ключей проверки для heartbeat (В19 ревью 2.r4).
func newBundleClient(cfg *config.Gateway, p aisecCrypto.Provider, tp aisecCrypto.TLSProvider, rnd aisecCrypto.Random,
	state *gateway.BundleState, control *controlClient, hb *handlerBuilder, sw *gateway.Switch, appTLS *gateway.TLSSwitch,
	pubs [][]byte, logger *slog.Logger) (*gateway.BundleClient, []string, error) {
	var verifiers []aisecCrypto.Verifier
	for i, data := range pubs {
		v, err := aisecCrypto.ParseVerifierPEM(p, cfg.BundlePubFiles[i], data, aisecCrypto.KeyKindSigningPublic)
		if err != nil {
			return nil, nil, fmt.Errorf("ключ проверки пакетов конфигурации: %w", err)
		}
		verifiers = append(verifiers, v)
	}
	recipient, err := state.Recipient(p)
	if err != nil {
		return nil, nil, err
	}
	opener, err := bundle.NewOpener(p, verifiers, recipient, control.gatewayID)
	if err != nil {
		return nil, nil, err
	}
	chain, err := loadTrustChain(p, verifiers, state, logger)
	if err != nil {
		return nil, nil, err
	}
	opener.SetTrust(chain, nil)
	// Сертификат заказчика проверяется до сборки обработчика: неверный
	// раздел gateway_tls отклоняет пакет целиком, и шлюз остаётся на
	// прежних обработчике и сертификате. Переключение TLS — после замены
	// обработчика (задача 3.27).
	apply := func(b *bundle.Bundle) error {
		prepared, err := appTLS.Prepare(b.Content.GatewayTLS, b.TLSKey, time.Now())
		clear(b.TLSKey)
		if err != nil {
			return err
		}
		h, err := buildFromBundle(b, tp, rnd, hb, logger)
		if err != nil {
			return err
		}
		sw.Store(h)
		appTLS.Use(prepared)
		return nil
	}
	bc, err := gateway.NewBundleClient(gateway.BundleConfig{Client: control.client, Server: cfg.Server, Opener: opener,
		RecipientKey: recipient.PublicKey(), State: state, Apply: apply, Logger: logger})
	return bc, opener.KeyIDs(), err
}

// loadTrustChain — цепочка доверия от -bundle-pub с заявлениями из
// trust.json (ADR-0018, п. 4.4). Якорь может быть ключом не первого
// заявления (3В9 ревью 3.r1): заявления до него пропускаются. Заявление,
// которое цепочка не принимает (файл подменён), и все следующие
// отбрасываются: шлюз продолжает с проверенной частью и получит остальное
// с пакетом.
func loadTrustChain(p aisecCrypto.Provider, verifiers []aisecCrypto.Verifier, state *gateway.BundleState,
	logger *slog.Logger) (*bundle.TrustChain, error) {
	chain, err := bundle.NewTrustChain(p, verifiers)
	if err != nil {
		return nil, err
	}
	chain.AllowReanchor()
	raws, err := state.LoadTrust()
	if err != nil {
		logger.Error("заявления о доверии не прочитаны; шлюз доверяет только -bundle-pub", "file", gateway.TrustFile, "error", err)
		return chain, nil
	}
	skipped := 0
	for i, raw := range raws {
		if _, err := chain.Append(raw); errors.Is(err, bundle.ErrTrustBeforeAnchor) {
			skipped++
			continue
		} else if err != nil {
			logger.Error("сохранённое заявление о доверии не проверяется по цепочке от -bundle-pub; оно и следующие отброшены",
				"file", gateway.TrustFile, "index", i, "error", err, "threat", "DM-42")
			break
		}
	}
	if skipped > 0 {
		logger.Warn("заявления о доверии до ключа -bundle-pub пропущены: якорь шлюза — более поздний ключ подписи",
			"file", gateway.TrustFile, "skipped", skipped)
	}
	if chain.Seq() > 0 {
		logger.Info("цепочка доверия восстановлена", "trust_seq", chain.Seq(), "signing_key_id", chain.ActiveKeyID())
	}
	return chain, nil
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
	return hb.build(b.Content.GatewayApplications(), provs, specs, recs, b.Content.UnavailableIDs(), b.Content.Budgets,
		b.Content.PromptBaselines)
}
