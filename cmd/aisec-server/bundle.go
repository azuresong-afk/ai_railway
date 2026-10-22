package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/api"
	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
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
	bundleSigningPubFile  = keyring.SigningPubFile
	bundleSigningNextFile = "bundle-signing.next.pub"
)

// serverTrust — цепочка доверия от якоря bundle-signing.pub (ADR-0018,
// п. 4.3, 6.2): ключ подписи пакетов, корни УЦ и заявления для шлюзов.
type serverTrust struct {
	chain     *bundle.TrustChain
	anchorID  string
	anchorPEM []byte
}

// loadServerTrust читает якорь и проверяет цепочку заявлений из БД. Нет
// bundle-signing.pub — nil: пакеты не подписываются, внутренний порт не
// открывается (как до ротации). Заявление, которое цепочка не принимает, —
// отказ запуска: доверие в БД подменено.
func loadServerTrust(ctx context.Context, p aisecCrypto.Provider, db *store.DB, keysDir string) (*serverTrust, error) {
	path := filepath.Join(keysDir, bundleSigningPubFile)
	data, err := aisecCrypto.ReadPEMFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ключ-якорь подписи пакетов: %w", err)
	}
	v, err := aisecCrypto.ParseVerifierPEM(p, path, data, aisecCrypto.KeyKindSigningPublic)
	if err != nil {
		return nil, fmt.Errorf("ключ-якорь подписи пакетов: %w", err)
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	chain, err := keyring.LoadTrust(ctx, db.Pool(), p, audit.DefaultOrgID, []aisecCrypto.Verifier{v})
	if err != nil {
		return nil, err
	}
	return &serverTrust{chain: chain, anchorID: bundle.KeyID(h, v.PublicKey()), anchorPEM: data}, nil
}

// watch — корни доверия под контролем целостности (В19 ревью 2.r4): якорь,
// второй ключ ротации 2.13, открытые ключи и сертификаты корней последнего
// заявления, если их файлы есть рядом.
func (t *serverTrust) watch(cfg *serverConfig) []integrity.WatchFile {
	out := []integrity.WatchFile{{Path: filepath.Join(cfg.KeysDir, bundleSigningPubFile), Data: t.anchorPEM}}
	add := func(path string) {
		if _, err := os.Stat(path); err == nil && !slices.ContainsFunc(out, func(w integrity.WatchFile) bool { return w.Path == path }) {
			out = append(out, integrity.WatchFile{Path: path})
		}
	}
	add(filepath.Join(cfg.KeysDir, bundleSigningNextFile))
	if st := t.chain.Latest(); st != nil {
		for _, k := range st.Keys {
			_, pub := keyring.SigningFiles(k.ID, t.anchorID)
			add(filepath.Join(cfg.KeysDir, pub))
		}
		if cfg.CACert != "" {
			for _, r := range st.Roots {
				crt, _ := keyring.CAFiles(r.ID, "")
				add(filepath.Join(filepath.Dir(cfg.CACert), crt))
			}
		}
	}
	return out
}

// loadBundleSigner читает действующий ключ подписи пакетов (0400): файл
// init до первой ротации, затем bundle-signing.<id>.key ключа без срока из
// последнего заявления. Ключ должен совпадать с ключом заявления.
func loadBundleSigner(p aisecCrypto.Provider, keysDir string, t *serverTrust) (aisecCrypto.Signer, error) {
	if t == nil {
		return nil, fmt.Errorf("ключ подписи пакетов конфигурации: нет %s в %s", bundleSigningPubFile, keysDir)
	}
	active := t.chain.ActiveKeyID()
	name, _ := keyring.SigningFiles(active, t.anchorID)
	path := filepath.Join(keysDir, name)
	data, err := aisecCrypto.ReadKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("ключ подписи пакетов конфигурации: %w", err)
	}
	defer clear(data)
	profile, seed, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindSigning)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer clear(seed)
	if profile != p.Name() {
		return nil, fmt.Errorf("%s: ключ профиля %s, а установка — %s", path, profile, p.Name())
	}
	s, err := p.NewSigner(seed)
	if err != nil {
		return nil, err
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	if bundle.KeyID(h, s.PublicKey()) != active {
		return nil, fmt.Errorf("%s не соответствует действующему ключу подписи %s из цепочки доверия", path, active)
	}
	return s, nil
}

// bundleKeys — ключи подписи пакетов для сверки с ключами шлюзов в
// heartbeat (В19 ревью 2.r4): действующий, второй на время ротации 2.13 и
// после ротаций — все ключи цепочки доверия.
func bundleKeys(p aisecCrypto.Provider, keysDir, current string, t *serverTrust) (gwregistry.BundleKeys, error) {
	keys := gwregistry.BundleKeys{Current: current}
	if t != nil && t.chain.Seq() > 0 {
		keys.Known = t.chain.KnownKeyIDs()
	}
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

// serverCA — внутренний УЦ после ротаций корня (ADR-0018, п. 6.2):
// действующий УЦ выпускает сертификаты, клиентам доверяют все корни
// последнего заявления.
type serverCA struct {
	ca         *aisecCrypto.CA
	clientCAs  []byte
	roots      gwregistry.RootSet
	anchorRoot string
}

// loadServerCA читает УЦ из -ca-cert и, если корни менялись, действующий
// корень из ca.<id>.crt рядом с ним.
func loadServerCA(cfg *serverConfig, p aisecCrypto.Provider, t *serverTrust) (*serverCA, error) {
	anchor, err := loadCA(cfg.CACert, cfg.CAKey)
	if err != nil {
		return nil, err
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	out := &serverCA{ca: anchor, clientCAs: anchor.CertPEM(), anchorRoot: gwregistry.RootID(h, anchor.CertDER())}
	if t == nil {
		return out, nil
	}
	st := t.chain.Latest()
	if st == nil || len(st.Roots) == 0 {
		return out, nil
	}
	active, _ := st.ActiveRoot()
	if active.ID != out.anchorRoot {
		crt, key := keyring.CAFiles(active.ID, out.anchorRoot)
		dir := filepath.Dir(cfg.CACert)
		if out.ca, err = loadCA(filepath.Join(dir, crt), filepath.Join(dir, key)); err != nil {
			return nil, err
		}
		if !aisecCrypto.Equal(out.ca.CertDER(), active.DER) {
			return nil, fmt.Errorf("%s не совпадает с действующим корнем %s из цепочки доверия", crt, active.ID)
		}
	}
	out.roots = gwregistry.RootSet{Active: active.ID, NotAfter: map[string]time.Time{}}
	var ders [][]byte
	for _, r := range st.Roots {
		var end time.Time
		if r.NotAfter != nil {
			end = *r.NotAfter
		}
		out.roots.NotAfter[r.ID] = end
		ders = append(ders, r.DER)
	}
	out.clientCAs = aisecCrypto.RootPoolPEM(ders)
	return out, nil
}

// bundleReuse — сколько секунд опросы шлюзов получают уже собранный
// результат без новой выборки данных (Н26 ревью 2.r3b).
const bundleReuse = 5 * time.Second

// newBundleRoutes — сборка и выдача пакетов конфигурации шлюзам (задача
// 2.13): маршруты внутреннего порта. Изменения приложений и политик
// проверяются сборкой при сохранении (В16 ревью 2.r3b).
func newBundleRoutes(cfg *serverConfig, p aisecCrypto.Provider, db *store.DB, auditLog *audit.Log,
	appsSvc *apps.Service, policiesSvc *versions.Service, gateways *gwregistry.Service, trust *serverTrust,
	logger *slog.Logger) ([]api.Route, *build.Service, error) {
	signer, err := loadBundleSigner(p, cfg.KeysDir, trust)
	if err != nil {
		return nil, nil, err
	}
	sealer, err := bundle.NewSealer(p, signer)
	if err != nil {
		return nil, nil, err
	}
	// Заявления о доверии уходят шлюзам в каждом пакете (ADR-0018, п. 4.3).
	sealer.SetTrust(trust.chain)
	keys, err := bundleKeys(p, cfg.KeysDir, sealer.KeyID(), trust)
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
	logger.Info("пакеты конфигурации шлюзов подписываются ключом", "key_id", sealer.KeyID(), "trust_seq", sealer.TrustSeq())
	return api.BundleRoutes(svc, gateways, logger.With("listener", "internal")), svc, nil
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
