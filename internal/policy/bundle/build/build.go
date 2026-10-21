// Пакет build — сборка пакета конфигурации для шлюзов на сервере
// управления (задача 2.13, решение Р7, ADR-0009): содержимое из приложений
// (2.11) и политик (2.12), версии в таблице config_bundles, подпись и
// шифрование учётных данных для конкретного шлюза при выдаче.
//
// Сборка ленивая: при запросе шлюза содержимое собирается из текущих
// данных и сравнивается по хешу с последней версией. Изменилось — новая
// версия и запись bundle.build в аудит той же транзакцией. Содержимое
// проверяется так же, как его проверит шлюз; не прошло — шлюзам выдаётся
// последняя корректная версия, неудача пишется в аудит один раз на
// содержимое.
package build

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

// ErrNoBundle — корректного пакета ещё нет: данные не прошли проверку, а
// прежних версий нет.
var ErrNoBundle = errors.New("корректного пакета конфигурации ещё нет")

// ErrNoRecipientKey — шлюз не передал ключ для шифрования учётных данных.
var ErrNoRecipientKey = errors.New("нет ключа шлюза для шифрования учётных данных")

// Пределы выборки.
const (
	appsPage = 500
	// reportEvery — не чаще одной записи отчёта шлюза в аудит на причину.
	reportEvery = time.Minute
)

// Итоги применения пакета на шлюзе.
const (
	ResultApplied  = "applied"
	ResultRejected = "rejected"
)

// Options — зависимости сервиса.
type Options struct {
	Apps     *apps.Service
	Policies *versions.Service
	Store    Store
	Audit    Auditor
	Sealer   *bundle.Sealer
	Provider aisecCrypto.Provider
	OrgID    string
	Clock    func() time.Time
	Logger   *slog.Logger
}

// Service — сборка и выдача пакетов.
type Service struct {
	apps     *apps.Service
	policies *versions.Service
	store    Store
	audit    Auditor
	sealer   *bundle.Sealer
	hasher   aisecCrypto.Hasher
	orgID    string
	clock    func() time.Time
	logger   *slog.Logger

	// mu упорядочивает сборку: одна версия на изменение, даже если шлюзы
	// пришли одновременно.
	mu sync.Mutex
	// failedHash — хеш содержимого, неудача которого уже записана в аудит.
	failedHash []byte
	// lastReport — шлюз|итог|причина → время последней записи отчёта.
	lastReport map[string]time.Time
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Apps == nil || o.Policies == nil || o.Store == nil || o.Audit == nil || o.Sealer == nil || o.Provider == nil {
		return nil, errors.New("пакеты: не заданы приложения, политики, хранилище, аудит, подпись или криптопрофиль")
	}
	h, err := o.Provider.Hasher()
	if err != nil {
		return nil, err
	}
	s := &Service{apps: o.Apps, policies: o.Policies, store: o.Store, audit: o.Audit, sealer: o.Sealer, hasher: h,
		orgID: o.OrgID, clock: o.Clock, logger: o.Logger, lastReport: map[string]time.Time{}}
	if s.orgID == "" {
		s.orgID = audit.DefaultOrgID
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	return s, nil
}

var systemActor = audit.Actor{Type: audit.ActorSystem, ID: "bundle-builder", Name: "Сборка пакетов конфигурации"}

// Current — последняя корректная версия; при изменении данных собирает новую.
func (s *Service) Current(ctx context.Context) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	latest, err := s.store.Latest(ctx, s.orgID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Record{}, err
	}
	have := err == nil
	content, stats, cerr := s.collect(ctx)
	if cerr != nil && !isInvalid(cerr) {
		return Record{}, cerr
	}
	var data, hash []byte
	if cerr == nil {
		if data, cerr = content.Marshal(); cerr != nil {
			return Record{}, cerr
		}
		hash = s.hasher.Sum(data)
		if have && bytes.Equal(hash, latest.Hash) {
			return latest, nil
		}
		if bytes.Equal(hash, s.failedHash) {
			// Это содержимое уже не прошло проверку; запись в аудите есть.
			return s.fallback(latest, have)
		}
		cerr = s.check(data)
	}
	if cerr != nil {
		s.buildFailed(ctx, cerr, hash)
		return s.fallback(latest, have)
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	version := now.UnixMilli()
	if have && version <= latest.Version {
		version = latest.Version + 1
	}
	rec := Record{OrgID: s.orgID, Version: version, Content: data, Hash: hash, HashAlg: s.hasher.Name(), CreatedAt: now}
	stats["version"] = version
	stats["content_hash"] = fmt.Sprintf("%x", hash)
	entry := audit.Entry{OrgID: s.orgID, Actor: systemActor, Action: "bundle.build",
		Object: audit.Object{Type: "config_bundle", ID: strconv.FormatInt(version, 10)}, Result: audit.ResultSuccess, Details: stats}
	if err := s.store.Create(ctx, rec, entry); err != nil {
		if errors.Is(err, ErrConflict) {
			// Версию собрал другой экземпляр сервера.
			return s.store.Latest(ctx, s.orgID)
		}
		return Record{}, err
	}
	s.failedHash = nil
	s.logger.Info("собрана новая версия пакета конфигурации", "version", version)
	return rec, nil
}

// fallback — последняя корректная версия, если она есть.
func (s *Service) fallback(latest Record, have bool) (Record, error) {
	if have {
		return latest, nil
	}
	return Record{}, ErrNoBundle
}

// invalidError — данные не годятся для пакета (ошибка конфигурации, не сбой).
type invalidError struct{ err error }

func (e *invalidError) Error() string { return e.err.Error() }

func isInvalid(err error) bool {
	var ie *invalidError
	return errors.As(err, &ie)
}

// check проверяет содержимое так, как его проверит шлюз: строгий разбор,
// пределы, компиляция политик по словарям приложений.
func (s *Service) check(data []byte) error {
	if len(data) > bundle.MaxSize/2 {
		// Половина предела: остальное — base64 и секреты в конверте.
		return &invalidError{fmt.Errorf("содержимое пакета больше %d байт", bundle.MaxSize/2)}
	}
	parsed, err := bundle.ParseContent(data)
	if err != nil {
		return &invalidError{err}
	}
	specs, err := parsed.Specs()
	if err != nil {
		return &invalidError{err}
	}
	if err := gateway.CheckApplications(parsed.GatewayApplications(), specs); err != nil {
		return &invalidError{err}
	}
	return nil
}

// buildFailed пишет неудачу сборки в технический журнал и в аудит — один
// раз на одно и то же содержимое (шлюзы опрашивают сервер каждые 30 с).
// Без хеша (данные не собрались) — раз на одну и ту же причину.
func (s *Service) buildFailed(ctx context.Context, cause error, hash []byte) {
	sum := hash
	if sum == nil {
		sum = s.hasher.Sum([]byte(cause.Error()))
	}
	if bytes.Equal(sum, s.failedHash) {
		return
	}
	// В тексте ошибки — ID приложений и политик и причина, без секретов:
	// учётных данных в содержимом нет.
	msg := cause.Error()
	if len(msg) > 2000 {
		msg = msg[:2000] + "…"
	}
	s.logger.Error("пакет конфигурации не собран: шлюзы остаются на последней корректной версии", "error", msg)
	entry := audit.Entry{OrgID: s.orgID, Actor: systemActor, Action: "bundle.build",
		Object: audit.Object{Type: "config_bundle", ID: "new"}, Result: audit.ResultFailure,
		Details: map[string]any{"reason": msg}}
	if err := s.audit.Record(ctx, entry); err != nil {
		s.logger.Error("запись аудита о неудачной сборке пакета", "error", err)
		return
	}
	s.failedHash = sum
}

// collect собирает содержимое из текущих данных: действующие приложения и
// их действующие ключи, провайдеры этих приложений, текущие версии политик
// организации, на которые они ссылаются. Списки упорядочены по ID.
func (s *Service) collect(ctx context.Context) (*bundle.Content, map[string]any, error) {
	now := s.clock()
	provs, err := s.apps.Providers(ctx)
	if err != nil {
		return nil, nil, err
	}
	byID := map[string]apps.Provider{}
	for _, p := range provs {
		byID[p.ID] = p
	}
	c := &bundle.Content{Providers: []bundle.Provider{}, Applications: []bundle.Application{}, Policies: []bundle.Policy{}}
	usedProv := map[string]bool{}
	usedPol := map[string]bool{}
	var after *apps.Cursor
	keys := 0
	for {
		page, err := s.apps.Applications(ctx, "", after, appsPage)
		if err != nil {
			return nil, nil, err
		}
		for _, a := range page {
			if a.Archived() {
				continue
			}
			p, ok := byID[a.ProviderID]
			if !ok {
				return nil, nil, &invalidError{fmt.Errorf("приложение %s: провайдер не найден", a.Slug)}
			}
			ba, err := s.application(ctx, a, p.Slug, now)
			if err != nil {
				return nil, nil, err
			}
			keys += len(ba.Keys)
			c.Applications = append(c.Applications, ba)
			if !usedProv[p.ID] {
				usedProv[p.ID] = true
				c.Providers = append(c.Providers, provider(p))
			}
			if !policy.IsTemplate(ba.Policy) && !usedPol[ba.Policy] {
				usedPol[ba.Policy] = true
				doc, err := s.policies.Get(ctx, ba.Policy, 0)
				if errors.Is(err, versions.ErrNotFound) {
					return nil, nil, &invalidError{fmt.Errorf("приложение %s: политика %s не найдена", a.Slug, ba.Policy)}
				}
				if err != nil {
					return nil, nil, err
				}
				c.Policies = append(c.Policies, bundle.Policy{ID: ba.Policy, Version: doc.Version.Version, YAML: string(doc.Version.YAML)})
			}
		}
		if len(page) < appsPage {
			break
		}
		last := page[len(page)-1]
		after = &apps.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	slices.SortFunc(c.Applications, func(a, b bundle.Application) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Providers, func(a, b bundle.Provider) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Policies, func(a, b bundle.Policy) int { return strings.Compare(a.ID, b.ID) })
	stats := map[string]any{"applications": len(c.Applications), "providers": len(c.Providers),
		"policies": len(c.Policies), "app_keys": keys}
	return c, stats, nil
}

func (s *Service) application(ctx context.Context, a apps.Application, providerSlug string, now time.Time) (bundle.Application, error) {
	ks, err := s.apps.Keys(ctx, a.ID, "")
	if err != nil {
		return bundle.Application{}, err
	}
	ba := bundle.Application{ID: a.Slug, Env: a.Env, Provider: providerSlug, Models: slices.Clone(a.Models),
		Aliases: a.Aliases, Policy: a.Policy, PolicyMode: a.PolicyMode, FailMode: a.FailMode, Storage: a.Storage,
		UserFrom: a.UserFrom, Quotas: bundle.Quotas(a.Quotas), ExfilAllowDomains: a.ExfilAllowDomains, Keys: []bundle.Key{}}
	if ba.Policy == "" {
		ba.Policy = policy.DefaultTemplate
	}
	if len(ba.Aliases) == 0 {
		ba.Aliases = nil
	}
	for _, l := range a.Lists {
		ba.Lists = append(ba.Lists, bundle.List(l))
	}
	for _, k := range ks {
		// Только действующие ключи: отозванный или истёкший ключ на шлюзе
		// не нужен, его отказ — «неизвестный ключ».
		if k.Status(now) != apps.KeyActive {
			continue
		}
		bk := bundle.Key{Prefix: k.Prefix, SHA256: fmt.Sprintf("%x", k.Hash), ExpiresAt: k.ExpiresAt.UTC()}
		for _, c := range k.AllowedCIDRs {
			bk.AllowedCIDRs = append(bk.AllowedCIDRs, c.String())
		}
		ba.Keys = append(ba.Keys, bk)
	}
	slices.SortFunc(ba.Keys, func(x, y bundle.Key) int { return strings.Compare(x.Prefix, y.Prefix) })
	return ba, nil
}

func provider(p apps.Provider) bundle.Provider {
	bp := bundle.Provider{ID: p.Slug, Type: p.Type, BaseURL: p.BaseURL, CAPEM: p.CAPEM, AuthURL: p.AuthURL,
		Scope: p.Scope, FolderID: p.FolderID, ConnectTimeout: p.ConnectTimeout, HeaderTimeout: p.HeaderTimeout,
		ResponseTimeout: p.ResponseTimeout, StreamIdleTimeout: p.StreamIdleTimeout, External: p.External}
	if p.Credential != nil {
		t := p.Credential.SetAt.UTC()
		bp.CredentialSetAt = &t
	}
	return bp
}

// Gateway — шлюз, запросивший пакет (из проверенного сертификата).
type Gateway struct {
	ID string
	IP netip.Addr
}

// Delivery — ответ на запрос пакета.
type Delivery struct {
	Version int64
	ETag    string
	// NotModified — у шлюза уже эта версия (If-None-Match), тела нет.
	NotModified bool
	Body        []byte
}

// Deliver выдаёт шлюзу последнюю корректную версию: подписывает её и
// шифрует учётные данные провайдеров ключом шлюза recipientKey. Выдача
// пакета пишется в аудит (bundle.deliver); ответ 304 — нет.
func (s *Service) Deliver(ctx context.Context, gw Gateway, recipientKey []byte, ifNoneMatch string) (Delivery, error) {
	if len(recipientKey) != aisecCrypto.RecipientPublicKeySize {
		return Delivery{}, ErrNoRecipientKey
	}
	rec, err := s.Current(ctx)
	if err != nil {
		return Delivery{}, err
	}
	d := Delivery{Version: rec.Version, ETag: bundle.ETag(rec.Version)}
	if etagMatches(ifNoneMatch, d.ETag) {
		d.NotModified = true
		return d, nil
	}
	content, err := bundle.ParseContent(rec.Content)
	if err != nil {
		return Delivery{}, fmt.Errorf("пакеты: сохранённая версия %d не разбирается: %w", rec.Version, err)
	}
	secrets, err := s.secrets(ctx, content)
	defer secrets.Clear()
	if err != nil {
		return Delivery{}, err
	}
	d.Body, err = s.sealer.Seal(bundle.SealInput{Version: rec.Version, IssuedAt: s.clock(), GatewayID: gw.ID,
		Content: rec.Content, Secrets: secrets, RecipientKey: recipientKey})
	if err != nil {
		return Delivery{}, err
	}
	if err := s.audit.Record(ctx, audit.Entry{OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: gw.ID},
		SourceIP: gw.IP, Action: "bundle.deliver", Object: audit.Object{Type: "config_bundle", ID: strconv.FormatInt(rec.Version, 10)},
		Result: audit.ResultSuccess, Details: map[string]any{"version": rec.Version, "encrypted_providers": len(secrets),
			"signing_key_id": s.sealer.KeyID()}}); err != nil {
		// Выдача без записи в аудит не выполняется (РСБ.2).
		return Delivery{}, err
	}
	return d, nil
}

// secrets расшифровывает учётные данные провайдеров пакета (ключ данных,
// keyring.Box). Провайдер без учётных данных или удалённый — без секрета.
func (s *Service) secrets(ctx context.Context, c *bundle.Content) (bundle.Secrets, error) {
	out := bundle.Secrets{}
	provs, err := s.apps.Providers(ctx)
	if err != nil {
		return out, err
	}
	bySlug := map[string]apps.Provider{}
	for _, p := range provs {
		bySlug[p.Slug] = p
	}
	for _, bp := range c.Providers {
		p, ok := bySlug[bp.ID]
		if !ok || p.Credential == nil {
			continue
		}
		cred, err := s.apps.OpenCredential(ctx, p.ID)
		if errors.Is(err, apps.ErrNoCredential) {
			continue
		}
		if err != nil {
			return out, fmt.Errorf("пакеты: учётные данные провайдера %s: %w", bp.ID, err)
		}
		out[bp.ID] = string(cred)
		clear(cred)
	}
	return out, nil
}

// etagMatches — If-None-Match содержит etag (список через запятую или *).
func etagMatches(header, etag string) bool {
	for _, v := range strings.Split(header, ",") {
		v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "W/"))
		if v == etag || v == "*" {
			return true
		}
	}
	return false
}

// Report — итог применения пакета на шлюзе.
type Report struct {
	Result  string
	Version int64
	// Reason — причина отказа из bundle.Reasons; для applied пусто.
	Reason string
}

// ErrInvalidReport — неверный отчёт шлюза.
var ErrInvalidReport = errors.New("неверный отчёт о применении пакета")

// Validate проверяет отчёт.
func (r Report) Validate() error {
	switch r.Result {
	case ResultApplied:
		if r.Reason != "" || r.Version < 1 {
			return ErrInvalidReport
		}
	case ResultRejected:
		if !slices.Contains(bundle.Reasons, r.Reason) || r.Version < 0 {
			return ErrInvalidReport
		}
	default:
		return ErrInvalidReport
	}
	return nil
}

// RecordReport пишет отчёт шлюза в аудит: bundle.applied или
// bundle.rejected (обнаруженная подмена, DM-42). Одинаковые отчёты — не
// чаще раза в минуту на шлюз.
func (s *Service) RecordReport(ctx context.Context, gw Gateway, r Report) error {
	if err := r.Validate(); err != nil {
		return err
	}
	now := s.clock()
	key := gw.ID + "|" + r.Result + "|" + r.Reason + "|" + strconv.FormatInt(r.Version, 10)
	s.mu.Lock()
	for k, t := range s.lastReport {
		if now.Sub(t) >= reportEvery {
			delete(s.lastReport, k)
		}
	}
	if t, ok := s.lastReport[key]; ok && now.Sub(t) < reportEvery {
		s.mu.Unlock()
		return nil
	}
	s.lastReport[key] = now
	s.mu.Unlock()
	action, result := "bundle.applied", audit.ResultSuccess
	details := map[string]any{"version": r.Version}
	if r.Result == ResultRejected {
		action, result = "bundle.rejected", audit.ResultFailure
		details["reason"] = r.Reason
		details["threat"] = "DM-42"
		s.logger.Warn("шлюз отклонил пакет конфигурации", "gateway_id", gw.ID, "reason", r.Reason, "version", r.Version)
	}
	err := s.audit.Record(ctx, audit.Entry{OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: gw.ID},
		SourceIP: gw.IP, Action: action, Object: audit.Object{Type: "config_bundle", ID: strconv.FormatInt(r.Version, 10)},
		Result: result, Details: details})
	if err != nil {
		s.mu.Lock()
		delete(s.lastReport, key)
		s.mu.Unlock()
	}
	return err
}
