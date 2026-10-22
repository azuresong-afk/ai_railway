// Пакет build — сборка пакета конфигурации для шлюзов на сервере
// управления (задача 2.13, решение Р7, ADR-0009): содержимое из приложений
// (2.11) и политик (2.12), версии в таблице config_bundles, подпись и
// шифрование учётных данных для конкретного шлюза при выдаче.
//
// Сборка ленивая: при запросе шлюза содержимое собирается из текущих
// данных и сравнивается по хешу с последней версией. Собирается оно только
// при смене счётчика изменений конфигурации (config_revisions, Н26, задача
// 3.34) или по сроку ближайшего ключа; опрос без изменений данных
// приложений не выбирает. Изменилось — новая
// версия и запись bundle.build в аудит той же транзакцией. Каждое
// приложение проверяется так же, как его проверит шлюз; не прошедшее
// исключается (в пакете остаются его ID и ключи, шлюз отвечает 503), и
// остальное, в том числе отзыв ключей, доставляется (В16 ревью 2.r3b).
// Не прошло всё содержимое (размер) — шлюзам выдаётся последняя корректная
// версия, неудача пишется в аудит один раз на содержимое.
package build

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

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
	// Reuse — сколько выдавать собранный результат без новой выборки
	// данных (Н26 ревью 2.r3b), если Revision не задан; 0 — собирать при
	// каждом запросе.
	Reuse time.Duration
	// Revision — счётчик изменений конфигурации (Н26, задача 3.34): растёт
	// в транзакции каждого изменения приложений, ключей, провайдеров,
	// политик, цен, бюджетов и настроек установки. Пока он прежний и не
	// наступил срок ближайшего ключа, выдаётся уже собранный результат.
	// nil — повторное использование по Reuse.
	Revision func(ctx context.Context) (int64, error)
}

// Excluded — приложение, не вошедшее в пакет, и причина (В16 ревью 2.r3b).
type Excluded struct {
	Application string `json:"application"`
	Reason      string `json:"reason"`
}

// Health — итог последней сборки для «Состояния системы».
type Health struct {
	// Failed — содержимое не собрано целиком (сбой уровня пакета, например
	// размер): шлюзам выдаётся прежняя корректная версия.
	Failed bool
	// Reason — причина Failed.
	Reason string
	// Excluded — приложения, исключённые из выдаваемой версии.
	Excluded []Excluded
	// Version и BuiltAt — текущая корректная версия; 0 — её нет.
	Version int64
	BuiltAt time.Time
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
	reuse    time.Duration
	revision func(ctx context.Context) (int64, error)
	// builds — число выборок данных для сборки (для тестов Н26).
	builds atomic.Int64

	// sem упорядочивает сборку: одна версия на изменение, даже если шлюзы
	// пришли одновременно; ожидание прерывается ctx запроса (Н26).
	sem chan struct{}
	// Поля ниже — под sem.
	// failedHash — хеш содержимого, неудача которого уже записана в аудит.
	failedHash []byte
	failReason string
	excluded   []Excluded
	// checks — итоги проверки отдельных приложений по хешу их содержимого:
	// неизменившееся приложение не проверяется заново.
	checks map[string]string
	// last, lastErr, lastAt — результат последней сборки для Reuse.
	last    Record
	lastErr error
	lastAt  time.Time
	// rev — счётчик изменений, при котором собран last (revOK — он есть);
	// expiry — срок ближайшего ключа в last: после него ключ выпадает из
	// пакета, хотя счётчик не менялся. collected — срок из последней
	// выборки данных.
	rev       int64
	revOK     bool
	expiry    time.Time
	collected time.Time

	// sealedMu защищает sealed — подписанные пакеты по шлюзам (задача
	// 3.34): повторная выдача той же версии тому же шлюзу не расшифровывает
	// учётные данные и не подписывает пакет заново.
	sealedMu sync.Mutex
	sealed   map[string]sealedBody

	// mu защищает lastReport.
	mu sync.Mutex
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
		orgID: o.OrgID, clock: o.Clock, logger: o.Logger, reuse: o.Reuse, revision: o.Revision,
		sem: make(chan struct{}, 1), checks: map[string]string{}, lastReport: map[string]time.Time{}, sealed: map[string]sealedBody{}}
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

func (s *Service) lock(ctx context.Context) error {
	select {
	case s.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) unlock() { <-s.sem }

// Current — последняя корректная версия; при изменении данных собирает новую.
func (s *Service) Current(ctx context.Context) (Record, error) {
	if err := s.lock(ctx); err != nil {
		return Record{}, err
	}
	defer s.unlock()
	return s.current(ctx)
}

func (s *Service) current(ctx context.Context) (Record, error) {
	now := s.clock()
	if s.revision != nil {
		return s.currentByRevision(ctx, now)
	}
	if s.reuse > 0 && !s.lastAt.IsZero() && !now.Before(s.lastAt) && now.Sub(s.lastAt) < s.reuse {
		return s.last, s.lastErr
	}
	rec, err := s.rebuild(ctx, now)
	if err == nil || errors.Is(err, ErrNoBundle) {
		s.last, s.lastErr, s.lastAt = rec, err, now
	}
	return rec, err
}

// currentByRevision — сборка только при смене счётчика изменений или после
// срока ближайшего ключа (Н26, задача 3.34). Счётчик читается до выборки
// данных: изменение, зафиксированное позже, даст ещё одну сборку, а не
// пропуск.
func (s *Service) currentByRevision(ctx context.Context, now time.Time) (Record, error) {
	rev, err := s.revision(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("пакеты: счётчик изменений конфигурации: %w", err)
	}
	if s.revOK && rev == s.rev && (s.expiry.IsZero() || now.Before(s.expiry)) {
		return s.last, s.lastErr
	}
	rec, err := s.rebuild(ctx, now)
	if err == nil || errors.Is(err, ErrNoBundle) {
		s.last, s.lastErr, s.lastAt = rec, err, now
		s.rev, s.revOK, s.expiry = rev, true, s.collected
	}
	return rec, err
}

// Builds — сколько раз данные выбирались для сборки (Н26).
func (s *Service) Builds() int64 { return s.builds.Load() }

// Health — итог сборки: сначала собирает версию по текущим данным.
func (s *Service) Health(ctx context.Context) (Health, error) {
	if err := s.lock(ctx); err != nil {
		return Health{}, err
	}
	defer s.unlock()
	rec, err := s.current(ctx)
	if err != nil && !errors.Is(err, ErrNoBundle) {
		return Health{}, err
	}
	h := Health{Failed: s.failedHash != nil, Reason: s.failReason, Excluded: slices.Clone(s.excluded),
		Version: rec.Version, BuiltAt: rec.CreatedAt}
	if h.Excluded == nil {
		h.Excluded = []Excluded{}
	}
	return h, nil
}

func (s *Service) rebuild(ctx context.Context, now time.Time) (Record, error) {
	latest, err := s.store.Latest(ctx, s.orgID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Record{}, err
	}
	have := err == nil
	content, stats, excluded, cerr := s.collect(ctx, now)
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
			s.succeeded(excluded)
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
	ts := now.UTC().Truncate(time.Microsecond)
	version := ts.UnixMilli()
	if have && version <= latest.Version {
		version = latest.Version + 1
	}
	rec := Record{OrgID: s.orgID, Version: version, Content: data, Hash: hash, HashAlg: s.hasher.Name(), CreatedAt: ts}
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
	s.succeeded(excluded)
	for _, x := range excluded {
		s.logger.Warn("приложение исключено из пакета конфигурации: его запросы на шлюзах — 503", "application", x.Application,
			"reason", x.Reason, "version", version)
	}
	s.logger.Info("собрана новая версия пакета конфигурации", "version", version, "excluded", len(excluded))
	return rec, nil
}

func (s *Service) succeeded(excluded []Excluded) {
	s.failedHash, s.failReason, s.excluded = nil, "", excluded
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
	msg := clip(cause.Error(), 2000)
	s.logger.Error("пакет конфигурации не собран: шлюзы остаются на последней корректной версии", "error", msg)
	entry := audit.Entry{OrgID: s.orgID, Actor: systemActor, Action: "bundle.build",
		Object: audit.Object{Type: "config_bundle", ID: "new"}, Result: audit.ResultFailure,
		Details: map[string]any{"reason": msg}}
	if err := s.audit.Record(ctx, entry); err != nil {
		s.logger.Error("запись аудита о неудачной сборке пакета", "error", err)
		return
	}
	s.failedHash, s.failReason = sum, msg
}

func clip(msg string, n int) string {
	if len(msg) <= n {
		return msg
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut] + "…"
}

// maxExcludedListed — исключённых приложений в подробностях bundle.build.
const maxExcludedListed = 50

// collect собирает содержимое из текущих данных: действующие приложения и
// их действующие ключи, провайдеры этих приложений, текущие версии политик
// организации, на которые они ссылаются. Приложение, которое шлюз не смог
// бы применить (нет провайдера или политики, политика ссылается на словарь,
// которого у него нет, и т. п.), исключается: в пакет идут только его ID и
// ключи, шлюз отвечает на его запросы 503, а остальное доставляется (В16
// ревью 2.r3b). Списки упорядочены по ID.
func (s *Service) collect(ctx context.Context, now time.Time) (*bundle.Content, map[string]any, []Excluded, error) {
	s.builds.Add(1)
	s.collected = time.Time{}
	provs, err := s.apps.Providers(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	byID := map[string]apps.Provider{}
	for _, p := range provs {
		byID[p.ID] = p
	}
	keys, err := s.keysByApp(ctx, now)
	if err != nil {
		return nil, nil, nil, err
	}
	c := &bundle.Content{Providers: []bundle.Provider{}, Applications: []bundle.Application{}, Policies: []bundle.Policy{}}
	usedProv := map[string]bool{}
	pols := map[string]*bundle.Policy{}
	checks := map[string]string{}
	var excluded []Excluded
	var after *apps.Cursor
	nkeys := 0
	for {
		page, err := s.apps.Applications(ctx, "", after, appsPage)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, a := range page {
			if a.Archived() {
				continue
			}
			p, ok := byID[a.ProviderID]
			ba := application(a, p.Slug, keys[a.ID])
			for _, k := range ba.Keys {
				if s.collected.IsZero() || k.ExpiresAt.Before(s.collected) {
					s.collected = k.ExpiresAt
				}
			}
			reason := ""
			var pol *bundle.Policy
			switch {
			case !ok:
				reason = "провайдер не найден"
			case !policy.IsTemplate(ba.Policy):
				if pol, err = s.policyOf(ctx, pols, ba.Policy); err != nil {
					return nil, nil, nil, err
				}
				if pol == nil {
					reason = fmt.Sprintf("политика %s не найдена", ba.Policy)
				}
			}
			if reason == "" {
				reason = s.checkApp(s.checks, checks, ba, provider(p), pol)
			}
			if reason != "" {
				excluded = append(excluded, Excluded{Application: a.Slug, Reason: clip(reason, 500)})
				c.Unavailable = append(c.Unavailable, bundle.Unavailable{ID: ba.ID, Env: ba.Env, Keys: ba.Keys})
				nkeys += len(ba.Keys)
				continue
			}
			nkeys += len(ba.Keys)
			c.Applications = append(c.Applications, ba)
			if !usedProv[p.ID] {
				usedProv[p.ID] = true
				c.Providers = append(c.Providers, provider(p))
			}
			if pol != nil && !slices.ContainsFunc(c.Policies, func(x bundle.Policy) bool { return x.ID == pol.ID }) {
				c.Policies = append(c.Policies, *pol)
			}
		}
		if len(page) < appsPage {
			break
		}
		last := page[len(page)-1]
		after = &apps.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	s.checks = checks
	slices.SortFunc(c.Applications, func(a, b bundle.Application) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Providers, func(a, b bundle.Provider) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Policies, func(a, b bundle.Policy) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Unavailable, func(a, b bundle.Unavailable) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(excluded, func(a, b Excluded) int { return strings.Compare(a.Application, b.Application) })
	stats := map[string]any{"applications": len(c.Applications), "providers": len(c.Providers),
		"policies": len(c.Policies), "app_keys": nkeys}

	if len(excluded) > 0 {
		stats["excluded_count"] = len(excluded)
		stats["excluded"] = excluded[:min(len(excluded), maxExcludedListed)]
	}
	return c, stats, excluded, nil
}

// keysByApp — действующие ключи всех приложений одним запросом (Н25, Н26).
func (s *Service) keysByApp(ctx context.Context, now time.Time) (map[string][]bundle.Key, error) {
	ks, err := s.apps.ActiveKeysAt(ctx, now)
	if err != nil {
		return nil, err
	}
	out := map[string][]bundle.Key{}
	for _, k := range ks {
		bk := bundle.Key{Prefix: k.Prefix, SHA256: fmt.Sprintf("%x", k.Hash), ExpiresAt: k.ExpiresAt.UTC()}
		for _, c := range k.AllowedCIDRs {
			bk.AllowedCIDRs = append(bk.AllowedCIDRs, c.String())
		}
		out[k.AppID] = append(out[k.AppID], bk)
	}
	return out, nil
}

// policyOf — текущая версия политики организации; nil — политики нет.
func (s *Service) policyOf(ctx context.Context, cache map[string]*bundle.Policy, id string) (*bundle.Policy, error) {
	if p, ok := cache[id]; ok {
		return p, nil
	}
	doc, err := s.policies.Get(ctx, id, 0)
	if errors.Is(err, versions.ErrNotFound) {
		cache[id] = nil
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := &bundle.Policy{ID: id, Version: doc.Version.Version, YAML: string(doc.Version.YAML)}
	cache[id] = p
	return p, nil
}

// checkApp проверяет одно приложение с его провайдером и политикой так же,
// как шлюз проверит пакет; пусто — годится. Итог берётся из prev и
// запоминается в next по хешу содержимого приложения (prev — s.checks,
// только под sem; nil — без памяти).
func (s *Service) checkApp(prev, next map[string]string, ba bundle.Application, bp bundle.Provider, pol *bundle.Policy) string {
	one := bundle.Content{Providers: []bundle.Provider{bp}, Applications: []bundle.Application{ba}, Policies: []bundle.Policy{}}
	if pol != nil {
		one.Policies = append(one.Policies, *pol)
	}
	data, err := one.Marshal()
	if err != nil {
		return err.Error()
	}
	h := string(s.hasher.Sum(data))
	reason, ok := prev[h]
	if !ok {
		if err := s.check(data); err != nil {
			reason = err.Error()
		}
	}
	next[h] = reason
	return reason
}

func application(a apps.Application, providerSlug string, keys []bundle.Key) bundle.Application {
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
	// Только действующие ключи: отозванный или истёкший ключ на шлюзе не
	// нужен, его отказ — «неизвестный ключ».
	ba.Keys = append(ba.Keys, keys...)
	slices.SortFunc(ba.Keys, func(x, y bundle.Key) int { return strings.Compare(x.Prefix, y.Prefix) })
	return ba
}

// CheckApplication проверяет приложение после изменения так, как его
// проверит сборка: провайдер, политика, словари, размер пакета (В16 ревью
// 2.r3b; ошибка — с apps.ErrBreaksBundle). before — приложение до изменения
// (nil при создании).
func (s *Service) CheckApplication(ctx context.Context, before *apps.Application, after apps.Application) error {
	p, err := s.apps.Provider(ctx, after.ProviderID)
	if errors.Is(err, apps.ErrNotFound) {
		return nil // отсутствующий провайдер отклоняет само хранилище
	}
	if err != nil {
		return err
	}
	ba := application(after, p.Slug, nil)
	var pol *bundle.Policy
	if !policy.IsTemplate(ba.Policy) {
		if pol, err = s.policyOf(ctx, map[string]*bundle.Policy{}, ba.Policy); err != nil || pol == nil {
			return err
		}
	}
	if reason := s.checkApp(nil, map[string]string{}, ba, provider(p), pol); reason != "" {
		return fmt.Errorf("%w: %s", apps.ErrBreaksBundle, clip(reason, 500))
	}
	return s.checkSize(ctx, before, ba)
}

// checkSize — содержимое пакета после замены приложения не больше предела:
// оценка по текущей версии (В16: словари пяти приложений по 1 МиБ иначе
// остановили бы сборку целиком).
func (s *Service) checkSize(ctx context.Context, before *apps.Application, ba bundle.Application) error {
	latest, err := s.store.Latest(ctx, s.orgID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	size := len(latest.Content)
	if b, err := json.Marshal(ba); err == nil {
		size += len(b)
	}
	if before != nil {
		if b, err := json.Marshal(application(*before, "", nil)); err == nil {
			size -= len(b)
		}
	}
	if size > bundle.MaxSize/2 {
		return fmt.Errorf("%w: содержимое пакета превысило бы %d байт — сократите словари", apps.ErrBreaksBundle, bundle.MaxSize/2)
	}
	return nil
}

// CheckPolicy проверяет новую версию политики организации со всеми
// действующими приложениями, которые на неё ссылаются (В16 ревью 2.r3b):
// правило на словарь, которого нет у приложения, — versions.ErrBreaksBundle.
// Приложение, которое не проходит и с текущей версией (уже исключено из
// пакета), сохранение не блокирует: иначе нельзя было бы срочно ужесточить
// общую политику, пока не исправлено чужое приложение (самопроверка H4, С3).
func (s *Service) CheckPolicy(ctx context.Context, spec *policy.Spec) error {
	var cur *policy.Spec
	switch doc, err := s.policies.Get(ctx, spec.ID, 0); {
	case errors.Is(err, versions.ErrNotFound):
	case err != nil:
		return err
	default:
		cur = doc.Spec
	}
	var failed []string
	var after *apps.Cursor
	for {
		page, err := s.apps.Applications(ctx, "", after, appsPage)
		if err != nil {
			return err
		}
		var batch []bundle.Application
		for _, a := range page {
			if !a.Archived() && a.Policy == spec.ID {
				batch = append(batch, application(a, "", nil))
			}
		}
		for _, ba := range batch {
			one := bundle.Content{Applications: []bundle.Application{ba}}
			if err := gateway.CheckApplications(one.GatewayApplications(), []policy.Spec{*spec}); err == nil {
				continue
			}
			if cur != nil && gateway.CheckApplications(one.GatewayApplications(), []policy.Spec{*cur}) != nil {
				continue
			}
			failed = append(failed, ba.ID)
		}
		if len(page) < appsPage {
			break
		}
		last := page[len(page)-1]
		after = &apps.Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	if len(failed) == 0 {
		return nil
	}
	list := strings.Join(failed[:min(len(failed), 10)], ", ")
	if len(failed) > 10 {
		list += fmt.Sprintf(" и ещё %d", len(failed)-10)
	}
	return fmt.Errorf("%w: версия не применится к приложениям %s — проверьте словари приложений (lists)", versions.ErrBreaksBundle, list)
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
// пакета пишется в аудит (bundle.deliver); ответ 304 — нет. trustSeq —
// последнее заявление о доверии, известное шлюзу (−1 — шлюз прежней
// версии): шлюз, которому нужны новые заявления, получает пакет целиком
// даже с той же версией (ADR-0018, п. 4).
func (s *Service) Deliver(ctx context.Context, gw Gateway, recipientKey []byte, ifNoneMatch string, trustSeq int64) (Delivery, error) {
	if len(recipientKey) != aisecCrypto.RecipientPublicKeySize {
		return Delivery{}, ErrNoRecipientKey
	}
	rec, err := s.Current(ctx)
	if err != nil {
		return Delivery{}, err
	}
	d := Delivery{Version: rec.Version, ETag: bundle.ETag(rec.Version)}
	seq := s.sealer.TrustSeq()
	if trustSeq > seq {
		// Шлюз знает заявление новее сервера: БД сервера восстановлена из
		// дампа до ротации или подменена (3Н2 ревью 3.r1).
		if err := s.trustRollback(ctx, gw, trustSeq); err != nil {
			return Delivery{}, err
		}
	}
	if etagMatches(ifNoneMatch, d.ETag) && (trustSeq < 0 || trustSeq >= seq) {
		d.NotModified = true
		return d, nil
	}
	want := sealedBody{version: rec.Version, trustSeq: seq, keyID: s.sealer.KeyID(), recipient: string(recipientKey)}
	body, providers, ok := s.cachedBody(gw.ID, want)
	if !ok {
		content, err := bundle.ParseContent(rec.Content)
		if err != nil {
			return Delivery{}, fmt.Errorf("пакеты: сохранённая версия %d не разбирается: %w", rec.Version, err)
		}
		secrets, err := s.secrets(ctx, content)
		defer secrets.Clear()
		if err != nil {
			return Delivery{}, err
		}
		body, err = s.sealer.Seal(bundle.SealInput{Version: rec.Version, IssuedAt: s.clock(), GatewayID: gw.ID,
			Content: rec.Content, Secrets: secrets, RecipientKey: recipientKey})
		if err != nil {
			return Delivery{}, err
		}
		providers = len(secrets)
		want.body, want.providers = body, providers
		s.cacheBody(gw.ID, want)
	}
	d.Body = body
	if err := s.audit.Record(ctx, audit.Entry{OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: gw.ID},
		SourceIP: gw.IP, Action: "bundle.deliver", Object: audit.Object{Type: "config_bundle", ID: strconv.FormatInt(rec.Version, 10)},
		Result: audit.ResultSuccess, Details: map[string]any{"version": rec.Version, "encrypted_providers": providers,
			"signing_key_id": want.keyID, "trust_seq": seq, "cached": ok}}); err != nil {
		// Выдача без записи в аудит не выполняется (РСБ.2).
		return Delivery{}, err
	}
	return d, nil
}

// trustRollback пишет bundle.trust_rollback не чаще reportEvery на шлюз:
// номер заявления о доверии у шлюза больше, чем у сервера. Пакет выдаётся
// как обычно — шлюз сам не примет заявление старее своего; запись нужна,
// чтобы администратор увидел откат цепочки (правило безопасности по коду
// аудита, ADR-0020).
func (s *Service) trustRollback(ctx context.Context, gw Gateway, trustSeq int64) error {
	now := s.clock()
	key := gw.ID + "|trust_rollback"
	s.mu.Lock()
	if t, ok := s.lastReport[key]; ok && now.Sub(t) < reportEvery {
		s.mu.Unlock()
		return nil
	}
	s.lastReport[key] = now
	s.mu.Unlock()
	s.logger.Error("шлюз знает заявление о доверии новее сервера: БД сервера восстановлена из дампа до ротации ключей или подменена",
		"gateway_id", gw.ID, "gateway_trust_seq", trustSeq, "server_trust_seq", s.sealer.TrustSeq(), "class", "integrity")
	err := s.audit.Record(ctx, audit.Entry{OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: gw.ID},
		SourceIP: gw.IP, Action: "bundle.trust_rollback", Object: audit.Object{Type: "gateway", ID: gw.ID},
		Result: audit.ResultFailure, Details: map[string]any{"gateway_trust_seq": trustSeq,
			"server_trust_seq": s.sealer.TrustSeq(), "threat": "DM-42"}})
	if err != nil {
		s.mu.Lock()
		delete(s.lastReport, key)
		s.mu.Unlock()
	}
	return err
}

// maxSealedCached — подписанных пакетов в памяти (по одному на шлюз).
const maxSealedCached = 256

// sealedBody — подписанный пакет шлюза и то, для чего он подписан.
type sealedBody struct {
	version, trustSeq int64
	keyID, recipient  string
	body              []byte
	providers         int
}

func (b sealedBody) same(o sealedBody) bool {
	return b.version == o.version && b.trustSeq == o.trustSeq && b.keyID == o.keyID && b.recipient == o.recipient
}

// cachedBody — подписанный пакет шлюза для той же версии, заявлений,
// ключа подписи и ключа получателя.
func (s *Service) cachedBody(gatewayID string, want sealedBody) ([]byte, int, bool) {
	s.sealedMu.Lock()
	defer s.sealedMu.Unlock()
	b, ok := s.sealed[gatewayID]
	if !ok || !b.same(want) {
		return nil, 0, false
	}
	return b.body, b.providers, true
}

// cacheBody запоминает подписанный пакет шлюза; пакеты прежних версий
// забываются.
func (s *Service) cacheBody(gatewayID string, b sealedBody) {
	s.sealedMu.Lock()
	defer s.sealedMu.Unlock()
	for id, x := range s.sealed {
		if x.version != b.version {
			delete(s.sealed, id)
		}
	}
	if _, ok := s.sealed[gatewayID]; !ok && len(s.sealed) >= maxSealedCached {
		return
	}
	s.sealed[gatewayID] = b
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
