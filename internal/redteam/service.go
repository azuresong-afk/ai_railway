package redteam

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect/judge"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Коды аудита (ADR-0031, раздел 8).
const (
	ActionTargetCreated = "redteam.target_created"
	ActionTargetUpdated = "redteam.target_updated"
	ActionTargetDeleted = "redteam.target_deleted"
	ActionRunStarted    = "redteam.run_started"
	ActionRunFinished   = "redteam.run_finished"
	ActionRunCancelled  = "redteam.run_cancelled"
	objectTarget        = "redteam_target"
	objectRun           = "redteam_run"
)

// Ожидание ключа запуска на шлюзе (ADR-0031, раздел 2).
const (
	DefaultKeyWait = 90 * time.Second
	DefaultKeyPoll = 3 * time.Second
	// keyGrace — запас срока ключа запуска в пакете после срока запуска.
	keyGrace = time.Minute
	// MaxAuthValue — значение секретного заголовка цели, байты.
	MaxAuthValue = 4096
	// MaxRunFilter — строк матрицы в фильтре запуска.
	MaxRunFilter = 64
	// MaxRunsList — запусков в списке.
	MaxRunsList = 200
)

// Apps — приложения и провайдеры продукта (apps.Service).
type Apps interface {
	Application(ctx context.Context, id, ownerID string) (apps.Application, error)
	Providers(ctx context.Context) ([]apps.Provider, error)
	OpenCredential(ctx context.Context, id string) ([]byte, error)
}

// JudgeClients — адаптер оценщика judge.llm по slug провайдера; nil без
// ошибки — провайдера нет или он не «у заказчика».
type JudgeClients func(ctx context.Context, slug string) (judge.Client, error)

// Options — зависимости сервиса.
type Options struct {
	Store      Store
	ServiceDBs servicedb.Store
	Provider   aisecCrypto.Provider
	// Box — ключ данных: выдержки ответов режима masked хранятся только
	// запечатанными (5В3 ревью 5.r3).
	Box   *keyring.Box
	OrgID string
	Apps  Apps
	// GatewayURL и GatewayCA — адрес шлюза для целей gateway (флаги
	// -redteam-gateway-url и -redteam-gateway-ca); пусто — цели gateway
	// не запускаются.
	GatewayURL string
	GatewayCA  []byte
	// Judges — оценщик; nil — без judge.llm.
	Judges JudgeClients
	// Location — часовой пояс установки для расписаний; nil — UTC.
	Location func(ctx context.Context) (*time.Location, error)
	Clock    func() time.Time
	Logger   *slog.Logger
	// KeyWait и KeyPoll — ожидание ключа запуска на шлюзе; 0 — по умолчанию.
	KeyWait, KeyPoll time.Duration
	// Lookup — разрешение имён (тесты); nil — системное.
	Lookup Lookup
	// Vendor — ключ производителя для базы сценариев (только тесты).
	Vendor aisecCrypto.Verifier
}

// By — субъект действия.
type By struct {
	Actor audit.Actor
	IP    netip.Addr
	// Confirm — повторная проверка паролем или кодом (цель endpoint); nil
	// — недоступна (токен API).
	Confirm func(ctx context.Context) error
}

func (b By) name() string {
	if b.Actor.Name != "" {
		return b.Actor.Name
	}
	return b.Actor.ID
}

// Service — тестирование устойчивости.
type Service struct {
	o         Options
	tp        aisecCrypto.TLSProvider
	hasher    aisecCrypto.Hasher
	random    aisecCrypto.Random
	ids       *ids.Generator
	scenarios *servicedb.Manager
	gateway   *url.URL
	// connect — соединение с проверенным адресом цели endpoint (тесты).
	connect Connect
	// runTimeout — срок запуска вместо предела цели (тесты).
	runTimeout time.Duration

	mu       sync.Mutex
	base     context.Context
	active   map[string]*execution // по ID запуска
	byTarget map[string]string     // цель → запуск
	wg       sync.WaitGroup
}

// New проверяет зависимости.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.ServiceDBs == nil || o.Provider == nil || o.Apps == nil || o.Box == nil {
		return nil, errors.New("тестирование устойчивости: нет хранилища, служебных баз, приложений, криптопрофиля или ключа данных")
	}
	if o.OrgID == "" {
		o.OrgID = audit.DefaultOrgID
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.KeyWait <= 0 {
		o.KeyWait = DefaultKeyWait
	}
	if o.KeyPoll <= 0 {
		o.KeyPoll = DefaultKeyPoll
	}
	h, err := o.Provider.Hasher()
	if err != nil {
		return nil, err
	}
	rnd, err := o.Provider.Random()
	if err != nil {
		return nil, err
	}
	s := &Service{o: o, hasher: h, random: rnd, ids: ids.NewGenerator(rnd), base: context.Background(),
		active: map[string]*execution{}, byTarget: map[string]string{}}
	if tp, err := o.Provider.TLS(); err == nil {
		s.tp = tp
	}
	if o.GatewayURL != "" {
		u, err := url.Parse(o.GatewayURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("тестирование устойчивости: адрес шлюза — https://узел:порт или http://узел:порт без учётных данных")
		}
		if u.Scheme == "https" && len(o.GatewayCA) == 0 {
			return nil, errors.New("тестирование устойчивости: для адреса шлюза https нужен корневой сертификат (-redteam-gateway-ca)")
		}
		s.gateway = u
	}
	s.scenarios, err = servicedb.NewManager(servicedb.Options{Store: o.ServiceDBs, Provider: o.Provider, Kind: DBKind(), OrgID: o.OrgID,
		Clock: o.Clock, Logger: o.Logger.With("kind", ScenariosKind), Vendor: o.Vendor})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// DB — служебная база сценариев.
func (s *Service) DB() *servicedb.Manager { return s.scenarios }

// GatewayConfigured — адрес шлюза для целей gateway задан.
func (s *Service) GatewayConfigured() bool { return s.gateway != nil }

// Start — запуск сервиса: незавершённые запуски прошлого процесса получают
// failed (interrupted); ctx — срок жизни исполнителя (остановка сервера
// отменяет идущие запуски).
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	s.base = ctx
	s.mu.Unlock()
	n, err := s.o.Store.Interrupt(ctx, s.o.OrgID, s.o.Clock().UTC(), func(r Run) audit.Entry {
		return systemEntry(ActionRunFinished, r, map[string]any{"status": r.Status, "reason": r.Reason})
	})
	if n > 0 {
		s.o.Logger.Warn("тестирование устойчивости: прерванные перезапуском запуски завершены", "runs", n)
	}
	if err != nil {
		return err
	}
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.purgeLoop(ctx)
	}()
	go func() {
		defer s.wg.Done()
		s.scheduleLoop(ctx)
	}()
	return nil
}

// Сроки хранения (ADR-0031, раздел 7).
const (
	ResultsRetention = 90 * 24 * time.Hour
	RunsRetention    = 365 * 24 * time.Hour
	purgeInterval    = time.Hour
)

func (s *Service) purgeLoop(ctx context.Context) {
	t := time.NewTicker(purgeInterval)
	defer t.Stop()
	for {
		now := s.o.Clock().UTC()
		if err := s.o.Store.Purge(ctx, s.o.OrgID, now.Add(-ResultsRetention), now.Add(-RunsRetention)); err != nil && ctx.Err() == nil {
			s.o.Logger.Error("тестирование устойчивости: очистка по сроку хранения", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Wait ждёт завершения идущих запусков (после отмены контекста Start).
func (s *Service) Wait() { s.wg.Wait() }

func systemEntry(action string, r Run, details map[string]any) audit.Entry {
	return audit.Entry{Actor: audit.Actor{Type: audit.ActorSystem, ID: "redteam", Name: "Тестирование устойчивости"}, Action: action,
		Object: audit.Object{Type: objectRun, ID: r.ID}, Result: audit.ResultSuccess, Details: details}
}

func (b By) entry(action, objType, objID string, details map[string]any) audit.Entry {
	return audit.Entry{Actor: b.Actor, SourceIP: b.IP, Action: action, Object: audit.Object{Type: objType, ID: objID},
		Result: audit.ResultSuccess, Details: details}
}

// targetAudit — поля цели для аудита: без секретов (значения заголовков и
// корневой сертификат — только признаком).
func targetAudit(t Target) map[string]any {
	d := map[string]any{"name": t.Name, "kind": t.Kind, "limits": t.Limits}
	switch t.Kind {
	case KindGateway:
		d["app_id"], d["model"] = t.AppID, t.Model
	case KindEndpoint:
		names := make([]string, 0, len(t.Headers))
		for _, h := range t.Headers {
			names = append(names, h.Name)
		}
		d["url"], d["header_names"], d["auth_header"], d["has_ca"], d["storage"] = t.URL, names, t.AuthHeader, t.CAPEM != "", t.Storage
		d["authorization_note"] = t.AuthorizationNote
	}
	if t.JudgeProvider != "" {
		d["judge_provider"], d["judge_model"] = t.JudgeProvider, t.JudgeModel
	}
	return d
}

// Targets — цели организации.
func (s *Service) Targets(ctx context.Context) ([]Target, error) {
	return s.o.Store.Targets(ctx, s.o.OrgID)
}

// Target — цель по ID.
func (s *Service) Target(ctx context.Context, id string) (Target, error) {
	if !uuidRe.MatchString(id) {
		return Target{}, ErrNotFound
	}
	return s.o.Store.Target(ctx, s.o.OrgID, id)
}

// checkTarget — проверки цели против продукта: приложение и модель цели
// gateway, корневой сертификат, провайдер оценщика.
func (s *Service) checkTarget(ctx context.Context, t Target) error {
	return checkTargetRefs(ctx, s.tp, s.o.Apps, t)
}

// TargetRefs — то, на что ссылается цель: приложение (цель gateway) и
// провайдеры-оценщики. Apps ему соответствует; копия конфигурации передаёт
// объекты из копии.
type TargetRefs interface {
	Application(ctx context.Context, id, ownerID string) (apps.Application, error)
	Providers(ctx context.Context) ([]apps.Provider, error)
}

// checkTargetRefs — проверки цели, которым нужны другие объекты: модель
// приложения, корневой сертификат по криптопрофилю, оценщик «у заказчика».
func checkTargetRefs(ctx context.Context, tp aisecCrypto.TLSProvider, refs TargetRefs, t Target) error {
	if t.Kind == KindGateway {
		a, err := refs.Application(ctx, t.AppID, "")
		if errors.Is(err, apps.ErrNotFound) || err == nil && a.Archived() {
			return invalidf("app_id — приложение не найдено или в архиве")
		}
		if err != nil {
			return err
		}
		if _, alias := a.Aliases[t.Model]; !alias && !slices.Contains(a.Models, t.Model) {
			return invalidf("model — модель не разрешена приложению")
		}
	}
	if t.CAPEM != "" {
		if tp == nil {
			return invalidf("ca_pem — TLS недоступен в криптопрофиле")
		}
		if _, err := tp.ClientConfig([]byte(t.CAPEM)); err != nil {
			return invalidf("ca_pem — не найден корневой сертификат в PEM")
		}
	}
	if t.JudgeProvider != "" {
		provs, err := refs.Providers(ctx)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(provs, func(p apps.Provider) bool { return p.Slug == t.JudgeProvider })
		if i < 0 || !provs[i].OnPremise {
			return invalidf("judge_provider — провайдер не найден или не помечен «размещён у заказчика» (ADR-0030)")
		}
	}
	return nil
}

// addressChanged — у цели endpoint меняется то, куда и с чем продукт
// отправит атаки (адрес, заголовки, корневой сертификат), или продукт
// начинает хранить выдержки ответов (storage → masked, 5Н22 ревью 5.r3).
func addressChanged(before, after Target) bool {
	return before.Kind != after.Kind || before.URL != after.URL || before.AuthHeader != after.AuthHeader ||
		before.CAPEM != after.CAPEM || !slices.Equal(before.Headers, after.Headers) ||
		before.Storage != StorageMasked && after.Storage == StorageMasked
}

func confirm(ctx context.Context, by By) error {
	if by.Confirm == nil {
		return ErrConfirmRequired
	}
	return by.Confirm(ctx)
}

// CreateTarget добавляет цель. Цель endpoint — с повторной проверкой.
func (s *Service) CreateTarget(ctx context.Context, by By, in TargetInput) (Target, error) {
	t, err := in.Target()
	if err != nil {
		return Target{}, err
	}
	if err := s.checkTarget(ctx, t); err != nil {
		return Target{}, err
	}
	if t.Kind == KindEndpoint {
		if err := confirm(ctx, by); err != nil {
			return Target{}, err
		}
	}
	u, err := s.ids.New()
	if err != nil {
		return Target{}, err
	}
	now := s.o.Clock().UTC()
	t.ID, t.OrgID, t.CreatedAt, t.CreatedBy, t.UpdatedAt, t.UpdatedBy = u.String(), s.o.OrgID, now, by.name(), now, by.name()
	if err := s.o.Store.CreateTarget(ctx, t, by.entry(ActionTargetCreated, objectTarget, t.ID, targetAudit(t))); err != nil {
		return Target{}, err
	}
	return t, nil
}

// UpdateTarget меняет цель. Вид цели не меняется; смена адреса цели
// endpoint — с повторной проверкой.
func (s *Service) UpdateTarget(ctx context.Context, by By, id string, in TargetInput) (Target, error) {
	before, err := s.Target(ctx, id)
	if err != nil {
		return Target{}, err
	}
	t, err := in.Target()
	if err != nil {
		return Target{}, err
	}
	if t.Kind != before.Kind {
		return Target{}, invalidf("kind — вид цели не меняется: создайте новую цель")
	}
	if err := s.checkTarget(ctx, t); err != nil {
		return Target{}, err
	}
	if t.Kind == KindEndpoint && addressChanged(before, t) {
		if err := confirm(ctx, by); err != nil {
			return Target{}, err
		}
	}
	t.ID, t.OrgID, t.CreatedAt, t.CreatedBy, t.UpdatedAt, t.UpdatedBy = before.ID, before.OrgID, before.CreatedAt, before.CreatedBy,
		s.o.Clock().UTC(), by.name()
	rec := by.entry(ActionTargetUpdated, objectTarget, t.ID, map[string]any{"before": targetAudit(before), "after": targetAudit(t)})
	if err := s.o.Store.UpdateTarget(ctx, t, rec); err != nil {
		return Target{}, err
	}
	return t, nil
}

// DeleteTarget удаляет цель; идущий запуск цели отменяется.
func (s *Service) DeleteTarget(ctx context.Context, by By, id string) error {
	t, err := s.Target(ctx, id)
	if err != nil {
		return err
	}
	// Расписания цели удаляются вместе с ней; их ID — в записи аудита.
	details := targetAudit(t)
	scs, err := s.o.Store.Schedules(ctx, s.o.OrgID)
	if err != nil {
		return err
	}
	var gone []string
	for _, sc := range scs {
		if sc.TargetID == id {
			gone = append(gone, sc.ID)
		}
	}
	if len(gone) > 0 {
		details["schedules_deleted"] = gone
	}
	if err := s.o.Store.DeleteTarget(ctx, s.o.OrgID, id, by.entry(ActionTargetDeleted, objectTarget, id, details)); err != nil {
		return err
	}
	s.mu.Lock()
	runID := s.byTarget[id]
	s.mu.Unlock()
	if runID != "" {
		_ = s.Cancel(ctx, by, runID) //nolint:gosec // G104: запуск мог завершиться сам; цель уже удалена
	}
	return nil
}

// StartInput — запуск: цель, выбор сценариев и значение секретного
// заголовка цели endpoint (только в памяти до конца запуска).
type StartInput struct {
	TargetID  string   `json:"target_id"`
	Scenarios []string `json:"scenarios,omitempty"`
	Threats   []string `json:"threats,omitempty"`
	Lang      string   `json:"lang,omitempty"`
	AuthValue string   `json:"auth_value,omitempty"` //nolint:gosec // G117: значение заголовка цели живёт только в памяти исполнителя
}

// selectScenarios — сценарии базы по фильтру запуска.
func selectScenarios(b *Base, in StartInput) ([]Scenario, error) {
	var l errList
	if len(in.Scenarios) > MaxRunScenarios {
		l.add("scenarios — не больше %d ID", MaxRunScenarios)
	}
	for i, id := range in.Scenarios {
		if !scenarioIDRe.MatchString(id) {
			l.add("scenarios[%d] — ID сценария", i)
		} else if _, ok := b.Scenario(id); !ok {
			l.add("scenarios[%d] — сценария %s нет в базе", i, id)
		}
	}
	if len(in.Threats) > MaxRunFilter {
		l.add("threats — не больше %d строк", MaxRunFilter)
	}
	for i, th := range in.Threats {
		if !threatRe.MatchString(th) {
			l.add("threats[%d] — строка матрицы DM-NN", i)
		}
	}
	if in.Lang != "" && in.Lang != LangRU && in.Lang != LangEN {
		l.add("lang — ru или en")
	}
	if err := l.err(); err != nil {
		return nil, err
	}
	var out []Scenario
	for _, sc := range b.Scenarios {
		if (len(in.Scenarios) == 0 || slices.Contains(in.Scenarios, sc.ID)) && (len(in.Threats) == 0 || slices.Contains(in.Threats, sc.Threat)) &&
			(in.Lang == "" || in.Lang == sc.Lang) {
			out = append(out, sc)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoScenarios
	}
	if len(out) > MaxRunScenarios {
		return nil, invalidf("под условия подходит %d сценариев, в запуске — не больше %d: сузьте выбор (threats, lang, scenarios)",
			len(out), MaxRunScenarios)
	}
	return out, nil
}

// StartRun начинает запуск: проверка, запись запуска с аудитом и
// выполнение в фоне. Возвращает запуск в состоянии running.
func (s *Service) StartRun(ctx context.Context, by By, in StartInput) (Run, error) {
	t, err := s.Target(ctx, in.TargetID)
	if errors.Is(err, ErrNotFound) {
		return Run{}, invalidf("target_id — цель не найдена")
	}
	if err != nil {
		return Run{}, err
	}
	switch {
	case t.AuthHeader == "" && in.AuthValue != "":
		return Run{}, invalidf("auth_value — у цели нет секретного заголовка")
	case t.AuthHeader != "" && (in.AuthValue == "" || len(in.AuthValue) > MaxAuthValue || !plainText(in.AuthValue, false)):
		return Run{}, invalidf("auth_value — значение заголовка %s: до %d байт без управляющих символов", t.AuthHeader, MaxAuthValue)
	case t.Kind == KindGateway && s.gateway == nil:
		return Run{}, ErrGatewayNotConfigured
	}
	v, err := s.scenarios.Active(ctx)
	if err != nil {
		return Run{}, err
	}
	if v == nil {
		return Run{}, ErrNoScenarios
	}
	base, ok := v.Content.Value.(*Base)
	if !ok {
		return Run{}, ErrNoScenarios
	}
	scs, err := selectScenarios(base, in)
	if err != nil {
		return Run{}, err
	}
	u, err := s.ids.New()
	if err != nil {
		return Run{}, err
	}
	now := s.o.Clock().UTC()
	runTimeout := time.Duration(t.Limits.RunTimeoutMin) * time.Minute
	if s.runTimeout > 0 {
		runTimeout = s.runTimeout
	}
	run := Run{ID: u.String(), OrgID: s.o.OrgID, TargetID: t.ID, TargetName: t.Name, TargetKind: t.Kind, AppID: t.AppID, Status: RunRunning,
		Scenarios: len(scs), Counts: Counts{}, DBVersion: base.Version, StartedAt: now, StartedBy: by.name(),
		Deadline: now.Add(runTimeout)}
	var key string
	if t.Kind == KindGateway {
		// Ключ запуска: сам ключ — только в памяти, в БД — префикс и хеш.
		raw, prefix, hexHash, err := auth.NewAppKey(s.random, s.hasher)
		if err != nil {
			return Run{}, err
		}
		if run.KeyHash, err = hex.DecodeString(hexHash); err != nil {
			return Run{}, err
		}
		key, run.KeyPrefix = raw, prefix
		run.Deadline = run.Deadline.Add(s.o.KeyWait)
	}
	s.mu.Lock()
	if len(s.active) >= MaxParallelRuns || s.byTarget[t.ID] != "" {
		s.mu.Unlock()
		return Run{}, ErrBusy
	}
	runCtx, cancel := context.WithDeadline(s.base, run.Deadline)
	x := &execution{s: s, run: run, target: t, scenarios: scs, key: key, authValue: in.AuthValue, cancel: cancel}
	s.active[run.ID], s.byTarget[t.ID] = x, run.ID
	s.mu.Unlock()
	details := map[string]any{"target_id": t.ID, "target": t.Name, "kind": t.Kind, "scenarios": len(scs), "db_version": base.Version}
	if len(in.Threats) > 0 {
		details["threats"] = in.Threats
	}
	if in.Lang != "" {
		details["lang"] = in.Lang
	}
	if err := s.o.Store.CreateRun(ctx, run, by.entry(ActionRunStarted, objectRun, run.ID, details)); err != nil {
		s.release(x)
		cancel()
		return Run{}, err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		x.execute(runCtx)
	}()
	return run, nil
}

func (s *Service) release(x *execution) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, x.run.ID)
	if s.byTarget[x.target.ID] == x.run.ID {
		delete(s.byTarget, x.target.ID)
	}
}

// Cancel отменяет идущий запуск: запросы в полёте прерываются, оставшиеся
// сценарии — skipped, запись аудита redteam.run_cancelled от by.
func (s *Service) Cancel(ctx context.Context, by By, id string) error {
	if !uuidRe.MatchString(id) {
		return ErrNotFound
	}
	if _, err := s.o.Store.Run(ctx, s.o.OrgID, id); err != nil {
		return err
	}
	s.mu.Lock()
	x := s.active[id]
	s.mu.Unlock()
	if x == nil {
		return ErrNotRunning
	}
	x.cancelBy(by)
	return nil
}

// Runs — запуски, новые первыми.
func (s *Service) Runs(ctx context.Context, targetID string, limit int) ([]Run, error) {
	if targetID != "" && !uuidRe.MatchString(targetID) {
		return []Run{}, nil
	}
	if limit <= 0 || limit > MaxRunsList {
		limit = MaxRunsList
	}
	return s.o.Store.Runs(ctx, s.o.OrgID, targetID, limit)
}

// Run — запуск и его результаты.
func (s *Service) Run(ctx context.Context, id string) (Run, []Result, error) {
	if !uuidRe.MatchString(id) {
		return Run{}, nil, ErrNotFound
	}
	r, err := s.o.Store.Run(ctx, s.o.OrgID, id)
	if err != nil {
		return Run{}, nil, err
	}
	res, err := s.o.Store.Results(ctx, s.o.OrgID, id)
	if err != nil {
		return Run{}, nil, err
	}
	return r, res, nil
}

// TestKeys — ключи идущих запусков для пакета шлюзов (build.Options.TestKeys):
// по ID приложения, срок — до срока запуска с запасом.
func (s *Service) TestKeys(ctx context.Context, now time.Time) (map[string][]bundle.Key, error) {
	runs, err := s.o.Store.ActiveKeys(ctx, s.o.OrgID, now)
	if err != nil {
		return nil, err
	}
	out := map[string][]bundle.Key{}
	for _, r := range runs {
		out[r.AppID] = append(out[r.AppID], bundle.Key{Prefix: r.KeyPrefix, SHA256: hex.EncodeToString(r.KeyHash),
			ExpiresAt: r.Deadline.Add(keyGrace).UTC(), Test: true})
	}
	return out, nil
}

// NewJudgeClients — адаптеры оценщика judge.llm по провайдерам продукта с
// признаком on_premise (ADR-0030, раздел 1): транспорт только к частной
// сети с проверкой при каждом соединении.
func NewJudgeClients(a Apps, tp aisecCrypto.TLSProvider, logger *slog.Logger) JudgeClients {
	return func(ctx context.Context, slug string) (judge.Client, error) {
		provs, err := a.Providers(ctx)
		if err != nil {
			return nil, err
		}
		i := slices.IndexFunc(provs, func(p apps.Provider) bool { return p.Slug == slug })
		if i < 0 || !provs[i].OnPremise || provs[i].External {
			return nil, nil
		}
		var key string
		if provs[i].Credential != nil {
			raw, err := a.OpenCredential(ctx, provs[i].ID)
			if err != nil {
				return nil, err
			}
			key = strings.TrimSpace(string(raw))
		}
		return newJudgeClient(provs[i], key, tp, logger)
	}
}

// ScenarioInfo — сведения о сценарии для консоли и CLI: без текста шагов
// и условий успеха (промпты атак не показываются, ТЗ 5.5).
type ScenarioInfo struct {
	ID       string `json:"id"`
	Lang     string `json:"lang"`
	Threat   string `json:"threat"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Steps    int    `json:"steps"`
	Judge    bool   `json:"judge"`
	Source   string `json:"source"`
	License  string `json:"license"`
}

// ScenariosView — состояние базы сценариев и сведения о сценариях
// действующей версии.
type ScenariosView struct {
	State     servicedb.State `json:"state"`
	Scenarios []ScenarioInfo  `json:"scenarios"`
}

// Scenarios — состояние базы сценариев и сценарии действующей версии.
func (s *Service) Scenarios(ctx context.Context) (ScenariosView, error) {
	st, v, err := s.scenarios.Snapshot(ctx)
	if err != nil {
		return ScenariosView{}, err
	}
	out := ScenariosView{State: st, Scenarios: []ScenarioInfo{}}
	if v == nil {
		return out, nil
	}
	b, ok := v.Content.Value.(*Base)
	if !ok {
		return out, nil
	}
	for _, sc := range b.Scenarios {
		out.Scenarios = append(out.Scenarios, ScenarioInfo{ID: sc.ID, Lang: sc.Lang, Threat: sc.Threat, Category: sc.Category,
			Title: sc.Title, Steps: len(sc.Steps), Judge: sc.Success.Judge != "", Source: sc.Source, License: sc.License})
	}
	return out, nil
}

func (b By) db() servicedb.By { return servicedb.By{Actor: b.Actor, IP: b.IP} }

// UploadScenarios проверяет и сохраняет подписанную базу сценариев
// (ADR-0028); отказ — *servicedb.RejectError, попытка пишется в аудит.
func (s *Service) UploadScenarios(ctx context.Context, by By, data []byte) (ScenariosView, error) {
	if _, err := s.scenarios.Upload(ctx, by.db(), data); err != nil {
		return ScenariosView{}, err
	}
	return s.Scenarios(ctx)
}

// RollbackScenarios возвращает предыдущую версию базы сценариев после
// повторной проверки.
func (s *Service) RollbackScenarios(ctx context.Context, by By) (ScenariosView, error) {
	if _, err := s.scenarios.Rollback(ctx, by.db()); err != nil {
		return ScenariosView{}, err
	}
	return s.Scenarios(ctx)
}
