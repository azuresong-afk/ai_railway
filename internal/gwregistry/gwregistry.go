package gwregistry

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// Состояния шлюза.
const (
	StatusPending = "pending" // токен выпущен, сертификата ещё нет
	StatusActive  = "active"
	StatusRevoked = "revoked" // окончательно
)

// TokenPrefix — префикс токена регистрации шлюза.
const TokenPrefix = "aisec_gwreg_"

// Пределы.
const (
	tokenBytes = 32
	// DefaultTokenTTL — срок токена регистрации по умолчанию; MaxTokenTTL — предел.
	DefaultTokenTTL = 24 * time.Hour
	MaxTokenTTL     = 7 * 24 * time.Hour
	// DefaultHeartbeatInterval — период heartbeat, который сервер сообщает шлюзу.
	DefaultHeartbeatInterval = 30 * time.Second
	// DefaultHeartbeatMinInterval — heartbeat чаще считается перегрузкой (429).
	DefaultHeartbeatMinInterval = 10 * time.Second
	// deniedAuditEvery — не чаще одной записи аудита об отказе на сертификат.
	deniedAuditEvery = time.Minute
	// maxTracked — предел записей в памяти для частоты heartbeat и отказов.
	maxTracked = 10000
	maxVersion = 64
	maxETag    = 128
)

// TokenLen — длина токена регистрации с префиксом.
var TokenLen = len(TokenPrefix) + base64.RawURLEncoding.EncodedLen(tokenBytes)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// keyIDRe — KeyID ключа подписи пакетов (bundle.KeyID): 8 байт в hex.
var keyIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// Ошибки. Тексты для журнала; клиенту внутреннего API причины отказа не
// раскрываются.
var (
	ErrNotFound     = errors.New("шлюз не найден")
	ErrNameTaken    = errors.New("шлюз с таким именем уже есть")
	ErrRevoked      = errors.New("шлюз отозван")
	ErrTokenInvalid = errors.New("токен регистрации неверный, истёк или уже использован")
	ErrUnknownCert  = errors.New("сертификат не принадлежит действующему шлюзу")
	ErrTooFrequent  = errors.New("heartbeat слишком часто")
	ErrNoRollback   = errors.New("откат не обнаружен: шлюз работает на манифесте не старше проверенного")
	// ErrRollbackViolated — откат не принимается при нарушенной целостности.
	ErrRollbackViolated = errors.New("откат не принимается: последняя проверка целостности шлюза выявила нарушение")
	ErrNoCA             = errors.New("внутренний УЦ не подключён: регистрация шлюзов недоступна")
	ErrInvalidRequest   = errors.New("неверные данные")
)

// Gateway — шлюз в реестре.
type Gateway struct {
	ID           string
	OrgID        string
	Name         string
	Status       string
	CreatedAt    time.Time
	CreatedBy    string
	RegisteredAt time.Time // нулевое — не зарегистрирован
	RevokedAt    time.Time
	CertSerial   string
	CertNotAfter time.Time
	LastSeenAt   time.Time
	LastAddr     netip.Addr
	Version      string
	BundleETag   string
	// Selftest и Integrity — последние итоги, которые шлюз сообщил в heartbeat
	// (задача 2.20); nil — шлюз их не присылал (старая версия или ещё нет).
	Selftest  *CheckReport
	Integrity *CheckReport
	// ManifestMaxVersion и ManifestMaxCreated — самый поздний манифест
	// успешной проверки шлюза; текущий манифест (Integrity) старше — откат
	// (В20 ревью 2.r4). Нулевое время — шлюз манифест не присылал.
	ManifestMaxVersion string
	ManifestMaxCreated time.Time
	// BundleKeysOK — ключи проверки пакетов шлюза совпадают с ключом подписи
	// сервера (В19 ревью 2.r4); nil — шлюз их не присылал.
	BundleKeysOK *bool
	// VerifyRequestedAt — администратор запросил проверку целостности, итога
	// ещё нет (Н38 ревью 2.r4); нулевое — запроса нет.
	VerifyRequestedAt time.Time
	// StartedAt — время запуска процесса шлюза из heartbeat (В27 ревью
	// 2.r5); нулевое — шлюз остановлен корректно или не сообщал.
	StartedAt time.Time
	// CertCA — корень УЦ действующего сертификата (ADR-0018, п. 6); пусто —
	// корень из -ca-cert (сертификат выпущен до ротаций).
	CertCA string
	// NextCert* — перевыпущенный сертификат, которым шлюз ещё не пришёл;
	// пустой серийный номер — его нет.
	NextCertSerial   string
	NextCertNotAfter time.Time
	NextCertCA       string
	// BundleKey — закреплённый ключ получателя HPKE (Н27); nil — не закреплён.
	BundleKey []byte
}

// Rollback — шлюз работает на выпуске старше того, что уже проверялся
// успешно (В20 ревью 2.r4, DM-42). Успешная проверка без сведений о
// манифесте после выпуска, который их присылал, — тоже откат: на выпуск,
// вышедший до этих сведений.
func (g Gateway) Rollback() bool {
	if g.Integrity == nil || g.ManifestMaxCreated.IsZero() {
		return false
	}
	if g.Integrity.ManifestCreated.IsZero() {
		return g.Integrity.OK
	}
	return g.Integrity.ManifestCreated.Before(g.ManifestMaxCreated)
}

// checkAcceptRollback — откат шлюза принимается, только если он есть и
// последняя проверка целостности шлюза успешна (как у сервера).
func checkAcceptRollback(g Gateway) error {
	switch {
	case !g.Rollback():
		return ErrNoRollback
	case !g.Integrity.OK:
		return ErrRollbackViolated
	}
	return nil
}

// CheckReport — итог самотеста или контроля целостности шлюза: только
// результат и счётчик, без путей и имён детекторов.
type CheckReport struct {
	OK     bool
	At     time.Time
	Reason string // для целостности — причина из перечня; для самотеста пусто
	Failed int
	// Только у целостности (В20, Н34 ревью 2.r4): версия и время сборки
	// манифеста (пусто — манифест не прочитан) и тестовый ключ манифеста.
	ManifestVersion string
	ManifestCreated time.Time
	TestSigned      bool
}

// NewToken — выпуск токена регистрации (aisec-cli).
type NewToken struct {
	OrgID string
	// GatewayID — ID нового шлюза; для перерегистрации не используется.
	GatewayID string
	Name      string
	TokenID   string
	HashAlg   string
	Hash      []byte
	CreatedAt time.Time
	CreatedBy string
	ExpiresAt time.Time
	// Reregister — новый токен для уже существующего шлюза (потерян ключ,
	// истекает сертификат); иначе существующее имя — ErrNameTaken.
	Reregister bool
}

// Heartbeat — сведения шлюза о себе.
type Heartbeat struct {
	Version    string
	BundleETag string // пусто — пакета ещё нет (задача 2.13)
	Addr       netip.Addr
	At         time.Time
	// Selftest и Integrity — nil: итог не обновляется.
	Selftest  *CheckReport
	Integrity *CheckReport
	// BundleKeysOK — итог сверки ключей проверки пакетов; nil — не обновляется.
	BundleKeysOK *bool
	// VerifyRequest — запрос проверки, на который выполнена проверка с итогом
	// Integrity (Н38 ревью 2.r4); нулевое — шлюз не сообщил.
	VerifyRequest time.Time
	// StartedAt — время запуска процесса шлюза (В27 ревью 2.r5); нулевое —
	// шлюз не сообщил (прежняя версия).
	StartedAt time.Time
	// Stopping — последний heartbeat при корректной остановке шлюза.
	Stopping bool
}

// TouchChange — что heartbeat изменил в строке шлюза; по нему сервис
// решает, что записать в журнал аудита в той же транзакции.
type TouchChange struct {
	// VerifyRequested — текущий запрос проверки (нулевое — запроса нет);
	// VerifyDone — шлюз прислал итог на этот запрос, запрос снят.
	VerifyRequested time.Time
	VerifyDone      bool
	// Started — запущен новый процесс шлюза: StartedAt отличается от
	// сохранённого. PrevStartedAt — прежний запуск, о чьей остановке шлюз
	// не сообщил (нулевое — такого нет).
	Started       bool
	PrevStartedAt time.Time
	// Stopped — шлюз сообщил о корректной остановке записанного запуска.
	Stopped bool
	// CertCA и CertNotAfter — действующий сертификат шлюза: по ним сервис
	// решает, нужен ли перевыпуск.
	CertCA       string
	CertNotAfter time.Time
}

// Store — хранилище реестра (миграция 0007_gateways). Рабочая реализация —
// PGStore, для тестов без PostgreSQL — Memory. Изменения пишутся вместе с
// записью аудита в одной транзакции (РСБ.1).
type Store interface {
	// CreateToken создаёт шлюз в состоянии pending (или берёт существующий
	// при Reregister) и токен; прежние непогашенные токены шлюза гасятся.
	CreateToken(ctx context.Context, t NewToken, rec func(Gateway) audit.Entry) (Gateway, error)
	// Register гасит токен по хешу (неизвестный, истёкший, погашенный или
	// шлюз отозван — ErrTokenInvalid), вызывает issue для выпуска
	// сертификата и делает шлюз активным с новым серийным номером — всё
	// одной транзакцией вместе с rec.
	// Новая регистрация записывает корень УЦ и ключ получателя из Issued
	// (nil — не закреплён) и снимает следующий сертификат.
	Register(ctx context.Context, hashAlg string, hash []byte, now time.Time,
		issue func(Gateway) (Issued, error), rec func(Gateway) audit.Entry) (Gateway, error)
	// BySerial — шлюз, чей действующий или следующий сертификат имеет этот
	// серийный номер.
	BySerial(ctx context.Context, serial string) (Gateway, error)
	// SetNextCert сохраняет перевыпущенный сертификат активного шлюза как
	// следующий (заменяет прежний следующий) вместе с rec.
	SetNextCert(ctx context.Context, id string, next Issued, rec func(Gateway) audit.Entry) (Gateway, error)
	// PromoteNext делает следующий сертификат с серийным номером serial
	// действующим вместе с rec; уже сделан — без изменений.
	PromoteNext(ctx context.Context, id, serial string, rec func(Gateway) audit.Entry) (Gateway, error)
	// PinBundleKey закрепляет ключ получателя, если он не закреплён (с rec),
	// и возвращает шлюз с закреплённым ключом.
	PinBundleKey(ctx context.Context, id string, key []byte, rec func(Gateway) audit.Entry) (Gateway, error)
	// Touch отмечает heartbeat активного шлюза. Если шлюз прислал итог
	// целостности на текущий запрос проверки, запрос снимается. Новый
	// StartedAt запоминается, Stopping с тем же StartedAt его стирает.
	// Записи audits(изменение) пишутся в той же транзакции.
	Touch(ctx context.Context, id string, hb Heartbeat, audits func(TouchChange) []audit.Entry) (TouchChange, error)
	// RequestVerify отмечает запрос проверки у всех активных шлюзов
	// организации и пишет rec(число шлюзов) одной транзакцией.
	RequestVerify(ctx context.Context, orgID string, at time.Time, rec func(n int) audit.Entry) (int, error)
	// Revoke отзывает шлюз по имени и гасит его токены.
	Revoke(ctx context.Context, orgID, name string, now time.Time, rec func(Gateway) audit.Entry) (Gateway, error)
	// List — все шлюзы организации по имени.
	List(ctx context.Context, orgID string) ([]Gateway, error)
	// AcceptRollback сбрасывает максимум манифеста шлюза до текущего
	// (намеренный откат выпуска, В20 ревью 2.r4); отката нет — ErrNoRollback.
	AcceptRollback(ctx context.Context, orgID, name string, rec func(prev, cur Gateway) audit.Entry) (Gateway, error)
}

// Auditor — журнал аудита для событий без изменения данных (отказы).
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) error
}

// Options — зависимости Service.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	// CA — внутренний УЦ; nil — регистрация недоступна (aisec-cli).
	CA    *aisecCrypto.CA
	Audit Auditor
	OrgID string // пусто — организация по умолчанию
	Clock func() time.Time
	// CertValidity — срок сертификата шлюза; ноль — ClientCertValidity.
	CertValidity time.Duration
	// HeartbeatMinInterval — ноль — DefaultHeartbeatMinInterval.
	HeartbeatMinInterval time.Duration
	Logger               *slog.Logger
	// AnchorRoot — ID корня из -ca-cert (ca.crt init): им выпущены
	// сертификаты без cert_ca. Пусто — корень CA.
	AnchorRoot string
}

// BundleKeys — ключи подписи пакетов конфигурации сервера (KeyID, задача
// 2.13): Current — действующий, Next — второй на время ротации (может быть
// пустым), Known — все ключи цепочки доверия после ротаций (ADR-0018, п. 4.5;
// пусто — ротаций не было).
type BundleKeys struct {
	Current string
	Next    string
	Known   []string
}

// Match — ключи проверки шлюза совпадают с ключами сервера (В19 ревью
// 2.r4): действующий ключ у шлюза есть, а других, кроме второго ключа
// ротации, нет. После ротаций шлюз сообщает свои якоря -bundle-pub: они
// должны быть в цепочке доверия. Чужой ключ у шлюза — признак подмены
// -bundle-pub.
func (k BundleKeys) Match(gateway []string) bool {
	if len(k.Known) > 0 {
		for _, id := range gateway {
			if !slices.Contains(k.Known, id) && (k.Next == "" || id != k.Next) {
				return false
			}
		}
		return len(gateway) > 0
	}
	if !slices.Contains(gateway, k.Current) {
		return false
	}
	for _, id := range gateway {
		if id != k.Current && (k.Next == "" || id != k.Next) {
			return false
		}
	}
	return true
}

// Service — регистрация, проверка и учёт шлюзов.
type Service struct {
	store    Store
	ca       *aisecCrypto.CA
	hasher   aisecCrypto.Hasher
	random   aisecCrypto.Random
	ids      *ids.Generator
	audit    Auditor
	orgID    string
	clock    func() time.Time
	validity time.Duration
	minHB    time.Duration
	logger   *slog.Logger
	// bundleKeys — ключи подписи пакетов; nil — сверка не выполняется
	// (сервер без ключа подписи).
	bundleKeys atomic.Pointer[BundleKeys]
	// roots — корни УЦ после ротаций; nil — один корень ca.
	roots      atomic.Pointer[RootSet]
	anchorRoot string
	// budgets — счётчики расхода из heartbeat (задача 3.18); nil — не
	// сохраняются.
	budgets BudgetSync

	mu       sync.Mutex
	lastHB   map[string]time.Time // ID шлюза → последний принятый heartbeat
	lastDeny map[string]time.Time // серийный номер → последняя запись об отказе
	// lastReissue и lastMismatch — по ID шлюза: перевыпуск и запись о
	// чужом ключе получателя не чаще раза в минуту.
	lastReissue, lastMismatch map[string]time.Time

	// malformed — запросы регистрации с токеном неверного формата: они идут
	// в технический журнал, а не в аудит (Н17 ревью 2.r3a, как В9).
	malformed atomic.Uint64
}

// MalformedTokens — число запросов регистрации с токеном неверного формата.
func (s *Service) MalformedTokens() uint64 { return s.malformed.Load() }

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Provider == nil || o.Audit == nil {
		return nil, errors.New("реестр шлюзов: не заданы хранилище, криптопрофиль или журнал аудита")
	}
	h, err := o.Provider.Hasher()
	if err != nil {
		return nil, err
	}
	r, err := o.Provider.Random()
	if err != nil {
		return nil, err
	}
	s := &Service{
		store: o.Store, ca: o.CA, hasher: h, random: r, ids: ids.NewGenerator(r), audit: o.Audit,
		orgID: o.OrgID, clock: o.Clock, validity: o.CertValidity, minHB: o.HeartbeatMinInterval, logger: o.Logger,
		lastHB: map[string]time.Time{}, lastDeny: map[string]time.Time{},
		lastReissue: map[string]time.Time{}, lastMismatch: map[string]time.Time{}, anchorRoot: o.AnchorRoot,
	}
	if s.anchorRoot == "" && s.ca != nil {
		s.anchorRoot = RootID(h, s.ca.CertDER())
	}
	if s.orgID == "" {
		s.orgID = audit.DefaultOrgID
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.validity == 0 {
		s.validity = aisecCrypto.ClientCertValidity
	}
	if s.minHB == 0 {
		s.minHB = DefaultHeartbeatMinInterval
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	return s, nil
}

// SetBundleKeys задаёт ключи подписи пакетов для сверки в heartbeat;
// вызывается после загрузки ключа подписи.
func (s *Service) SetBundleKeys(k BundleKeys) {
	if k.Current == "" {
		s.bundleKeys.Store(nil)
		return
	}
	s.bundleKeys.Store(&k)
}

// ValidName — допустимое имя шлюза: как логин, латиница в нижнем регистре.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// TokenInput — выпуск токена регистрации.
type TokenInput struct {
	Name       string
	TTL        time.Duration // ноль — DefaultTokenTTL
	Reregister bool
	Actor      audit.Actor
}

// IssueToken выпускает одноразовый токен регистрации шлюза (aisec-cli
// gateway token). Токен возвращается один раз; в БД, журнал и аудит
// попадает только его хеш или ID записи.
func (s *Service) IssueToken(ctx context.Context, in TokenInput) (string, Gateway, error) {
	if !ValidName(in.Name) {
		return "", Gateway{}, fmt.Errorf("%w: имя шлюза — 1–64 символа a-z, 0-9, «.», «_», «-», с буквы или цифры", ErrInvalidRequest)
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = DefaultTokenTTL
	}
	if ttl < time.Minute || ttl > MaxTokenTTL {
		return "", Gateway{}, fmt.Errorf("%w: срок токена — от минуты до %s", ErrInvalidRequest, MaxTokenTTL)
	}
	raw, err := aisecCrypto.RandomBytes(s.random, tokenBytes)
	if err != nil {
		return "", Gateway{}, err
	}
	gwID, err := s.ids.New()
	if err != nil {
		return "", Gateway{}, err
	}
	tokID, err := s.ids.New()
	if err != nil {
		return "", Gateway{}, err
	}
	now := s.clock().UTC()
	gw, err := s.store.CreateToken(ctx, NewToken{
		OrgID: s.orgID, GatewayID: gwID.String(), Name: in.Name, TokenID: tokID.String(),
		HashAlg: s.hasher.Name(), Hash: s.hasher.Sum(raw), CreatedAt: now, CreatedBy: actorRef(in.Actor),
		ExpiresAt: now.Add(ttl), Reregister: in.Reregister,
	}, func(gw Gateway) audit.Entry {
		return audit.Entry{
			OrgID: s.orgID, Actor: in.Actor, Action: "gateway.token_issue",
			Object: audit.Object{Type: "gateway", ID: gw.ID}, Result: audit.ResultSuccess,
			Details: map[string]any{
				"name": gw.Name, "registration_id": tokID.String(), "expires_at": now.Add(ttl).Format(time.RFC3339),
				"reregister": in.Reregister,
			},
		}
	})
	if err != nil {
		return "", Gateway{}, err
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(raw), gw, nil
}

func actorRef(a audit.Actor) string {
	ref := string(a.Type) + ":" + a.ID
	if len(ref) > 128 {
		ref = ref[:128]
	}
	return ref
}

// parseToken строго разбирает токен регистрации: префикс, точная длина,
// каноническая base64url. Хешируются исходные байты.
func parseToken(s string) ([]byte, error) {
	if len(s) != TokenLen || !strings.HasPrefix(s, TokenPrefix) {
		return nil, ErrTokenInvalid
	}
	enc := s[len(TokenPrefix):]
	b, err := base64.RawURLEncoding.Strict().DecodeString(enc)
	if err != nil || len(b) != tokenBytes || base64.RawURLEncoding.EncodeToString(b) != enc {
		return nil, ErrTokenInvalid
	}
	return b, nil
}

// RegisterInput — запрос шлюза на регистрацию.
type RegisterInput struct {
	Token    string
	CSR      []byte
	SourceIP netip.Addr
	// BundleKey — открытый ключ получателя HPKE шлюза (Н27): закрепляется
	// при регистрации; nil — закрепится при первом запросе пакета.
	BundleKey []byte
}

// Registration — итог регистрации для ответа шлюзу.
type Registration struct {
	Gateway Gateway
	CertPEM []byte
	CAPEM   []byte
}

// Register выпускает шлюзу сертификат по токену (ИАФ.10). Неверный CSR —
// ErrInvalidRequest до проверки токена (токен не тратится). Любой отказ по
// токену — ErrTokenInvalid с записью аудита без токена.
func (s *Service) Register(ctx context.Context, in RegisterInput) (Registration, error) {
	if s.ca == nil {
		return Registration{}, ErrNoCA
	}
	if err := aisecCrypto.CheckCSR(in.CSR); err != nil {
		return Registration{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err) //nolint:errorlint // причина CSR — только текстом
	}
	if in.BundleKey != nil && len(in.BundleKey) != aisecCrypto.RecipientPublicKeySize {
		return Registration{}, fmt.Errorf("%w: ключ получателя — %d байт", ErrInvalidRequest, aisecCrypto.RecipientPublicKeySize)
	}
	now := s.clock().UTC()
	raw, err := parseToken(in.Token)
	if err != nil {
		// Мусор вместо токена — не попытка с настоящим токеном: счётчик и
		// технический журнал без записи в аудит, чтобы перебор с открытого
		// маршрута не раздувал журнал аудита (Н17 ревью 2.r3a).
		n := s.malformed.Add(1)
		s.logger.Warn("регистрация шлюза: токен неверного формата", "source_ip", in.SourceIP.String(), "total", n)
		return Registration{}, ErrTokenInvalid
	}
	// Поиск по хешу: время сравнения в индексе зависит от хеша, а не от
	// токена; совпавший хеш дополнительно сверяется за постоянное время.
	hash := s.hasher.Sum(raw)
	var certPEM []byte
	gw, err := s.store.Register(ctx, s.hasher.Name(), hash, now, func(gw Gateway) (Issued, error) {
		c, info, err := s.ca.IssueClient(in.CSR, gw.ID, s.validity, now)
		certPEM = c
		return Issued{Info: info, CA: s.activeRoot(), BundleKey: in.BundleKey}, err
	}, func(gw Gateway) audit.Entry {
		return audit.Entry{
			OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: gw.ID, Name: gw.Name},
			SourceIP: in.SourceIP, Action: "gateway.register", Object: audit.Object{Type: "gateway", ID: gw.ID},
			Result: audit.ResultSuccess,
			Details: map[string]any{
				"cert_serial": gw.CertSerial, "cert_not_after": gw.CertNotAfter.UTC().Format(time.RFC3339),
				"root_id": gw.CertCA, "bundle_key_pinned": gw.BundleKey != nil,
			},
		}
	})
	if errors.Is(err, ErrTokenInvalid) {
		return Registration{}, s.registerFailed(ctx, in.SourceIP, "token")
	}
	if err != nil {
		return Registration{}, err
	}
	return Registration{Gateway: gw, CertPEM: certPEM, CAPEM: s.ca.CertPEM()}, nil
}

func (s *Service) registerFailed(ctx context.Context, ip netip.Addr, reason string) error {
	err := s.audit.Record(ctx, audit.Entry{
		OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: "unknown", Name: "Незарегистрированный шлюз"},
		SourceIP: ip, Action: "gateway.register", Result: audit.ResultDenied,
		Details: map[string]any{"reason": reason},
	})
	if err != nil {
		return fmt.Errorf("аудит отказа регистрации: %w", err)
	}
	return ErrTokenInvalid
}

// Authenticate находит действующий шлюз по проверенному при рукопожатии
// сертификату: серийный номер должен совпадать с текущим или следующим
// (перевыпущенным) сертификатом шлюза, имя — с ID шлюза, корень цепочки —
// с корнем без истёкшего перекрытия (ADR-0018, п. 6.2). Первый запрос со
// следующим сертификатом делает его действующим. Отказ пишется в аудит не
// чаще раза в минуту на сертификат.
func (s *Service) Authenticate(ctx context.Context, peer aisecCrypto.PeerIdentity, ip netip.Addr) (Gateway, error) {
	gw, err := s.store.BySerial(ctx, peer.Serial)
	if err == nil {
		if reason := s.checkRoot(peer.RootDER, s.clock()); reason != "" {
			return Gateway{}, s.denied(ctx, peer, ip, reason, ErrUnknownCert)
		}
	}
	if err == nil && gw.Status == StatusActive && gw.ID == peer.CommonName && gw.NextCertSerial != "" &&
		peer.Serial == gw.NextCertSerial && s.clock().Before(gw.NextCertNotAfter) {
		if gw, err = s.promote(ctx, gw, ip); err != nil {
			return Gateway{}, err
		}
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return Gateway{}, s.denied(ctx, peer, ip, "unknown_certificate", ErrUnknownCert)
	case err != nil:
		return Gateway{}, err
	case gw.ID != peer.CommonName || gw.OrgID != s.orgID:
		return Gateway{}, s.denied(ctx, peer, ip, "unknown_certificate", ErrUnknownCert)
	case gw.Status != StatusActive:
		return Gateway{}, s.denied(ctx, peer, ip, "revoked", ErrRevoked)
	case !s.clock().Before(gw.CertNotAfter):
		return Gateway{}, s.denied(ctx, peer, ip, "expired", ErrUnknownCert)
	}
	return gw, nil
}

func (s *Service) denied(ctx context.Context, peer aisecCrypto.PeerIdentity, ip netip.Addr, reason string, cause error) error {
	now := s.clock()
	s.mu.Lock()
	last, seen := s.lastDeny[peer.Serial]
	write := !seen || now.Sub(last) >= deniedAuditEvery
	if write {
		prune(s.lastDeny, now, deniedAuditEvery)
		s.lastDeny[peer.Serial] = now
	}
	s.mu.Unlock()
	if !write {
		return cause
	}
	// Сертификат выпущен нашим УЦ (цепочка проверена), CN — до 64 символов.
	id := peer.CommonName
	if id == "" {
		id = "unknown"
	}
	if err := s.audit.Record(ctx, audit.Entry{
		OrgID: s.orgID, Actor: audit.Actor{Type: audit.ActorGateway, ID: id}, SourceIP: ip,
		Action: "gateway.mtls_denied", Result: audit.ResultDenied,
		Details: map[string]any{"reason": reason, "cert_serial": peer.Serial},
	}); err != nil {
		s.logger.Error("аудит отказа шлюзу не записан", "error", err)
	}
	return cause
}

// prune удаляет записи старше age, если их слишком много: память ограничена.
func prune(m map[string]time.Time, now time.Time, age time.Duration) {
	if len(m) < maxTracked {
		return
	}
	for k, t := range m {
		if now.Sub(t) >= age {
			delete(m, k)
		}
	}
	// Если все свежие — сбрасываем: лучше лишняя запись или heartbeat,
	// чем неограниченный рост.
	if len(m) >= maxTracked {
		clear(m)
	}
}

// HeartbeatInput — тело heartbeat после разбора.
type HeartbeatInput struct {
	Version    string
	BundleETag string
	// Selftest и Integrity — необязательные итоги проверок шлюза (задача 2.20).
	Selftest  *CheckReport
	Integrity *CheckReport
	// BundleKeys — KeyID ключей проверки пакетов шлюза (-bundle-pub, В19
	// ревью 2.r4); пусто — шлюз их не присылает (прежняя версия).
	BundleKeys []string
	// VerifyRequest — время запроса проверки из консоли, на который шлюз
	// выполнил проверку с итогом Integrity (Н38 ревью 2.r4); нулевое — нет.
	VerifyRequest time.Time
	// StartedAt — время запуска процесса шлюза, Stopping — шлюз
	// останавливается (В27 ревью 2.r5, РСБ.2); нулевое StartedAt — шлюз
	// прежней версии.
	StartedAt time.Time
	Stopping  bool
	// Budget — счётчики расхода процесса шлюза (задача 3.18); nil — шлюз
	// их не присылает (нет раздела budgets в пакете или прежняя версия).
	Budget *BudgetReport
}

// Пределы итогов проверок в heartbeat.
const (
	maxReportFailed = 1000
	// maxBundleKeys — ключей проверки пакетов у шлюза (config.MaxBundlePubFiles).
	maxBundleKeys = 2
	// maxManifestVersion — длина версии манифеста (integrity.maxVersionLen).
	maxManifestVersion = 128
	// maxReportFuture — насколько время проверки может опережать часы сервера.
	maxReportFuture = 5 * time.Minute
)

// integrityReasons — причины итога целостности (миграция 0008_integrity).
var integrityReasons = []string{"ok", "manifest_missing", "manifest_invalid", "signature_invalid", "files_mismatch"}

func (r *CheckReport) validate(name string, integrity bool) error {
	if r == nil {
		return nil
	}
	if !integrity && (r.ManifestVersion != "" || !r.ManifestCreated.IsZero() || r.TestSigned) {
		return fmt.Errorf("%w: %s: сведения о манифесте только у integrity", ErrInvalidRequest, name)
	}
	if (r.ManifestVersion == "") != r.ManifestCreated.IsZero() || len(r.ManifestVersion) > maxManifestVersion {
		return fmt.Errorf("%w: %s: manifest_version (до %d символов) и manifest_created задаются вместе", ErrInvalidRequest, name, maxManifestVersion)
	}
	for i := 0; i < len(r.ManifestVersion); i++ {
		if c := r.ManifestVersion[i]; c < 0x20 || c > 0x7e {
			return fmt.Errorf("%w: %s.manifest_version — только печатные символы ASCII", ErrInvalidRequest, name)
		}
	}
	if r.Failed < 0 || r.Failed > maxReportFailed {
		return fmt.Errorf("%w: %s.failed — от 0 до %d", ErrInvalidRequest, name, maxReportFailed)
	}
	if r.At.IsZero() {
		return fmt.Errorf("%w: %s.checked_at обязателен", ErrInvalidRequest, name)
	}
	if r.OK && r.Failed != 0 {
		return fmt.Errorf("%w: %s: ok при ненулевом failed", ErrInvalidRequest, name)
	}
	if !integrity {
		if r.Reason != "" {
			return fmt.Errorf("%w: %s.reason не используется", ErrInvalidRequest, name)
		}
		return nil
	}
	if !slices.Contains(integrityReasons, r.Reason) || r.OK != (r.Reason == "ok") {
		return fmt.Errorf("%w: %s.reason не из перечня или не согласован с ok", ErrInvalidRequest, name)
	}
	return nil
}

// Validate проверяет поля heartbeat: версия — 1–64 символа
// [0-9A-Za-z.+_-], ETag — до 128 печатных символов ASCII, итоги проверок —
// по пределам CheckReport.
func (in HeartbeatInput) Validate() error {
	if err := in.Selftest.validate("selftest", false); err != nil {
		return err
	}
	if err := in.Integrity.validate("integrity", true); err != nil {
		return err
	}
	if !in.VerifyRequest.IsZero() && in.Integrity == nil {
		return fmt.Errorf("%w: verify_request — только вместе с итогом integrity", ErrInvalidRequest)
	}
	if in.Stopping && in.StartedAt.IsZero() {
		return fmt.Errorf("%w: stopping — только вместе с started_at", ErrInvalidRequest)
	}
	if in.Budget != nil && in.StartedAt.IsZero() {
		return fmt.Errorf("%w: budget — только вместе с started_at", ErrInvalidRequest)
	}
	if err := in.Budget.validate(); err != nil {
		return err
	}
	if in.Version == "" || len(in.Version) > maxVersion {
		return fmt.Errorf("%w: version — от 1 до %d символов", ErrInvalidRequest, maxVersion)
	}
	for i := 0; i < len(in.Version); i++ {
		c := in.Version[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && strings.IndexByte(".+_-", c) < 0 {
			return fmt.Errorf("%w: version — только латиница, цифры и «.+_-»", ErrInvalidRequest)
		}
	}
	if len(in.BundleKeys) > maxBundleKeys {
		return fmt.Errorf("%w: bundle_keys — не больше %d", ErrInvalidRequest, maxBundleKeys)
	}
	for i, id := range in.BundleKeys {
		if !keyIDRe.MatchString(id) || slices.Contains(in.BundleKeys[:i], id) {
			return fmt.Errorf("%w: bundle_keys — 16 строчных шестнадцатеричных цифр без повторов", ErrInvalidRequest)
		}
	}
	if len(in.BundleETag) > maxETag {
		return fmt.Errorf("%w: bundle_etag — до %d символов", ErrInvalidRequest, maxETag)
	}
	for i := 0; i < len(in.BundleETag); i++ {
		if c := in.BundleETag[i]; c < 0x21 || c > 0x7e {
			return fmt.Errorf("%w: bundle_etag — только печатные символы ASCII", ErrInvalidRequest)
		}
	}
	return nil
}

// Heartbeat отмечает контакт шлюза. Чаще HeartbeatMinInterval — ErrTooFrequent.
func (s *Service) Heartbeat(ctx context.Context, gatewayID string, in HeartbeatInput, ip netip.Addr) (HeartbeatResult, error) {
	if err := in.Validate(); err != nil {
		return HeartbeatResult{}, err
	}
	now := s.clock().UTC()
	for _, r := range []*CheckReport{in.Selftest, in.Integrity} {
		if r != nil && (r.At.After(now.Add(maxReportFuture)) || r.ManifestCreated.After(now.Add(maxReportFuture))) {
			return HeartbeatResult{}, fmt.Errorf("%w: время проверки в будущем", ErrInvalidRequest)
		}
	}
	if in.StartedAt.After(now.Add(maxReportFuture)) {
		return HeartbeatResult{}, fmt.Errorf("%w: started_at в будущем", ErrInvalidRequest)
	}
	// PostgreSQL хранит микросекунды: шлюз присылает то же время в каждом
	// heartbeat, сравнение идёт после того же округления.
	in.StartedAt = in.StartedAt.Truncate(time.Microsecond)
	// Сверка ключей проверки пакетов с ключом подписи сервера (В19).
	var keysOK *bool
	if k := s.bundleKeys.Load(); k != nil && len(in.BundleKeys) > 0 {
		ok := k.Match(in.BundleKeys)
		keysOK = &ok
	}
	// Heartbeat остановки идёт сразу за обычным: у него свой предел частоты,
	// чтобы остановка записалась, а поток таких heartbeat не обходил предел.
	key := gatewayID
	if in.Stopping {
		key += "\x00stopping"
	}
	s.mu.Lock()
	if last, ok := s.lastHB[key]; ok && now.Sub(last) < s.minHB {
		s.mu.Unlock()
		return HeartbeatResult{}, ErrTooFrequent
	}
	prune(s.lastHB, now, s.minHB)
	s.lastHB[key] = now
	s.mu.Unlock()
	ch, err := s.store.Touch(ctx, gatewayID, Heartbeat{
		Version: in.Version, BundleETag: in.BundleETag, Addr: ip, At: now, Selftest: in.Selftest, Integrity: in.Integrity,
		BundleKeysOK: keysOK, VerifyRequest: in.VerifyRequest, StartedAt: in.StartedAt, Stopping: in.Stopping,
	}, func(ch TouchChange) []audit.Entry {
		return s.heartbeatEntries(gatewayID, in, ip, ch)
	})
	if err != nil {
		return HeartbeatResult{}, err
	}
	out := HeartbeatResult{At: now, Reissue: s.needReissue(ch.CertCA, ch.CertNotAfter, now),
		Budget: s.syncBudget(ctx, gatewayID, in)}
	if !ch.VerifyDone {
		out.VerifyRequestedAt = ch.VerifyRequested
	}
	return out, nil
}

// heartbeatEntries — записи аудита по итогам heartbeat: проверка
// целостности по команде (Н38 ревью 2.r4), запуск и остановка шлюза
// (РСБ.2, В27 ревью 2.r5).
func (s *Service) heartbeatEntries(gatewayID string, in HeartbeatInput, ip netip.Addr, ch TouchChange) []audit.Entry {
	actor := audit.Actor{Type: audit.ActorSystem, ID: "gateway:" + gatewayID}
	obj := audit.Object{Type: "component", ID: "gateway:" + gatewayID}
	var out []audit.Entry
	if ch.VerifyDone {
		r := in.Integrity
		res := audit.ResultSuccess
		if !r.OK {
			res = audit.ResultFailure
		}
		out = append(out, audit.Entry{
			OrgID: s.orgID, Actor: actor, Action: "integrity.check", Object: obj, Result: res, SourceIP: ip,
			Details: map[string]any{"trigger": "manual", "requested_at": ch.VerifyRequested.UTC().Format(time.RFC3339Nano),
				"reason": r.Reason, "failed": r.Failed, "manifest_version": r.ManifestVersion, "test_signed": r.TestSigned},
		})
	}
	started := in.StartedAt.UTC().Format(time.RFC3339Nano)
	if ch.Started {
		d := map[string]any{"component": "gateway", "version": in.Version, "started_at": started}
		// Прежний запуск без записи об остановке — аварийная остановка или
		// потеря связи при остановке.
		if !ch.PrevStartedAt.IsZero() {
			d["previous_started_at"] = ch.PrevStartedAt.UTC().Format(time.RFC3339Nano)
			d["previous_stop_recorded"] = false
		}
		out = append(out, audit.Entry{OrgID: s.orgID, Actor: actor, Action: "component.start", Object: obj,
			Result: audit.ResultSuccess, SourceIP: ip, Details: d})
	}
	if ch.Stopped {
		out = append(out, audit.Entry{OrgID: s.orgID, Actor: actor, Action: "component.stop", Object: obj,
			Result: audit.ResultSuccess, SourceIP: ip,
			Details: map[string]any{"component": "gateway", "version": in.Version, "started_at": started}})
	}
	return out
}

// HeartbeatResult — ответ на heartbeat: время сервера и запрос проверки
// целостности (нулевое — запроса нет).
type HeartbeatResult struct {
	At                time.Time
	VerifyRequestedAt time.Time
	// Reissue — шлюзу нужен новый сертификат (ADR-0018, п. 6.3).
	Reissue bool
	// Budget — расход остальных процессов по приложениям с жёстким
	// бюджетом (задача 3.18); nil — счётчики не присланы или не сохранены.
	Budget *BudgetState
}

// RequestVerify — проверка целостности всех активных шлюзов по команде
// администратора (Н38 ревью 2.r4, ОЦЛ.2): признак уходит шлюзам в ответах
// heartbeat, итог каждого шлюза пишется в журнал аудита, когда придёт.
// Возвращает число шлюзов, которым передан запрос.
func (s *Service) RequestVerify(ctx context.Context, by audit.Actor, ip netip.Addr) (int, error) {
	at := s.clock().UTC().Truncate(time.Microsecond)
	return s.store.RequestVerify(ctx, s.orgID, at, func(n int) audit.Entry {
		return audit.Entry{
			OrgID: s.orgID, Actor: by, Action: "integrity.verify_requested", SourceIP: ip,
			Object: audit.Object{Type: "component", ID: "gateways"}, Result: audit.ResultSuccess,
			Details: map[string]any{"gateways": n, "requested_at": at.Format(time.RFC3339Nano)},
		}
	})
}

// HeartbeatMinInterval — минимальный промежуток между heartbeat шлюза.
func (s *Service) HeartbeatMinInterval() time.Duration { return s.minHB }

// Revoke отзывает шлюз (aisec-cli gateway revoke): его сертификат перестаёт
// приниматься сразу, токены гасятся.
func (s *Service) Revoke(ctx context.Context, name string, actor audit.Actor) (Gateway, error) {
	if !ValidName(name) {
		return Gateway{}, fmt.Errorf("%w: неверное имя шлюза", ErrInvalidRequest)
	}
	now := s.clock().UTC()
	return s.store.Revoke(ctx, s.orgID, name, now, func(gw Gateway) audit.Entry {
		return audit.Entry{
			OrgID: s.orgID, Actor: actor, Action: "gateway.revoke",
			Object: audit.Object{Type: "gateway", ID: gw.ID}, Result: audit.ResultSuccess,
			Details: map[string]any{"name": gw.Name, "cert_serial": gw.CertSerial},
		}
	})
}

// AcceptRollback — намеренный откат шлюза на более старый выпуск (aisec-cli
// verify -accept-rollback -gateway): максимум манифеста шлюза становится
// текущим, запись integrity.rollback_accepted — с обеими версиями.
func (s *Service) AcceptRollback(ctx context.Context, name string, actor audit.Actor) (Gateway, error) {
	if !ValidName(name) {
		return Gateway{}, fmt.Errorf("%w: неверное имя шлюза", ErrInvalidRequest)
	}
	return s.store.AcceptRollback(ctx, s.orgID, name, func(prev, cur Gateway) audit.Entry {
		return audit.Entry{
			OrgID: s.orgID, Actor: actor, Action: "integrity.rollback_accepted",
			Object: audit.Object{Type: "component", ID: "gateway:" + cur.ID}, Result: audit.ResultSuccess,
			Details: map[string]any{"name": cur.Name, "previous_version": prev.ManifestMaxVersion,
				"previous_created": prev.ManifestMaxCreated.UTC().Format(time.RFC3339),
				"manifest_version": cur.Integrity.ManifestVersion,
				"manifest_created": cur.Integrity.ManifestCreated.UTC().Format(time.RFC3339)},
		}
	})
}

// List — шлюзы организации.
func (s *Service) List(ctx context.Context) ([]Gateway, error) { return s.store.List(ctx, s.orgID) }

// startChange — запуск и остановка по heartbeat (общее для хранилищ):
// prev — сохранённое время запуска (нулевое — нет). set — StartedAt
// строки меняется на next (нулевое — стирается).
func startChange(prev time.Time, hb Heartbeat, ch *TouchChange) (next time.Time, set bool) {
	switch {
	case hb.Stopping:
		if !prev.IsZero() && prev.Equal(hb.StartedAt) {
			ch.Stopped = true
			return time.Time{}, true
		}
	case !hb.StartedAt.IsZero() && !prev.Equal(hb.StartedAt):
		ch.Started, ch.PrevStartedAt = true, prev
		return hb.StartedAt, true
	}
	return time.Time{}, false
}
