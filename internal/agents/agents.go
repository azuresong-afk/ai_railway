// Пакет agents — реестр агентов, MCP-серверов и инструментов в сервере
// управления (ТЗ 5.10, 5.16; задача 4.8, ADR-0023, раздел 1).
//
// Агент принадлежит приложению и обращается только к своим MCP-серверам.
// Инструмент — пара (MCP-сервер, имя) или (агент, function/<имя>); шлюз
// сообщает об увиденных описаниях (tools:observe), сервер хранит хеш
// последнего увиденного и одобренного описания. Изменённое после одобрения
// описание переводит инструмент в changed: вызовы блокируются до повторного
// одобрения (DM-25), поднимается оповещение agents.tool_changed. Учётные
// данные MCP-сервера шифруются ключом данных (keyring.Box, AAD
// mcp_servers|credential|<id>) и не возвращаются в ответах. Каждое
// изменение пишется в журнал аудита той же транзакцией (РСБ.1).
package agents

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/tooldesc"
)

// Пределы (ADR-0023, раздел 1).
const (
	MaxAgents        = 256  // агентов в организации
	MaxServers       = 64   // MCP-серверов в организации
	MaxTools         = 2000 // инструментов в организации
	MaxToolsPerOwner = 256  // инструментов на MCP-сервер или на агента (функции)
	MaxAgentServers  = 64   // MCP-серверов в списке агента
	// MaxObserve — описаний в одном сообщении tools:observe.
	MaxObserve = 256
	// ObserveInterval — не чаще раза за этот срок на MCP-сервер (агента).
	ObserveInterval = 10 * time.Second
	// MaxCAPEM — корневые сертификаты MCP-сервера.
	MaxCAPEM = 256 << 10
	// MaxCredential — учётные данные MCP-сервера.
	MaxCredential = 16 << 10
	// DefaultCallTimeout и MaxCallTimeout — срок tools/call, секунды
	// (ADR-0023, раздел 6).
	DefaultCallTimeout = 120
	MaxCallTimeout     = 600
	maxName            = 200
	maxDescription     = 2000
	maxOwner           = 200
	maxComment         = 500
	maxURL             = 2048
	maxHeaderName      = 64
)

// Состояния агента.
const (
	AgentActive   = "active"
	AgentDisabled = "disabled"
)

// Версии протокола MCP (ADR-0023, раздел 6).
const (
	MCP20260728 = "2026-07-28"
	MCP20251125 = "2025-11-25"
)

// MCPVersions — поддерживаемые версии MCP.
var MCPVersions = []string{MCP20260728, MCP20251125}

// Ошибки.
var (
	ErrNotFound    = errors.New("не найдено")
	ErrSlugTaken   = errors.New("ID уже занят")
	ErrInUse       = errors.New("объект используется")
	ErrTooMany     = errors.New("достигнут предел числа объектов")
	ErrNoDataKey   = errors.New("ключ данных не подключён: учётные данные MCP-серверов недоступны")
	ErrNoApp       = errors.New("приложение не найдено")
	ErrArchivedApp = errors.New("приложение в архиве")
	// ErrConfirmRequired — ослабление защиты без повторной проверки
	// субъекта: её нечем выполнить.
	ErrConfirmRequired = errors.New("ослабление защиты требует повторной проверки")
	// ErrSecurityRequired — изменение доступно только с правом
	// agents.tools.approve (администратор безопасности).
	ErrSecurityRequired = errors.New("нужно право agents.tools.approve")
	// ErrStale — описание изменилось после того, как его показали
	// администратору: одобрять нужно увиденное.
	ErrStale = errors.New("описание инструмента изменилось")
	// ErrServerChanged — адрес или корневые сертификаты MCP-сервера сменили,
	// пока задавали учётные данные.
	ErrServerChanged = errors.New("адрес MCP-сервера изменился")
	// ErrTooSoon — tools:observe по этому MCP-серверу чаще ObserveInterval.
	ErrTooSoon = errors.New("сообщение об инструментах чаще раза в 10 с")
	// errUnchanged — fn отказалась от изменения: без записи аудита.
	errUnchanged = errors.New("без изменений")
)

// InputError — неверные данные запроса; текст показывается пользователю.
type InputError struct{ Errs []error }

func (e *InputError) Error() string { return errors.Join(e.Errs...).Error() }

func invalid(errs ...error) error { return &InputError{Errs: errs} }

func invalidf(format string, a ...any) error { return invalid(fmt.Errorf(format, a...)) }

// Sealed — зашифрованные учётные данные MCP-сервера.
type Sealed struct {
	Data  []byte
	KeyID string
	Alg   string
	SetAt time.Time
}

// Agent — агент приложения.
type Agent struct {
	ID          string
	OrgID       string
	AppID       string
	Slug        string
	Name        string
	Description string
	Owner       string
	// Servers — ID MCP-серверов, к которым агенту можно обращаться.
	Servers   []string
	Status    string
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
}

// MCPServer — вышестоящий MCP-сервер.
type MCPServer struct {
	ID    string
	OrgID string
	Slug  string
	Name  string
	URL   string
	CAPEM string
	// AuthHeader — имя заголовка учётных данных; пусто — Authorization:
	// Bearer.
	AuthHeader string
	Credential *Sealed
	// External — сервер вне контура заказчика (по умолчанию).
	External bool
	// InsecureHTTP — разрешён адрес http:// (только администратор
	// безопасности, ослабление DM-40).
	InsecureHTTP bool
	// CallTimeout — срок tools/call, секунды; 0 — DefaultCallTimeout.
	CallTimeout int
	Versions    []string
	CreatedAt   time.Time
	CreatedBy   string
	UpdatedAt   time.Time
	UpdatedBy   string
}

// Tool — инструмент в реестре.
type Tool struct {
	ID    string
	OrgID string
	// ServerID — MCP-сервер; пусто — функция агента AgentID.
	ServerID string
	AgentID  string
	Name     string
	// Descriptor и Hash — последнее увиденное описание (каноническая форма)
	// и его хеш; ApprovedDescriptor и ApprovedHash — одобренное.
	Descriptor         []byte
	Hash               []byte
	ApprovedDescriptor []byte
	ApprovedHash       []byte
	HashAlg            string
	Risk               policy.ToolRisk
	Status             policy.ToolStatus
	FirstSeen          time.Time
	LastSeen           time.Time
	// DecidedBy, DecidedAt, Comment — последнее решение администратора
	// (одобрение, снятие, риск).
	DecidedBy string
	DecidedAt time.Time
	Comment   string
	UpdatedAt time.Time
}

// AppInfo — приложение для проверки агента: владелец и архив.
type AppInfo struct {
	ID       string
	Slug     string
	OwnerID  string
	Archived bool
}

// Apps — приложения организации (internal/apps).
type Apps interface {
	// App — ErrNoApp, если приложения нет.
	App(ctx context.Context, id string) (AppInfo, error)
	// Owned — ID приложений владельца.
	Owned(ctx context.Context, ownerID string) ([]string, error)
}

// ToolFilter — отбор инструментов.
type ToolFilter struct {
	ServerID string
	AgentID  string
	Status   policy.ToolStatus
}

// Observed — увиденное шлюзом описание.
type Observed struct {
	Desc Descriptor
	Hash []byte
	// Suspicious — детекторы шлюза нашли внедрённые инструкции (DM-24).
	Suspicious bool
}

// Store — хранилище (миграция 0052_agents). Рабочая реализация — PGStore,
// для тестов без PostgreSQL — Memory. Функции fn выполняются внутри
// транзакции над заблокированной строкой и возвращают запись аудита,
// которая фиксируется вместе с изменением (РСБ.1).
type Store interface {
	// CreateServer — ErrSlugTaken, ErrTooMany.
	CreateServer(ctx context.Context, m MCPServer, rec audit.Entry) error
	UpdateServer(ctx context.Context, orgID, id string, fn func(*MCPServer) (audit.Entry, error)) (MCPServer, error)
	// DeleteServer — ErrInUse, если сервер в списке агента; инструменты
	// сервера удаляются вместе с ним.
	DeleteServer(ctx context.Context, orgID, id string, fn func(MCPServer) (audit.Entry, error)) (MCPServer, error)
	Server(ctx context.Context, orgID, id string) (MCPServer, error)
	ServerBySlug(ctx context.Context, orgID, slug string) (MCPServer, error)
	Servers(ctx context.Context, orgID string) ([]MCPServer, error)

	// CreateAgent — ErrSlugTaken, ErrTooMany, ErrNotFound (сервер).
	CreateAgent(ctx context.Context, a Agent, rec audit.Entry) error
	UpdateAgent(ctx context.Context, orgID, id string, fn func(*Agent) (audit.Entry, error)) (Agent, error)
	// DeleteAgent — ErrInUse, если к агенту привязан ключ приложения.
	DeleteAgent(ctx context.Context, orgID, id string, fn func(Agent) (audit.Entry, error)) (Agent, error)
	Agent(ctx context.Context, orgID, id string) (Agent, error)
	AgentBySlug(ctx context.Context, orgID, appID, slug string) (Agent, error)
	// Agents — по приложению и slug; appIDs не nil — только этих приложений.
	Agents(ctx context.Context, orgID string, appIDs []string) ([]Agent, error)

	// Observe блокирует MCP-сервер (агента для функций) и передаёт fn
	// инструменты, известные по именам из списка; fn возвращает новые и
	// изменённые записи с аудитом, которые сохраняются той же транзакцией.
	// total — инструментов в организации, owned — у сервера (агента).
	Observe(ctx context.Context, orgID, serverID, agentID string, names []string,
		fn func(known map[string]Tool, total, owned int) ([]Tool, []audit.Entry, error)) error
	UpdateTool(ctx context.Context, orgID, id string, fn func(*Tool) (audit.Entry, error)) (Tool, error)
	Tool(ctx context.Context, orgID, id string) (Tool, error)
	// Tools — по серверу (функции — по агенту) и имени.
	Tools(ctx context.Context, orgID string, f ToolFilter) ([]Tool, error)
}

// Options — зависимости Service.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	// Box — ключ данных для учётных данных MCP-серверов; nil — их нельзя
	// задать (ErrNoDataKey).
	Box   *keyring.Box
	Apps  Apps
	OrgID string // пусто — организация по умолчанию
	Clock func() time.Time
	// AllowedNetworks — сети, разрешённые для MCP-серверов вопреки правилу
	// адресов (internal/netguard).
	AllowedNetworks []netip.Prefix
}

// Service — агенты, MCP-серверы и инструменты.
type Service struct {
	store   Store
	tls     aisecCrypto.TLSProvider
	hasher  aisecCrypto.Hasher
	ids     *ids.Generator
	box     *keyring.Box
	apps    Apps
	orgID   string
	clock   func() time.Time
	allowed []netip.Prefix

	mu       sync.Mutex
	observed map[string]time.Time // последний tools:observe по серверу (агенту)
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Provider == nil || o.Apps == nil {
		return nil, errors.New("агенты: не заданы хранилище, криптопрофиль или приложения")
	}
	h, err := o.Provider.Hasher()
	if err != nil {
		return nil, err
	}
	r, err := o.Provider.Random()
	if err != nil {
		return nil, err
	}
	t, err := o.Provider.TLS()
	if err != nil {
		return nil, err
	}
	s := &Service{store: o.Store, tls: t, hasher: h, ids: ids.NewGenerator(r), box: o.Box, apps: o.Apps,
		orgID: o.OrgID, clock: o.Clock, allowed: o.AllowedNetworks, observed: map[string]time.Time{}}
	if s.orgID == "" {
		s.orgID = audit.DefaultOrgID
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	return s, nil
}

// HashAlg — алгоритм хеша описаний на этом сервере.
func (s *Service) HashAlg() string { return s.hasher.Name() }

// Hash — хеш описания на криптопрофиле сервера.
func (s *Service) Hash(d Descriptor) []byte { return DescriptorHash(s.hasher, d) }

// By — кто и откуда выполняет действие (РСБ.1).
type By struct {
	Actor audit.Actor
	IP    netip.Addr
	// Security — у субъекта есть право agents.tools.approve (снятие
	// external, insecure_http).
	Security bool
	// Confirm — повторная проверка субъекта (пароль или код TOTP) перед
	// одобрением и ослаблением; nil — отказ с ErrConfirmRequired.
	Confirm func(ctx context.Context) error
}

func (b By) confirm(ctx context.Context) error {
	if b.Confirm == nil {
		return ErrConfirmRequired
	}
	return b.Confirm(ctx)
}

func (b By) entry(action, objType, objID string, details any) audit.Entry {
	return audit.Entry{Actor: b.Actor, SourceIP: b.IP, Action: action, Object: audit.Object{Type: objType, ID: objID},
		Result: audit.ResultSuccess, Details: details}
}

// ref — ссылка на субъекта в полях created_by и подобных.
func (b By) ref() string {
	s := string(b.Actor.Type) + ":" + b.Actor.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

func (s *Service) newID() (string, error) {
	id, err := s.ids.New()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// slugRe — slug агента и MCP-сервера (ADR-0023, раздел 1): тот же вид, что
// в правилах политики вызовов.
var slugRe = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// ValidToolName — имя инструмента подходит для реестра и правил.
func ValidToolName(n string) bool { return tooldesc.ValidName(n) }

func textLen(field, v string, lo, hi int) error {
	n := len([]rune(v))
	if n < lo || n > hi {
		if lo > 0 {
			return fmt.Errorf("%s — от %d до %d символов", field, lo, hi)
		}
		return fmt.Errorf("%s — не больше %d символов", field, hi)
	}
	return nil
}

// noControl — в строке нет управляющих символов.
func noControl(field, v string) error {
	if strings.IndexFunc(v, unicode.IsControl) >= 0 {
		return errors.New(field + " — без управляющих символов")
	}
	return nil
}

// text — проверка текстового поля: длина и отсутствие управляющих символов.
func text(field, v string, lo, hi int) []error {
	var errs []error
	if err := textLen(field, v, lo, hi); err != nil {
		errs = append(errs, err)
	}
	if err := noControl(field, v); err != nil {
		errs = append(errs, err)
	}
	return errs
}
