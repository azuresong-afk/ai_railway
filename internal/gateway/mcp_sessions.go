package gateway

import (
	"encoding/hex"
	"errors"
	"sync"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Сессии MCP 2025-11-25 (Mcp-Session-Id; ADR-0023, раздел 6). Клиент
// получает идентификатор шлюза, а не вышестоящего сервера: сессия связана
// с ключом приложения, агентом и сервером, и чужой или неизвестный
// идентификатор — 404 (клиент по спецификации начинает новую сессию).
// Идентификатор сервера клиенту не виден и подставляется шлюзом.

// Пределы таблицы сессий.
const (
	// MCPSessionTTL — сессия без запросов дольше закрывается.
	MCPSessionTTL = 24 * time.Hour
	// MaxMCPSessions — сессий на процесс шлюза; MaxMCPSessionsPerOwner —
	// на ключ, агента и сервер (сверх — вытесняется самая давняя своя:
	// одно приложение не занимает таблицу целиком).
	MaxMCPSessions         = 10000
	MaxMCPSessionsPerOwner = 256
)

// errMCPSessionsFull — таблица сессий заполнена.
var errMCPSessionsFull = errors.New("MCP: таблица сессий заполнена")

// mcpSession — сессия клиента.
type mcpSession struct {
	owner    string
	upstream string // Mcp-Session-Id вышестоящего сервера; пусто — сервер сессий не ведёт
	used     time.Time
}

// MCPSessions — таблица сессий; переживает смену пакета конфигурации.
type MCPSessions struct {
	mu   sync.Mutex
	rnd  aisecCrypto.Random
	now  func() time.Time
	by   map[string]*mcpSession
	nOwn map[string]int
}

// NewMCPSessions — таблица на источнике случайности rnd (internal/crypto).
func NewMCPSessions(rnd aisecCrypto.Random, now func() time.Time) *MCPSessions {
	if now == nil {
		now = time.Now
	}
	return &MCPSessions{rnd: rnd, now: now, by: map[string]*mcpSession{}, nOwn: map[string]int{}}
}

// mcpOwner — владелец сессии: приложение, префикс ключа, агент и сервер.
func mcpOwner(app, keyPrefix, agent, server string) string {
	return app + "\x1f" + keyPrefix + "\x1f" + agent + "\x1f" + server
}

// create открывает сессию и возвращает идентификатор для клиента (32 hex,
// 128 случайных бит).
func (s *MCPSessions) create(owner, upstream string) (string, error) {
	var b [16]byte
	if err := s.rnd.Read(b[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)
	if s.nOwn[owner] >= MaxMCPSessionsPerOwner {
		s.evictOwnLocked(owner)
	}
	if len(s.by) >= MaxMCPSessions {
		return "", errMCPSessionsFull
	}
	s.by[id] = &mcpSession{owner: owner, upstream: upstream, used: now}
	s.nOwn[owner]++
	return id, nil
}

// get — идентификатор сервера для сессии id владельца owner; чужая,
// истёкшая или неизвестная — false.
func (s *MCPSessions) get(id, owner string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss, ok := s.by[id]
	if !ok || ss.owner != owner {
		return "", false
	}
	now := s.now()
	if now.Sub(ss.used) > MCPSessionTTL {
		s.dropLocked(id, ss)
		return "", false
	}
	ss.used = now
	return ss.upstream, true
}

// drop закрывает сессию (вышестоящий сервер ответил 404).
func (s *MCPSessions) drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss, ok := s.by[id]; ok {
		s.dropLocked(id, ss)
	}
}

// Len — открытых сессий (для тестов и отчётов).
func (s *MCPSessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.by)
}

func (s *MCPSessions) dropLocked(id string, ss *mcpSession) {
	delete(s.by, id)
	if s.nOwn[ss.owner]--; s.nOwn[ss.owner] <= 0 {
		delete(s.nOwn, ss.owner)
	}
}

// expireLocked удаляет истёкшие сессии. Полный проход — только при
// создании сессии, таблица ограничена MaxMCPSessions.
func (s *MCPSessions) expireLocked(now time.Time) {
	for id, ss := range s.by {
		if now.Sub(ss.used) > MCPSessionTTL {
			s.dropLocked(id, ss)
		}
	}
}

// evictOwnLocked вытесняет самую давнюю сессию владельца.
func (s *MCPSessions) evictOwnLocked(owner string) {
	var oldID string
	var old *mcpSession
	for id, ss := range s.by {
		if ss.owner == owner && (old == nil || ss.used.Before(old.used)) {
			oldID, old = id, ss
		}
	}
	if old != nil {
		s.dropLocked(oldID, old)
	}
}
