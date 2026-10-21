package gwregistry

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Memory — Store в памяти для тестов без PostgreSQL. Повторяет правила
// PGStore и триггеров миграции 0007: отзыв окончательный, токен гасится
// один раз, записи аудита изменений копятся в Records.
type Memory struct {
	mu       sync.Mutex
	gateways map[string]*Gateway
	tokens   []memToken
	// Records — записи аудита, переданные вместе с изменениями.
	Records []audit.Entry
}

type memToken struct {
	id, gatewayID, alg string
	hash               []byte
	expires            time.Time
	used               bool
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory { return &Memory{gateways: map[string]*Gateway{}} }

func (m *Memory) byName(orgID, name string) *Gateway {
	for _, g := range m.gateways {
		if g.OrgID == orgID && g.Name == name {
			return g
		}
	}
	return nil
}

// CreateToken — см. Store.
func (m *Memory) CreateToken(_ context.Context, t NewToken, rec func(Gateway) audit.Entry) (Gateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.byName(t.OrgID, t.Name)
	switch {
	case g == nil && t.Reregister:
		return Gateway{}, ErrNotFound
	case g != nil && !t.Reregister:
		return Gateway{}, ErrNameTaken
	case g != nil && g.Status == StatusRevoked:
		return Gateway{}, ErrRevoked
	case g == nil:
		g = &Gateway{ID: t.GatewayID, OrgID: t.OrgID, Name: t.Name, Status: StatusPending, CreatedAt: t.CreatedAt, CreatedBy: t.CreatedBy}
		m.gateways[g.ID] = g
	}
	for i := range m.tokens {
		if m.tokens[i].gatewayID == g.ID {
			m.tokens[i].used = true
		}
	}
	m.tokens = append(m.tokens, memToken{id: t.TokenID, gatewayID: g.ID, alg: t.HashAlg, hash: slices.Clone(t.Hash), expires: t.ExpiresAt})
	m.Records = append(m.Records, rec(*g))
	return *g, nil
}

// Register — см. Store.
func (m *Memory) Register(_ context.Context, hashAlg string, hash []byte, now time.Time,
	issue func(Gateway) (aisecCrypto.CertInfo, error), rec func(Gateway) audit.Entry) (Gateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := -1
	for i, t := range m.tokens {
		if t.alg == hashAlg && aisecCrypto.Equal(t.hash, hash) {
			idx = i
		}
	}
	if idx < 0 || m.tokens[idx].used || !now.Before(m.tokens[idx].expires) {
		return Gateway{}, ErrTokenInvalid
	}
	g := m.gateways[m.tokens[idx].gatewayID]
	if g == nil || g.Status == StatusRevoked {
		return Gateway{}, ErrTokenInvalid
	}
	info, err := issue(*g)
	if err != nil {
		return Gateway{}, err
	}
	next := *g
	next.Status, next.RegisteredAt, next.CertSerial, next.CertNotAfter = StatusActive, now, info.Serial, info.NotAfter
	m.tokens[idx].used = true
	*g = next
	m.Records = append(m.Records, rec(next))
	return next, nil
}

// BySerial — см. Store.
func (m *Memory) BySerial(_ context.Context, serial string) (Gateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.gateways {
		if serial != "" && g.CertSerial == serial {
			return *g, nil
		}
	}
	return Gateway{}, ErrNotFound
}

// Touch — см. Store.
func (m *Memory) Touch(_ context.Context, id string, hb Heartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.gateways[id]
	if g == nil || g.Status != StatusActive {
		return ErrNotFound
	}
	g.LastSeenAt, g.LastAddr, g.Version, g.BundleETag = hb.At, hb.Addr, hb.Version, hb.BundleETag
	return nil
}

// Revoke — см. Store.
func (m *Memory) Revoke(_ context.Context, orgID, name string, now time.Time, rec func(Gateway) audit.Entry) (Gateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.byName(orgID, name)
	if g == nil {
		return Gateway{}, ErrNotFound
	}
	if g.Status == StatusRevoked {
		return Gateway{}, ErrRevoked
	}
	g.Status, g.RevokedAt = StatusRevoked, now
	for i := range m.tokens {
		if m.tokens[i].gatewayID == g.ID {
			m.tokens[i].used = true
		}
	}
	m.Records = append(m.Records, rec(*g))
	return *g, nil
}

// List — см. Store.
func (m *Memory) List(_ context.Context, orgID string) ([]Gateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Gateway
	for _, g := range m.gateways {
		if g.OrgID == orgID {
			out = append(out, *g)
		}
	}
	slices.SortFunc(out, func(a, b Gateway) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
