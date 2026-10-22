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
	issue func(Gateway) (Issued, error), rec func(Gateway) audit.Entry) (Gateway, error) {
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
	iss, err := issue(*g)
	if err != nil {
		return Gateway{}, err
	}
	next := *g
	next.Status, next.RegisteredAt, next.CertSerial, next.CertNotAfter = StatusActive, now, iss.Info.Serial, iss.Info.NotAfter
	next.CertCA, next.BundleKey = iss.CA, slices.Clone(iss.BundleKey)
	next.NextCertSerial, next.NextCertNotAfter, next.NextCertCA = "", time.Time{}, ""
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
		if serial != "" && (g.CertSerial == serial || g.NextCertSerial == serial) {
			return *g, nil
		}
	}
	return Gateway{}, ErrNotFound
}

// ByID — см. Store.
func (m *Memory) ByID(_ context.Context, id string) (Gateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g, ok := m.gateways[id]; ok {
		return *g, nil
	}
	return Gateway{}, ErrNotFound
}

// Touch — см. Store.
func (m *Memory) Touch(_ context.Context, id string, hb Heartbeat, audits func(TouchChange) []audit.Entry) (TouchChange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.gateways[id]
	if g == nil || g.Status != StatusActive {
		return TouchChange{}, ErrNotFound
	}
	ch := TouchChange{VerifyRequested: g.VerifyRequestedAt, CertCA: g.CertCA, CertNotAfter: g.CertNotAfter}
	if !ch.VerifyRequested.IsZero() && hb.Integrity != nil && hb.VerifyRequest.Equal(ch.VerifyRequested) {
		g.VerifyRequestedAt, ch.VerifyDone = time.Time{}, true
	}
	if next, set := startChange(g.StartedAt, hb, &ch); set {
		g.StartedAt = next
	}
	g.LastSeenAt, g.LastAddr, g.Version, g.BundleETag = hb.At, hb.Addr, hb.Version, hb.BundleETag
	if hb.Selftest != nil {
		r := *hb.Selftest
		g.Selftest = &r
	}
	if hb.Integrity != nil {
		r := *hb.Integrity
		g.Integrity = &r
		if r.OK && !r.ManifestCreated.IsZero() && (g.ManifestMaxCreated.IsZero() || r.ManifestCreated.After(g.ManifestMaxCreated)) {
			g.ManifestMaxVersion, g.ManifestMaxCreated = r.ManifestVersion, r.ManifestCreated
		}
	}
	if hb.BundleKeysOK != nil {
		ok := *hb.BundleKeysOK
		g.BundleKeysOK = &ok
	}
	m.Records = append(m.Records, audits(ch)...)
	return ch, nil
}

// RequestVerify — см. Store.
func (m *Memory) RequestVerify(_ context.Context, orgID string, at time.Time, rec func(int) audit.Entry) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, g := range m.gateways {
		if g.OrgID == orgID && g.Status == StatusActive {
			g.VerifyRequestedAt = at
			n++
		}
	}
	m.Records = append(m.Records, rec(n))
	return n, nil
}

// AcceptRollback — см. Store.
func (m *Memory) AcceptRollback(_ context.Context, orgID, name string, rec func(prev, cur Gateway) audit.Entry) (Gateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.gateways {
		if g.OrgID != orgID || g.Name != name {
			continue
		}
		if err := checkAcceptRollback(*g); err != nil {
			return Gateway{}, err
		}
		prev := *g
		g.ManifestMaxVersion, g.ManifestMaxCreated = g.Integrity.ManifestVersion, g.Integrity.ManifestCreated
		m.Records = append(m.Records, rec(prev, *g))
		return *g, nil
	}
	return Gateway{}, ErrNotFound
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

// SetNextCert — см. Store.
func (m *Memory) SetNextCert(_ context.Context, id string, next Issued, rec func(Gateway) audit.Entry) (Gateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.gateways[id]
	if g == nil || g.Status != StatusActive {
		return Gateway{}, ErrNotFound
	}
	g.NextCertSerial, g.NextCertNotAfter, g.NextCertCA = next.Info.Serial, next.Info.NotAfter, next.CA
	m.Records = append(m.Records, rec(*g))
	return *g, nil
}

// PromoteNext — см. Store.
func (m *Memory) PromoteNext(_ context.Context, id, serial string, rec func(Gateway) audit.Entry) (Gateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.gateways[id]
	if g == nil || g.Status != StatusActive {
		return Gateway{}, ErrNotFound
	}
	if serial == "" || g.NextCertSerial != serial {
		return *g, nil
	}
	g.CertSerial, g.CertNotAfter, g.CertCA = g.NextCertSerial, g.NextCertNotAfter, g.NextCertCA
	g.NextCertSerial, g.NextCertNotAfter, g.NextCertCA = "", time.Time{}, ""
	m.Records = append(m.Records, rec(*g))
	return *g, nil
}

// PinBundleKey — см. Store.
func (m *Memory) PinBundleKey(_ context.Context, id string, key []byte, rec func(Gateway) audit.Entry) (Gateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.gateways[id]
	if g == nil || g.Status != StatusActive {
		return Gateway{}, ErrNotFound
	}
	if g.BundleKey == nil {
		g.BundleKey = slices.Clone(key)
		m.Records = append(m.Records, rec(*g))
	}
	return *g, nil
}
