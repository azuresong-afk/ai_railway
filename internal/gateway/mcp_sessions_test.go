package gateway

import (
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func testMCPSessions(t *testing.T, now *time.Time) *MCPSessions {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	return NewMCPSessions(rnd, func() time.Time { return *now })
}

// Сессия связана с владельцем (ключ, агент, сервер): чужой, неизвестный и
// истёкший идентификатор не находится.
func TestMCPSessionsOwnerAndTTL(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s := testMCPSessions(t, &now)
	own := mcpOwner("app", "aisec_bound", "report-bot", "files")
	id, err := s.create(own, "up-1")
	if err != nil || len(id) != 32 {
		t.Fatalf("create: %q %v", id, err)
	}
	if up, ok := s.get(id, own); !ok || up != "up-1" {
		t.Fatalf("get: %q %v", up, ok)
	}
	for _, other := range []string{mcpOwner("app", "aisec_free", "report-bot", "files"), mcpOwner("app", "aisec_bound", "other", "files"),
		mcpOwner("app", "aisec_bound", "report-bot", "db")} {
		if _, ok := s.get(id, other); ok {
			t.Fatalf("чужой владелец %q", other)
		}
	}
	if _, ok := s.get("0123456789abcdef0123456789abcdef", own); ok {
		t.Fatal("неизвестная сессия")
	}
	// Запрос продлевает сессию; без запросов дольше MCPSessionTTL — закрыта.
	now = now.Add(MCPSessionTTL - time.Minute)
	if _, ok := s.get(id, own); !ok {
		t.Fatal("сессия закрылась раньше срока")
	}
	now = now.Add(MCPSessionTTL + time.Second)
	if _, ok := s.get(id, own); ok || s.Len() != 0 {
		t.Fatalf("истёкшая сессия: %d", s.Len())
	}
	id, _ = s.create(own, "")
	s.drop(id)
	if _, ok := s.get(id, own); ok {
		t.Fatal("закрытая сессия")
	}
}

// Сверх MaxMCPSessionsPerOwner вытесняется самая давняя сессия владельца,
// сессии других владельцев не трогаются.
func TestMCPSessionsPerOwnerLimit(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s := testMCPSessions(t, &now)
	own, other := mcpOwner("app", "k1", "a", "files"), mcpOwner("app", "k2", "a", "files")
	keep, _ := s.create(other, "")
	first, _ := s.create(own, "")
	for range MaxMCPSessionsPerOwner {
		now = now.Add(time.Second)
		if _, err := s.create(own, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := s.get(first, own); ok {
		t.Fatal("самая давняя сессия не вытеснена")
	}
	if _, ok := s.get(keep, other); !ok {
		t.Fatal("вытеснена сессия другого владельца")
	}
	if s.Len() != MaxMCPSessionsPerOwner+1 {
		t.Fatalf("сессий: %d", s.Len())
	}
}
