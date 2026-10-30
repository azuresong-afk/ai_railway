package build

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Ошибки хранилища.
var (
	// ErrNotFound — версий пакета ещё нет.
	ErrNotFound = errors.New("пакетов конфигурации ещё нет")
	// ErrConflict — версия не больше последней (параллельная сборка).
	ErrConflict = errors.New("версия пакета не больше последней")
)

// Record — сохранённая версия пакета: открытое содержимое без секретов.
type Record struct {
	OrgID     string
	Version   int64
	Content   []byte
	Hash      []byte
	HashAlg   string
	CreatedAt time.Time
}

// Store — версии пакетов (миграция 0018_config_bundles). Рабочая
// реализация — PGStore, для тестов — Memory.
type Store interface {
	// Latest — последняя версия организации или ErrNotFound.
	Latest(ctx context.Context, orgID string) (Record, error)
	// Create сохраняет версию и запись аудита одной транзакцией;
	// версия не больше последней — ErrConflict.
	Create(ctx context.Context, rec Record, entry audit.Entry) error
}

// KeysTimeStore — момент последнего получения ключей IdP (миграция 0067,
// 4Н14 ревью 4.r2): срок ключей прежней версии отсчитывается от него и
// после перезапуска сервера. Memory и PGStore его реализуют; хранилище без
// него — отсчёт от запуска.
type KeysTimeStore interface {
	// UserTokenKeysAt — сохранённый момент; нулевое время — его нет.
	UserTokenKeysAt(ctx context.Context, orgID string) (time.Time, error)
	SetUserTokenKeysAt(ctx context.Context, orgID string, at time.Time) error
}

// Auditor — журнал аудита для записей без изменения данных (выдача пакета,
// отчёт шлюза, неудачная сборка).
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) error
}

// Memory — Store в памяти; повторяет правила триггера миграции 0018.
type Memory struct {
	mu      sync.Mutex
	recs    map[string][]Record
	entries []audit.Entry
	keysAt  map[string]time.Time
}

// NewMemory создаёт пустое хранилище.
func NewMemory() *Memory { return &Memory{recs: map[string][]Record{}, keysAt: map[string]time.Time{}} }

// UserTokenKeysAt — см. KeysTimeStore.
func (m *Memory) UserTokenKeysAt(_ context.Context, orgID string) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keysAt[orgID], nil
}

// SetUserTokenKeysAt — см. KeysTimeStore.
func (m *Memory) SetUserTokenKeysAt(_ context.Context, orgID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keysAt[orgID] = at
	return nil
}

// Latest — см. Store.
func (m *Memory) Latest(_ context.Context, orgID string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rs := m.recs[orgID]
	if len(rs) == 0 {
		return Record{}, ErrNotFound
	}
	r := rs[len(rs)-1]
	r.Content, r.Hash = bytes.Clone(r.Content), bytes.Clone(r.Hash)
	return r, nil
}

// Create — см. Store.
func (m *Memory) Create(_ context.Context, rec Record, entry audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rs := m.recs[rec.OrgID]
	if len(rs) > 0 && rec.Version <= rs[len(rs)-1].Version {
		return ErrConflict
	}
	rec.Content, rec.Hash = bytes.Clone(rec.Content), bytes.Clone(rec.Hash)
	m.recs[rec.OrgID] = append(rs, rec)
	m.entries = append(m.entries, entry)
	return nil
}

// Versions — число сохранённых версий организации.
func (m *Memory) Versions(orgID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recs[orgID])
}

// Records — копия записей аудита, сделанных вместе с версиями.
func (m *Memory) Records() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.entries)
}

const (
	pgTimeout         = 10 * time.Second
	pgRollbackTimeout = 5 * time.Second
)

// PGDB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type PGDB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGStore — Store на PostgreSQL.
type PGStore struct {
	db    PGDB
	audit *audit.Log
}

// NewPGStore создаёт хранилище; журнал должен работать через тот же пул.
func NewPGStore(db PGDB, a *audit.Log) (*PGStore, error) {
	if db == nil || a == nil {
		return nil, errors.New("пакеты: нет БД или журнала аудита")
	}
	return &PGStore{db: db, audit: a}, nil
}

func pgCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

// Latest — см. Store.
func (s *PGStore) Latest(ctx context.Context, orgID string) (Record, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	r := Record{OrgID: orgID}
	err := s.db.QueryRow(ctx, `SELECT version, content, content_hash, hash_alg, created_at FROM config_bundles
		WHERE org_id = $1 ORDER BY version DESC LIMIT 1`, orgID).Scan(&r.Version, &r.Content, &r.Hash, &r.HashAlg, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("пакеты: чтение: %w", err)
	}
	return r, nil
}

// Create — см. Store.
func (s *PGStore) Create(ctx context.Context, rec Record, entry audit.Entry) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("пакеты: начало транзакции: %w", err)
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pgRollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rctx) //nolint:gosec // G104: откат после коммита безвреден, ошибку скрывает исходная
	}()
	_, err = tx.Exec(ctx, `INSERT INTO config_bundles (org_id, version, content, content_hash, hash_alg, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, rec.OrgID, rec.Version, rec.Content, rec.Hash, rec.HashAlg, rec.CreatedAt)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (pe.Code == "23505" || pe.Code == "23514") {
		// 23505 — та же версия, 23514 — триггер: версия не больше последней.
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("пакеты: запись версии: %w", err)
	}
	if err := s.audit.RecordTx(ctx, tx, entry); err != nil {
		return fmt.Errorf("пакеты: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("пакеты: фиксация: %w", err)
	}
	return nil
}

// UserTokenKeysAt — см. KeysTimeStore.
func (s *PGStore) UserTokenKeysAt(ctx context.Context, orgID string) (time.Time, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var at time.Time
	err := s.db.QueryRow(ctx, `SELECT fetched_at FROM user_token_keys_state WHERE org_id = $1`, orgID).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("пакеты: момент получения ключей IdP: %w", err)
	}
	return at, nil
}

// SetUserTokenKeysAt — см. KeysTimeStore. Момент не уходит назад: другой
// экземпляр сервера мог записать более поздний.
func (s *PGStore) SetUserTokenKeysAt(ctx context.Context, orgID string, at time.Time) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var ok bool
	err := s.db.QueryRow(ctx, `INSERT INTO user_token_keys_state (org_id, fetched_at) VALUES ($1, $2)
		ON CONFLICT (org_id) DO UPDATE SET fetched_at = greatest(user_token_keys_state.fetched_at, EXCLUDED.fetched_at)
		RETURNING true`, orgID, at).Scan(&ok)
	if err != nil {
		return fmt.Errorf("пакеты: запись момента получения ключей IdP: %w", err)
	}
	return nil
}

// Revision — счётчик изменений конфигурации организации (миграция
// 0030_config_revision, задача 3.34): 0 — изменений ещё не было.
func (s *PGStore) Revision(ctx context.Context, orgID string) (int64, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var rev int64
	err := s.db.QueryRow(ctx, `SELECT revision FROM config_revisions WHERE org_id = $1`, orgID).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("пакеты: счётчик изменений: %w", err)
	}
	return rev, nil
}
