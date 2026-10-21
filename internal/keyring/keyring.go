// Пакет keyring — ключ данных установки для сервера (ТЗ 7.9 ЗИ.1, 10.4;
// ADR-0007): мастер-ключ читается из файла каталога ключей aisec-cli init,
// им расшифровывается действующий ключ данных из таблицы data_keys, а
// дальше секреты в БД (TOTP, позже — секреты провайдеров и содержимое
// событий) шифруются ключом данных с AAD места хранения.
package keyring

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// MasterKeyFile — имя файла мастер-ключа в каталоге ключей (aisec-cli init).
const MasterKeyFile = "master.key"

// reserveBatch — сколько шифрований резервируется одним обращением к БД
// (ADR-0007, п. 8): неиспользованный резерв теряется при перезапуске.
const reserveBatch = 4096

// pgTimeout — предел на одно обращение к БД без своего срока у контекста.
const pgTimeout = 10 * time.Second

var (
	// ErrNoDataKey — в БД нет действующего ключа данных (не выполнен aisec-cli init).
	ErrNoDataKey = errors.New("ключ данных: нет действующего ключа (выполните aisec-cli init)")
	// ErrExhausted — ключ данных исчерпал предел шифрований, нужна ротация.
	ErrExhausted = errors.New("ключ данных: исчерпан предел шифрований, нужна ротация")
	// ErrUnknownKey — шифротекст сделан другим (выведенным) ключом данных.
	ErrUnknownKey = errors.New("ключ данных: шифротекст другого ключа")
)

// DB — доступ к PostgreSQL; *pgxpool.Pool ему соответствует.
type DB interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Box шифрует секреты ключом данных. Безопасен для одновременного использования.
type Box struct {
	keyID string
	aead  aisecCrypto.AEAD
	// reserve резервирует n шифрований ключа; nil — без учёта (тесты).
	reserve func(ctx context.Context, n int64) error

	mu   sync.Mutex
	left int64
}

// Load читает мастер-ключ из dir, расшифровывает действующий ключ данных
// организации orgID и возвращает Box. Открытые копии ключей затираются.
func Load(ctx context.Context, db DB, p aisecCrypto.Provider, dir, orgID string) (*Box, error) {
	if db == nil || p == nil {
		return nil, errors.New("ключ данных: нет БД или криптопрофиля")
	}
	data, err := aisecCrypto.ReadKeyFile(filepath.Join(dir, MasterKeyFile))
	if err != nil {
		return nil, fmt.Errorf("ключ данных: мастер-ключ: %w", err)
	}
	profile, master, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindMaster)
	clear(data)
	if err != nil {
		return nil, fmt.Errorf("ключ данных: мастер-ключ: %w", err)
	}
	defer clear(master)
	if profile != p.Name() {
		return nil, fmt.Errorf("ключ данных: мастер-ключ профиля %q, сервер работает в профиле %q", profile, p.Name())
	}
	qctx, cancel := dbCtx(ctx)
	defer cancel()
	var (
		id, keyProfile string
		wrapped        []byte
	)
	err = db.QueryRow(qctx, `SELECT id::text, profile, wrapped FROM data_keys
		WHERE org_id = $1 AND retired_at IS NULL`, orgID).Scan(&id, &keyProfile, &wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoDataKey
	}
	if err != nil {
		return nil, fmt.Errorf("ключ данных: чтение: %w", err)
	}
	if keyProfile != p.Name() {
		return nil, fmt.Errorf("ключ данных: ключ профиля %q, сервер работает в профиле %q", keyProfile, p.Name())
	}
	wrap, err := p.NewAEAD(master)
	if err != nil {
		return nil, err
	}
	aad, err := aisecCrypto.StorageAAD("data_keys", "wrapped", id)
	if err != nil {
		return nil, err
	}
	key, err := wrap.Open(wrapped, aad)
	if err != nil {
		return nil, fmt.Errorf("ключ данных: не расшифрован мастер-ключом: %w", err)
	}
	defer clear(key)
	aead, err := p.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	b := &Box{keyID: id, aead: aead}
	b.reserve = func(ctx context.Context, n int64) error { return reserveDB(ctx, db, id, n) }
	return b, nil
}

// NewStatic — Box без учёта шифрований в БД (тесты и хранилище в памяти).
func NewStatic(keyID string, aead aisecCrypto.AEAD) *Box {
	return &Box{keyID: keyID, aead: aead}
}

func dbCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

// reserveDB увеличивает счётчик шифрований ключа (ADR-0007, п. 8).
// Нарушение CHECK — ключ исчерпан; выведенный ключ — тоже отказ.
func reserveDB(ctx context.Context, db DB, id string, n int64) error {
	ctx, cancel := dbCtx(ctx)
	defer cancel()
	var sealed int64
	err := db.QueryRow(ctx, `UPDATE data_keys SET sealed = sealed + $2 WHERE id = $1 AND retired_at IS NULL
		RETURNING sealed`, id, n).Scan(&sealed)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23514" {
		return ErrExhausted
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrExhausted
	}
	if err != nil {
		return fmt.Errorf("ключ данных: резерв шифрований: %w", err)
	}
	return nil
}

// KeyID — ID действующего ключа данных (хранится рядом с шифротекстом).
func (b *Box) KeyID() string { return b.keyID }

// Alg — имя алгоритма шифрования.
func (b *Box) Alg() string { return b.aead.Name() }

// Seal шифрует plaintext ключом данных с AAD места хранения (таблица,
// столбец, ID строки). Перед шифрованием резервирует его в счётчике ключа.
func (b *Box) Seal(ctx context.Context, plaintext []byte, table, column, rowID string) ([]byte, error) {
	aad, err := aisecCrypto.StorageAAD(table, column, rowID)
	if err != nil {
		return nil, err
	}
	if err := b.take(ctx); err != nil {
		return nil, err
	}
	return b.aead.Seal(plaintext, aad)
}

// take берёт одно шифрование из резерва, пополняя его пачкой.
func (b *Box) take(ctx context.Context) error {
	if b.reserve == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.left == 0 {
		if err := b.reserve(ctx, reserveBatch); err != nil {
			return err
		}
		b.left = reserveBatch
	}
	b.left--
	return nil
}

// Open расшифровывает шифротекст ключа keyID с AAD места хранения.
func (b *Box) Open(keyID string, sealed []byte, table, column, rowID string) ([]byte, error) {
	if keyID != b.keyID {
		return nil, ErrUnknownKey
	}
	aad, err := aisecCrypto.StorageAAD(table, column, rowID)
	if err != nil {
		return nil, err
	}
	return b.aead.Open(sealed, aad)
}
