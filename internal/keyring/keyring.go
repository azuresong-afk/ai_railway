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
	"regexp"
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
	// Производные ключи (ADR-0007, п. 8): kdf хранит только состояние
	// HKDF после извлечения; nil — выведение недоступно (NewStatic).
	provider      aisecCrypto.Provider
	kdf           aisecCrypto.KDF
	reserveDerive func(ctx context.Context, purpose, day string, n int64) error

	mu      sync.Mutex
	left    int64
	derived map[string]*Derived
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
	b, err := newBox(p, id, key)
	if err != nil {
		return nil, err
	}
	b.reserve = func(ctx context.Context, n int64) error { return reserveDB(ctx, db, id, n) }
	b.reserveDerive = func(ctx context.Context, purpose, day string, n int64) error {
		return reserveDerivedDB(ctx, db, id, purpose, day, n)
	}
	return b, nil
}

func newBox(p aisecCrypto.Provider, keyID string, key []byte) (*Box, error) {
	aead, err := p.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	kdf, err := p.NewKDF(key)
	if err != nil {
		return nil, err
	}
	return &Box{keyID: keyID, aead: aead, provider: p, kdf: kdf}, nil
}

// NewStatic — Box без учёта шифрований в БД (тесты и хранилище в памяти).
// Производных ключей у него нет.
func NewStatic(keyID string, aead aisecCrypto.AEAD) *Box {
	return &Box{keyID: keyID, aead: aead}
}

// NewStaticKey — Box из открытого ключа данных без учёта шифрований в БД,
// с производными ключами (тесты и хранилище в памяти).
func NewStaticKey(p aisecCrypto.Provider, keyID string, key []byte) (*Box, error) {
	return newBox(p, keyID, key)
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

// Производные ключи суток (ADR-0007, п. 8): поток шифрований содержимого
// событий в режиме full велик (500 RPS — 2^31 шифрований примерно за 50
// дней), поэтому для каждых суток и назначения выводится свой ключ
// HKDF(ключ данных, «aisec-derived-v1|назначение|ID ключа|ГГГГ-ММ-ДД»), а
// предел 2^31 считается на производный ключ в derived_key_usage.

// maxDerivedCached — предел производных ключей в памяти: обычно нужны
// сегодняшние и вчерашние сутки (события около полуночи).
const maxDerivedCached = 8

var purposeRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,31}$`)

// ErrNoDerive — у Box нет выведения ключей (NewStatic).
var ErrNoDerive = errors.New("ключ данных: производные ключи недоступны")

// Derived — производный ключ суток для одного назначения.
type Derived struct {
	keyID   string
	purpose string
	day     string
	aead    aisecCrypto.AEAD
	reserve func(ctx context.Context, n int64) error

	mu   sync.Mutex
	left int64
}

// KeyID — ID ключа данных, из которого выведен ключ.
func (d *Derived) KeyID() string { return d.keyID }

// Alg — имя алгоритма шифрования.
func (d *Derived) Alg() string { return d.aead.Name() }

// Seal шифрует plaintext производным ключом с AAD места хранения,
// предварительно резервируя шифрование в счётчике производного ключа.
func (d *Derived) Seal(ctx context.Context, plaintext []byte, table, column, rowID string) ([]byte, error) {
	aad, err := aisecCrypto.StorageAAD(table, column, rowID)
	if err != nil {
		return nil, err
	}
	if err := d.take(ctx); err != nil {
		return nil, err
	}
	return d.aead.Seal(plaintext, aad)
}

func (d *Derived) take(ctx context.Context) error {
	if d.reserve == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.left == 0 {
		if err := d.reserve(ctx, reserveBatch); err != nil {
			return err
		}
		d.left = reserveBatch
	}
	d.left--
	return nil
}

// dayKey — сутки UTC в виде ГГГГ-ММ-ДД.
func dayKey(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// Derive возвращает производный ключ суток day (UTC) для назначения
// purpose. Ключ для одних суток и назначения в процессе один: счётчик
// резерва общий.
func (b *Box) Derive(purpose string, day time.Time) (*Derived, error) {
	if b.kdf == nil {
		return nil, ErrNoDerive
	}
	if !purposeRe.MatchString(purpose) {
		return nil, fmt.Errorf("ключ данных: неверное назначение производного ключа %q", purpose)
	}
	dk := dayKey(day)
	name := purpose + "|" + dk
	b.mu.Lock()
	defer b.mu.Unlock()
	if d, ok := b.derived[name]; ok {
		return d, nil
	}
	aead, err := b.deriveAEAD(purpose, dk)
	if err != nil {
		return nil, err
	}
	d := &Derived{keyID: b.keyID, purpose: purpose, day: dk, aead: aead}
	if b.reserveDerive != nil {
		d.reserve = func(ctx context.Context, n int64) error { return b.reserveDerive(ctx, purpose, dk, n) }
	}
	if b.derived == nil || len(b.derived) >= maxDerivedCached {
		// Старые сутки больше не шифруются: их резерв просто теряется.
		b.derived = map[string]*Derived{}
	}
	b.derived[name] = d
	return d, nil
}

func (b *Box) deriveAEAD(purpose, day string) (aisecCrypto.AEAD, error) {
	key, err := b.kdf.Derive([]byte("aisec-derived-v1|"+purpose+"|"+b.keyID+"|"+day), aisecCrypto.AEADKeySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return b.provider.NewAEAD(key)
}

// MAC возвращает имитовставку на ключе назначения purpose, выведенном из
// действующего ключа данных: HKDF(ключ данных, «aisec-mac-v1|назначение|ID
// ключа»). Ключ не зависит от суток и не входит в учёт шифрований: он ничего
// не шифрует. Так ключ имитовставки хранится вне БД (под мастер-ключом), а
// не рядом с данными, которые он защищает (опора цепочки аудита, ADR-0008).
func (b *Box) MAC(purpose string) (aisecCrypto.MAC, error) {
	if b.kdf == nil {
		return nil, ErrNoDerive
	}
	if !purposeRe.MatchString(purpose) {
		return nil, fmt.Errorf("ключ данных: неверное назначение ключа имитовставки %q", purpose)
	}
	key, err := b.kdf.Derive([]byte("aisec-mac-v1|"+purpose+"|"+b.keyID), aisecCrypto.MinMACKeySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return b.provider.NewMAC(key)
}

// OpenDerived расшифровывает шифротекст производного ключа суток day для
// назначения purpose, выведенного из ключа данных keyID.
func (b *Box) OpenDerived(keyID, purpose string, day time.Time, sealed []byte, table, column, rowID string) ([]byte, error) {
	if keyID != b.keyID {
		return nil, ErrUnknownKey
	}
	if b.kdf == nil {
		return nil, ErrNoDerive
	}
	if !purposeRe.MatchString(purpose) {
		return nil, fmt.Errorf("ключ данных: неверное назначение производного ключа %q", purpose)
	}
	aad, err := aisecCrypto.StorageAAD(table, column, rowID)
	if err != nil {
		return nil, err
	}
	// Ключ для чтения выводится заново, без кэша и резерва шифрований:
	// просмотр содержимого за разные сутки не вытесняет из кэша ключ
	// текущих суток и не растит счётчик derived_key_usage (Н23 ревью 2.r3a).
	aead, err := b.deriveAEAD(purpose, dayKey(day))
	if err != nil {
		return nil, err
	}
	return aead.Open(sealed, aad)
}

// reserveDerivedDB увеличивает счётчик шифрований производного ключа.
// Ключ данных выведен из употребления или предел исчерпан — ErrExhausted.
func reserveDerivedDB(ctx context.Context, db DB, keyID, purpose, day string, n int64) error {
	ctx, cancel := dbCtx(ctx)
	defer cancel()
	var sealed int64
	err := db.QueryRow(ctx, `INSERT INTO derived_key_usage (data_key_id, purpose, day, sealed)
		SELECT id, $2, $3::date, $4 FROM data_keys WHERE id = $1 AND retired_at IS NULL
		ON CONFLICT (data_key_id, purpose, day) DO UPDATE SET sealed = derived_key_usage.sealed + EXCLUDED.sealed
		RETURNING sealed`, keyID, purpose, day, n).Scan(&sealed)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23514" {
		return ErrExhausted
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrExhausted
	}
	if err != nil {
		return fmt.Errorf("ключ данных: резерв шифрований производного ключа: %w", err)
	}
	return nil
}
