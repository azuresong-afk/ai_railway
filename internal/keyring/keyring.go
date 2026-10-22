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
	"slices"
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
//
// Box знает все версии ключа данных, которые ещё не удалены (ADR-0018, п. 3):
// действующей шифрует (Seal), любой расшифровывает (Open). Box из Load
// перечитывает версии, когда действующую вывела ротация (aisec-cli keys
// rotate-data): при отказе в резерве шифрований, при шифротексте неизвестной
// версии и по Watch.
type Box struct {
	provider aisecCrypto.Provider
	// src — откуда перечитывать версии; nil — версии постоянны (NewStatic).
	src *source
	// reserve резервирует n шифрований ключа keyID; nil — без учёта (тесты).
	reserve func(ctx context.Context, keyID string, n int64) error
	// reserveDerive — то же для производного ключа суток.
	reserveDerive func(ctx context.Context, keyID, purpose, day string, n int64) error

	mu       sync.Mutex
	active   *version
	versions map[string]*version
	left     int64
	derived  map[string]*Derived
	// reloadedAt — последнее перечитывание по шифротексту неизвестной версии.
	reloadedAt time.Time
}

// version — одна версия ключа данных. Производные ключи (ADR-0007, п. 8):
// kdf хранит только состояние HKDF после извлечения; nil — выведение
// недоступно (NewStatic).
type version struct {
	id   string
	num  int
	aead aisecCrypto.AEAD
	kdf  aisecCrypto.KDF
}

// source — каталог ключей и БД, из которых Box перечитывает версии.
type source struct {
	db    DB
	dir   string
	orgID string
}

// Querier — чтение нескольких строк; *pgxpool.Pool ему соответствует. Без
// него Load берёт только действующую версию.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Load читает мастер-ключ из dir, расшифровывает версии ключа данных
// организации orgID и возвращает Box. Открытые копии ключей затираются.
func Load(ctx context.Context, db DB, p aisecCrypto.Provider, dir, orgID string) (*Box, error) {
	if db == nil || p == nil {
		return nil, errors.New("ключ данных: нет БД или криптопрофиля")
	}
	b := &Box{provider: p, src: &source{db: db, dir: dir, orgID: orgID}}
	active, all, err := b.src.load(ctx, p)
	if err != nil {
		return nil, err
	}
	b.active, b.versions = active, all
	b.reserve = func(ctx context.Context, keyID string, n int64) error { return reserveDB(ctx, db, keyID, n) }
	b.reserveDerive = func(ctx context.Context, keyID, purpose, day string, n int64) error {
		return reserveDerivedDB(ctx, db, keyID, purpose, day, n)
	}
	return b, nil
}

// ReadMaster читает мастер-ключ из файла каталога ключей и проверяет
// профиль. Вызывающий затирает результат.
func ReadMaster(dir string, p aisecCrypto.Provider) ([]byte, error) {
	return readMasterFile(filepath.Join(dir, MasterKeyFile), p)
}

func readMasterFile(path string, p aisecCrypto.Provider) ([]byte, error) {
	data, err := aisecCrypto.ReadKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("ключ данных: мастер-ключ: %w", err)
	}
	profile, master, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindMaster)
	clear(data)
	if err != nil {
		return nil, fmt.Errorf("ключ данных: мастер-ключ: %w", err)
	}
	if profile != p.Name() {
		clear(master)
		return nil, fmt.Errorf("ключ данных: мастер-ключ профиля %q, сервер работает в профиле %q", profile, p.Name())
	}
	return master, nil
}

// load читает мастер-ключ и расшифровывает действующую версию и, если БД
// умеет Query, все невыведенные из таблицы прежние.
func (s *source) load(ctx context.Context, p aisecCrypto.Provider) (*version, map[string]*version, error) {
	master, err := ReadMaster(s.dir, p)
	if err != nil {
		return nil, nil, err
	}
	defer clear(master)
	wrap, err := p.NewAEAD(master)
	if err != nil {
		return nil, nil, err
	}
	qctx, cancel := dbCtx(ctx)
	defer cancel()
	var r keyRow
	err = s.db.QueryRow(qctx, `SELECT id::text, version, profile, wrapped FROM data_keys
		WHERE org_id = $1 AND retired_at IS NULL`, s.orgID).Scan(&r.id, &r.num, &r.profile, &r.wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNoDataKey
	}
	if err != nil {
		return nil, nil, fmt.Errorf("ключ данных: чтение: %w", err)
	}
	active, err := r.open(p, wrap)
	if err != nil {
		return nil, nil, err
	}
	all := map[string]*version{active.id: active}
	q, ok := s.db.(Querier)
	if !ok {
		return active, all, nil
	}
	rows, err := q.Query(qctx, `SELECT id::text, version, profile, wrapped FROM data_keys
		WHERE org_id = $1 AND retired_at IS NOT NULL ORDER BY version`, s.orgID)
	if err != nil {
		return nil, nil, fmt.Errorf("ключ данных: чтение прежних версий: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r keyRow
		if err := rows.Scan(&r.id, &r.num, &r.profile, &r.wrapped); err != nil {
			return nil, nil, fmt.Errorf("ключ данных: чтение прежних версий: %w", err)
		}
		v, err := r.open(p, wrap)
		if err != nil {
			return nil, nil, err
		}
		all[v.id] = v
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("ключ данных: чтение прежних версий: %w", err)
	}
	return active, all, nil
}

// keyRow — строка data_keys.
type keyRow struct {
	id, profile string
	num         int
	wrapped     []byte
}

// open расшифровывает ключ строки мастер-ключом (AAD — место хранения).
func (r keyRow) open(p aisecCrypto.Provider, wrap aisecCrypto.AEAD) (*version, error) {
	if r.profile != p.Name() {
		return nil, fmt.Errorf("ключ данных: ключ профиля %q, сервер работает в профиле %q", r.profile, p.Name())
	}
	aad, err := aisecCrypto.StorageAAD("data_keys", "wrapped", r.id)
	if err != nil {
		return nil, err
	}
	key, err := wrap.Open(r.wrapped, aad)
	if err != nil {
		return nil, fmt.Errorf("ключ данных: версия %d не расшифрована мастер-ключом: %w", r.num, err)
	}
	defer clear(key)
	return newVersion(p, r.id, r.num, key)
}

func newVersion(p aisecCrypto.Provider, id string, num int, key []byte) (*version, error) {
	aead, err := p.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	kdf, err := p.NewKDF(key)
	if err != nil {
		return nil, err
	}
	return &version{id: id, num: num, aead: aead, kdf: kdf}, nil
}

func newBox(p aisecCrypto.Provider, v *version) *Box {
	return &Box{provider: p, active: v, versions: map[string]*version{v.id: v}}
}

// NewStatic — Box без учёта шифрований в БД (тесты и хранилище в памяти).
// Производных ключей у него нет.
func NewStatic(keyID string, aead aisecCrypto.AEAD) *Box {
	return newBox(nil, &version{id: keyID, num: 1, aead: aead})
}

// NewStaticKey — Box из открытого ключа данных без учёта шифрований в БД,
// с производными ключами (тесты и хранилище в памяти).
func NewStaticKey(p aisecCrypto.Provider, keyID string, key []byte) (*Box, error) {
	v, err := newVersion(p, keyID, 1, key)
	if err != nil {
		return nil, err
	}
	return newBox(p, v), nil
}

func dbCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, pgTimeout)
}

// errRetired — ключ выведен ротацией: резерв отклонён, нужна новая версия.
var errRetired = errors.New("ключ данных: версия выведена ротацией")

// reserveDB увеличивает счётчик шифрований ключа (ADR-0007, п. 8).
// Нарушение CHECK — ключ исчерпан; выведенный ключ — errRetired.
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
		return errRetired
	}
	if err != nil {
		return fmt.Errorf("ключ данных: резерв шифрований: %w", err)
	}
	return nil
}

// reloadLocked перечитывает версии из БД; сбой не отнимает известные.
// Вызывается под b.mu. Смена действующей версии сбрасывает резерв и
// производные ключи.
func (b *Box) reloadLocked(ctx context.Context) error {
	if b.src == nil {
		return errors.New("ключ данных: версии не перечитываются")
	}
	active, all, err := b.src.load(ctx, b.provider)
	if err != nil {
		return err
	}
	if active.id != b.active.id {
		b.left = 0
		b.derived = nil
	}
	// Версия, удалённая из таблицы, остаётся в памяти: строки, прочитанные
	// до удаления, ещё могут прийти на расшифрование.
	for id, v := range b.versions {
		if _, ok := all[id]; !ok {
			all[id] = v
		}
	}
	b.active, b.versions = active, all
	return nil
}

// Refresh перечитывает версии ключа данных (Watch и тесты).
func (b *Box) Refresh(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reloadLocked(ctx)
}

// WatchInterval — период опроса действующей версии сервером.
const WatchInterval = 30 * time.Second

// Watch раз в interval сверяет действующую версию с БД и перечитывает
// версии после ротации, пока не отменён ctx. Так сервер перестаёт
// шифровать выведенной версией из остатка резерва (ADR-0018, п. 3.5).
// report получает ошибки опроса (может быть nil).
func (b *Box) Watch(ctx context.Context, interval time.Duration, report func(error)) {
	if b.src == nil || interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := b.checkActive(ctx); err != nil && report != nil && ctx.Err() == nil {
			report(err)
		}
	}
}

// checkActive перечитывает версии, если действующая в БД не та, что в памяти.
func (b *Box) checkActive(ctx context.Context) error {
	qctx, cancel := dbCtx(ctx)
	defer cancel()
	var id string
	err := b.src.db.QueryRow(qctx, `SELECT id::text FROM data_keys WHERE org_id = $1 AND retired_at IS NULL`, b.src.orgID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoDataKey
	}
	if err != nil {
		return fmt.Errorf("ключ данных: опрос действующей версии: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if id == b.active.id {
		return nil
	}
	return b.reloadLocked(ctx)
}

// KeyID — ID действующего ключа данных. Для записи рядом с шифротекстом
// берите ID из SealKey: между вызовами версия может смениться.
func (b *Box) KeyID() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.active.id
}

// Version — номер действующей версии ключа данных.
func (b *Box) Version() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.active.num
}

// KeyIDs — ID всех известных версий: действующая первой, затем прежние по
// убыванию номера.
func (b *Box) KeyIDs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.versions))
	for _, v := range b.versions {
		out = append(out, v.id)
	}
	slices.SortFunc(out, func(x, y string) int { return b.versions[y].num - b.versions[x].num })
	return out
}

// Alg — имя алгоритма шифрования (одно у всех версий профиля).
func (b *Box) Alg() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.active.aead.Name()
}

// Seal шифрует plaintext действующей версией ключа данных с AAD места
// хранения (таблица, столбец, ID строки). Перед шифрованием резервирует его
// в счётчике ключа. ID ключа для записи рядом с шифротекстом — SealKey.
func (b *Box) Seal(ctx context.Context, plaintext []byte, table, column, rowID string) ([]byte, error) {
	_, sealed, err := b.SealKey(ctx, plaintext, table, column, rowID)
	return sealed, err
}

// SealKey — Seal, который возвращает и ID версии, которой зашифровано.
func (b *Box) SealKey(ctx context.Context, plaintext []byte, table, column, rowID string) (string, []byte, error) {
	aad, err := aisecCrypto.StorageAAD(table, column, rowID)
	if err != nil {
		return "", nil, err
	}
	v, err := b.take(ctx)
	if err != nil {
		return "", nil, err
	}
	sealed, err := v.aead.Seal(plaintext, aad)
	return v.id, sealed, err
}

// take берёт одно шифрование действующей версии из резерва, пополняя его
// пачкой. Если ротация вывела версию, Box перечитывает версии и берёт
// резерв новой.
func (b *Box) take(ctx context.Context) (*version, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reserve == nil {
		return b.active, nil
	}
	if b.left == 0 {
		err := b.reserve(ctx, b.active.id, reserveBatch)
		if errors.Is(err, errRetired) && b.src != nil {
			prev := b.active.id
			if rerr := b.reloadLocked(ctx); rerr == nil && b.active.id != prev {
				err = b.reserve(ctx, b.active.id, reserveBatch)
			}
		}
		if errors.Is(err, errRetired) {
			// Новой версии не нашлось: шифровать нечем.
			return nil, ErrExhausted
		}
		if err != nil {
			return nil, err
		}
		b.left = reserveBatch
	}
	b.left--
	return b.active, nil
}

// minUnknownReload — не чаще одного перечитывания за этот срок из-за
// шифротекста неизвестной версии.
const minUnknownReload = 5 * time.Second

// lookup находит версию keyID; неизвестную пробует найти перечитыванием.
func (b *Box) lookup(ctx context.Context, keyID string) (*version, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if v, ok := b.versions[keyID]; ok {
		return v, nil
	}
	if b.src != nil && time.Since(b.reloadedAt) >= minUnknownReload {
		b.reloadedAt = time.Now()
		if err := b.reloadLocked(ctx); err == nil {
			if v, ok := b.versions[keyID]; ok {
				return v, nil
			}
		}
	}
	return nil, ErrUnknownKey
}

// Open расшифровывает шифротекст версии keyID с AAD места хранения.
func (b *Box) Open(keyID string, sealed []byte, table, column, rowID string) ([]byte, error) {
	return b.OpenContext(context.Background(), keyID, sealed, table, column, rowID)
}

// OpenContext — Open с контекстом для перечитывания версий.
func (b *Box) OpenContext(ctx context.Context, keyID string, sealed []byte, table, column, rowID string) ([]byte, error) {
	aad, err := aisecCrypto.StorageAAD(table, column, rowID)
	if err != nil {
		return nil, err
	}
	v, err := b.lookup(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return v.aead.Open(sealed, aad)
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
// Если ротация вывела ключ данных — ошибка ErrExhausted; SealDerived в
// этом случае переходит на новую версию сам.
func (d *Derived) Seal(ctx context.Context, plaintext []byte, table, column, rowID string) ([]byte, error) {
	sealed, err := d.seal(ctx, plaintext, table, column, rowID)
	if errors.Is(err, errRetired) {
		return nil, ErrExhausted
	}
	return sealed, err
}

func (d *Derived) seal(ctx context.Context, plaintext []byte, table, column, rowID string) ([]byte, error) {
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
// purpose от действующей версии. Ключ для одних суток и назначения в
// процессе один: счётчик резерва общий.
func (b *Box) Derive(purpose string, day time.Time) (*Derived, error) {
	if !purposeRe.MatchString(purpose) {
		return nil, fmt.Errorf("ключ данных: неверное назначение производного ключа %q", purpose)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active.kdf == nil {
		return nil, ErrNoDerive
	}
	dk := dayKey(day)
	name := purpose + "|" + dk
	if d, ok := b.derived[name]; ok {
		return d, nil
	}
	v := b.active
	aead, err := b.deriveAEAD(v, purpose, dk)
	if err != nil {
		return nil, err
	}
	d := &Derived{keyID: v.id, purpose: purpose, day: dk, aead: aead}
	if b.reserveDerive != nil {
		reserve := b.reserveDerive
		d.reserve = func(ctx context.Context, n int64) error { return reserve(ctx, v.id, purpose, dk, n) }
	}
	if b.derived == nil || len(b.derived) >= maxDerivedCached {
		// Старые сутки больше не шифруются: их резерв просто теряется.
		b.derived = map[string]*Derived{}
	}
	b.derived[name] = d
	return d, nil
}

// SealDerived шифрует производным ключом суток day действующей версии и
// возвращает ID версии и имя алгоритма для записи рядом с шифротекстом.
// Если ротация вывела версию, Box перечитывает версии и шифрует новой.
func (b *Box) SealDerived(ctx context.Context, purpose string, day time.Time, plaintext []byte,
	table, column, rowID string) (keyID, alg string, sealed []byte, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		var d *Derived
		if d, err = b.Derive(purpose, day); err != nil {
			return "", "", nil, err
		}
		sealed, err = d.seal(ctx, plaintext, table, column, rowID)
		if err == nil {
			return d.keyID, d.Alg(), sealed, nil
		}
		if !errors.Is(err, errRetired) || b.src == nil || attempt > 0 {
			break
		}
		b.mu.Lock()
		rerr := b.reloadLocked(ctx)
		changed := b.active.id != d.keyID
		b.mu.Unlock()
		if rerr != nil || !changed {
			break
		}
	}
	if errors.Is(err, errRetired) {
		err = ErrExhausted
	}
	return "", "", nil, err
}

func (b *Box) deriveAEAD(v *version, purpose, day string) (aisecCrypto.AEAD, error) {
	key, err := v.kdf.Derive([]byte("aisec-derived-v1|"+purpose+"|"+v.id+"|"+day), aisecCrypto.AEADKeySize)
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
	return b.MACFor(b.KeyID(), purpose)
}

// MACFor — MAC на ключе, выведенном из версии keyID (опоры цепочки аудита,
// сделанные до ротации, ADR-0018, п. 3.4).
func (b *Box) MACFor(keyID, purpose string) (aisecCrypto.MAC, error) {
	if !purposeRe.MatchString(purpose) {
		return nil, fmt.Errorf("ключ данных: неверное назначение ключа имитовставки %q", purpose)
	}
	b.mu.Lock()
	v, ok := b.versions[keyID]
	b.mu.Unlock()
	if !ok {
		return nil, ErrUnknownKey
	}
	if v.kdf == nil {
		return nil, ErrNoDerive
	}
	key, err := v.kdf.Derive([]byte("aisec-mac-v1|"+purpose+"|"+v.id), aisecCrypto.MinMACKeySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return b.provider.NewMAC(key)
}

// OpenDerived расшифровывает шифротекст производного ключа суток day для
// назначения purpose, выведенного из версии keyID.
func (b *Box) OpenDerived(keyID, purpose string, day time.Time, sealed []byte, table, column, rowID string) ([]byte, error) {
	return b.OpenDerivedContext(context.Background(), keyID, purpose, day, sealed, table, column, rowID)
}

// OpenDerivedContext — OpenDerived с контекстом для перечитывания версий.
func (b *Box) OpenDerivedContext(ctx context.Context, keyID, purpose string, day time.Time, sealed []byte,
	table, column, rowID string) ([]byte, error) {
	if !purposeRe.MatchString(purpose) {
		return nil, fmt.Errorf("ключ данных: неверное назначение производного ключа %q", purpose)
	}
	aad, err := aisecCrypto.StorageAAD(table, column, rowID)
	if err != nil {
		return nil, err
	}
	v, err := b.lookup(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if v.kdf == nil {
		return nil, ErrNoDerive
	}
	// Ключ для чтения выводится заново, без кэша и резерва шифрований:
	// просмотр содержимого за разные сутки не вытесняет из кэша ключ
	// текущих суток и не растит счётчик derived_key_usage (Н23 ревью 2.r3a).
	aead, err := b.deriveAEAD(v, purpose, dayKey(day))
	if err != nil {
		return nil, err
	}
	return aead.Open(sealed, aad)
}

// reserveDerivedDB увеличивает счётчик шифрований производного ключа.
// Предел исчерпан — ErrExhausted; ключ данных выведен — errRetired.
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
		return errRetired
	}
	if err != nil {
		return fmt.Errorf("ключ данных: резерв шифрований производного ключа: %w", err)
	}
	return nil
}
