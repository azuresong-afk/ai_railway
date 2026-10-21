package keyring_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
)

const (
	orgID = "00000000-0000-0000-0000-000000000001"
	keyID = "01900000-0000-7000-8000-0000000000d1"
)

func provider(t testing.TB) aisecCrypto.Provider {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeRow — строка результата: значения по порядку столбцов или ошибка.
type fakeRow struct {
	vals []any
	err  error
}

func (r fakeRow) Scan(dst ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, d := range dst {
		switch d := d.(type) {
		case *string:
			*d = r.vals[i].(string)
		case *[]byte:
			*d = bytes.Clone(r.vals[i].([]byte))
		case *int64:
			*d = r.vals[i].(int64)
		}
	}
	return nil
}

// fakeDB — data_keys из одной строки; UPDATE считает резервы.
type fakeDB struct {
	mu       sync.Mutex
	id       string
	profile  string
	wrapped  []byte
	none     bool
	reserves int
	sealed   int64
	limit    int64
	retired  bool
	// Производные ключи: счётчики по «назначение|сутки».
	derived      map[string]int64
	derivedRes   int
	derivedLimit int64
}

func (f *fakeDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(strings.TrimSpace(sql), "SELECT") {
		if f.none || args[0] != orgID {
			return fakeRow{err: pgx.ErrNoRows}
		}
		return fakeRow{vals: []any{f.id, f.profile, f.wrapped}}
	}
	if f.retired {
		return fakeRow{err: pgx.ErrNoRows}
	}
	if strings.Contains(sql, "derived_key_usage") {
		name := args[1].(string) + "|" + args[2].(string)
		n := args[3].(int64)
		if f.derived == nil {
			f.derived = map[string]int64{}
		}
		if f.derivedLimit > 0 && f.derived[name]+n > f.derivedLimit {
			return fakeRow{err: &pgconn.PgError{Code: "23514"}}
		}
		f.derivedRes++
		f.derived[name] += n
		return fakeRow{vals: []any{f.derived[name]}}
	}
	n := args[1].(int64)
	if f.limit > 0 && f.sealed+n > f.limit {
		return fakeRow{err: &pgconn.PgError{Code: "23514"}}
	}
	f.reserves++
	f.sealed += n
	return fakeRow{vals: []any{f.sealed}}
}

// install — каталог с master.key и обёрнутый им ключ данных.
func install(t *testing.T, p aisecCrypto.Provider) (string, *fakeDB) {
	t.Helper()
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	master, err := aisecCrypto.RandomBytes(r, aisecCrypto.AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	data, err := aisecCrypto.RandomBytes(r, aisecCrypto.AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := p.NewAEAD(master)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := aisecCrypto.StorageAAD("data_keys", "wrapped", keyID)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrap.Seal(data, aad)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindMaster, p.Name(), master)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, keyring.MasterKeyFile), pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, &fakeDB{id: keyID, profile: p.Name(), wrapped: wrapped}
}

func TestLoadSealOpen(t *testing.T) {
	p := provider(t)
	dir, db := install(t, p)
	b, err := keyring.Load(context.Background(), db, p, dir, orgID)
	if err != nil {
		t.Fatal(err)
	}
	if b.KeyID() != keyID || b.Alg() == "" {
		t.Fatalf("ключ %q, алгоритм %q", b.KeyID(), b.Alg())
	}
	secret := []byte("синтетический секрет")
	sealed, err := b.Seal(context.Background(), secret, "user_mfa", "secret", "u1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("шифротекст содержит открытый текст")
	}
	got, err := b.Open(keyID, sealed, "user_mfa", "secret", "u1")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("расшифровка: %q %v", got, err)
	}
	// AAD привязывает шифротекст к месту хранения: перенос в другую строку,
	// столбец или таблицу не расшифровывается.
	for _, place := range [][3]string{{"user_mfa", "secret", "u2"}, {"user_mfa", "other", "u1"}, {"other", "secret", "u1"}} {
		if _, err := b.Open(keyID, sealed, place[0], place[1], place[2]); err == nil {
			t.Errorf("расшифровано в чужом месте %v", place)
		}
	}
	if _, err := b.Open("01900000-0000-7000-8000-0000000000d2", sealed, "user_mfa", "secret", "u1"); !errors.Is(err, keyring.ErrUnknownKey) {
		t.Fatalf("чужой ключ: %v", err)
	}
}

func TestLoadRejects(t *testing.T) {
	p := provider(t)
	ctx := context.Background()
	t.Run("нет master.key", func(t *testing.T) {
		_, db := install(t, p)
		if _, err := keyring.Load(ctx, db, p, t.TempDir(), orgID); err == nil {
			t.Fatal("загружен без мастер-ключа")
		}
	})
	t.Run("права master.key", func(t *testing.T) {
		dir, db := install(t, p)
		if err := os.Chmod(filepath.Join(dir, keyring.MasterKeyFile), 0o644); err != nil { //nolint:gosec // G302: тест нарочно открывает мастер-ключ всем, чтобы проверить отказ
			t.Fatal(err)
		}
		if _, err := keyring.Load(ctx, db, p, dir, orgID); err == nil {
			t.Fatal("принят мастер-ключ, доступный всем")
		}
	})
	t.Run("нет ключа данных", func(t *testing.T) {
		dir, db := install(t, p)
		db.none = true
		if _, err := keyring.Load(ctx, db, p, dir, orgID); !errors.Is(err, keyring.ErrNoDataKey) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("чужой мастер-ключ", func(t *testing.T) {
		dir, _ := install(t, p)
		_, other := install(t, p)
		if _, err := keyring.Load(ctx, other, p, dir, orgID); err == nil {
			t.Fatal("ключ данных расшифрован чужим мастер-ключом")
		}
	})
	t.Run("ключ другого профиля", func(t *testing.T) {
		dir, db := install(t, p)
		db.profile = "gost"
		if _, err := keyring.Load(ctx, db, p, dir, orgID); err == nil {
			t.Fatal("принят ключ данных другого профиля")
		}
	})
	t.Run("подмена строки ключа", func(t *testing.T) {
		dir, db := install(t, p)
		db.id = "01900000-0000-7000-8000-0000000000d9"
		if _, err := keyring.Load(ctx, db, p, dir, orgID); err == nil {
			t.Fatal("обёртка ключа данных не привязана к ID строки")
		}
	})
	t.Run("нет БД", func(t *testing.T) {
		if _, err := keyring.Load(ctx, nil, p, t.TempDir(), orgID); err == nil {
			t.Fatal("загружен без БД")
		}
	})
}

// Шифрования резервируются пачками в счётчике ключа (ADR-0007, п. 8).
func TestReserveBatches(t *testing.T) {
	p := provider(t)
	dir, db := install(t, p)
	b, err := keyring.Load(context.Background(), db, p, dir, orgID)
	if err != nil {
		t.Fatal(err)
	}
	const batch = 4096
	for i := 0; i < batch+1; i++ {
		if _, err := b.Seal(context.Background(), []byte("x"), "t", "c", "r"); err != nil {
			t.Fatal(err)
		}
	}
	if db.reserves != 2 || db.sealed != 2*batch {
		t.Fatalf("резервов %d, счётчик %d", db.reserves, db.sealed)
	}
}

func TestReserveExhausted(t *testing.T) {
	p := provider(t)
	for name, mutate := range map[string]func(*fakeDB){
		"предел счётчика": func(f *fakeDB) { f.limit = 100 },
		"ключ выведен":    func(f *fakeDB) { f.retired = true },
	} {
		t.Run(name, func(t *testing.T) {
			dir, db := install(t, p)
			b, err := keyring.Load(context.Background(), db, p, dir, orgID)
			if err != nil {
				t.Fatal(err)
			}
			mutate(db)
			if _, err := b.Seal(context.Background(), []byte("x"), "t", "c", "r"); !errors.Is(err, keyring.ErrExhausted) {
				t.Fatalf("%v", err)
			}
		})
	}
}

func TestNewStaticNoReserve(t *testing.T) {
	p := provider(t)
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	k, err := aisecCrypto.RandomBytes(r, aisecCrypto.AEADKeySize)
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.NewAEAD(k)
	if err != nil {
		t.Fatal(err)
	}
	b := keyring.NewStatic(keyID, a)
	sealed, err := b.Seal(context.Background(), []byte("s"), "t", "c", "r")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Open(keyID, sealed, "t", "c", "r"); err != nil || string(got) != "s" {
		t.Fatalf("%q %v", got, err)
	}
}

// Производные ключи суток (ADR-0007, п. 8): свой ключ на сутки и
// назначение, счётчик — на производный ключ, а не на ключ данных.
func TestDeriveSealOpen(t *testing.T) {
	p := provider(t)
	dir, db := install(t, p)
	b, err := keyring.Load(context.Background(), db, p, dir, orgID)
	if err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 10, 21, 23, 59, 0, 0, time.UTC)
	d, err := b.Derive("event-content", day)
	if err != nil {
		t.Fatal(err)
	}
	if d.KeyID() != keyID || d.Alg() == "" {
		t.Fatalf("ключ %s, алгоритм %s", d.KeyID(), d.Alg())
	}
	sealed, err := d.Seal(context.Background(), []byte("содержимое"), "event_content", "sealed", "row-1")
	if err != nil {
		t.Fatal(err)
	}
	// Те же сутки в другом часовом поясе — тот же ключ.
	msk := time.FixedZone("MSK", 3*3600)
	got, err := b.OpenDerived(keyID, "event-content", day.In(msk), sealed, "event_content", "sealed", "row-1")
	if err != nil || string(got) != "содержимое" {
		t.Fatalf("%q %v", got, err)
	}
	for name, open := range map[string]func() ([]byte, error){
		"другие сутки": func() ([]byte, error) {
			return b.OpenDerived(keyID, "event-content", day.Add(time.Minute), sealed, "event_content", "sealed", "row-1")
		},
		"другое назначение": func() ([]byte, error) {
			return b.OpenDerived(keyID, "other", day, sealed, "event_content", "sealed", "row-1")
		},
		"другая строка": func() ([]byte, error) {
			return b.OpenDerived(keyID, "event-content", day, sealed, "event_content", "sealed", "row-2")
		},
		"ключом данных": func() ([]byte, error) { return b.Open(keyID, sealed, "event_content", "sealed", "row-1") },
	} {
		if _, err := open(); !errors.Is(err, aisecCrypto.ErrDecrypt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := b.OpenDerived("other-key", "event-content", day, sealed, "event_content", "sealed", "row-1"); !errors.Is(err, keyring.ErrUnknownKey) {
		t.Fatalf("чужой ключ: %v", err)
	}
	if db.sealed != 0 || db.derived["event-content|2026-10-21"] != 4096 {
		t.Fatalf("счётчики: ключ данных %d, производные %v", db.sealed, db.derived)
	}
}

func TestDeriveReserveBatches(t *testing.T) {
	p := provider(t)
	dir, db := install(t, p)
	b, err := keyring.Load(context.Background(), db, p, dir, orgID)
	if err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 4097; i++ {
		d, err := b.Derive("event-content", day)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Seal(context.Background(), []byte("x"), "t", "c", "r"); err != nil {
			t.Fatal(err)
		}
	}
	if db.derivedRes != 2 || db.derived["event-content|2026-10-21"] != 2*4096 {
		t.Fatalf("резервов %d, счётчики %v", db.derivedRes, db.derived)
	}
	db.derivedLimit = 1
	d, err := b.Derive("event-content", day.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Seal(context.Background(), []byte("x"), "t", "c", "r"); !errors.Is(err, keyring.ErrExhausted) {
		t.Fatalf("предел производного ключа: %v", err)
	}
}

func TestDeriveRejects(t *testing.T) {
	p := provider(t)
	a, err := p.NewAEAD(make([]byte, aisecCrypto.AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.NewStatic(keyID, a).Derive("event-content", time.Now()); !errors.Is(err, keyring.ErrNoDerive) {
		t.Fatalf("NewStatic: %v", err)
	}
	b, err := keyring.NewStaticKey(p, keyID, make([]byte, aisecCrypto.AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []string{"", "Event", "a|b", strings.Repeat("a", 33)} {
		if _, err := b.Derive(purpose, time.Now()); err == nil {
			t.Errorf("назначение %q принято", purpose)
		}
	}
	d1, err := b.Derive("event-content", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d2, err := b.Derive("event-content", time.Now())
	if err != nil || d1 != d2 {
		t.Fatal("ключ суток должен быть один на процесс")
	}
}
