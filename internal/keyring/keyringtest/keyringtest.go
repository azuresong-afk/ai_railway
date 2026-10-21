// Пакет keyringtest — ключи установки для тестов на PostgreSQL: то, что
// делает aisec-cli init (master.key в каталоге и обёрнутый ключ данных в
// data_keys), в минимальном виде. В рабочие бинарники не входит.
package keyringtest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Execer — доступ к БД с правом INSERT в data_keys (владелец схемы).
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Install создаёт каталог ключей с master.key и действующий ключ данных
// организации orgID. Возвращает каталог и ID ключа данных.
func Install(t testing.TB, ctx context.Context, db Execer, p aisecCrypto.Provider, orgID string) (dir, keyID string) {
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
	id, err := store.NewUUIDv7(time.Now(), r)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := p.NewAEAD(master)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := aisecCrypto.StorageAAD("data_keys", "wrapped", string(id))
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrap.Seal(data, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO data_keys (id, org_id, version, profile, alg, wrapped, created_at)
		VALUES ($1, $2, 1, $3, $4, $5, now())`, string(id), orgID, p.Name(), wrap.Name(), wrapped); err != nil {
		t.Fatal(err)
	}
	pem, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindMaster, p.Name(), master)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, keyring.MasterKeyFile), pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, string(id)
}
