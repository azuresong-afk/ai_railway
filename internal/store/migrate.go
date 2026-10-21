package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

const (
	// maxMigrationSize ограничивает размер одного файла миграции.
	maxMigrationSize = 1 << 20
	// migrateTimeout — предел на весь прогон миграций.
	migrateTimeout = 5 * time.Minute
	// migrateLockID — ключ рекомендательной блокировки: два aisec-cli migrate
	// одновременно не применят одну миграцию дважды.
	migrateLockID = 0x41495345 // "AISE"
)

// Migration — одна миграция.
type Migration struct {
	Version int    // номер из имени файла
	Name    string // краткое имя из имени файла
	SQL     string
}

// Applied — запись о применённой миграции.
type Applied struct {
	Version  int
	Name     string
	Checksum string // SHA-256 текста миграции, hex
}

// Tx — транзакция, в которой работает исполнитель миграций.
type Tx interface {
	// Exec выполняет запрос; значения передаются только параметрами.
	Exec(ctx context.Context, sql string, args ...any) error
	// Applied возвращает применённые миграции по возрастанию номера.
	Applied(ctx context.Context) ([]Applied, error)
}

// Executor открывает транзакцию; при ошибке fn она откатывается.
type Executor interface {
	InTx(ctx context.Context, fn func(Tx) error) error
}

// ParseMigrationName разбирает имя файла NNNN_имя.sql.
func ParseMigrationName(file string) (version int, name string, err error) {
	base, ok := strings.CutSuffix(file, ".sql")
	if !ok {
		return 0, "", errors.New("имя миграции должно оканчиваться на .sql")
	}
	num, name, ok := strings.Cut(base, "_")
	if !ok || len(num) != 4 || name == "" || len(name) > 64 {
		return 0, "", errors.New("имя миграции: NNNN_имя.sql")
	}
	for _, c := range num {
		if c < '0' || c > '9' {
			return 0, "", errors.New("номер миграции — четыре цифры")
		}
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return 0, "", errors.New("имя миграции: строчная латиница, цифры и _")
		}
	}
	version, err = strconv.Atoi(num)
	if err != nil || version < 1 {
		return 0, "", errors.New("номер миграции начинается с 0001")
	}
	return version, name, nil
}

// LoadMigrations читает *.sql из корня fsys; номера идут подряд с 1.
func LoadMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("чтение миграций: %w", err)
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		v, name, err := ParseMigrationName(e.Name())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if len(data) > maxMigrationSize {
			return nil, fmt.Errorf("%s: больше %d байт", e.Name(), maxMigrationSize)
		}
		out = append(out, Migration{Version: v, Name: name, SQL: string(data)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("номера миграций должны идти подряд с 1: ожидалась %04d, найдена %04d", i+1, m.Version)
		}
	}
	return out, nil
}

// Migrator применяет миграции.
type Migrator struct {
	Exec       Executor
	Hasher     crypto.Hasher
	Migrations []Migration
}

func (m *Migrator) checksum(sql string) string {
	return hex.EncodeToString(m.Hasher.Sum([]byte(sql)))
}

// Up применяет неприменённые миграции в одной транзакции и возвращает их
// номера. Изменённая или пропавшая уже применённая миграция — ошибка:
// схему правят новой миграцией.
func (m *Migrator) Up(ctx context.Context) ([]int, error) {
	ctx, cancel := context.WithTimeout(ctx, migrateTimeout)
	defer cancel()
	var done []int
	err := m.Exec.InTx(ctx, func(tx Tx) error {
		done = nil
		if err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrateLockID); err != nil {
			return fmt.Errorf("блокировка миграций: %w", err)
		}
		if err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version    integer     PRIMARY KEY,
			name       text        NOT NULL,
			checksum   text        NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			return fmt.Errorf("таблица schema_migrations: %w", err)
		}
		applied, err := tx.Applied(ctx)
		if err != nil {
			return fmt.Errorf("список применённых миграций: %w", err)
		}
		if len(applied) > len(m.Migrations) {
			return fmt.Errorf("в базе %d миграций, в сборке %d: база новее программы", len(applied), len(m.Migrations))
		}
		for i, a := range applied {
			want := m.Migrations[i]
			if a.Version != want.Version || a.Name != want.Name {
				return fmt.Errorf("миграция %04d_%s в базе не совпадает с %04d_%s в сборке", a.Version, a.Name, want.Version, want.Name)
			}
			if a.Checksum != m.checksum(want.SQL) {
				return fmt.Errorf("миграция %04d_%s изменена после применения", a.Version, a.Name)
			}
		}
		for _, mg := range m.Migrations[len(applied):] {
			if err := tx.Exec(ctx, mg.SQL); err != nil {
				return fmt.Errorf("миграция %04d_%s: %w", mg.Version, mg.Name, err)
			}
			if err := tx.Exec(ctx, "INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
				mg.Version, mg.Name, m.checksum(mg.SQL)); err != nil {
				return fmt.Errorf("запись миграции %04d: %w", mg.Version, err)
			}
			done = append(done, mg.Version)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return done, nil
}
