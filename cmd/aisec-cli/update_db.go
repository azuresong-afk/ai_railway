package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// БД при обновлении (ADR-0036, разделы 3 и 4): применённые миграции,
// размер, копия pg_dump, восстановление одной транзакцией psql и записи
// журнала аудита.

// updateDB — действия с БД; в тестах — подмена или живая PostgreSQL.
type updateDB interface {
	Applied(ctx context.Context) ([]store.Applied, error)
	Size(ctx context.Context) (int64, error)
	Dump(ctx context.Context, file string) error
	Restore(ctx context.Context, file string) error
	Audit(ctx context.Context, e audit.Entry) error
	Close()
}

const (
	dumpFile    = "db.dump"
	dumpTimeout = 6 * time.Hour
)

// pgTools — клиенты PostgreSQL той же версии, что СУБД (как backup.sh).
type pgTools struct {
	PGDump, PGRestore, PSQL string
}

var defaultPGTools = pgTools{PGDump: "/usr/bin/pg_dump", PGRestore: "/usr/bin/pg_restore", PSQL: "/usr/bin/psql"}

// pgUpdateDB — БД установки: строка подключения владельца схемы без
// пароля, пароль — в PGPASSFILE (ADR-0034, раздел 5).
type pgUpdateDB struct {
	// dsn — для pgx; toolDSN — для pg_dump и psql (libpq не знает
	// параметра search_path, в установке строки совпадают).
	dsn, toolDSN string
	env          []string
	tools        pgTools
	db           *store.DB
	log          *audit.Log
	schema       string
}

func openUpdateDB(ctx context.Context, p aisecCrypto.Provider, dsn, toolDSN string, env []string, tools pgTools) (*pgUpdateDB, error) {
	db, err := store.Open(ctx, dsn, 2)
	if err != nil {
		return nil, err
	}
	l, err := openAuditLog(db, p, nil)
	if err != nil {
		db.Close()
		return nil, err
	}
	var schema string
	if err := db.Pool().QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		db.Close()
		return nil, err
	}
	return &pgUpdateDB{dsn: dsn, toolDSN: toolDSN, env: env, tools: tools, db: db, log: l, schema: schema}, nil
}

func (d *pgUpdateDB) Close() { d.db.Close() }

func (d *pgUpdateDB) Applied(ctx context.Context) ([]store.Applied, error) {
	rows, err := d.db.Pool().Query(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("список применённых миграций: %w", err)
	}
	defer rows.Close()
	var out []store.Applied
	for rows.Next() {
		var a store.Applied
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *pgUpdateDB) Size(ctx context.Context) (int64, error) {
	var n int64
	err := d.db.Pool().QueryRow(ctx, "SELECT pg_database_size(current_database())").Scan(&n)
	return n, err
}

func (d *pgUpdateDB) Audit(ctx context.Context, e audit.Entry) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	return d.log.Record(ctx, e)
}

// Dump — pg_dump схемы установки в формате custom: временный файл 0600,
// fsync, переименование.
func (d *pgUpdateDB) Dump(ctx context.Context, file string) error {
	tmp := file + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: путь в каталоге обновления root 0700
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, dumpTimeout)
	defer cancel()
	// Имя схемы в кавычках — буквально, не шаблон pg_dump.
	cmd := exec.CommandContext(ctx, d.tools.PGDump, "--no-password", "--format=custom", "--strict-names", //nolint:gosec // G204: программа — константа, схема из каталога СУБД
		`--schema="`+strings.ReplaceAll(d.schema, `"`, `""`)+`"`, "--dbname="+d.toolDSN)
	cmd.SysProcAttr = ownGroup()
	cmd.Env = d.env
	cmd.Stdout = f
	var errOut limitedBuffer
	cmd.Stderr = &errOut
	cmd.Dir = "/"
	runErr := cmd.Run()
	syncErr := f.Sync()
	closeErr := f.Close()
	if runErr != nil {
		_ = os.Remove(tmp) //nolint:gosec // G104: недописанная копия не нужна
		return fmt.Errorf("pg_dump: %w: %s", runErr, lastLine(errOut.String()))
	}
	if syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp) //nolint:gosec // G104: недописанная копия не нужна
		return errors.Join(syncErr, closeErr)
	}
	if err := os.Rename(tmp, file); err != nil {
		return err
	}
	return updSyncDir(filepath.Dir(file))
}

// Restore восстанавливает схему из копии одной транзакцией: заголовок
// удаляет схему со всеми объектами (в том числе созданными новыми
// миграциями) и создаёт её с прежними владельцем и правами, затем
// сценарий pg_restore без записи о самой схеме. Сбой — откат транзакции,
// база остаётся как была (ADR-0036, раздел 4).
func (d *pgUpdateDB) Restore(ctx context.Context, file string) error {
	if _, err := os.Lstat(file); err != nil {
		return fmt.Errorf("копия БД %s: %w", file, err)
	}
	ctx, cancel := context.WithTimeout(ctx, dumpTimeout)
	defer cancel()
	header, err := d.schemaHeader(ctx)
	if err != nil {
		return err
	}
	list, err := runCmd(ctx, d.env, nil, d.tools.PGRestore, "--list", file)
	if err != nil {
		return err
	}
	listFile := file + ".list"
	if err := os.Remove(listFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lf, err := os.OpenFile(listFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: путь в каталоге обновления root 0700
	if err != nil {
		return err
	}
	defer os.Remove(listFile) //nolint:errcheck // временный список
	if _, err := lf.WriteString(filterTOC(list, d.schema)); err != nil {
		_ = lf.Close() //nolint:gosec // G104: ошибка записи важнее
		return err
	}
	if err := lf.Close(); err != nil {
		return err
	}

	restore := exec.CommandContext(ctx, d.tools.PGRestore, "--use-list="+listFile, "--file=-", file) //nolint:gosec // G204: программа — константа, пути — каталог обновления
	restore.SysProcAttr = ownGroup()
	restore.Env = d.env
	restore.Dir = "/"
	var restoreErr limitedBuffer
	restore.Stderr = &restoreErr
	script, err := restore.StdoutPipe()
	if err != nil {
		return err
	}
	psql := exec.CommandContext(ctx, d.tools.PSQL, "--no-password", "--no-psqlrc", "--quiet", "--single-transaction", //nolint:gosec // G204: программа — константа
		"--set=ON_ERROR_STOP=1", "--dbname="+d.toolDSN)
	psql.SysProcAttr = ownGroup()
	psql.Env = d.env
	psql.Dir = "/"
	psql.Stdin = io.MultiReader(strings.NewReader(header), script)
	var psqlOut limitedBuffer
	psql.Stdout = io.Discard
	psql.Stderr = &psqlOut
	if err := restore.Start(); err != nil {
		return fmt.Errorf("pg_restore: %w", err)
	}
	psqlErr := psql.Run()
	if psqlErr != nil {
		_ = restore.Process.Kill() //nolint:gosec // G104: psql уже завершился с ошибкой
	}
	waitErr := restore.Wait()
	if psqlErr != nil {
		return fmt.Errorf("psql: восстановление не выполнено, БД не изменена: %w: %s", psqlErr, lastLine(psqlOut.String()))
	}
	if waitErr != nil {
		return fmt.Errorf("pg_restore: %w: %s", waitErr, lastLine(restoreErr.String()))
	}
	return nil
}

// schemaHeader — SQL заголовка восстановления: удаление и создание схемы с
// владельцем и правами из каталога СУБД.
func (d *pgUpdateDB) schemaHeader(ctx context.Context) (string, error) {
	var owner string
	if err := d.db.Pool().QueryRow(ctx, "SELECT r.rolname FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner WHERE n.nspname = $1", d.schema).Scan(&owner); err != nil {
		return "", fmt.Errorf("владелец схемы: %w", err)
	}
	rows, err := d.db.Pool().Query(ctx, `SELECT COALESCE(r.rolname, ''), a.privilege_type, a.is_grantable
		FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a LEFT JOIN pg_roles r ON r.oid = a.grantee
		WHERE n.nspname = $1 AND a.grantee <> n.nspowner ORDER BY 1, 2`, d.schema)
	if err != nil {
		return "", fmt.Errorf("права схемы: %w", err)
	}
	defer rows.Close()
	s := pgx.Identifier{d.schema}.Sanitize()
	var b strings.Builder
	fmt.Fprintf(&b, "DROP SCHEMA %s CASCADE;\nCREATE SCHEMA %s;\nALTER SCHEMA %s OWNER TO %s;\n", s, s, s, pgx.Identifier{owner}.Sanitize())
	for rows.Next() {
		var grantee, priv string
		var grantable bool
		if err := rows.Scan(&grantee, &priv, &grantable); err != nil {
			return "", err
		}
		if priv != "USAGE" && priv != "CREATE" {
			return "", fmt.Errorf("права схемы: неожиданное право %q", priv)
		}
		to := "PUBLIC"
		if grantee != "" {
			to = pgx.Identifier{grantee}.Sanitize()
		}
		opt := ""
		if grantable {
			opt = " WITH GRANT OPTION"
		}
		fmt.Fprintf(&b, "GRANT %s ON SCHEMA %s TO %s%s;\n", priv, s, to, opt)
	}
	return b.String(), rows.Err()
}

// filterTOC убирает из списка pg_restore запись о самой схеме: её создаёт
// заголовок восстановления.
func filterTOC(list, schema string) string {
	var b strings.Builder
	for _, line := range strings.Split(list, "\n") {
		if !strings.HasPrefix(line, ";") {
			// «id; oid oid SCHEMA - имя владелец»
			if _, rest, ok := strings.Cut(line, "; "); ok {
				f := strings.Fields(rest)
				if len(f) >= 5 && f[2] == "SCHEMA" && f[3] == "-" && f[4] == schema {
					continue
				}
			}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
