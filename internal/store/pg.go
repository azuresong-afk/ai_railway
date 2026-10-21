package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// queryTimeout — предел на один вызов к БД, если у контекста нет своего срока.
	queryTimeout = 30 * time.Second
	// connectTimeout — предел на установление соединения и первую проверку.
	connectTimeout = 10 * time.Second
	maxDSNLen      = 2048
)

// DB — пул соединений PostgreSQL.
type DB struct {
	pool *pgxpool.Pool
}

// Option — необязательная настройка пула.
type Option func(*pgxpool.Config)

// WithStatementTimeout задаёт statement_timeout сессий пула: СУБД сама
// прерывает запрос дольше d, даже если клиент перестал читать ответ (пул
// чтения событий, В11 ревью 2.r3a).
func WithStatementTimeout(d time.Duration) Option {
	return func(c *pgxpool.Config) {
		c.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(d.Milliseconds(), 10)
	}
}

// Open открывает пул и проверяет доступность БД. Строка подключения — URL
// postgres://…; ошибки не содержат саму строку (в ней пароль).
func Open(ctx context.Context, dsn string, maxConns int32, opts ...Option) (*DB, error) {
	if dsn == "" || len(dsn) > maxDSNLen {
		return nil, errors.New("строка подключения к БД пуста или длиннее 2048 байт")
	}
	if u, err := url.Parse(dsn); err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, errors.New("строка подключения к БД: ожидается URL postgres://…")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("строка подключения к БД не разобрана")
	}
	if maxConns < 1 || maxConns > 200 {
		return nil, errors.New("число соединений пула: от 1 до 200")
	}
	cfg.MaxConns = maxConns
	cfg.ConnConfig.ConnectTimeout = connectTimeout
	for _, o := range opts {
		o(cfg)
	}
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("не удалось создать пул соединений с БД")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("БД недоступна")
	}
	return &DB{pool: pool}, nil
}

// Close закрывает пул.
func (d *DB) Close() { d.pool.Close() }

// Ping проверяет доступность БД.
func (d *DB) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	return d.pool.Ping(ctx)
}

// InTx реализует Executor: транзакция откатывается, если fn вернула ошибку.
func (d *DB) InTx(ctx context.Context, fn func(Tx) error) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("начало транзакции: %w", err)
	}
	// Откат после коммита безвреден; ошибку отката скрывает исходная.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() //nolint:gosec // G104: откат после коммита безвреден, ошибку скрывает исходная
	if err := fn(pgTx{tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type pgTx struct{ tx pgx.Tx }

func (t pgTx) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := t.tx.Exec(ctx, sql, args...)
	return err
}

func (t pgTx) Applied(ctx context.Context) ([]Applied, error) {
	rows, err := t.tx.Query(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Applied
	for rows.Next() {
		var a Applied
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
