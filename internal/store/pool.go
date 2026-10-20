package store

import "github.com/jackc/pgx/v5/pgxpool"

// Pool возвращает пул соединений для пакетов со своими запросами
// (internal/audit). Запросы — только параметризованные, с контекстом и
// таймаутом; закрывает пул только владелец DB.
func (d *DB) Pool() *pgxpool.Pool { return d.pool }
