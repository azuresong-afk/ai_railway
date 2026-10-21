package audit

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// RecordTx пишет запись в журнал аудита внутри транзакции вызывающего:
// действие и запись о нём фиксируются или откатываются вместе (aisec-cli
// init, архивация журнала). Срок выполнения задаёт контекст вызывающего.
func (l *Log) RecordTx(ctx context.Context, tx pgx.Tx, e Entry) error {
	_, err := l.recordTx(ctx, tx, e)
	return err
}
