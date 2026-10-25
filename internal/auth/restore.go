package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RestoreRevoked — что завершено после полного восстановления.
type RestoreRevoked struct {
	Sessions  int64
	APITokens int64
}

// RevokeAllForRestoreTx завершает все незавершённые сессии консоли и
// отзывает все действующие токены API организации в транзакции tx (В2
// ревью B1 этапа 3, РВ.2). Полная копия возвращает их в состояние на
// момент копии, в том числе отозванные позже; после восстановления
// пользователи входят заново, владельцы выпускают токены заново. Токены —
// без автора с причиной backup_restore, как при восстановлении копии
// конфигурации. Запись аудита пишет вызывающий в той же транзакции.
func RevokeAllForRestoreTx(ctx context.Context, tx pgx.Tx, orgID string, now time.Time) (RestoreRevoked, error) {
	var r RestoreRevoked
	tag, err := tx.Exec(ctx, `UPDATE sessions s SET revoked_at = $2, revoke_reason = $3
		FROM users u WHERE u.id = s.user_id AND u.org_id = $1 AND s.revoked_at IS NULL`, orgID, now, RevokeBackupRestore)
	if err != nil {
		return r, fmt.Errorf("сессии: завершение: %w", err)
	}
	r.Sessions = tag.RowsAffected()
	tag, err = tx.Exec(ctx, `UPDATE api_tokens SET revoked_at = $2, revoked_by = NULL, revoke_reason = $3
		WHERE org_id = $1 AND revoked_at IS NULL`, orgID, now, APITokenRevokedByBackupRestore)
	if err != nil {
		return r, fmt.Errorf("токены API: отзыв: %w", err)
	}
	r.APITokens = tag.RowsAffected()
	return r, nil
}
