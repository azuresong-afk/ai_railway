-- Завершение сессий после полного восстановления пилота (В2 ревью B1
-- этапа 3, РВ.2): aisec-cli restore-finish завершает все сессии консоли
-- восстановленной копии с причиной backup_restore — сессия, завершённая
-- после даты копии, не возвращается в силу. Токены API отзываются с
-- той же причиной (миграция 0023).

ALTER TABLE sessions DROP CONSTRAINT sessions_revoke_reason_check,
    ADD CONSTRAINT sessions_revoke_reason_check CHECK (revoke_reason IN ('logout', 'idle', 'expired', 'limit', 'admin',
        'password_changed', 'password_reset', 'deactivated', 'locked', 'mfa_reset', 'mfa_passed', 'mfa_required',
        'backup_restore'));
