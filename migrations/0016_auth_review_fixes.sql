-- Исправления по ревью 2.r2 (замечания В6–В8).
--
-- 1. Признак пройденного второго фактора у сессии (В6). Ставится, когда в
--    сессии принят код TOTP или код восстановления: при входе с фактором,
--    при его подключении, при выпуске новых кодов. Полная сессия без
--    признака, которой фактор стал обязателен (роль получила права на
--    изменение или включён mfa_required_all), завершается с причиной
--    mfa_required: пользователь входит заново через второй фактор.
--    Сессии до этой миграции признака не имеют — после обновления
--    пользователи ролей с обязательным фактором один раз входят заново.
-- 2. Отзыв токенов API при сбросе пароля администратором и при
--    принудительном завершении сессий (В8). Сброс пароля через aisec-cli
--    (В7) выполняет не пользователь консоли: revoked_by пуст, причина —
--    password_reset.

ALTER TABLE sessions ADD COLUMN mfa_verified boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT sessions_mfa_verified_state CHECK (NOT mfa_verified OR state IN ('active', 'password_change'));
ALTER TABLE sessions DROP CONSTRAINT sessions_revoke_reason_check,
    ADD CONSTRAINT sessions_revoke_reason_check CHECK (revoke_reason IN ('logout', 'idle', 'expired', 'limit', 'admin',
        'password_changed', 'password_reset', 'deactivated', 'locked', 'mfa_reset', 'mfa_passed', 'mfa_required'));
GRANT UPDATE (mfa_verified) ON sessions TO aisec_app;

ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_revoke_reason_check,
    ADD CONSTRAINT api_tokens_revoke_reason_check CHECK (revoke_reason IN ('owner', 'admin', 'password_reset', 'sessions_revoked'));
ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_check1,
    ADD CONSTRAINT api_tokens_revoked_fields CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)
        AND (revoked_by IS NULL OR revoked_at IS NOT NULL)
        AND (revoked_by IS NOT NULL OR revoked_at IS NULL OR revoke_reason = 'password_reset'));
