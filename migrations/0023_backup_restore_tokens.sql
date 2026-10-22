-- Токены API при восстановлении из резервной копии (ревью 2.r4 этапа 2,
-- В21; ТЗ 7.6 РВ.1): действующие токены копии восстанавливаются
-- отозванными без автора (причина backup_restore) — токен, отозванный после
-- даты копии, не возвращается в силу. Флаг -keep-api-tokens оставляет их
-- как в копии.

ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_revoke_reason_check,
    ADD CONSTRAINT api_tokens_revoke_reason_check CHECK (revoke_reason IN ('owner', 'admin', 'password_reset',
        'sessions_revoked', 'backup_restore'));
ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_revoked_fields,
    ADD CONSTRAINT api_tokens_revoked_fields CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)
        AND (revoked_by IS NULL OR revoked_at IS NOT NULL)
        AND (revoked_by IS NOT NULL OR revoked_at IS NULL OR revoke_reason IN ('password_reset', 'backup_restore')));
