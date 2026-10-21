-- Токены API (ТЗ 7.3: ИАФ.9; задача 2.10). Хранятся только префикс и хеш
-- профиля всего токена; сам токен показывается один раз при выпуске. Права
-- токена — область permissions, пересечённая с текущими правами роли
-- владельца (internal/auth.TokenGrants). Токены не удаляются: отзыв —
-- отметка revoked_at, отозванный токен не оживает.

CREATE TABLE api_tokens (
    id            uuid        PRIMARY KEY,
    org_id        uuid        NOT NULL REFERENCES organizations (id),
    user_id       uuid        NOT NULL REFERENCES users (id),
    name          text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    prefix        text        NOT NULL UNIQUE CHECK (prefix ~ '^aisec_pat_[a-z0-9]{8}$'),
    token_hash    bytea       NOT NULL CHECK (octet_length(token_hash) BETWEEN 16 AND 64),
    hash_alg      text        NOT NULL CHECK (char_length(hash_alg) BETWEEN 1 AND 32),
    -- Область токена: «разрешение:область»; проверяется кодом при выпуске
    -- и при чтении (неизвестное разрешение прав не даёт).
    permissions   text[]      NOT NULL CHECK (cardinality(permissions) BETWEEN 1 AND 64),
    expires_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL,
    last_used_at  timestamptz,
    last_used_ip  inet        CHECK (masklen(last_used_ip) = CASE family(last_used_ip) WHEN 4 THEN 32 ELSE 128 END),
    revoked_at    timestamptz,
    revoked_by    uuid,
    revoke_reason text        CHECK (revoke_reason IN ('owner', 'admin')),
    -- Срок обязателен: от 1 до 365 суток по 24 ч (APITokenMaxDays).
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '8760 hours'),
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL) AND (revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX api_tokens_org_list ON api_tokens (org_id, created_at, id);
CREATE INDEX api_tokens_user_list ON api_tokens (user_id, created_at, id);

-- Отозванный токен не меняется; хеш, область, срок и владелец неизменны;
-- токены не удаляются — ни ролью приложения, ни владельцем таблицы.
CREATE FUNCTION api_tokens_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'api_tokens: токены не удаляются, только отзываются'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'api_tokens: отозванный токен не меняется'
            USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.org_id, NEW.user_id, NEW.name, NEW.prefix, NEW.token_hash, NEW.hash_alg, NEW.permissions,
        NEW.expires_at, NEW.created_at) IS DISTINCT FROM
       (OLD.id, OLD.org_id, OLD.user_id, OLD.name, OLD.prefix, OLD.token_hash, OLD.hash_alg, OLD.permissions,
        OLD.expires_at, OLD.created_at) THEN
        RAISE EXCEPTION 'api_tokens: меняются только отметки использования и отзыва'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER api_tokens_guard BEFORE UPDATE OR DELETE ON api_tokens
    FOR EACH ROW EXECUTE FUNCTION api_tokens_guard();

-- Права роли приложения: без DELETE; UPDATE — только отметки использования и отзыва.
REVOKE ALL ON api_tokens FROM PUBLIC;
GRANT SELECT, INSERT ON api_tokens TO aisec_app;
GRANT UPDATE (last_used_at, last_used_ip, revoked_at, revoked_by, revoke_reason) ON api_tokens TO aisec_app;
