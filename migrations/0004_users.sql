-- Учётные записи и сессии консоли (ТЗ 7.2–7.3: ИАФ.1–4, УПД.4–5; решение
-- Р6 этапа 2; задача 2.7). Пароли — только хешами PHC через криптопрофиль;
-- токены сессий и CSRF — только хешами. Пользователи не удаляются, а
-- деактивируются (УПД.5): ссылки в журнале аудита остаются действительными.

CREATE TABLE users (
    id                       uuid        PRIMARY KEY,
    org_id                   uuid        NOT NULL REFERENCES organizations (id),
    login                    text        NOT NULL CHECK (login ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    display_name             text        NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
    -- Предустановленные роли (ТЗ 1.3); свои роли — задача 2.9.
    role                     text        NOT NULL CHECK (role IN ('security_admin', 'system_admin', 'analyst', 'auditor', 'app_owner')),
    status                   text        NOT NULL CHECK (status IN ('active', 'deactivated')),
    password_hash            text        NOT NULL CHECK (char_length(password_hash) BETWEEN 1 AND 256),
    password_changed_at      timestamptz NOT NULL,
    must_change_password     boolean     NOT NULL,
    temp_password_expires_at timestamptz,
    failed_attempts          integer     NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    -- locked_at без locked_until — блокировка до разблокировки администратором.
    locked_at                timestamptz,
    locked_until             timestamptz CHECK (locked_until IS NULL OR locked_at IS NOT NULL),
    created_at               timestamptz NOT NULL,
    created_by               text        NOT NULL CHECK (char_length(created_by) <= 128),
    deactivated_at           timestamptz,
    last_login_at            timestamptz,
    UNIQUE (org_id, login)
);

CREATE INDEX users_list ON users (org_id, created_at, id);

-- Пользователи не удаляются никем, включая владельца таблицы (УПД.5).
CREATE FUNCTION users_no_delete() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    RAISE EXCEPTION '%: % запрещено (учётные записи деактивируются, а не удаляются)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER users_no_delete BEFORE DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION users_no_delete();
CREATE TRIGGER users_no_truncate BEFORE TRUNCATE ON users
    FOR EACH STATEMENT EXECUTE FUNCTION users_no_delete();

-- Прежние хеши паролей для запрета повторов (ИАФ.2). Хранится не больше
-- глубины истории из настроек; старые удаляются при смене пароля.
CREATE TABLE password_history (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       uuid        NOT NULL REFERENCES users (id),
    password_hash text        NOT NULL CHECK (char_length(password_hash) BETWEEN 1 AND 256),
    created_at    timestamptz NOT NULL
);

CREATE INDEX password_history_user ON password_history (user_id, id);

-- Сессии консоли (Р6, УПД.4): в cookie — 32 случайных байта, здесь — хеш
-- профиля. CSRF-токен привязан к сессии и тоже хранится хешем.
CREATE TABLE sessions (
    id            uuid        PRIMARY KEY,
    user_id       uuid        NOT NULL REFERENCES users (id),
    token_hash    bytea       NOT NULL UNIQUE CHECK (octet_length(token_hash) BETWEEN 16 AND 64),
    csrf_hash     bytea       NOT NULL CHECK (octet_length(csrf_hash) BETWEEN 16 AND 64),
    state         text        NOT NULL CHECK (state IN ('active', 'password_change')),
    created_at    timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    revoke_reason text        CHECK (revoke_reason IN ('logout', 'idle', 'expired', 'limit', 'admin',
                                     'password_changed', 'password_reset', 'deactivated', 'locked')),
    source_ip     inet        CHECK (masklen(source_ip) = CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END),
    user_agent    text        NOT NULL CHECK (char_length(user_agent) <= 256),
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);

CREATE INDEX sessions_user_active ON sessions (user_id, created_at) WHERE revoked_at IS NULL;

-- Настройки входа организации (ИАФ.2, ИАФ.4, УПД.4, ИАФ.3). Нет строки —
-- действуют значения по умолчанию из internal/auth (DefaultPolicy).
-- Границы совпадают с Policy.Validate.
CREATE TABLE auth_settings (
    org_id                uuid        PRIMARY KEY REFERENCES organizations (id),
    password_min_length   integer     NOT NULL CHECK (password_min_length BETWEEN 8 AND 64),
    password_min_classes  integer     NOT NULL CHECK (password_min_classes BETWEEN 1 AND 4),
    password_history      integer     NOT NULL CHECK (password_history BETWEEN 0 AND 24),
    password_max_age_days integer     NOT NULL CHECK (password_max_age_days BETWEEN 0 AND 365),
    password_warn_days    integer     NOT NULL CHECK (password_warn_days BETWEEN 0 AND 60),
    lockout_threshold     integer     NOT NULL CHECK (lockout_threshold BETWEEN 3 AND 20),
    lockout_minutes       integer     NOT NULL CHECK (lockout_minutes BETWEEN 0 AND 1440),
    session_idle_minutes  integer     NOT NULL CHECK (session_idle_minutes BETWEEN 1 AND 240),
    session_max_per_user  integer     NOT NULL CHECK (session_max_per_user BETWEEN 1 AND 20),
    temp_password_hours   integer     NOT NULL CHECK (temp_password_hours BETWEEN 1 AND 168),
    updated_at            timestamptz NOT NULL
);

-- Завершённая сессия не оживает: снять отметку revoked_at не может никто,
-- включая владельца таблицы.
CREATE FUNCTION sessions_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'sessions: завершённая сессия не меняется'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER sessions_guard BEFORE UPDATE ON sessions
    FOR EACH ROW EXECUTE FUNCTION sessions_guard();

-- Права роли приложения: без DELETE у пользователей и сессий (сессии
-- завершаются отметкой revoked_at); история паролей подрезается. UPDATE —
-- только на столбцы, которые меняет сервер: логин, роль, организация,
-- автор и время создания записи, токены и привязка сессии неизменны.
REVOKE ALL ON users, password_history, sessions, auth_settings FROM PUBLIC;
GRANT SELECT, INSERT ON users, sessions, auth_settings TO aisec_app;
GRANT UPDATE (status, password_hash, password_changed_at, must_change_password, temp_password_expires_at,
    failed_attempts, locked_at, locked_until, deactivated_at, last_login_at) ON users TO aisec_app;
GRANT UPDATE (state, last_seen_at, revoked_at, revoke_reason) ON sessions TO aisec_app;
GRANT UPDATE (password_min_length, password_min_classes, password_history, password_max_age_days,
    password_warn_days, lockout_threshold, lockout_minutes, session_idle_minutes, session_max_per_user,
    temp_password_hours, updated_at) ON auth_settings TO aisec_app;
GRANT SELECT, INSERT, DELETE ON password_history TO aisec_app;
