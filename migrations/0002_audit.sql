-- Журнал аудита (ТЗ 7.4, РСБ.1–4, 7; решение Р5 этапа 2).
-- Защита от правки и удаления — две линии: права (роль приложения может только
-- читать и добавлять) и триггеры, которые запрещают UPDATE и TRUNCATE всем,
-- включая владельца таблицы. Целостность содержимого — цепочка хешей,
-- её считает и проверяет internal/audit через криптопрофиль.

-- Роли без входа. Логины сервера и процедуры архивации получают их через
-- GRANT при установке; роли общие для кластера, поэтому IF NOT EXISTS.
-- Логину aisec-cli migrate нужно право CREATEROLE (или роли создаёт
-- администратор СУБД заранее).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisec_app') THEN
        CREATE ROLE aisec_app NOLOGIN;
    END IF;
    -- Права на удаление архивированных записей выдаёт задача 2.5 (ADR-0008).
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisec_audit_archiver') THEN
        CREATE ROLE aisec_audit_archiver NOLOGIN;
    END IF;
END
$$;

CREATE TABLE audit_log (
    seq        bigint      PRIMARY KEY CHECK (seq > 0),
    id         uuid        NOT NULL UNIQUE,
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    ts         timestamptz NOT NULL CHECK (isfinite(ts)),
    actor_type text        NOT NULL CHECK (actor_type IN ('user', 'api_token', 'system', 'gateway', 'cli')),
    actor_id   text        NOT NULL CHECK (char_length(actor_id) <= 128),
    actor_name text        NOT NULL CHECK (char_length(actor_name) <= 256),
    -- Только адрес узла: маска в хеш не входит, поэтому она всегда полная.
    source_ip  inet        CHECK (masklen(source_ip) = CASE family(source_ip) WHEN 4 THEN 32 ELSE 128 END),
    action     text        NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$' AND char_length(action) <= 64),
    object_type text       NOT NULL CHECK (char_length(object_type) <= 64),
    object_id  text        NOT NULL CHECK (char_length(object_id) <= 256),
    result     text        NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    -- json, а не jsonb: текст хранится как записан. Хешируется каноническая
    -- форма; проверка требует, чтобы хранимый текст с ней совпадал.
    details    json        NOT NULL,
    hash_alg   text        NOT NULL CHECK (char_length(hash_alg) BETWEEN 1 AND 32),
    prev_hash  bytea       NOT NULL CHECK (octet_length(prev_hash) BETWEEN 16 AND 64),
    hash       bytea       NOT NULL CHECK (octet_length(hash) BETWEEN 16 AND 64)
);

CREATE INDEX audit_log_ts ON audit_log (org_id, ts);
CREATE INDEX audit_log_action ON audit_log (org_id, action, ts);

-- UPDATE и TRUNCATE запрещены всем; DELETE — только процедуре архивации
-- (aisec-cli audit archive, задача 2.5) под ролью aisec_audit_archiver.
-- Проверяется current_user, а не членство: суперпользователь формально член
-- любой роли, а удаление должно идти только явным SET ROLE.
-- SECURITY INVOKER явно: проверка опирается на current_user вызывающего.
CREATE FUNCTION audit_log_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_user = 'aisec_audit_archiver' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '%: % запрещено (только добавление)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_guard();
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_guard();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_guard();

-- Новая запись продолжает цепочку: номер следующий, prev_hash — хеш последней.
-- Сам хеш считает internal/audit (криптопрофиль), здесь — только связность,
-- чтобы вставка в обход internal/audit не встроилась в середину цепочки.
-- Пустая таблица (первая запись или после архивации) — начало проверяет
-- internal/audit по контрольной точке.
-- Таблица читается по схеме триггера, а не по search_path: временная
-- таблица audit_log в сессии не подменит последнюю запись.
CREATE FUNCTION audit_log_link() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE
    last_seq  bigint;
    last_hash bytea;
BEGIN
    EXECUTE format('SELECT seq, hash FROM %I.%I ORDER BY seq DESC LIMIT 1', TG_TABLE_SCHEMA, TG_TABLE_NAME)
        INTO last_seq, last_hash;
    IF last_seq IS NOT NULL AND (NEW.seq <> last_seq + 1 OR NEW.prev_hash <> last_hash) THEN
        RAISE EXCEPTION 'журнал аудита: запись % не продолжает цепочку', NEW.seq
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER audit_log_link BEFORE INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_link();

-- Настройки аудита (РСБ.3): отключённые необязательные события и срок
-- хранения. Обязательные события internal/audit пишет всегда, даже если их
-- код оказался в disabled_actions.
CREATE TABLE audit_settings (
    org_id           uuid        PRIMARY KEY REFERENCES organizations (id),
    disabled_actions text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(disabled_actions) <= 256),
    retention_days   integer     NOT NULL DEFAULT 365 CHECK (retention_days BETWEEN 30 AND 3650),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Результаты проверок цепочки: последняя проверенная запись нужна, чтобы
-- заметить удаление хвоста журнала.
CREATE TABLE audit_verifications (
    id         uuid        PRIMARY KEY,
    ts         timestamptz NOT NULL,
    ok         boolean     NOT NULL,
    checked    bigint      NOT NULL CHECK (checked >= 0),
    last_seq   bigint      NOT NULL CHECK (last_seq >= 0),
    last_hash  bytea,
    reason     text        NOT NULL CHECK (char_length(reason) <= 64),
    broken_seq bigint
);

CREATE INDEX audit_verifications_ts ON audit_verifications (ts);

-- Подмена истории проверок спрятала бы удаление хвоста: UPDATE, DELETE и
-- TRUNCATE запрещены всем, без исключения для архивации.
CREATE FUNCTION audit_append_only() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    RAISE EXCEPTION '%: % запрещено (только добавление)', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER audit_verifications_no_update BEFORE UPDATE ON audit_verifications
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER audit_verifications_no_delete BEFORE DELETE ON audit_verifications
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER audit_verifications_no_truncate BEFORE TRUNCATE ON audit_verifications
    FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();

-- Журнал технического состояния (РСБ.7): запуск, остановка, инициализация,
-- состояние компонентов и интерфейсов, ошибки с классификацией, загрузка.
CREATE TABLE tech_log (
    id        uuid        PRIMARY KEY,
    org_id    uuid        NOT NULL REFERENCES organizations (id),
    ts        timestamptz NOT NULL,
    component text        NOT NULL CHECK (component ~ '^[a-z][a-z0-9_-]{0,31}$'),
    kind      text        NOT NULL CHECK (kind IN ('start', 'stop', 'init', 'state', 'error', 'load')),
    level     text        NOT NULL CHECK (level IN ('info', 'warning', 'error', 'critical')),
    class     text        CHECK (class IN ('config', 'db', 'network', 'provider', 'integrity', 'crypto', 'internal')),
    message   text        NOT NULL CHECK (char_length(message) BETWEEN 1 AND 1024),
    details   json        NOT NULL
);

CREATE INDEX tech_log_ts ON tech_log (org_id, ts);

-- Права: роль приложения только читает и добавляет; настройки — меняет.
REVOKE ALL ON audit_log, audit_verifications, tech_log, audit_settings FROM PUBLIC;
GRANT SELECT, INSERT ON audit_log, audit_verifications, tech_log TO aisec_app;
GRANT SELECT, INSERT, UPDATE ON audit_settings TO aisec_app;
