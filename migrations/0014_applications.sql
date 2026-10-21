-- Приложения, ключи приложений и провайдеры в сервере управления (ТЗ 5.4,
-- 7.2 ИАФ.8, 7.9 ЗИ.1; задача 2.11). Ключ приложения показывается один раз,
-- хранятся только префикс и хеш профиля. Учётные данные провайдера
-- шифруются ключом данных с AAD providers|credential|<id> (ADR-0007, Р4).
-- Приложения и ключи не удаляются: приложение архивируется, ключ
-- отзывается — ссылки из событий и аудита сохраняются.

CREATE TABLE providers (
    id                  uuid        PRIMARY KEY,
    org_id              uuid        NOT NULL REFERENCES organizations (id),
    -- slug — ID провайдера в файле шлюза и пакете (2.13); неизменяем.
    slug                text        NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name                text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    type                text        NOT NULL CHECK (type IN ('openai', 'gigachat', 'yandexgpt')),
    base_url            text        NOT NULL CHECK (char_length(base_url) BETWEEN 9 AND 2048),
    -- Корневые сертификаты провайдера (PEM); доверие системному хранилищу
    -- задаётся только явно, его содержимым.
    ca_pem              text        NOT NULL CHECK (char_length(ca_pem) BETWEEN 1 AND 262144),
    auth_url            text        CHECK (char_length(auth_url) BETWEEN 9 AND 2048),
    scope               text        CHECK (scope IN ('GIGACHAT_API_PERS', 'GIGACHAT_API_B2B', 'GIGACHAT_API_CORP')),
    folder_id           text        CHECK (folder_id ~ '^[a-z0-9]{1,50}$'),
    -- Таймауты, секунды; 0 — значение шлюза по умолчанию.
    connect_timeout_s   integer     NOT NULL DEFAULT 0 CHECK (connect_timeout_s BETWEEN 0 AND 600),
    header_timeout_s    integer     NOT NULL DEFAULT 0 CHECK (header_timeout_s BETWEEN 0 AND 600),
    response_timeout_s  integer     NOT NULL DEFAULT 0 CHECK (response_timeout_s BETWEEN 0 AND 600),
    stream_idle_timeout_s integer   NOT NULL DEFAULT 0 CHECK (stream_idle_timeout_s BETWEEN 0 AND 600),
    -- Провайдер вне контура заказчика (5.4). По умолчанию внешний; снимает
    -- признак только администратор безопасности (DM-40).
    external            boolean     NOT NULL DEFAULT true,
    credential          bytea       CHECK (octet_length(credential) BETWEEN 16 AND 17408),
    credential_key_id   uuid        REFERENCES data_keys (id),
    credential_alg      text        CHECK (char_length(credential_alg) BETWEEN 1 AND 32),
    credential_set_at   timestamptz,
    created_at          timestamptz NOT NULL,
    created_by          text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at          timestamptz NOT NULL,
    updated_by          text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    UNIQUE (org_id, slug),
    CHECK ((credential IS NULL) = (credential_key_id IS NULL)
       AND (credential IS NULL) = (credential_alg IS NULL)
       AND (credential IS NULL) = (credential_set_at IS NULL))
);

CREATE TABLE applications (
    id                  uuid        PRIMARY KEY,
    org_id              uuid        NOT NULL REFERENCES organizations (id),
    -- slug — ID приложения в событиях и пакете; неизменяем.
    slug                text        NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name                text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    description         text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    department          text        NOT NULL DEFAULT '' CHECK (char_length(department) <= 200),
    -- Владелец видит только свои приложения (УПД.8).
    owner_id            uuid        NOT NULL REFERENCES users (id),
    env                 text        NOT NULL CHECK (env IN ('prod', 'test')),
    provider_id         uuid        NOT NULL REFERENCES providers (id),
    models              text[]      NOT NULL CHECK (cardinality(models) BETWEEN 1 AND 100),
    aliases             jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(aliases) = 'object'),
    -- Поля защиты (меняет только администратор безопасности, УПД.2):
    -- политика (шаблон или политика организации), режим и режим хранения.
    policy              text        NOT NULL CHECK (policy ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    policy_mode         text        NOT NULL CHECK (policy_mode IN ('monitor', 'enforce')),
    storage             text        NOT NULL CHECK (storage IN ('none', 'masked', 'full')),
    fail_mode           text        NOT NULL CHECK (fail_mode IN ('fail_open', 'fail_closed')),
    user_from           text        NOT NULL CHECK (user_from IN ('header', 'field', 'none')),
    quotas              jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(quotas) = 'object'),
    lists               jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(lists) = 'array'),
    exfil_allow_domains text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(exfil_allow_domains) <= 1000),
    created_at          timestamptz NOT NULL,
    created_by          text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at          timestamptz NOT NULL,
    updated_by          text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    archived_at         timestamptz,
    UNIQUE (org_id, slug)
);

CREATE INDEX applications_list ON applications (org_id, created_at, id);
CREATE INDEX applications_owner ON applications (owner_id, created_at, id);
CREATE INDEX applications_provider ON applications (provider_id);

CREATE TABLE app_keys (
    id           uuid        PRIMARY KEY,
    org_id       uuid        NOT NULL REFERENCES organizations (id),
    app_id       uuid        NOT NULL REFERENCES applications (id),
    name         text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    prefix       text        NOT NULL UNIQUE CHECK (prefix ~ '^aisec_[a-z0-9]{8}$'),
    key_hash     bytea       NOT NULL CHECK (octet_length(key_hash) BETWEEN 16 AND 64),
    hash_alg     text        NOT NULL CHECK (char_length(hash_alg) BETWEEN 1 AND 32),
    allowed_cidrs cidr[]     NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_cidrs) <= 64),
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL,
    created_by   text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    -- Ротация: новый ключ ссылается на прежний, у прежнего сокращается срок.
    rotated_from uuid        REFERENCES app_keys (id),
    revoked_at   timestamptz,
    revoked_by   text        CHECK (char_length(revoked_by) BETWEEN 1 AND 128),
    -- Срок обязателен: не больше 730 суток (apps.MaxKeyDays).
    CHECK (expires_at >= created_at AND expires_at <= created_at + interval '17520 hours'),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX app_keys_app ON app_keys (app_id, created_at, id);

-- Ключ: меняются только срок (только в сторону сокращения) и отметка
-- отзыва; отозванный ключ не меняется и не оживает; ключи не удаляются.
CREATE FUNCTION app_keys_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'app_keys: ключи не удаляются, только отзываются'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'app_keys: отозванный ключ не меняется'
            USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.org_id, NEW.app_id, NEW.name, NEW.prefix, NEW.key_hash, NEW.hash_alg, NEW.allowed_cidrs,
        NEW.created_at, NEW.created_by, NEW.rotated_from) IS DISTINCT FROM
       (OLD.id, OLD.org_id, OLD.app_id, OLD.name, OLD.prefix, OLD.key_hash, OLD.hash_alg, OLD.allowed_cidrs,
        OLD.created_at, OLD.created_by, OLD.rotated_from) THEN
        RAISE EXCEPTION 'app_keys: меняются только срок и отметка отзыва'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NEW.expires_at > OLD.expires_at THEN
        RAISE EXCEPTION 'app_keys: срок ключа не продлевается — выпустите новый ключ'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER app_keys_guard BEFORE UPDATE OR DELETE ON app_keys
    FOR EACH ROW EXECUTE FUNCTION app_keys_guard();

-- Приложение: не удаляется; ID, организация, slug и создание неизменны;
-- архивированное приложение не меняется.
CREATE FUNCTION applications_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'applications: приложения не удаляются, только архивируются'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.archived_at IS NOT NULL THEN
        RAISE EXCEPTION 'applications: архивированное приложение не меняется'
            USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.org_id, NEW.slug, NEW.created_at, NEW.created_by) IS DISTINCT FROM
       (OLD.id, OLD.org_id, OLD.slug, OLD.created_at, OLD.created_by) THEN
        RAISE EXCEPTION 'applications: ID, slug и сведения о создании не меняются'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER applications_guard BEFORE UPDATE OR DELETE ON applications
    FOR EACH ROW EXECUTE FUNCTION applications_guard();

-- Провайдер: ID, организация, slug и создание неизменны. Удаление —
-- только без приложений (внешний ключ applications.provider_id).
CREATE FUNCTION providers_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
    IF (NEW.id, NEW.org_id, NEW.slug, NEW.created_at, NEW.created_by) IS DISTINCT FROM
       (OLD.id, OLD.org_id, OLD.slug, OLD.created_at, OLD.created_by) THEN
        RAISE EXCEPTION 'providers: ID, slug и сведения о создании не меняются'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER providers_guard BEFORE UPDATE ON providers
    FOR EACH ROW EXECUTE FUNCTION providers_guard();

REVOKE ALL ON providers, applications, app_keys FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON providers TO aisec_app;
GRANT SELECT, INSERT, UPDATE ON applications TO aisec_app;
GRANT SELECT, INSERT ON app_keys TO aisec_app;
GRANT UPDATE (expires_at, revoked_at, revoked_by) ON app_keys TO aisec_app;
