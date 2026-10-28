-- Теневой ИИ (ТЗ 5.11, DM-37; задача 4.22 этапа 4, ADR-0027).
--
-- Хранятся только агрегаты: сервис каталога, псевдоним пользователя (HMAC
-- на ключе псевдонимов, как в событиях) и час UTC — обращения и байты.
-- Сырые строки журналов, URL, домены вне каталога, имена файлов и исходные
-- идентификаторы пользователей не хранятся. Журнал импорта — счётчики и
-- хеш файла (повтор того же файла отклоняется). Каталог — подписанный файл
-- служебной базы целиком: подпись проверяется заново при запуске сервера.

CREATE TABLE shadow_ai_catalog (
    org_id        uuid        PRIMARY KEY REFERENCES organizations (id),
    version       bigint      NOT NULL CHECK (version > 0),
    catalog_date  date        NOT NULL,
    -- Номер заверения рабочего ключа и отпечаток ключа (ADR-0027, п. 2).
    subkey_serial bigint      NOT NULL CHECK (subkey_serial > 0),
    fingerprint   text        NOT NULL CHECK (char_length(fingerprint) BETWEEN 1 AND 128),
    services      integer     NOT NULL CHECK (services > 0),
    file          bytea       NOT NULL CHECK (octet_length(file) BETWEEN 1 AND 4194304),
    uploaded_at   timestamptz NOT NULL,
    uploaded_by   text        NOT NULL CHECK (char_length(uploaded_by) BETWEEN 1 AND 128)
);

CREATE TABLE shadow_ai_imports (
    id                  uuid        PRIMARY KEY,
    org_id              uuid        NOT NULL REFERENCES organizations (id),
    created_at          timestamptz NOT NULL,
    created_by          text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    format              text        NOT NULL CHECK (format IN ('csv', 'squid', 'cef')),
    sha256              text        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    catalog_version     bigint      NOT NULL CHECK (catalog_version > 0),
    lines               bigint      NOT NULL CHECK (lines >= 0),
    matched             bigint      NOT NULL CHECK (matched >= 0),
    unmatched           bigint      NOT NULL CHECK (unmatched >= 0),
    errors              bigint      NOT NULL CHECK (errors >= 0),
    outdated            bigint      NOT NULL CHECK (outdated >= 0),
    -- Номера первых ошибочных строк, без содержимого.
    error_lines         bigint[]    NOT NULL CHECK (cardinality(error_lines) <= 20),
    services            integer     NOT NULL CHECK (services >= 0),
    users_pseudonymized boolean     NOT NULL,
    period_from         timestamptz,
    period_to           timestamptz,
    UNIQUE (org_id, sha256)
);

CREATE INDEX shadow_ai_imports_created ON shadow_ai_imports (org_id, created_at DESC);

CREATE TABLE shadow_ai_hour (
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    bucket     timestamptz NOT NULL CHECK (isfinite(bucket) AND bucket = date_trunc('hour', bucket)),
    service    text        NOT NULL CHECK (service ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
    -- Псевдоним: 32 hex; пусто — пользователь не учтён (вид none).
    user_alias text        NOT NULL CHECK (user_alias ~ '^([0-9a-f]{32})?$'),
    user_kind  text        NOT NULL CHECK (user_kind IN ('user', 'address', 'none')),
    requests   bigint      NOT NULL CHECK (requests > 0),
    bytes      bigint      NOT NULL CHECK (bytes >= 0),
    PRIMARY KEY (org_id, bucket, service, user_alias, user_kind),
    CHECK ((user_kind = 'none') = (user_alias = ''))
);

CREATE INDEX shadow_ai_hour_service ON shadow_ai_hour (org_id, service, bucket);

-- Срок хранения агрегатов (по умолчанию 1 год).
ALTER TABLE install_settings
    ADD COLUMN shadow_ai_retention_days integer NOT NULL DEFAULT 365
        CHECK (shadow_ai_retention_days BETWEEN 30 AND 1825);

REVOKE ALL ON shadow_ai_catalog, shadow_ai_imports, shadow_ai_hour FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON shadow_ai_catalog TO aisec_app;
GRANT SELECT, INSERT ON shadow_ai_imports TO aisec_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON shadow_ai_hour TO aisec_app;
