-- Пользователь приложения по JWT корпоративного IdP и доступ к моделям по
-- группам (ТЗ 4.3, 7.3 УПД.9, 5.16 DM-33; ADR-0025, раздел 4; задача 4.21
-- этапа 4). Одна запись на приложение; нет записи — прежнее поведение
-- (пользователь по user_from). Настройка входит в пакет конфигурации
-- шлюзов (раздел user_tokens), ключи издателя — в раздел user_token_keys.

CREATE TABLE app_user_access (
    app_id         uuid        PRIMARY KEY REFERENCES applications (id),
    org_id         uuid        NOT NULL REFERENCES organizations (id),
    -- off — только X-AISec-User (поле user); optional — JWT или
    -- X-AISec-User; required — без действительного JWT отказ 401.
    mode           text        NOT NULL CHECK (mode IN ('off', 'optional', 'required')),
    issuer         text        NOT NULL CHECK (issuer = '' OR (issuer ~ '^https://' AND char_length(issuer) <= 512)),
    audience       text        NOT NULL CHECK (char_length(audience) <= 256),
    groups_claim   text        NOT NULL CHECK (char_length(groups_claim) BETWEEN 1 AND 64),
    leeway_seconds integer     NOT NULL CHECK (leeway_seconds BETWEEN 0 AND 300),
    -- Модель или псевдоним → группы, которым она доступна.
    model_groups   jsonb       NOT NULL CHECK (jsonb_typeof(model_groups) = 'object' AND octet_length(model_groups::text) <= 262144),
    updated_at     timestamptz NOT NULL,
    updated_by     text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    CHECK (mode = 'off' OR (issuer <> '' AND audience <> ''))
);

CREATE INDEX app_user_access_org ON app_user_access (org_id);

-- Настройка входит в пакет: изменение увеличивает счётчик изменений
-- (миграция 0030).
CREATE TRIGGER app_user_access_revision AFTER INSERT OR UPDATE OR DELETE ON app_user_access
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();

-- Ключи издателя в пакете берутся по настройке IdP (ADR-0025, 3.6): смена
-- издателя или корневых сертификатов IdP — новая сборка пакета. Ротацию
-- ключей у самого IdP сервер замечает сам (не реже раза в 5 минут).
CREATE TRIGGER oidc_settings_revision AFTER INSERT OR DELETE ON oidc_settings
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER oidc_settings_revision_update AFTER UPDATE ON oidc_settings
    FOR EACH ROW WHEN (OLD.issuer IS DISTINCT FROM NEW.issuer OR OLD.ca_pem IS DISTINCT FROM NEW.ca_pem
        OR OLD.client_id IS DISTINCT FROM NEW.client_id)
    EXECUTE FUNCTION config_revision_bump();

REVOKE ALL ON app_user_access FROM PUBLIC;
GRANT SELECT, INSERT ON app_user_access TO aisec_app;
GRANT UPDATE (mode, issuer, audience, groups_claim, leeway_seconds, model_groups, updated_at, updated_by)
    ON app_user_access TO aisec_app;
