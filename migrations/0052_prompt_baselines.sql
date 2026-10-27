-- Эталон системного промпта приложения (ТЗ 5.4, 5.16 DM-26; задача 4.14
-- этапа 4). Одна запись на приложение. Текст эталона — шифротекст ключа
-- данных с AAD prompt_baselines|text|<app_id> (ЗИ.1, ADR-0007),
-- перешифровывается при ротации ключа данных (aisec-cli keys rotate-data).
-- В пакет конфигурации шлюзов попадают только хеш нормализованного текста
-- (hash, хеш криптопрофиля) и режим контроля; режим off в пакет не
-- попадает.

CREATE TABLE prompt_baselines (
    app_id       uuid        PRIMARY KEY REFERENCES applications (id),
    org_id       uuid        NOT NULL REFERENCES organizations (id),
    -- off — эталон хранится, но не сверяется; alert — находка и оповещение;
    -- block — запрос с другим системным промптом блокируется.
    mode         text        NOT NULL CHECK (mode IN ('off', 'alert', 'block')),
    hash         text        NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    -- Размер текста эталона, байт (предел — 128 КиБ).
    text_bytes   integer     NOT NULL CHECK (text_bytes BETWEEN 1 AND 131072),
    text_sealed  bytea       NOT NULL CHECK (octet_length(text_sealed) BETWEEN 16 AND 140000),
    text_key_id  uuid        NOT NULL REFERENCES data_keys (id),
    text_alg     text        NOT NULL CHECK (char_length(text_alg) BETWEEN 1 AND 64),
    created_at   timestamptz NOT NULL,
    created_by   text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at   timestamptz NOT NULL,
    updated_by   text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128)
);

CREATE INDEX prompt_baselines_org ON prompt_baselines (org_id);
CREATE INDEX prompt_baselines_key ON prompt_baselines (text_key_id);

-- Хеш и режим входят в пакет конфигурации шлюзов (раздел
-- prompt_baselines): их изменение увеличивает счётчик изменений
-- (миграция 0030). Перешифрование текста пакет не меняет.
CREATE TRIGGER prompt_baselines_revision AFTER INSERT OR DELETE ON prompt_baselines
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER prompt_baselines_revision_update AFTER UPDATE ON prompt_baselines
    FOR EACH ROW WHEN (OLD.mode IS DISTINCT FROM NEW.mode OR OLD.hash IS DISTINCT FROM NEW.hash)
    EXECUTE FUNCTION config_revision_bump();

REVOKE ALL ON prompt_baselines FROM PUBLIC;
-- UPDATE — всё, кроме приложения, организации и сведений о первой записи.
GRANT SELECT, INSERT, DELETE ON prompt_baselines TO aisec_app;
GRANT UPDATE (mode, hash, text_bytes, text_sealed, text_key_id, text_alg, updated_at, updated_by)
    ON prompt_baselines TO aisec_app;
