-- Пакеты конфигурации для шлюзов (решение Р7, ТЗ 5.3 «Доставка в шлюзы»,
-- ОЦЛ.3; задача 2.13, ADR-0009). Хранится открытое содержимое каждой
-- версии пакета: приложения с хешами ключей, провайдеры без учётных
-- данных, политики. Подпись и шифрование учётных данных для конкретного
-- шлюза выполняются при выдаче и в БД не хранятся. История версий
-- показывает, какая конфигурация действовала на шлюзах.

CREATE TABLE config_bundles (
    org_id       uuid        NOT NULL REFERENCES organizations (id),
    -- version — max(прежняя + 1, время сборки в мс): строго растёт и после
    -- восстановления БД из резервной копии не уходит назад.
    version      bigint      NOT NULL CHECK (version >= 1),
    content      bytea       NOT NULL CHECK (octet_length(content) BETWEEN 2 AND 8388608),
    content_hash bytea       NOT NULL CHECK (octet_length(content_hash) BETWEEN 16 AND 64),
    hash_alg     text        NOT NULL CHECK (char_length(hash_alg) BETWEEN 1 AND 32),
    created_at   timestamptz NOT NULL,
    PRIMARY KEY (org_id, version)
);

-- Версия неизменяема и не удаляется никем, включая владельца схемы; новая
-- версия — только больше последней.
CREATE FUNCTION config_bundles_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE
    last bigint;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'config_bundles: версии пакетов неизменяемы'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT max(version) INTO last FROM config_bundles WHERE org_id = NEW.org_id;
    IF last IS NOT NULL AND NEW.version <= last THEN
        RAISE EXCEPTION 'config_bundles: версия пакета — больше последней'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER config_bundles_guard BEFORE INSERT OR UPDATE OR DELETE ON config_bundles
    FOR EACH ROW EXECUTE FUNCTION config_bundles_guard();
CREATE TRIGGER config_bundles_no_truncate BEFORE TRUNCATE ON config_bundles
    FOR EACH STATEMENT EXECUTE FUNCTION config_bundles_guard();

REVOKE ALL ON config_bundles FROM PUBLIC;
GRANT SELECT, INSERT ON config_bundles TO aisec_app;
