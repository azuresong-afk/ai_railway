-- Счётчик изменений конфигурации шлюзов (Н26 ревью 2.r3b, задача 3.34
-- этапа 3). Растёт в той же транзакции, что и изменение приложения, ключа,
-- провайдера, политики (новая версия меняет строку policies) или настроек
-- установки: его увеличивают триггеры, поэтому ни одно хранилище и ни одна
-- команда aisec-cli его не обходят. Сервер собирает пакет конфигурации
-- заново только при смене счётчика (или по сроку ближайшего ключа), опрос
-- шлюза без изменений не выбирает данные приложений.

CREATE TABLE config_revisions (
    org_id     uuid        PRIMARY KEY REFERENCES organizations (id),
    revision   bigint      NOT NULL CHECK (revision >= 1),
    changed_at timestamptz NOT NULL
);

-- Увеличение счётчика организации изменённой строки. Изменение без
-- различий (UPDATE тех же значений) счётчик не трогает: условие WHEN у
-- триггеров UPDATE.
CREATE FUNCTION config_revision_bump() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE
    org uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        org := OLD.org_id;
    ELSE
        org := NEW.org_id;
    END IF;
    INSERT INTO config_revisions (org_id, revision, changed_at) VALUES (org, 1, clock_timestamp())
        ON CONFLICT (org_id) DO UPDATE
        SET revision = config_revisions.revision + 1, changed_at = clock_timestamp();
    RETURN NULL;
END
$$;

CREATE TRIGGER providers_revision AFTER INSERT OR DELETE ON providers
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER providers_revision_update AFTER UPDATE ON providers
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER applications_revision AFTER INSERT ON applications
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER applications_revision_update AFTER UPDATE ON applications
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER app_keys_revision AFTER INSERT ON app_keys
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER app_keys_revision_update AFTER UPDATE ON app_keys
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER policies_revision AFTER INSERT ON policies
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER policies_revision_update AFTER UPDATE ON policies
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER install_settings_revision AFTER INSERT ON install_settings
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER install_settings_revision_update AFTER UPDATE ON install_settings
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION config_revision_bump();

REVOKE ALL ON config_revisions FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON config_revisions TO aisec_app;
