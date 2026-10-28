-- Лицензия продукта (ТЗ 5.15, ЗИ.2; задачи 4.26, 4.27 этапа 4, ADR-0026).
--
-- licenses — загруженные лицензии: файл целиком (подпись проверяется заново
-- при запуске сервера и раз в минуту), номер и кто загрузил. Таблица только
-- дополняется: триггеры запрещают изменение, удаление и TRUNCATE, у роли приложения
-- нет прав UPDATE и DELETE. Текущая лицензия — с наибольшим номером; пустая
-- таблица — режим «пилот по договору», после первой загрузки вернуться в
-- него нельзя.
--
-- license_clock — отметка часов (ADR-0026, п. 7): наибольшее время сервера,
-- которое видела лицензия. Только растёт (триггер), поэтому перевод часов
-- назад не возвращает установку из льготного периода или запрета изменений.

CREATE TABLE licenses (
    org_id    uuid        NOT NULL REFERENCES organizations (id),
    number    bigint      NOT NULL CHECK (number BETWEEN 1 AND 9007199254740991),
    file      bytea       NOT NULL CHECK (octet_length(file) BETWEEN 1 AND 16384),
    loaded_at timestamptz NOT NULL,
    loaded_by text        NOT NULL CHECK (char_length(loaded_by) BETWEEN 1 AND 128),
    PRIMARY KEY (org_id, number)
);

CREATE FUNCTION licenses_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'licenses: загруженные лицензии не изменяются и не удаляются' USING ERRCODE = 'check_violation';
END;
$$;

CREATE TRIGGER licenses_guard BEFORE UPDATE OR DELETE ON licenses
    FOR EACH ROW EXECUTE FUNCTION licenses_guard();
CREATE TRIGGER licenses_no_truncate BEFORE TRUNCATE ON licenses
    FOR EACH STATEMENT EXECUTE FUNCTION licenses_guard();

CREATE TABLE license_clock (
    org_id     uuid        PRIMARY KEY REFERENCES organizations (id),
    high_water timestamptz NOT NULL CHECK (isfinite(high_water))
);

CREATE FUNCTION license_clock_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'license_clock: отметка часов не удаляется' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.org_id <> OLD.org_id OR NEW.high_water < OLD.high_water THEN
        RAISE EXCEPTION 'license_clock: отметка часов только растёт' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER license_clock_guard BEFORE UPDATE OR DELETE ON license_clock
    FOR EACH ROW EXECUTE FUNCTION license_clock_guard();
CREATE TRIGGER license_clock_no_truncate BEFORE TRUNCATE ON license_clock
    FOR EACH STATEMENT EXECUTE FUNCTION license_clock_guard();

REVOKE ALL ON licenses, license_clock FROM PUBLIC;
GRANT SELECT, INSERT ON licenses TO aisec_app;
GRANT SELECT, INSERT, UPDATE ON license_clock TO aisec_app;

-- Условия «Состояния системы» по лицензии (DM-44, правило
-- system.license_expiry): за 30 и 7 суток до конца срока, льготный период,
-- запрет изменений, недействительная лицензия, часы раньше выдачи или
-- отметки часов.
ALTER TABLE system_alert_state DROP CONSTRAINT system_alert_state_condition_check;
ALTER TABLE system_alert_state ADD CONSTRAINT system_alert_state_condition_check
    CHECK (char_length(condition) <= 128 AND (
        condition IN ('time_sync', 'audit_storage', 'integrity', 'audit_chain', 'config_bundle', 'integrity:server',
                      'test_build', 'ca_expiry', 'ca_expiry:critical',
                      'customer_cert_expiry', 'customer_cert_expiry:critical', 'alert_job_stale',
                      'license_expiry', 'license_expiry:critical', 'license_grace', 'license_restricted',
                      'license_invalid', 'license_clock')
        OR condition ~ '^(integrity:gateway|config_bundle_lag|events_dropped|gateway_offline|cert_expiry|reports_stale|gateway_clock|gateway_tls):[0-9a-f-]{1,64}$'));
