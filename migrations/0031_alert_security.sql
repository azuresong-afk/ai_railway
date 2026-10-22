-- Системные правила и правила безопасности, срок хранения оповещений
-- (ТЗ 5.6, 5.16 DM-38–DM-44, раздел 7; ADR-0020; задача 3.11 этапа 3).

-- Условия DM-44 по шлюзу ведутся в system_alert_state: шлюз отбрасывает
-- события, недоступен, сертификат скоро истекает, итог контроля
-- целостности устарел (Н29).
ALTER TABLE system_alert_state DROP CONSTRAINT system_alert_state_condition_check;
ALTER TABLE system_alert_state ADD CONSTRAINT system_alert_state_condition_check
    CHECK (char_length(condition) <= 128 AND (
        condition IN ('time_sync', 'audit_storage', 'integrity', 'audit_chain', 'config_bundle', 'integrity:server',
                      'test_build')
        OR condition ~ '^(integrity:gateway|config_bundle_lag|events_dropped|gateway_offline|cert_expiry|reports_stale):[0-9a-f-]{1,64}$'));

-- Срок хранения закрытых оповещений, суток (решение волны B этапа 3):
-- сокращение — с повторной проверкой и записью в аудит (DM-40).
ALTER TABLE install_settings
    ADD COLUMN alert_retention_days integer NOT NULL DEFAULT 365 CHECK (alert_retention_days BETWEEN 90 AND 1825);

-- Удаление закрытых оповещений по сроку хранения (фоновая задача сервера).
-- Роль сервера получает DELETE, но триггеры пропускают только закрытое
-- оповещение без инцидента старше срока из install_settings вместе с его
-- ссылками и историей; открытые, «в работе» и связанные с инцидентом не
-- удаляются никогда.
CREATE FUNCTION alert_retention_days(org uuid) RETURNS integer
    LANGUAGE sql STABLE AS
$$ SELECT COALESCE((SELECT alert_retention_days FROM install_settings WHERE org_id = org), 365) $$;

CREATE FUNCTION alert_expired(a uuid) RETURNS boolean
    LANGUAGE sql STABLE AS
$$ SELECT EXISTS (SELECT 1 FROM alerts WHERE id = a AND status = 'closed' AND incident_id IS NULL
       AND closed_at < now() - make_interval(days => alert_retention_days(org_id))) $$;

CREATE FUNCTION alerts_delete_guard() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    -- Поля OLD читаются только в ветке своей таблицы: у alerts нет alert_id.
    IF TG_TABLE_NAME = 'alerts' THEN
        IF alert_expired(OLD.id) THEN
            RETURN OLD;
        END IF;
    ELSIF alert_expired(OLD.alert_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'оповещения удаляются только по сроку хранения' USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER alerts_delete_guard BEFORE DELETE ON alerts
    FOR EACH ROW EXECUTE FUNCTION alerts_delete_guard();
CREATE TRIGGER alert_events_delete_guard BEFORE DELETE ON alert_events
    FOR EACH ROW EXECUTE FUNCTION alerts_delete_guard();
CREATE TRIGGER alert_history_delete_guard BEFORE DELETE ON alert_history
    FOR EACH ROW EXECUTE FUNCTION alerts_delete_guard();

GRANT DELETE ON alerts, alert_events, alert_history TO aisec_app;
