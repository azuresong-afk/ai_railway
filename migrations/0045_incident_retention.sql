-- Срок хранения закрытых инцидентов (3Н37 ревью 3.r2 этапа 3, ТЗ 5.7,
-- ADR-0020, п. 5): закрытый инцидент хранится incident_retention_days
-- суток (по умолчанию 3 года) и затем удаляется фоновой задачей сервера
-- вместе с хронологией, комментариями, ссылками на события, этапами и
-- связанными оповещениями (их историей, ссылками и журналом доставки).
-- Незакрытые инциденты и инцидент, открытый заново (на него ссылается
-- следующий), не удаляются. Сокращение срока — с повторной проверкой и
-- записью в аудит (DM-40), как у оповещений (миграция 0032).
ALTER TABLE install_settings
    ADD COLUMN incident_retention_days integer NOT NULL DEFAULT 1095
        CHECK (incident_retention_days BETWEEN 365 AND 1825);

CREATE FUNCTION incident_retention_days(org uuid) RETURNS integer
    LANGUAGE sql STABLE AS
$$ SELECT COALESCE((SELECT incident_retention_days FROM install_settings WHERE org_id = org), 1095) $$;

CREATE FUNCTION incident_expired(i uuid) RETURNS boolean
    LANGUAGE sql STABLE AS
$$ SELECT EXISTS (SELECT 1 FROM incidents WHERE id = i AND status = 'closed'
       AND closed_at < now() - make_interval(days => incident_retention_days(org_id))) $$;

-- Оповещение инцидента удаляется по сроку инцидента (ADR-0020: «связанные с
-- инцидентом — по сроку инцидента»), остальные закрытые — по своему сроку.
CREATE OR REPLACE FUNCTION alert_expired(a uuid) RETURNS boolean
    LANGUAGE sql STABLE AS
$$ SELECT EXISTS (SELECT 1 FROM alerts WHERE id = a AND status = 'closed' AND (
       (incident_id IS NULL AND closed_at < now() - make_interval(days => alert_retention_days(org_id)))
       OR (incident_id IS NOT NULL AND incident_expired(incident_id)))) $$;

-- Роль сервера получает DELETE, но триггеры пропускают только записи
-- закрытого инцидента старше срока; ссылку reopened_from защищает внешний
-- ключ.
CREATE FUNCTION incidents_delete_guard() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    -- Поля OLD читаются только в ветке своей таблицы: у incidents нет incident_id.
    IF TG_TABLE_NAME = 'incidents' THEN
        IF incident_expired(OLD.id) THEN
            RETURN OLD;
        END IF;
    ELSIF incident_expired(OLD.incident_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'инциденты удаляются только по сроку хранения' USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER incidents_delete_guard BEFORE DELETE ON incidents
    FOR EACH ROW EXECUTE FUNCTION incidents_delete_guard();
CREATE TRIGGER incident_stages_delete_guard BEFORE DELETE ON incident_stages
    FOR EACH ROW EXECUTE FUNCTION incidents_delete_guard();
CREATE TRIGGER incident_events_delete_guard BEFORE DELETE ON incident_events
    FOR EACH ROW EXECUTE FUNCTION incidents_delete_guard();
CREATE TRIGGER incident_timeline_delete_guard BEFORE DELETE ON incident_timeline
    FOR EACH ROW EXECUTE FUNCTION incidents_delete_guard();
CREATE TRIGGER incident_comments_delete_guard BEFORE DELETE ON incident_comments
    FOR EACH ROW EXECUTE FUNCTION incidents_delete_guard();

GRANT DELETE ON incidents, incident_stages, incident_events, incident_timeline, incident_comments TO aisec_app;
