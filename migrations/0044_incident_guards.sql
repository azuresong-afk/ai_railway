-- Защита связи оповещений с инцидентами и автомата статусов инцидента на
-- уровне СУБД (3Н35 ревью 3.r2 этапа 3, ТЗ 5.7, ADR-0020, п. 4): кроме
-- проверок в коде сервера, их соблюдают и прямые запросы роли сервера.

-- Оповещение, связанное с инцидентом, не отвязывается и не
-- перепривязывается; с закрытым инцидентом оповещение не связывается, а
-- оповещение закрытого инцидента не открывается снова.
CREATE FUNCTION alerts_incident_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.incident_id IS NOT NULL AND NEW.incident_id IS DISTINCT FROM OLD.incident_id THEN
        RAISE EXCEPTION 'связь оповещения с инцидентом не меняется' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.incident_id IS NOT NULL AND (OLD.incident_id IS NULL OR NEW.status <> 'closed')
        AND EXISTS (SELECT 1 FROM incidents WHERE id = NEW.incident_id AND status = 'closed') THEN
        RAISE EXCEPTION 'закрытый инцидент не дополняется' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER alerts_incident_guard BEFORE UPDATE ON alerts
    FOR EACH ROW WHEN (OLD.incident_id IS NOT NULL OR NEW.incident_id IS NOT NULL)
    EXECUTE FUNCTION alerts_incident_guard();

-- Инцидент закрывается вместе со своими оповещениями (в той же
-- транзакции): к фиксации у закрытого инцидента нет незакрытых оповещений,
-- иначе приём событий дописывал бы в него и откатывался.
CREATE FUNCTION incidents_closed_alerts() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM alerts WHERE incident_id = NEW.id AND status <> 'closed') THEN
        RAISE EXCEPTION 'у закрытого инцидента остались незакрытые оповещения' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER incidents_closed_alerts AFTER UPDATE OF status ON incidents
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (NEW.status = 'closed') EXECUTE FUNCTION incidents_closed_alerts();

-- Автомат статусов только вперёд: new → in_progress → contained → closed;
-- время первой реакции и локализации не переписывается (срок реакции не
-- подделывается). Закрытый инцидент не меняется вовсе (миграция 0035).
CREATE FUNCTION incidents_forward_only() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    ord CONSTANT text[] := ARRAY['new', 'in_progress', 'contained', 'closed'];
BEGIN
    IF array_position(ord, NEW.status) < array_position(ord, OLD.status) THEN
        RAISE EXCEPTION 'статус инцидента не возвращается назад' USING ERRCODE = 'check_violation';
    END IF;
    IF (OLD.reacted_at IS NOT NULL AND NEW.reacted_at IS DISTINCT FROM OLD.reacted_at)
        OR (OLD.contained_at IS NOT NULL AND NEW.contained_at IS DISTINCT FROM OLD.contained_at) THEN
        RAISE EXCEPTION 'время реакции и локализации не меняется' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER incidents_forward_only BEFORE UPDATE ON incidents
    FOR EACH ROW WHEN (OLD.status <> 'closed') EXECUTE FUNCTION incidents_forward_only();

-- Запись «открыт заново» в хронологии закрытого инцидента — только одна и
-- только если он действительно открыт заново (есть инцидент с
-- reopened_from на него).
CREATE OR REPLACE FUNCTION incident_child_of_closed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'incident_timeline' THEN
        IF NEW.kind = 'reopened'
            AND EXISTS (SELECT 1 FROM incidents WHERE reopened_from = NEW.incident_id)
            AND NOT EXISTS (SELECT 1 FROM incident_timeline WHERE incident_id = NEW.incident_id AND kind = 'reopened') THEN
            RETURN NEW;
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM incidents WHERE id = NEW.incident_id AND status = 'closed') THEN
        RAISE EXCEPTION 'закрытый инцидент не дополняется' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
