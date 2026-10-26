-- Время закрытия инцидента и оповещения не ставится задним числом (3В33
-- ревью 3.r4 этапа 3, ADR-0020, п. 5): срок хранения (миграции 0032, 0045)
-- считается от closed_at, и прямой запрос роли сервера с closed_at в
-- прошлом сразу открывал бы удаление в обход срока. При закрытии closed_at
-- отличается от времени СУБД не больше чем на 5 минут (часы сервера и СУБД
-- на одном узле или синхронизированы, ТЗ 7, ВРМ.1); у закрытой записи
-- closed_at не меняется.
CREATE FUNCTION closed_at_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status = 'closed' THEN
        IF NEW.closed_at IS DISTINCT FROM OLD.closed_at THEN
            RAISE EXCEPTION 'время закрытия не меняется' USING ERRCODE = 'check_violation';
        END IF;
    ELSIF NEW.status = 'closed'
        AND (NEW.closed_at IS NULL OR abs(extract(epoch FROM NEW.closed_at - now())) > 300) THEN
        RAISE EXCEPTION 'время закрытия расходится с часами СУБД' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER incidents_closed_at_guard BEFORE UPDATE ON incidents
    FOR EACH ROW WHEN (NEW.status = 'closed') EXECUTE FUNCTION closed_at_guard();
CREATE TRIGGER alerts_closed_at_guard BEFORE UPDATE ON alerts
    FOR EACH ROW WHEN (NEW.status = 'closed') EXECUTE FUNCTION closed_at_guard();
