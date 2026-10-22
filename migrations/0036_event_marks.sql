-- Отметки аналитиков «ложное срабатывание» и «подтверждено» (ТЗ 5.5, 5.3;
-- решение Р8 этапа 3, задача 3.22). Событие неизменяемо (events_immutable),
-- поэтому отметка хранится отдельно: одна на событие, новая заменяет
-- прежнюю; история смен — в журнале аудита (events.mark_set,
-- events.mark_removed), запись — той же транзакцией. Содержимое запроса в
-- отметку не копируется: только значение, комментарий аналитика и автор.
-- Секции событий удаляются по сроку хранения (events_drop_expired); отметки
-- удалённых событий сервер удаляет в той же транзакции.

CREATE TABLE event_marks (
    event_id       uuid        NOT NULL,
    -- ts события (ключ секции): по нему отметка находит событие.
    event_ts       timestamptz NOT NULL CHECK (isfinite(event_ts)),
    org_id         uuid        NOT NULL REFERENCES organizations (id),
    mark           text        NOT NULL CHECK (mark IN ('false_positive', 'confirmed')),
    comment        text        NOT NULL DEFAULT '' CHECK (char_length(comment) <= 1000),
    marked_at      timestamptz NOT NULL CHECK (isfinite(marked_at)),
    marked_by      text        NOT NULL CHECK (char_length(marked_by) BETWEEN 1 AND 128),
    marked_by_name text        NOT NULL DEFAULT '' CHECK (char_length(marked_by_name) <= 128),
    PRIMARY KEY (event_id, event_ts)
);

-- Фильтр «mark» и доля ложных срабатываний по периоду.
CREATE INDEX event_marks_org_ts ON event_marks (org_id, event_ts);

GRANT SELECT, INSERT, UPDATE, DELETE ON event_marks TO aisec_app;
