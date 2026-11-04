-- Расписания запусков тестирования устойчивости (ТЗ 5.13; задача 5.33
-- этапа 5, ADR-0031, дополнение 5.33).
--
-- Расписание запускает уже заведённую цель: ежедневно, еженедельно или
-- ежемесячно (чаще раза в сутки не бывает), время — в часовом поясе
-- установки. Секретов в таблице нет: цель с секретным заголовком по
-- расписанию не запускается — значение заголовка в продукте не хранится.
-- Ключи пакета шлюзов расписание не трогает: ключ выпускает запуск.

CREATE TABLE redteam_schedules (
    id          uuid        PRIMARY KEY,
    org_id      uuid        NOT NULL REFERENCES organizations (id),
    name        text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    -- Удаление цели удаляет её расписания (запись аудита цели перечисляет их).
    target_id   uuid        NOT NULL REFERENCES redteam_targets (id) ON DELETE CASCADE,
    frequency   text        NOT NULL CHECK (frequency IN ('daily', 'weekly', 'monthly')),
    weekday     integer     NOT NULL CHECK (weekday BETWEEN 0 AND 7),
    day         integer     NOT NULL CHECK (day BETWEEN 0 AND 28),
    at_time     text        NOT NULL CHECK (at_time ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
    -- Отбор сценариев запуска (как в POST /redteam/runs): строки матрицы и язык.
    threats     jsonb       NOT NULL CHECK (jsonb_typeof(threats) = 'array' AND jsonb_array_length(threats) <= 64),
    lang        text        NOT NULL CHECK (lang IN ('', 'ru', 'en')),
    enabled     boolean     NOT NULL,
    next_run_at timestamptz NOT NULL,
    -- Плановое время последней попытки, её итог и запуск; retries — повторы
    -- запуска, который застал занятую цель или сервер.
    last_run_at timestamptz,
    last_run_id uuid        REFERENCES redteam_runs (id) ON DELETE SET NULL,
    last_status text        NOT NULL CHECK (char_length(last_status) <= 32),
    retries     integer     NOT NULL CHECK (retries BETWEEN 0 AND 100),
    version     integer     NOT NULL CHECK (version >= 1),
    created_at  timestamptz NOT NULL,
    created_by  text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at  timestamptz NOT NULL,
    updated_by  text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    CHECK ((frequency = 'weekly') = (weekday BETWEEN 1 AND 7)),
    CHECK ((frequency = 'monthly') = (day BETWEEN 1 AND 28))
);
CREATE INDEX redteam_schedules_org ON redteam_schedules (org_id, name, id);
CREATE INDEX redteam_schedules_due ON redteam_schedules (org_id, next_run_at) WHERE enabled;
CREATE INDEX redteam_schedules_target ON redteam_schedules (target_id);

REVOKE ALL ON redteam_schedules FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON redteam_schedules TO aisec_app;
