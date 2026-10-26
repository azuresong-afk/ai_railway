-- Расписания рассылки отчётов и журнал рассылки (ТЗ 5.8, Р6; задача 3.25
-- этапа 3). Содержимого отчётов здесь нет: отчёт строится при отправке из
-- агрегатов, а в журнале остаются период, число попыток и код ошибки.

CREATE TABLE report_schedules (
    id            uuid        PRIMARY KEY,
    org_id        uuid        NOT NULL REFERENCES organizations (id),
    name          text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    report        text        NOT NULL CHECK (report IN ('summary', 'incidents', 'pilot')),
    frequency     text        NOT NULL CHECK (frequency IN ('daily', 'weekly', 'monthly')),
    -- День недели (1 — понедельник … 7 — воскресенье) и день месяца: ровно
    -- тот, что нужен периодичности; 29–31 числа есть не в каждом месяце.
    weekday       smallint    CHECK (weekday BETWEEN 1 AND 7),
    day           smallint    CHECK (day BETWEEN 1 AND 28),
    -- Время суток в часовом поясе установки (install_settings.timezone).
    at_time       text        NOT NULL CHECK (at_time ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
    format        text        NOT NULL CHECK (format IN ('html', 'xlsx')),
    -- Почтовый канал (миграция 0033): сервер SMTP и получатели. Каналы не
    -- удаляются, ссылка остаётся действительной.
    channel_id    uuid        NOT NULL REFERENCES notify_channels (id),
    enabled       boolean     NOT NULL,
    next_run_at   timestamptz NOT NULL CHECK (isfinite(next_run_at)),
    last_run_at   timestamptz,
    version       integer     NOT NULL CHECK (version >= 1),
    created_at    timestamptz NOT NULL,
    created_by    text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at    timestamptz NOT NULL,
    updated_by    text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    UNIQUE (org_id, name),
    CHECK ((frequency = 'weekly') = (weekday IS NOT NULL)),
    CHECK ((frequency = 'monthly') = (day IS NOT NULL))
);

CREATE INDEX report_schedules_due ON report_schedules (next_run_at) WHERE enabled;
CREATE INDEX report_schedules_channel ON report_schedules (channel_id);

-- Журнал рассылки и очередь повторов: ошибка — код без текста ответа сервера.
CREATE TABLE report_runs (
    id           uuid        PRIMARY KEY,
    org_id       uuid        NOT NULL REFERENCES organizations (id),
    schedule_id  uuid        NOT NULL REFERENCES report_schedules (id) ON DELETE CASCADE,
    -- Запуск расписания, который породил рассылку, и дни отчёта.
    due_at       timestamptz NOT NULL,
    period_first date        NOT NULL,
    period_last  date        NOT NULL CHECK (period_last >= period_first),
    status       text        NOT NULL CHECK (status IN ('pending', 'sent', 'failed')),
    attempts     integer     NOT NULL CHECK (attempts BETWEEN 0 AND 5),
    next_at      timestamptz NOT NULL,
    error        text        NOT NULL CHECK (error ~ '^[a-z0-9_]{0,40}$'),
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    sent_at      timestamptz,
    CHECK ((status = 'sent') = (sent_at IS NOT NULL))
);

CREATE INDEX report_runs_due ON report_runs (next_at) WHERE status = 'pending';
CREATE INDEX report_runs_schedule ON report_runs (schedule_id, created_at DESC, id DESC);

REVOKE ALL ON report_schedules, report_runs FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON report_schedules, report_runs TO aisec_app;
GRANT UPDATE (name, report, frequency, weekday, day, at_time, format, channel_id, enabled, next_run_at, last_run_at, version,
    updated_at, updated_by) ON report_schedules TO aisec_app;
GRANT UPDATE (status, attempts, next_at, error, updated_at, sent_at) ON report_runs TO aisec_app;
