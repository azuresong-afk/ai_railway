-- Передача журнала аудита в SIEM (РСБ.6; ТЗ 5.6, 7; ADR-0020 п. 15;
-- задача 3.14 этапа 3) каналом syslog или webhook (общий формат JSON).

-- Подписка канала на журнал аудита. Снятие подписки — ослабление (DM-40).
ALTER TABLE notify_channels ADD COLUMN audit_stream boolean NOT NULL DEFAULT false;
ALTER TABLE notify_channels ADD CONSTRAINT notify_channels_audit_stream_type
    CHECK (NOT audit_stream OR type = 'syslog' OR (type = 'webhook' AND settings->>'format' = 'generic'));
GRANT UPDATE (audit_stream) ON notify_channels TO aisec_app;

-- Курсор передачи: последняя переданная запись журнала (seq). Источник
-- истины — сам журнал: курсор только указывает, откуда продолжить, поэтому
-- при недоступности приёмника записи не теряются. Повторы бессрочны с
-- задержкой до 10 минут; ошибка — код без текста ответа приёмника.
CREATE TABLE audit_stream_cursors (
    channel_id uuid        PRIMARY KEY REFERENCES notify_channels (id),
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    last_seq   bigint      NOT NULL CHECK (last_seq >= 0),
    attempts   integer     NOT NULL CHECK (attempts BETWEEN 0 AND 1000000),
    next_at    timestamptz NOT NULL,
    error      text        NOT NULL CHECK (error ~ '^[a-z0-9_]{0,40}$'),
    -- Условие отставания DM-44 возникло и записано в аудит (system.alert).
    lag_raised boolean     NOT NULL,
    sent_at    timestamptz,
    updated_at timestamptz NOT NULL
);

REVOKE ALL ON audit_stream_cursors FROM PUBLIC;
GRANT SELECT, INSERT ON audit_stream_cursors TO aisec_app;
GRANT UPDATE (last_seq, attempts, next_at, error, lag_raised, sent_at, updated_at) ON audit_stream_cursors TO aisec_app;
