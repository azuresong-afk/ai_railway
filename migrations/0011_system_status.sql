-- «Состояние системы» (ТЗ 7.5 РСБ.5, ОЦЛ.5, 7.8 ВРМ.1, 6.2 п. 12; задача 2.20).
--
-- 1. Итоги самотестирования и контроля целостности, которые шлюз сообщает в
--    heartbeat: только результат и счётчик, без путей и имён детекторов.
-- 2. Состояние условий для уведомлений раздела 7 (на этапе 2 — запись в
--    журнал аудита и поле на экране; доставка по каналам — этап 3). Запись
--    об изменении состояния пишется в аудит в той же транзакции, поэтому
--    повторный опрос и перезапуск сервера не плодят дубликатов.

ALTER TABLE gateways
    ADD COLUMN selftest_ok         boolean,
    ADD COLUMN selftest_at         timestamptz,
    ADD COLUMN selftest_failed     integer CHECK (selftest_failed BETWEEN 0 AND 1000),
    ADD COLUMN integrity_ok        boolean,
    ADD COLUMN integrity_at        timestamptz,
    ADD COLUMN integrity_reason    text    CHECK (integrity_reason IN ('ok', 'manifest_missing', 'manifest_invalid',
                                                'signature_invalid', 'files_mismatch')),
    ADD COLUMN integrity_failed    integer CHECK (integrity_failed BETWEEN 0 AND 1000),
    ADD CONSTRAINT gateways_selftest_all_or_none CHECK (
        (selftest_ok IS NULL) = (selftest_at IS NULL) AND (selftest_ok IS NULL) = (selftest_failed IS NULL)),
    ADD CONSTRAINT gateways_integrity_all_or_none CHECK (
        (integrity_ok IS NULL) = (integrity_at IS NULL) AND (integrity_ok IS NULL) = (integrity_reason IS NULL)
        AND (integrity_ok IS NULL) = (integrity_failed IS NULL));

GRANT UPDATE (selftest_ok, selftest_at, selftest_failed, integrity_ok, integrity_at, integrity_reason, integrity_failed)
    ON gateways TO aisec_app;

CREATE TABLE system_alert_state (
    org_id     uuid        NOT NULL REFERENCES organizations (id),
    condition  text        NOT NULL CHECK (condition IN ('time_sync', 'audit_storage', 'integrity')),
    active     boolean     NOT NULL,
    -- Когда условие возникло (для active) или когда снято.
    since      timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, condition)
);

REVOKE ALL ON system_alert_state FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON system_alert_state TO aisec_app;
