-- Исправления по ревью 2.r1 (замечания В1 и В2).
--
-- 1. Опора цепочки журнала аудита вне БД (В2): проверка цепочки сервером
--    хранит имитовставку головы (номер и хеш последней проверенной записи)
--    на ключе, выведенном из ключа данных (keyring, назначение audit-head).
--    Ключ данных расшифровывается мастер-ключом из файла, поэтому владелец
--    таблиц не может подделать имитовставку после переписывания журнала и
--    пересчёта цепочки. Строки без имитовставки (aisec-cli без каталога
--    ключей, проверки до этой миграции) как опора не используются.
-- 2. Уведомление о нарушении цепочки в «Состоянии системы» (В1, РСБ.4).

ALTER TABLE audit_verifications
    ADD COLUMN head_mac    bytea CHECK (octet_length(head_mac) BETWEEN 16 AND 64),
    ADD COLUMN mac_key_id  uuid,
    ADD CONSTRAINT audit_verifications_mac_all_or_none CHECK ((head_mac IS NULL) = (mac_key_id IS NULL)),
    ADD CONSTRAINT audit_verifications_mac_needs_head CHECK (head_mac IS NULL OR last_hash IS NOT NULL);

ALTER TABLE system_alert_state DROP CONSTRAINT system_alert_state_condition_check;
ALTER TABLE system_alert_state ADD CONSTRAINT system_alert_state_condition_check
    CHECK (condition IN ('time_sync', 'audit_storage', 'integrity', 'audit_chain'));
