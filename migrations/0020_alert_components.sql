-- Условия уведомлений «Состояния системы» по компоненту и пакет
-- конфигурации (ревью 2.r3b этапа 2, В16, В18, Н28).
--
-- ОЦЛ.5 ведётся отдельно для сервера (integrity:server) и каждого шлюза
-- (integrity:gateway:<ID>): одно общее условие не записывало второе
-- нарушение, пока первое не снято. ОЦЛ.3 — пакет конфигурации собран не
-- полностью (config_bundle) и шлюз дольше 10 минут на устаревшей версии
-- (config_bundle_lag:<ID>). ID шлюза — UUID; длина кода — до 128 символов.

ALTER TABLE system_alert_state DROP CONSTRAINT system_alert_state_condition_check;
ALTER TABLE system_alert_state ADD CONSTRAINT system_alert_state_condition_check
    CHECK (char_length(condition) <= 128 AND (
        condition IN ('time_sync', 'audit_storage', 'integrity', 'audit_chain', 'config_bundle', 'integrity:server')
        OR condition ~ '^(integrity:gateway|config_bundle_lag):[0-9a-f-]{1,64}$'));
