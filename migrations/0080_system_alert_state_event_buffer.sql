-- «Состояние системы» (РСБ.7, DM-44): условие буфера событий шлюза на диске
-- в ограничении system_alert_state (задача 6.31 этапа 6, ADR-0037).
--
--   gateway_event_buffer:<ID шлюза> — буфер заполнен на 80 % и больше или
--   за 15 минут росли повреждённые записи и ошибки записи на диск.
-- Список в коде (internal/sysstatus) сверяет с этим ограничением тест
-- TestStoredConditionsMatchCheck.

ALTER TABLE system_alert_state DROP CONSTRAINT system_alert_state_condition_check;
ALTER TABLE system_alert_state ADD CONSTRAINT system_alert_state_condition_check
    CHECK (char_length(condition) <= 128 AND (
        condition IN ('time_sync', 'audit_storage', 'integrity', 'audit_chain', 'config_bundle', 'integrity:server',
                      'test_build', 'ca_expiry', 'ca_expiry:critical',
                      'customer_cert_expiry', 'customer_cert_expiry:critical', 'alert_job_stale',
                      'license_expiry', 'license_expiry:critical', 'license_grace', 'license_restricted',
                      'license_invalid', 'license_clock', 'quota_approximate',
                      'shadow_ai_storage', 'shadow_ai_full')
        OR condition ~ '^(integrity:gateway|config_bundle_lag|events_dropped|gateway_offline|cert_expiry|reports_stale|gateway_clock|gateway_tls|quota_autonomous|gateway_limits|gateway_media_overloaded|gateway_media_unavailable|gateway_media_selftest|gateway_event_buffer):[0-9a-f-]{1,64}$'
        OR condition ~ '^(service_db_previous|service_db_unused):[a-z0-9_]{1,64}$'));
