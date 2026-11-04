-- «Состояние системы» (ЗИ.6, ЗИ.7, РСБ.7, ОЦЛ.5): условия этапов 4 и 5 в
-- ограничении system_alert_state (5В5 ревью 5.r4 этапа 5, дефект 5.49-1).
--
-- Последний раз список обновляла миграция 0064. Условия, добавленные позже,
-- база отвергала: состояние уведомления не сохранялось, и оповещение о сбое
-- функции безопасности терялось или повторялось на каждой проверке.
--   shadow_ai_storage, shadow_ai_full — хранилище сводок теневого ИИ (4Н25);
--   gateway_limits:<ID шлюза> — вытеснение счётчиков лимитов (5.9);
--   gateway_media_overloaded, gateway_media_unavailable,
--   gateway_media_selftest:<ID шлюза> — анализатор изображений (5.44);
--   service_db_previous, service_db_unused:<вид базы> — служебные базы
--   (5.9, ADR-0028; вид — как в service_dbs.kind).
-- Список в коде (internal/sysstatus) сверяет с этим ограничением тест
-- TestStoredConditionsMatchCheck: новое условие без новой миграции не
-- пройдёт сборку.

ALTER TABLE system_alert_state DROP CONSTRAINT system_alert_state_condition_check;
ALTER TABLE system_alert_state ADD CONSTRAINT system_alert_state_condition_check
    CHECK (char_length(condition) <= 128 AND (
        condition IN ('time_sync', 'audit_storage', 'integrity', 'audit_chain', 'config_bundle', 'integrity:server',
                      'test_build', 'ca_expiry', 'ca_expiry:critical',
                      'customer_cert_expiry', 'customer_cert_expiry:critical', 'alert_job_stale',
                      'license_expiry', 'license_expiry:critical', 'license_grace', 'license_restricted',
                      'license_invalid', 'license_clock', 'quota_approximate',
                      'shadow_ai_storage', 'shadow_ai_full')
        OR condition ~ '^(integrity:gateway|config_bundle_lag|events_dropped|gateway_offline|cert_expiry|reports_stale|gateway_clock|gateway_tls|quota_autonomous|gateway_limits|gateway_media_overloaded|gateway_media_unavailable|gateway_media_selftest):[0-9a-f-]{1,64}$'
        OR condition ~ '^(service_db_previous|service_db_unused):[a-z0-9_]{1,64}$'));
