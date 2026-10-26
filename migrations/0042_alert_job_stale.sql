-- Остановка фоновой задачи правил оповещений (3В17 ревью 3.r2 этапа 3,
-- DM-44): условие alert_job_stale в «Состоянии системы» — отметка прохода
-- alert_job_runs старше 5 минут при работающем сервере. Условие ведёт
-- sysstatus вне транзакции прохода, оповещение поднимает правило
-- system.alert_job.
ALTER TABLE system_alert_state DROP CONSTRAINT system_alert_state_condition_check;
ALTER TABLE system_alert_state ADD CONSTRAINT system_alert_state_condition_check
    CHECK (char_length(condition) <= 128 AND (
        condition IN ('time_sync', 'audit_storage', 'integrity', 'audit_chain', 'config_bundle', 'integrity:server',
                      'test_build', 'ca_expiry', 'ca_expiry:critical',
                      'customer_cert_expiry', 'customer_cert_expiry:critical', 'alert_job_stale')
        OR condition ~ '^(integrity:gateway|config_bundle_lag|events_dropped|gateway_offline|cert_expiry|reports_stale):[0-9a-f-]{1,64}$'));
