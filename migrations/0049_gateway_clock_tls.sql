-- Часы шлюза и действующий сертификат адреса приложений (3Н40, 3Н43 ревью
-- 3.r3 этапа 3, перенесено в этап 4, задача 4.5). Шлюз сообщает в heartbeat
-- свои часы и отпечаток сертификата, которым он отвечает приложениям;
-- сервер хранит расхождение часов и отпечаток последнего heartbeat.
-- «Состояние системы» ведёт по ним условия gateway_clock (расхождение
-- больше минуты, ВРМ.1) и gateway_tls (шлюз на актуальном пакете отвечает
-- не тем сертификатом, что загружен в консоли: ещё не действует по его
-- часам или истёк). NULL — шлюз прежней версии или остановлен.
ALTER TABLE gateways
    ADD COLUMN clock_skew_ms   bigint CHECK (abs(clock_skew_ms) <= 315360000000),
    ADD COLUMN tls_fingerprint text   CHECK (tls_fingerprint ~ '^([0-9a-f]{64})?$');

GRANT UPDATE (clock_skew_ms, tls_fingerprint) ON gateways TO aisec_app;

ALTER TABLE system_alert_state DROP CONSTRAINT system_alert_state_condition_check;
ALTER TABLE system_alert_state ADD CONSTRAINT system_alert_state_condition_check
    CHECK (char_length(condition) <= 128 AND (
        condition IN ('time_sync', 'audit_storage', 'integrity', 'audit_chain', 'config_bundle', 'integrity:server',
                      'test_build', 'ca_expiry', 'ca_expiry:critical',
                      'customer_cert_expiry', 'customer_cert_expiry:critical', 'alert_job_stale')
        OR condition ~ '^(integrity:gateway|config_bundle_lag|events_dropped|gateway_offline|cert_expiry|reports_stale|gateway_clock|gateway_tls):[0-9a-f-]{1,64}$'));
