-- Сертификат заказчика для адреса шлюза (S1, ТЗ 5.4; решение Р9 этапа 3,
-- задача 3.27). Одна запись на организацию: адрес приложений у всех шлюзов
-- установки общий. Цепочка — открытые данные (лист, промежуточные, корень
-- в PEM, проверены при загрузке), закрытый ключ — шифротекст ключа данных
-- с AAD gateway_tls|key|<org_id> (ЗИ.1, ADR-0007); перешифровывается при
-- ротации ключа данных (aisec-cli keys rotate-data). Сведения о
-- сертификате хранятся столбцами, чтобы консоль и «Состояние системы» не
-- разбирали цепочку и не трогали ключ.

CREATE TABLE gateway_tls (
    org_id       uuid        PRIMARY KEY REFERENCES organizations (id),
    -- Имя адреса шлюза для приложений: DNS-имя или IP-адрес из SAN листа.
    host         text        NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253 AND host = lower(host)),
    chain_pem    text        NOT NULL CHECK (octet_length(chain_pem) BETWEEN 1 AND 65536),
    chain_len    integer     NOT NULL CHECK (chain_len BETWEEN 1 AND 10),
    subject      text        NOT NULL CHECK (char_length(subject) <= 2048),
    issuer       text        NOT NULL CHECK (char_length(issuer) <= 2048),
    serial       text        NOT NULL CHECK (serial ~ '^[0-9a-f]{1,64}$'),
    -- SHA-256 листового сертификата в DER.
    fingerprint  text        NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    not_before   timestamptz NOT NULL CHECK (isfinite(not_before)),
    -- Самый ранний срок сертификатов цепочки.
    not_after    timestamptz NOT NULL CHECK (isfinite(not_after) AND not_after > not_before),
    dns_names    text[]      NOT NULL CHECK (cardinality(dns_names) <= 1000),
    ip_addresses text[]      NOT NULL CHECK (cardinality(ip_addresses) <= 1000),
    -- Алгоритм ключа сертификата: «RSA 2048», «ECDSA P-256»…
    cert_key_alg text        NOT NULL CHECK (char_length(cert_key_alg) BETWEEN 1 AND 32),
    key_sealed   bytea       NOT NULL CHECK (octet_length(key_sealed) BETWEEN 16 AND 20480),
    key_key_id   uuid        NOT NULL REFERENCES data_keys (id),
    key_alg      text        NOT NULL CHECK (char_length(key_alg) BETWEEN 1 AND 64),
    created_at   timestamptz NOT NULL,
    created_by   text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    updated_at   timestamptz NOT NULL,
    updated_by   text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128)
);

CREATE INDEX gateway_tls_key ON gateway_tls (key_key_id);

-- Сертификат входит в пакет конфигурации шлюзов (раздел gateway_tls):
-- его загрузка, замена и удаление увеличивают счётчик изменений
-- (миграция 0030), и шлюзы получают новый пакет.
CREATE TRIGGER gateway_tls_revision AFTER INSERT OR DELETE ON gateway_tls
    FOR EACH ROW EXECUTE FUNCTION config_revision_bump();
CREATE TRIGGER gateway_tls_revision_update AFTER UPDATE ON gateway_tls
    FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION config_revision_bump();

REVOKE ALL ON gateway_tls FROM PUBLIC;
-- UPDATE — всё, кроме организации и сведений о первой загрузке.
GRANT SELECT, INSERT, DELETE ON gateway_tls TO aisec_app;
GRANT UPDATE (host, chain_pem, chain_len, subject, issuer, serial, fingerprint, not_before, not_after, dns_names,
    ip_addresses, cert_key_alg, key_sealed, key_key_id, key_alg, updated_at, updated_by) ON gateway_tls TO aisec_app;

-- Срок сертификата заказчика (ЗИ.4, DM-44): условия customer_cert_expiry
-- (за 30 суток) и customer_cert_expiry:critical (за 7 суток) в «Состоянии
-- системы». Отдельное семейство: коды cert_expiry:<ID> относятся к шлюзам
-- и снимаются, когда шлюза нет в реестре.
ALTER TABLE system_alert_state DROP CONSTRAINT system_alert_state_condition_check;
ALTER TABLE system_alert_state ADD CONSTRAINT system_alert_state_condition_check
    CHECK (char_length(condition) <= 128 AND (
        condition IN ('time_sync', 'audit_storage', 'integrity', 'audit_chain', 'config_bundle', 'integrity:server',
                      'test_build', 'ca_expiry', 'ca_expiry:critical',
                      'customer_cert_expiry', 'customer_cert_expiry:critical')
        OR condition ~ '^(integrity:gateway|config_bundle_lag|events_dropped|gateway_offline|cert_expiry|reports_stale):[0-9a-f-]{1,64}$'));
