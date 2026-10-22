-- Роли и БД установки пилота (ADR-0019). Выполняет официальный образ
-- PostgreSQL один раз — при первом запуске на пустом каталоге данных.
--
-- aisec_owner — владелец схемы: aisec-cli migrate, init, аварийные команды;
--   член aisec_audit_archiver для aisec-cli audit archive (ADR-0008).
-- aisec_server — вход сервера управления, член aisec_app: журнал аудита
--   только добавляется, таблицы ему не принадлежат.
-- Роли без входа aisec_app и aisec_audit_archiver создаёт и миграция 0002
-- (IF NOT EXISTS); здесь они нужны раньше — для членства.
--
-- Пароли читаются из секретов compose и в вывод не попадают; текст команды
-- с паролем не пишется в журнал СУБД даже при ошибке.
\set ON_ERROR_STOP on
SET log_min_error_statement = panic;
SET log_statement = none;
\set owner_password `cat /run/secrets/db-owner-password`
\set server_password `cat /run/secrets/db-server-password`

CREATE ROLE aisec_app NOLOGIN;
CREATE ROLE aisec_audit_archiver NOLOGIN;
CREATE ROLE aisec_owner LOGIN PASSWORD :'owner_password' IN ROLE aisec_audit_archiver;
CREATE ROLE aisec_server LOGIN PASSWORD :'server_password' IN ROLE aisec_app;

CREATE DATABASE aisec OWNER aisec_owner;
REVOKE ALL ON DATABASE aisec FROM PUBLIC;
GRANT CONNECT ON DATABASE aisec TO aisec_app;
