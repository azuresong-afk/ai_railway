-- Получатели рассылки отчётов — пользователи консоли (решение владельца по
-- пилоту, задача 4.6 этапа 4). Расписание хранит идентификаторы
-- пользователей; адрес берётся из учётной записи (users.email, миграция
-- 0057) в момент отправки, поэтому смена или удаление адреса действует сразу.
-- Это дополнение к получателям почтового канала.
--
-- В журнале рассылки остаётся только число пропущенных получателей без
-- адреса: подсказка консоли «у N получателей нет e-mail». Адреса в журнал
-- доставки не пишутся (персональные данные).

ALTER TABLE report_schedules
    ADD COLUMN recipient_user_ids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(recipient_user_ids) <= 20);

ALTER TABLE report_runs
    ADD COLUMN skipped_no_email integer NOT NULL DEFAULT 0 CHECK (skipped_no_email BETWEEN 0 AND 20);

GRANT UPDATE (recipient_user_ids) ON report_schedules TO aisec_app;
GRANT UPDATE (skipped_no_email) ON report_runs TO aisec_app;
