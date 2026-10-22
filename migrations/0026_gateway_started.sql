-- Запуск и остановка шлюзов в журнале аудита (В27 ревью 2.r5, РСБ.2):
-- время запуска процесса шлюза из heartbeat. Новое время — запись
-- component.start, heartbeat остановки с тем же временем — component.stop
-- и NULL.
ALTER TABLE gateways ADD COLUMN started_at timestamptz CHECK (isfinite(started_at));

GRANT UPDATE (started_at) ON gateways TO aisec_app;
