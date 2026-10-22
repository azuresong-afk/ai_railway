-- Проверка шлюзов по команде из консоли (Н38 ревью 2.r4, ОЦЛ.2): время
-- запроса. Сервер передаёт признак verify_requested в ответе heartbeat,
-- шлюз проверяет целостность и присылает итог; итог не раньше запроса
-- снимает отметку и пишется в журнал аудита.
ALTER TABLE gateways ADD COLUMN verify_requested_at timestamptz CHECK (isfinite(verify_requested_at));

GRANT UPDATE (verify_requested_at) ON gateways TO aisec_app;
