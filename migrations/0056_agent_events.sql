-- События агентов (ТЗ 5.5, 5.10; задача 4.11 этапа 4, ADR-0023, раздел 7):
-- agent_tool_call — вызов инструмента через MCP-прокси шлюза или tool_calls
-- в ответе модели, agent_mcp — остальные методы MCP и нарушения протокола.
-- Подробности (агент, MCP-сервер, инструмент, хеш описания, подтверждение)
-- — в details.agent, без содержимого; аргументы и результат — в
-- event_content по режиму хранения, как у остальных событий. Ограничение
-- секционированной таблицы меняется на всех секциях сразу.

ALTER TABLE events DROP CONSTRAINT events_type_check;
ALTER TABLE events ADD CONSTRAINT events_type_check
    CHECK (type IN ('gateway_request', 'check', 'auth_failure', 'agent_tool_call', 'agent_mcp'));
