-- Признак «размещён у заказчика» у провайдера (ТЗ 5.2, judge.llm; задача
-- 5.28 этапа 5, ADR-0030, раздел 1). Оценщиком judge.llm может быть только
-- провайдер с этим признаком. Ставит его администратор безопасности
-- (providers.external) с повторной проверкой: текст запросов и ответов
-- начнёт уходить на этот адрес (DM-40). Признак «у заказчика» несовместим с
-- признаком «внешний» и сбрасывается при смене адресата провайдера.
-- Изменение строки providers меняет пакет конфигурации шлюзов (триггер
-- providers_revision_update, миграция 0030).
ALTER TABLE providers ADD COLUMN on_premise boolean NOT NULL DEFAULT false;
ALTER TABLE providers ADD CONSTRAINT providers_on_premise_internal CHECK (NOT (on_premise AND external));
ALTER TABLE providers ADD CONSTRAINT providers_on_premise_openai CHECK (NOT on_premise OR type = 'openai');
