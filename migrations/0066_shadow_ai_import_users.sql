-- Теневой ИИ: число пользователей импорта и новых для организации (4В27
-- ревью 4.r3 этапа 4, ADR-0027, п. 6).
--
-- Импорт журнала, где каждому подобранному логину отведён свой час, даёт
-- таблицу «логин → псевдоним» (оракул псевдонимов). Закрыть это нельзя, не
-- сломав сопоставление с событиями шлюза, поэтому перебор обнаруживается:
-- users — разных псевдонимов в файле, new_users — псевдонимов, которых не
-- было в сводках организации (у первого импорта с пользователями — все,
-- baseline: исходный состав). Сумма new_users организации за сутки —
-- основание встроенного правила security.shadow_ai_alias_probe; её
-- считает индекс shadow_ai_imports_created.

ALTER TABLE shadow_ai_imports
    ADD COLUMN users     bigint  NOT NULL DEFAULT 0 CHECK (users >= 0),
    ADD COLUMN new_users bigint  NOT NULL DEFAULT 0 CHECK (new_users >= 0 AND new_users <= users),
    ADD COLUMN baseline  boolean NOT NULL DEFAULT false;
