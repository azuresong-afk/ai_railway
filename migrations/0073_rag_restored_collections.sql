-- Коллекция RAG без манифеста (ревью 5.r2 этапа 5, 5Н15; ADR-0017,
-- дополнение; ADR-0029, п. 5).
--
-- Исключения документов администратором входят в резервную копию
-- конфигурации, манифесты — нет (их пришлёт индексатор). При восстановлении
-- коллекция, которой в установке нет, создаётся с версией 0: манифест ещё не
-- загружен, документов нет, исключения уже действуют. Первая загрузка
-- манифеста делает версию 1 без разницы с предыдущей.
ALTER TABLE rag_collections DROP CONSTRAINT rag_collections_version_check;
ALTER TABLE rag_collections ADD CONSTRAINT rag_collections_version_check CHECK (version >= 0);
-- Предыдущей версии нет у версий 0 и 1.
ALTER TABLE rag_collections DROP CONSTRAINT rag_collections_check1;
ALTER TABLE rag_collections ADD CONSTRAINT rag_collections_prev_check CHECK ((version <= 1) = (prev_loaded_at IS NULL));
-- У версии 0 документов нет.
ALTER TABLE rag_collections ADD CONSTRAINT rag_collections_empty_check CHECK (version > 0 OR documents = 0);
