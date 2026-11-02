-- Манифест коллекций RAG (ТЗ 5.12, 5.16: DM-30; задача 5.24 этапа 5,
-- ADR-0029, п. 5).
--
-- Продукт документы не индексирует и не хранит: индексатор заказчика
-- присылает список документов коллекции — ID, SHA-256 текста и размер.
-- Сервер хранит текущую и одну предыдущую версию манифеста и разницу между
-- ними; исключения документов администратором — отдельно. Содержимого
-- документов здесь нет.

-- Коллекция и её текущая версия. diff — разница текущей версии с
-- предыдущей: число новых, изменённых и пропавших документов и до 100 ID
-- каждого вида (для карточки коллекции).
CREATE TABLE rag_collections (
    id             uuid        PRIMARY KEY,
    org_id         uuid        NOT NULL REFERENCES organizations (id),
    slug           text        NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    version        integer     NOT NULL CHECK (version >= 1),
    documents      integer     NOT NULL CHECK (documents BETWEEN 0 AND 100000),
    size           bigint      NOT NULL CHECK (size >= 0),
    excluded       integer     NOT NULL CHECK (excluded BETWEEN 0 AND documents),
    loaded_at      timestamptz NOT NULL CHECK (isfinite(loaded_at)),
    loaded_by      text        NOT NULL CHECK (char_length(loaded_by) BETWEEN 1 AND 128),
    prev_loaded_at timestamptz CHECK (isfinite(prev_loaded_at)),
    diff           jsonb       NOT NULL CHECK (jsonb_typeof(diff) = 'object'),
    created_at     timestamptz NOT NULL,
    UNIQUE (org_id, slug),
    CHECK ((version = 1) = (prev_loaded_at IS NULL))
);

-- Документы версий манифеста: у коллекции хранятся текущая (version) и
-- предыдущая (version - 1) версии. excluded — индексатор не индексирует
-- документ: проверка до индексации вернула «исключить» (задача 5.25).
CREATE TABLE rag_documents (
    collection_id uuid    NOT NULL REFERENCES rag_collections (id) ON DELETE CASCADE,
    version       integer NOT NULL CHECK (version >= 1),
    doc_id        text    NOT NULL CHECK (octet_length(doc_id) BETWEEN 1 AND 512),
    sha256        bytea   NOT NULL CHECK (octet_length(sha256) = 32),
    size          bigint  NOT NULL CHECK (size BETWEEN 0 AND 1125899906842624),
    excluded      boolean NOT NULL,
    PRIMARY KEY (collection_id, version, doc_id)
);

-- Исключения документов администратором: по ID документа, действуют для
-- любой версии (и до появления документа в манифесте). Не больше 1000 на
-- коллекцию (проверяет сервис).
CREATE TABLE rag_exclusions (
    id            uuid        PRIMARY KEY,
    collection_id uuid        NOT NULL REFERENCES rag_collections (id) ON DELETE CASCADE,
    doc_id        text        NOT NULL CHECK (octet_length(doc_id) BETWEEN 1 AND 512),
    reason        text        NOT NULL CHECK (char_length(reason) <= 500),
    created_at    timestamptz NOT NULL,
    created_by    text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    UNIQUE (collection_id, doc_id)
);

REVOKE ALL ON rag_collections, rag_documents, rag_exclusions FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON rag_collections, rag_documents, rag_exclusions TO aisec_app;
