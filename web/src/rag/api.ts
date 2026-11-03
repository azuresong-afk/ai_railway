import { request } from "../api/client";
import type { components } from "../api/schema";

type S = components["schemas"];
export type Collection = S["RAGCollection"];
export type CollectionList = S["RAGCollectionList"];
export type CollectionCard = S["RAGCollectionCard"];
export type Exclusion = S["RAGExclusion"];
export type Diff = S["RAGDiff"];
export type Document = S["RAGDocument"];

export const documentPageSize = 200;
const id = encodeURIComponent;

export const ragApi = {
  collections: (signal?: AbortSignal) => request<CollectionList>("GET", "/api/v1/rag/collections", undefined, signal),
  collection: (slug: string, signal?: AbortSignal) => request<CollectionCard>("GET", `/api/v1/rag/collections/${id(slug)}`, undefined, signal),
  documents: (slug: string, after: string | undefined, signal?: AbortSignal) => {
    const p = new URLSearchParams({ limit: String(documentPageSize) });
    if (after) p.set("after", after);
    return request<S["RAGDocumentPage"]>("GET", `/api/v1/rag/collections/${id(slug)}/manifest?${p}`, undefined, signal);
  },
  exclude: (slug: string, b: S["NewRAGExclusion"]) => request<Exclusion>("POST", `/api/v1/rag/collections/${id(slug)}/exclusions`, b),
  // Снятие исключения — ослабление защиты: только в сессии консоли, право безопасности rag.unexclude.
  unexclude: (slug: string, exclusionId: string) => request<void>("DELETE", `/api/v1/rag/collections/${id(slug)}/exclusions/${id(exclusionId)}`),
};
