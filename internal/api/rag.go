package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/rag"
)

// ragRoutes — манифесты коллекций RAG (ТЗ 5.12, DM-30; задача 5.24 этапа 5,
// ADR-0029, п. 5): загрузка манифеста индексатором (токен с rag.manage),
// версии и разница с предыдущей, документы с хешами, исключения
// документов администратором. Снятие исключения — ослабление защиты:
// только из консоли. Изменения пишутся в аудит сервисом той же транзакцией.
func ragRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/rag/collections", Permission: auth.PermRAGRead, Handler: needRAG(d, d.listRAGCollections)},
		{Method: http.MethodGet, Path: "/api/v1/rag/collections/{slug}", Permission: auth.PermRAGRead, Handler: needRAG(d, d.getRAGCollection)},
		{Method: http.MethodGet, Path: "/api/v1/rag/collections/{slug}/manifest", Permission: auth.PermRAGRead,
			Handler: needRAG(d, d.getRAGManifest)},
		{Method: http.MethodPut, Path: "/api/v1/rag/collections/{slug}/manifest", Permission: auth.PermRAGManage, MaxBody: rag.MaxBody,
			Handler: needRAG(d, d.putRAGManifest)},
		{Method: http.MethodPost, Path: "/api/v1/rag/collections/{slug}/exclusions", Permission: auth.PermRAGManage,
			MaxBody: rag.MaxExclusionBody, Handler: needRAG(d, d.addRAGExclusion)},
		{Method: http.MethodDelete, Path: "/api/v1/rag/collections/{slug}/exclusions/{id}", Permission: auth.PermRAGManage,
			SessionOnly: true, Handler: needRAG(d, d.removeRAGExclusion)},
	}
}

func needRAG(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.RAG == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Манифесты коллекций RAG не подключены на сервере."))
			return
		}
		h(w, r)
	}
}

const ragCollectionNotFound = "Коллекция RAG не найдена."

// ragProblem переводит ошибки манифестов RAG. Неизвестная ошибка — 500,
// причина — в техническом журнале.
func ragProblem(logger *slog.Logger, err error) *Problem {
	var ie *rag.InputError
	switch {
	case errors.As(err, &ie):
		fields := make([]FieldError, 0, len(ie.Errs))
		for _, e := range ie.Errs {
			f := ""
			if m := fieldRe.FindStringSubmatch(e.Error()); m != nil {
				f = m[1]
			}
			fields = append(fields, FieldError{Field: f, Detail: e.Error()})
		}
		return Invalid("Проверьте данные манифеста.", fields...)
	case errors.Is(err, rag.ErrNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, ragCollectionNotFound)
	case errors.Is(err, rag.ErrExclusionNotFound):
		return NewProblem(http.StatusNotFound, CodeNotFound, "Исключение не найдено.")
	case errors.Is(err, rag.ErrExists):
		return NewProblem(http.StatusConflict, CodeConflict, "Документ уже исключён из индекса.")
	case errors.Is(err, rag.ErrTooManyCollections):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"Коллекций RAG уже "+strconv.Itoa(rag.MaxCollections)+": новая коллекция не создаётся.")
	case errors.Is(err, rag.ErrTooManyExclusions):
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
			"В коллекции уже "+strconv.Itoa(rag.MaxExclusions)+" исключений: снимите ненужные.")
	}
	logger.Error("RAG: ошибка обработки запроса", "error", err)
	return errInternal()
}

func (d Deps) ragBy(r *http.Request) (rag.By, bool) {
	a, ok := actorOf(r)
	if !ok {
		return rag.By{}, false
	}
	return rag.By{Actor: a.Actor, IP: a.IP}, true
}

// pathSlug — ID коллекции из пути; неверный — 404, как отсутствующий.
func pathSlug(w http.ResponseWriter, r *http.Request) (string, bool) {
	s := r.PathValue("slug")
	if !rag.ValidSlug(s) {
		WriteProblem(w, NewProblem(http.StatusNotFound, CodeNotFound, ragCollectionNotFound))
		return "", false
	}
	return s, true
}

// RAGDiffView — разница версии манифеста с предыдущей.
type RAGDiffView struct {
	Added      int      `json:"added"`
	Changed    int      `json:"changed"`
	Removed    int      `json:"removed"`
	AddedIDs   []string `json:"added_ids"`
	ChangedIDs []string `json:"changed_ids"`
	RemovedIDs []string `json:"removed_ids"`
}

// RAGCollectionView — коллекция в списке.
type RAGCollectionView struct {
	Slug         string      `json:"slug"`
	Version      int         `json:"version"`
	Documents    int         `json:"documents"`
	Size         int64       `json:"size"`
	Excluded     int         `json:"excluded"`
	Exclusions   int         `json:"exclusions"`
	LoadedAt     time.Time   `json:"loaded_at"`
	LoadedBy     string      `json:"loaded_by"`
	PrevLoadedAt *time.Time  `json:"prev_loaded_at,omitempty"`
	Diff         RAGDiffView `json:"diff"`
	CreatedAt    time.Time   `json:"created_at"`
}

// RAGExclusionView — исключение документа администратором.
type RAGExclusionView struct {
	ID         string    `json:"id"`
	DocumentID string    `json:"document_id"`
	Reason     string    `json:"reason"`
	CreatedAt  time.Time `json:"created_at"`
	CreatedBy  string    `json:"created_by"`
}

// RAGCollectionCard — карточка коллекции с исключениями.
type RAGCollectionCard struct {
	RAGCollectionView
	ExclusionList []RAGExclusionView `json:"exclusion_list"`
}

// RAGLimits — пределы манифеста.
type RAGLimits struct {
	Collections   int   `json:"collections"`
	Documents     int   `json:"documents"`
	BodyBytes     int64 `json:"body_bytes"`
	DocumentID    int   `json:"document_id_bytes"`
	Exclusions    int   `json:"exclusions"`
	DiffSampleIDs int   `json:"diff_sample_ids"`
}

// RAGCollectionList — ответ GET /api/v1/rag/collections.
type RAGCollectionList struct {
	Items  []RAGCollectionView `json:"items"`
	Limits RAGLimits           `json:"limits"`
}

func ragCollectionView(c rag.Collection) RAGCollectionView {
	return RAGCollectionView{Slug: c.Slug, Version: c.Version, Documents: c.Documents, Size: c.Size, Excluded: c.Excluded,
		Exclusions: c.ExclusionCount, LoadedAt: c.LoadedAt.UTC(), LoadedBy: c.LoadedBy, PrevLoadedAt: c.PrevLoadedAt,
		Diff: RAGDiffView{Added: c.Diff.Added, Changed: c.Diff.Changed, Removed: c.Diff.Removed, AddedIDs: nonNil(c.Diff.AddedIDs),
			ChangedIDs: nonNil(c.Diff.ChangedIDs), RemovedIDs: nonNil(c.Diff.RemovedIDs)},
		CreatedAt: c.CreatedAt.UTC()}
}

func (d Deps) listRAGCollections(w http.ResponseWriter, r *http.Request) {
	cs, err := d.RAG.Collections(r.Context())
	if err != nil {
		WriteProblem(w, ragProblem(d.Logger, err))
		return
	}
	v := RAGCollectionList{Items: make([]RAGCollectionView, 0, len(cs)), Limits: RAGLimits{Collections: rag.MaxCollections,
		Documents: rag.MaxDocuments, BodyBytes: rag.MaxBody, DocumentID: rag.MaxDocumentID, Exclusions: rag.MaxExclusions,
		DiffSampleIDs: rag.MaxDiffSample}}
	for _, c := range cs {
		v.Items = append(v.Items, ragCollectionView(c))
	}
	WriteJSON(w, http.StatusOK, v)
}

func (d Deps) getRAGCollection(w http.ResponseWriter, r *http.Request) {
	slug, ok := pathSlug(w, r)
	if !ok {
		return
	}
	c, err := d.RAG.Collection(r.Context(), slug)
	if err != nil {
		WriteProblem(w, ragProblem(d.Logger, err))
		return
	}
	card := RAGCollectionCard{RAGCollectionView: ragCollectionView(c), ExclusionList: make([]RAGExclusionView, 0, len(c.Exclusions))}
	for _, e := range c.Exclusions {
		card.ExclusionList = append(card.ExclusionList, ragExclusionView(e))
	}
	WriteJSON(w, http.StatusOK, card)
}

func ragExclusionView(e rag.Exclusion) RAGExclusionView {
	return RAGExclusionView{ID: e.ID, DocumentID: e.DocumentID, Reason: e.Reason, CreatedAt: e.CreatedAt.UTC(), CreatedBy: e.CreatedBy}
}

// RAGDocumentView — документ текущей версии манифеста. excluded — отметка
// индексатора (проверка до индексации), blocked — исключён администратором.
type RAGDocumentView struct {
	ID       string `json:"id"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Excluded bool   `json:"excluded"`
	Blocked  bool   `json:"blocked"`
}

// RAGDocumentPage — страница документов: next_after — ID последнего
// документа страницы, если есть следующая.
type RAGDocumentPage struct {
	Version   int               `json:"version"`
	Items     []RAGDocumentView `json:"items"`
	NextAfter string            `json:"next_after,omitempty"`
}

func (d Deps) getRAGManifest(w http.ResponseWriter, r *http.Request) {
	slug, ok := pathSlug(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	var bad []FieldError
	limit := rag.DefaultLimit
	if vs, ok := q["limit"]; ok {
		n, err := strconv.Atoi(first(vs))
		if len(vs) != 1 || err != nil || n < 1 || n > rag.MaxLimit {
			bad = append(bad, FieldError{Field: "limit", Detail: "Укажите целое число от 1 до " + strconv.Itoa(rag.MaxLimit) + "."})
		} else {
			limit = n
		}
	}
	after := oneParam(q, "after", rag.MaxDocumentID, &bad)
	if len(bad) > 0 {
		WriteProblem(w, Invalid("Параметры страницы заданы неверно.", bad...))
		return
	}
	// Версия читается до страницы: между запросами страниц индексатор может
	// загрузить новую — клиент сверяет version у страниц.
	c, err := d.RAG.Collection(r.Context(), slug)
	if err != nil {
		WriteProblem(w, ragProblem(d.Logger, err))
		return
	}
	docs, err := d.RAG.Documents(r.Context(), slug, after, limit+1)
	if err != nil {
		WriteProblem(w, ragProblem(d.Logger, err))
		return
	}
	page := RAGDocumentPage{Version: c.Version, Items: make([]RAGDocumentView, 0, min(len(docs), limit))}
	if len(docs) > limit {
		docs = docs[:limit]
		page.NextAfter = docs[len(docs)-1].ID
	}
	for _, doc := range docs {
		page.Items = append(page.Items, RAGDocumentView{ID: doc.ID, SHA256: hex.EncodeToString(doc.SHA256), Size: doc.Size,
			Excluded: doc.Excluded, Blocked: doc.Blocked})
	}
	WriteJSON(w, http.StatusOK, page)
}

// RAGManifestResult — ответ на загрузку манифеста: новая версия, разница с
// предыдущей и ID документов манифеста, исключённых администратором
// (индексатор их не индексирует).
type RAGManifestResult struct {
	RAGCollectionView
	Created bool     `json:"created"`
	Blocked []string `json:"blocked"`
}

func (d Deps) putRAGManifest(w http.ResponseWriter, r *http.Request) {
	by, ok := d.ragBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	slug, ok := pathSlug(w, r)
	if !ok {
		return
	}
	var raw json.RawMessage
	if p := DecodeJSON(w, r, &raw, rag.MaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	docs, err := rag.ParseManifest(raw)
	if err != nil {
		WriteProblem(w, ragProblem(d.Logger, err))
		return
	}
	res, err := d.RAG.LoadManifest(r.Context(), by, slug, docs)
	if err != nil {
		WriteProblem(w, ragProblem(d.Logger, err))
		return
	}
	status := http.StatusOK
	if res.Created {
		status = http.StatusCreated
	}
	WriteJSON(w, status, RAGManifestResult{RAGCollectionView: ragCollectionView(res.Collection), Created: res.Created, Blocked: res.Blocked})
}

func (d Deps) addRAGExclusion(w http.ResponseWriter, r *http.Request) {
	by, ok := d.ragBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	slug, ok := pathSlug(w, r)
	if !ok {
		return
	}
	var raw json.RawMessage
	if p := DecodeJSON(w, r, &raw, rag.MaxExclusionBody); p != nil {
		WriteProblem(w, p)
		return
	}
	in, err := rag.ParseExclusion(raw)
	if err != nil {
		WriteProblem(w, ragProblem(d.Logger, err))
		return
	}
	ex, err := d.RAG.Exclude(r.Context(), by, slug, in)
	if err != nil {
		WriteProblem(w, ragProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusCreated, ragExclusionView(ex))
}

func (d Deps) removeRAGExclusion(w http.ResponseWriter, r *http.Request) {
	by, ok := d.ragBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	slug, ok := pathSlug(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "Исключение не найдено.")
	if !ok {
		return
	}
	if err := d.RAG.RemoveExclusion(r.Context(), by, slug, id); err != nil {
		WriteProblem(w, ragProblem(d.Logger, err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
