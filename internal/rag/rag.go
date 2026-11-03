// Пакет rag — манифест коллекций RAG в сервере управления (ТЗ 5.12, 5.16:
// DM-30; задача 5.24 этапа 5, ADR-0029, п. 5).
//
// Продукт не индексирует и не разбирает документы: индексатор заказчика
// присылает манифест коллекции — список документов {id, sha256, size}.
// Сервер хранит текущую и предыдущую версии манифеста и разницу между ними.
// Документ, появившийся вне прошлой версии, изменённый или пропавший, даёт
// запись аудита rag.document_changed (число и ID документов, без
// содержимого), по которой встроенное правило поднимает оповещение.
// Администратор исключает документ из индекса; индексатор читает
// исключения вместе с манифестом. Каждое изменение пишется в журнал аудита
// той же транзакцией (РСБ.1).
package rag

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// Пределы (ADR-0029, п. 5).
const (
	// MaxDocuments — документов в манифесте коллекции.
	MaxDocuments = 100000
	// MaxBody — тело манифеста.
	MaxBody = 16 << 20
	// MaxDocumentID — длина ID документа, байты.
	MaxDocumentID = 512
	// MaxDocumentSize — размер документа, 2^50 байт.
	MaxDocumentSize int64 = 1 << 50
	// MaxCollections — коллекций в организации.
	MaxCollections = 100
	// MaxExclusions — исключений администратора в коллекции.
	MaxExclusions = 1000
	// MaxExclusionBody — тело исключения.
	MaxExclusionBody = 8 << 10
	// MaxReason — причина исключения, символы.
	MaxReason = 500
	// MaxDiffSample — ID документов каждого вида изменений, которые сервер
	// хранит для карточки коллекции; остальные — числом.
	MaxDiffSample = 100
	// MaxAlertIDs и MaxAlertIDBytes — ID документов в записи аудита
	// rag.document_changed: подробности записи и оповещения ограничены
	// 16 КиБ, ID документа — до 512 байт.
	MaxAlertIDs     = 20
	MaxAlertIDBytes = 4 << 10
	// DefaultLimit и MaxLimit — документов на странице манифеста.
	DefaultLimit = 200
	MaxLimit     = 1000
)

// Ошибки.
var (
	ErrNotFound = errors.New("коллекция не найдена")
	// ErrExclusionNotFound — исключения с этим ID нет в коллекции.
	ErrExclusionNotFound = errors.New("исключение не найдено")
	// ErrExists — документ уже исключён.
	ErrExists = errors.New("документ уже исключён")
	// ErrTooManyCollections и ErrTooManyExclusions — достигнут предел.
	ErrTooManyCollections = errors.New("достигнут предел числа коллекций")
	ErrTooManyExclusions  = errors.New("достигнут предел числа исключений")
)

// InputError — неверные данные запроса; текст показывается пользователю.
type InputError struct{ Errs []error }

func (e *InputError) Error() string { return errors.Join(e.Errs...).Error() }

func invalid(errs ...error) error { return &InputError{Errs: errs} }

// Document — документ манифеста: ID у индексатора, SHA-256 текста, который
// он индексирует, размер и признак «исключён проверкой до индексации».
type Document struct {
	ID       string
	SHA256   []byte
	Size     int64
	Excluded bool
	// Blocked — документ исключён администратором (заполняется при чтении
	// манифеста).
	Blocked bool
}

// Diff — разница версии манифеста с предыдущей: число документов каждого
// вида и до MaxDiffSample их ID (по возрастанию).
type Diff struct {
	Added      int      `json:"added"`
	Changed    int      `json:"changed"`
	Removed    int      `json:"removed"`
	AddedIDs   []string `json:"added_ids"`
	ChangedIDs []string `json:"changed_ids"`
	RemovedIDs []string `json:"removed_ids"`
}

// Empty — версии совпадают по составу и хешам.
func (d Diff) Empty() bool { return d.Added == 0 && d.Changed == 0 && d.Removed == 0 }

// Exclusion — документ, исключённый администратором из индекса.
type Exclusion struct {
	ID         string
	DocumentID string
	Reason     string
	CreatedAt  time.Time
	CreatedBy  string
}

// Collection — коллекция RAG и её текущая версия манифеста.
type Collection struct {
	ID    string
	OrgID string
	Slug  string
	// Version — номер текущей версии манифеста (с 1).
	Version   int
	Documents int
	Size      int64
	// Excluded — документов текущей версии, исключённых проверкой до
	// индексации (признак индексатора).
	Excluded int
	LoadedAt time.Time
	LoadedBy string
	// PrevLoadedAt — время предыдущей версии; nil — версия первая.
	PrevLoadedAt *time.Time
	// Diff — разница текущей версии с предыдущей; у первой версии пустая.
	Diff      Diff
	CreatedAt time.Time
	// Exclusions — исключения администратора (только в карточке);
	// ExclusionCount — их число.
	Exclusions     []Exclusion
	ExclusionCount int
}

// LoadResult — итог загрузки манифеста.
type LoadResult struct {
	Collection Collection
	// Created — коллекция создана этой загрузкой.
	Created bool
	// Blocked — ID документов манифеста, исключённых администратором (по
	// возрастанию): индексатор их не индексирует.
	Blocked []string
}

// Store — хранилище (миграция 0071_rag). Рабочая реализация — PGStore, для
// тестов без PostgreSQL — Memory. Функции fn выполняются внутри транзакции
// под блокировкой коллекции и возвращают записи аудита, которые фиксируются
// вместе с изменением (РСБ.1).
type Store interface {
	Collections(ctx context.Context, orgID string) ([]Collection, error)
	// Collection — коллекция с исключениями; ErrNotFound.
	Collection(ctx context.Context, orgID, slug string) (Collection, error)
	// Documents — документы текущей версии с ID больше after по
	// возрастанию ID, с признаком Blocked; ErrNotFound.
	Documents(ctx context.Context, orgID, slug, after string, limit int) ([]Document, error)
	// LoadManifest под блокировкой организации читает текущую версию
	// коллекции (nil и пустой список — коллекции нет) и передаёт её fn;
	// fn возвращает новое состояние коллекции и записи аудита. Хранилище
	// сохраняет документы новой версии, оставляет одну предыдущую и
	// возвращает ID документов новой версии, исключённых администратором.
	// ErrTooManyCollections — новая коллекция сверх MaxCollections.
	LoadManifest(ctx context.Context, orgID, slug string, docs []Document,
		fn func(cur *Collection, curDocs []Document) (Collection, []audit.Entry, error)) ([]string, error)
	// AddExclusion — ErrNotFound, ErrExists, ErrTooManyExclusions.
	AddExclusion(ctx context.Context, orgID, slug string, ex Exclusion, rec func(Collection) audit.Entry) error
	// RemoveExclusion — ErrNotFound, ErrExclusionNotFound.
	RemoveExclusion(ctx context.Context, orgID, slug, id string, rec func(Collection, Exclusion) audit.Entry) error
}

// Options — зависимости Service.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	OrgID    string // пусто — организация по умолчанию
	Clock    func() time.Time
}

// Service — манифесты коллекций RAG.
type Service struct {
	store Store
	ids   *ids.Generator
	orgID string
	clock func() time.Time
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Provider == nil {
		return nil, errors.New("RAG: не заданы хранилище или криптопрофиль")
	}
	r, err := o.Provider.Random()
	if err != nil {
		return nil, err
	}
	s := &Service{store: o.Store, ids: ids.NewGenerator(r), orgID: o.OrgID, clock: o.Clock}
	if s.orgID == "" {
		s.orgID = audit.DefaultOrgID
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	return s, nil
}

// By — кто и откуда выполняет действие (РСБ.1).
type By struct {
	Actor audit.Actor
	IP    netip.Addr
}

func (b By) entry(action string, c Collection, details map[string]any) audit.Entry {
	return audit.Entry{Actor: b.Actor, SourceIP: b.IP, Action: action, Object: audit.Object{Type: "rag_collection", ID: c.Slug},
		Result: audit.ResultSuccess, Details: details}
}

// ref — ссылка на субъекта в полях loaded_by и created_by.
func (b By) ref() string {
	s := string(b.Actor.Type) + ":" + b.Actor.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

func (s *Service) newID() (string, error) {
	id, err := s.ids.New()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func checkSlug(slug string) error {
	if !ValidSlug(slug) {
		return ErrNotFound
	}
	return nil
}

// Collections — коллекции организации по ID.
func (s *Service) Collections(ctx context.Context) ([]Collection, error) {
	return s.store.Collections(ctx, s.orgID)
}

// Collection — карточка коллекции: версия, разница с предыдущей,
// исключения администратора.
func (s *Service) Collection(ctx context.Context, slug string) (Collection, error) {
	if err := checkSlug(slug); err != nil {
		return Collection{}, err
	}
	return s.store.Collection(ctx, s.orgID, slug)
}

// Documents — страница документов текущей версии после ID after.
func (s *Service) Documents(ctx context.Context, slug, after string, limit int) ([]Document, error) {
	if err := checkSlug(slug); err != nil {
		return nil, err
	}
	if after != "" {
		if err := CheckDocumentID(after); err != nil {
			return nil, invalid(errors.New("after — ID документа: " + err.Error()))
		}
	}
	switch {
	case limit <= 0:
		limit = DefaultLimit
	case limit > MaxLimit+1:
		limit = MaxLimit + 1
	}
	return s.store.Documents(ctx, s.orgID, slug, after, limit)
}

// Compare — разница манифеста next с текущей версией cur (документы
// изменены, если отличаются хеш или размер; признак Excluded изменением
// не считается — содержимое то же).
func Compare(cur, next []Document) Diff {
	old := make(map[string]Document, len(cur))
	for _, d := range cur {
		old[d.ID] = d
	}
	var d Diff
	var added, changed, removed []string
	for _, n := range next {
		o, ok := old[n.ID]
		switch {
		case !ok:
			d.Added++
			added = append(added, n.ID)
		case o.Size != n.Size || !bytes.Equal(o.SHA256, n.SHA256):
			d.Changed++
			changed = append(changed, n.ID)
		}
		delete(old, n.ID)
	}
	for id := range old {
		d.Removed++
		removed = append(removed, id)
	}
	d.AddedIDs, d.ChangedIDs, d.RemovedIDs = sample(added), sample(changed), sample(removed)
	return d
}

// sample — первые MaxDiffSample ID по возрастанию; пустой — [].
func sample(ids []string) []string {
	slices.Sort(ids)
	if len(ids) > MaxDiffSample {
		ids = ids[:MaxDiffSample]
	}
	return append([]string{}, ids...)
}

// alertIDs — ID документов для записи аудита rag.document_changed: до
// MaxAlertIDs всего и до MaxAlertIDBytes в сумме, сначала изменённые, затем
// новые и пропавшие. truncated — показаны не все.
func alertIDs(d Diff) (map[string][]string, bool) {
	out := map[string][]string{"changed": {}, "added": {}, "removed": {}}
	n, size, truncated := 0, 0, false
	for _, part := range []struct {
		name string
		ids  []string
		all  int
	}{{"changed", d.ChangedIDs, d.Changed}, {"added", d.AddedIDs, d.Added}, {"removed", d.RemovedIDs, d.Removed}} {
		for _, id := range part.ids {
			if n >= MaxAlertIDs || size+len(id) > MaxAlertIDBytes {
				truncated = true
				break
			}
			out[part.name] = append(out[part.name], id)
			n++
			size += len(id)
		}
		if len(out[part.name]) < part.all {
			truncated = true
		}
	}
	return out, truncated
}

// LoadManifest загружает новую версию манифеста коллекции slug (коллекция
// создаётся первой загрузкой). Пишет rag.manifest_loaded, а при разнице с
// предыдущей версией — rag.document_changed (DM-30) той же транзакцией.
// Первая версия разницы не даёт: сравнивать не с чем.
func (s *Service) LoadManifest(ctx context.Context, by By, slug string, docs []Document) (LoadResult, error) {
	if !ValidSlug(slug) {
		return LoadResult{}, invalid(errors.New("slug — ID коллекции: строчные латинские буквы, цифры и «-», до 63 символов"))
	}
	id, err := s.newID()
	if err != nil {
		return LoadResult{}, err
	}
	now := s.now()
	var res LoadResult
	blocked, err := s.store.LoadManifest(ctx, s.orgID, slug, docs, func(cur *Collection, curDocs []Document) (Collection, []audit.Entry, error) {
		next := Collection{ID: id, OrgID: s.orgID, Slug: slug, Version: 1, LoadedAt: now, LoadedBy: by.ref(), CreatedAt: now,
			Diff: Diff{AddedIDs: []string{}, ChangedIDs: []string{}, RemovedIDs: []string{}}}
		if cur != nil {
			next.ID, next.CreatedAt, next.Version = cur.ID, cur.CreatedAt, cur.Version+1
			prev := cur.LoadedAt
			next.PrevLoadedAt = &prev
			next.Diff = Compare(curDocs, docs)
			next.ExclusionCount = cur.ExclusionCount
		}
		next.Documents = len(docs)
		for _, d := range docs {
			next.Size += d.Size
			if d.Excluded {
				next.Excluded++
			}
		}
		res.Collection, res.Created = next, cur == nil
		recs := []audit.Entry{by.entry("rag.manifest_loaded", next, map[string]any{
			"collection": slug, "version": next.Version, "documents": next.Documents, "size": next.Size, "excluded": next.Excluded,
			"created": cur == nil, "added": next.Diff.Added, "changed": next.Diff.Changed, "removed": next.Diff.Removed,
		})}
		if cur != nil && !next.Diff.Empty() {
			ids, truncated := alertIDs(next.Diff)
			recs = append(recs, by.entry("rag.document_changed", next, map[string]any{
				"collection": slug, "version": next.Version, "prev_version": cur.Version,
				"added": next.Diff.Added, "changed": next.Diff.Changed, "removed": next.Diff.Removed,
				"ids": ids, "ids_truncated": truncated,
			}))
		}
		return next, recs, nil
	})
	if err != nil {
		return LoadResult{}, err
	}
	slices.Sort(blocked)
	res.Blocked = blocked
	if res.Blocked == nil {
		res.Blocked = []string{}
	}
	return res, nil
}

// Exclude исключает документ коллекции из индекса (rag.document_excluded).
// Документа может ещё не быть в манифесте: исключение действует по ID.
func (s *Service) Exclude(ctx context.Context, by By, slug string, in ExclusionInput) (Exclusion, error) {
	if err := checkSlug(slug); err != nil {
		return Exclusion{}, err
	}
	id, err := s.newID()
	if err != nil {
		return Exclusion{}, err
	}
	ex := Exclusion{ID: id, DocumentID: in.DocumentID, Reason: strings.TrimSpace(in.Reason), CreatedAt: s.now(), CreatedBy: by.ref()}
	err = s.store.AddExclusion(ctx, s.orgID, slug, ex, func(c Collection) audit.Entry {
		return by.entry("rag.document_excluded", c, map[string]any{"collection": slug, "exclusion": id, "document": ex.DocumentID,
			"reason": ex.Reason})
	})
	if err != nil {
		return Exclusion{}, err
	}
	return ex, nil
}

// RemoveExclusion снимает исключение (rag.exclusion_removed). Это
// ослабление защиты (DM-40): документ снова попадёт в индекс; маршрут —
// только из консоли.
func (s *Service) RemoveExclusion(ctx context.Context, by By, slug, id string) error {
	if err := checkSlug(slug); err != nil {
		return err
	}
	return s.store.RemoveExclusion(ctx, s.orgID, slug, id, func(c Collection, ex Exclusion) audit.Entry {
		return by.entry("rag.exclusion_removed", c, map[string]any{"collection": slug, "exclusion": ex.ID, "document": ex.DocumentID,
			"reason": ex.Reason, "weakening": true, "weakening_reasons": []string{"rag_exclusion_removed"}})
	})
}
