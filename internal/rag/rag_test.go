package rag

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Манифест коллекции RAG на хранилище в памяти (задача 5.24): версии,
// разница с предыдущей, записи аудита, исключения администратора.

var tBy = By{Actor: audit.Actor{Type: audit.ActorAPIToken, ID: "tok-indexer", Name: "Индексатор"}}

func hashOf(s string) string { return strings.Repeat(hex.EncodeToString([]byte(s))[:2], 32) }

func docJSON(id, text string, size int, excluded bool) string {
	return fmt.Sprintf(`{"id":%q,"sha256":%q,"size":%d,"excluded":%t}`, id, hashOf(text), size, excluded)
}

func manifest(t *testing.T, docs ...string) []Document {
	t.Helper()
	ds, err := ParseManifest([]byte(`{"documents":[` + strings.Join(docs, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func newSvc(t *testing.T) (*Service, *Memory) {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMemory()
	s, err := New(Options{Store: m, Provider: p, Clock: func() time.Time { return time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	return s, m
}

func records(m *Memory, action string) []audit.Entry {
	var out []audit.Entry
	for _, r := range m.Records {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

func TestLoadManifestVersionsAndDiff(t *testing.T) {
	s, m := newSvc(t)
	ctx := context.Background()
	res, err := s.LoadManifest(ctx, tBy, "kb-hr", manifest(t, docJSON("hr/otpusk.md", "a", 10, false), docJSON("hr/bonus.md", "b", 20, false),
		docJSON("hr/old.md", "c", 30, false)))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.Collection.Version != 1 || res.Collection.Documents != 3 || res.Collection.Size != 60 || !res.Collection.Diff.Empty() {
		t.Fatalf("первая версия: %+v", res)
	}
	if n := len(records(m, "rag.document_changed")); n != 0 {
		t.Fatalf("первая версия дала rag.document_changed: %d", n)
	}
	// Вторая версия: изменён один, добавлен один, пропал один; признак
	// excluded у неизменённого документа изменением не считается.
	res, err = s.LoadManifest(ctx, tBy, "kb-hr", manifest(t, docJSON("hr/otpusk.md", "a", 10, true), docJSON("hr/bonus.md", "X", 20, false),
		docJSON("hr/new.md", "d", 5, false)))
	if err != nil {
		t.Fatal(err)
	}
	c := res.Collection
	if res.Created || c.Version != 2 || c.PrevLoadedAt == nil || c.Excluded != 1 {
		t.Fatalf("вторая версия: %+v", c)
	}
	d := c.Diff
	if d.Added != 1 || d.Changed != 1 || d.Removed != 1 || d.AddedIDs[0] != "hr/new.md" || d.ChangedIDs[0] != "hr/bonus.md" ||
		d.RemovedIDs[0] != "hr/old.md" {
		t.Fatalf("разница: %+v", d)
	}
	loaded := records(m, "rag.manifest_loaded")
	if len(loaded) != 2 || loaded[1].Object != (audit.Object{Type: "rag_collection", ID: "kb-hr"}) {
		t.Fatalf("rag.manifest_loaded: %+v", loaded)
	}
	ch := records(m, "rag.document_changed")
	if len(ch) != 1 {
		t.Fatalf("rag.document_changed: %+v", ch)
	}
	det := ch[0].Details.(map[string]any)
	ids := det["ids"].(map[string][]string)
	if det["added"] != 1 || det["changed"] != 1 || det["removed"] != 1 || det["prev_version"] != 1 || det["ids_truncated"] != false ||
		ids["changed"][0] != "hr/bonus.md" || ids["added"][0] != "hr/new.md" || ids["removed"][0] != "hr/old.md" {
		t.Fatalf("подробности: %+v", det)
	}
	// Хешей в записи нет.
	raw, err := json.Marshal(ch[0].Details)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), hashOf("X")) {
		t.Fatalf("хеш документа в аудите: %s", raw)
	}
	// Та же версия ещё раз — без разницы и без записи об изменении.
	if _, err := s.LoadManifest(ctx, tBy, "kb-hr", manifest(t, docJSON("hr/otpusk.md", "a", 10, true), docJSON("hr/bonus.md", "X", 20, false),
		docJSON("hr/new.md", "d", 5, false))); err != nil {
		t.Fatal(err)
	}
	if n := len(records(m, "rag.document_changed")); n != 1 {
		t.Fatalf("повтор версии дал изменение: %d", n)
	}
	docs, err := s.Documents(ctx, "kb-hr", "", 0)
	if err != nil || len(docs) != 3 || docs[0].ID != "hr/bonus.md" || !docs[2].Excluded {
		t.Fatalf("документы: %+v %v", docs, err)
	}
	docs, err = s.Documents(ctx, "kb-hr", "hr/bonus.md", 1)
	if err != nil || len(docs) != 1 || docs[0].ID != "hr/new.md" {
		t.Fatalf("страница после курсора: %+v %v", docs, err)
	}
	if _, err := s.Documents(ctx, "nope", "", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("нет коллекции: %v", err)
	}
	if _, err := s.Collection(ctx, "Bad_Slug"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("неверный slug: %v", err)
	}
}

// Пустой манифест после непустого — все документы пропали.
func TestLoadManifestAllRemoved(t *testing.T) {
	s, m := newSvc(t)
	ctx := context.Background()
	if _, err := s.LoadManifest(ctx, tBy, "kb", manifest(t, docJSON("a", "a", 1, false))); err != nil {
		t.Fatal(err)
	}
	res, err := s.LoadManifest(ctx, tBy, "kb", manifest(t))
	if err != nil || res.Collection.Diff.Removed != 1 || res.Collection.Documents != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if n := len(records(m, "rag.document_changed")); n != 1 {
		t.Fatalf("записей: %d", n)
	}
	var ie *InputError
	if _, err := s.LoadManifest(ctx, tBy, "-kb", nil); !errors.As(err, &ie) {
		t.Fatalf("неверный slug: %v", err)
	}
}

// ID в записи аудита — не больше MaxAlertIDs и MaxAlertIDBytes, признак
// усечения; в разнице карточки — до MaxDiffSample каждого вида.
func TestAlertIDsBounded(t *testing.T) {
	s, m := newSvc(t)
	ctx := context.Background()
	if _, err := s.LoadManifest(ctx, tBy, "kb", manifest(t)); err != nil {
		t.Fatal(err)
	}
	var docs []string
	for i := range MaxDiffSample + 50 {
		docs = append(docs, docJSON(fmt.Sprintf("%03d-%s", i, strings.Repeat("я", 200)), "a", 1, false))
	}
	res, err := s.LoadManifest(ctx, tBy, "kb", manifest(t, docs...))
	if err != nil {
		t.Fatal(err)
	}
	if res.Collection.Diff.Added != MaxDiffSample+50 || len(res.Collection.Diff.AddedIDs) != MaxDiffSample {
		t.Fatalf("разница: %d %d", res.Collection.Diff.Added, len(res.Collection.Diff.AddedIDs))
	}
	det := records(m, "rag.document_changed")[0].Details.(map[string]any)
	ids := det["ids"].(map[string][]string)
	size := 0
	for _, id := range ids["added"] {
		size += len(id)
	}
	if len(ids["added"]) == 0 || len(ids["added"]) > MaxAlertIDs || size > MaxAlertIDBytes || det["ids_truncated"] != true {
		t.Fatalf("ID в записи: %d (%d байт), усечено %v", len(ids["added"]), size, det["ids_truncated"])
	}
	raw, err := json.Marshal(det)
	if err != nil || len(raw) > 16<<10 {
		t.Fatalf("подробности %d байт: %v", len(raw), err)
	}
}

func TestExclusions(t *testing.T) {
	s, m := newSvc(t)
	ctx := context.Background()
	if _, err := s.Exclude(ctx, tBy, "kb", ExclusionInput{DocumentID: "a"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("исключение в несуществующей коллекции: %v", err)
	}
	if _, err := s.LoadManifest(ctx, tBy, "kb", manifest(t, docJSON("a", "a", 1, false), docJSON("b", "b", 1, false))); err != nil {
		t.Fatal(err)
	}
	ex, err := s.Exclude(ctx, tBy, "kb", ExclusionInput{DocumentID: "b", Reason: " инъекция в тексте "})
	if err != nil || ex.Reason != "инъекция в тексте" {
		t.Fatalf("%+v %v", ex, err)
	}
	if _, err := s.Exclude(ctx, tBy, "kb", ExclusionInput{DocumentID: "b"}); !errors.Is(err, ErrExists) {
		t.Fatalf("повтор: %v", err)
	}
	// Исключение по ID ещё не загруженного документа — допустимо.
	if _, err := s.Exclude(ctx, tBy, "kb", ExclusionInput{DocumentID: "later"}); err != nil {
		t.Fatal(err)
	}
	c, err := s.Collection(ctx, "kb")
	if err != nil || len(c.Exclusions) != 2 || c.ExclusionCount != 2 {
		t.Fatalf("карточка: %+v %v", c, err)
	}
	// Следующая загрузка возвращает исключённые документы манифеста.
	res, err := s.LoadManifest(ctx, tBy, "kb", manifest(t, docJSON("a", "a", 1, false), docJSON("b", "b", 1, false)))
	if err != nil || len(res.Blocked) != 1 || res.Blocked[0] != "b" {
		t.Fatalf("исключённые в ответе: %+v %v", res.Blocked, err)
	}
	docs, err := s.Documents(ctx, "kb", "", 0)
	if err != nil || docs[0].Blocked || !docs[1].Blocked {
		t.Fatalf("признак в документах: %+v %v", docs, err)
	}
	if err := s.RemoveExclusion(ctx, tBy, "kb", ex.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveExclusion(ctx, tBy, "kb", ex.ID); !errors.Is(err, ErrExclusionNotFound) {
		t.Fatalf("повторное снятие: %v", err)
	}
	rm := records(m, "rag.exclusion_removed")
	if len(rm) != 1 || rm[0].Details.(map[string]any)["weakening"] != true || rm[0].Details.(map[string]any)["document"] != "b" {
		t.Fatalf("rag.exclusion_removed: %+v", rm)
	}
	if n := len(records(m, "rag.document_excluded")); n != 2 {
		t.Fatalf("rag.document_excluded: %d", n)
	}
}

func TestCollectionsLimit(t *testing.T) {
	s, _ := newSvc(t)
	ctx := context.Background()
	for i := range MaxCollections {
		if _, err := s.LoadManifest(ctx, tBy, fmt.Sprintf("c%d", i), nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.LoadManifest(ctx, tBy, "extra", nil); !errors.Is(err, ErrTooManyCollections) {
		t.Fatalf("сверх предела: %v", err)
	}
	// Существующая коллекция обновляется и на пределе.
	if _, err := s.LoadManifest(ctx, tBy, "c0", nil); err != nil {
		t.Fatal(err)
	}
	cs, err := s.Collections(ctx)
	if err != nil || len(cs) != MaxCollections || cs[0].Slug != "c0" || cs[0].Version != 2 {
		t.Fatalf("%d %v", len(cs), err)
	}
}
