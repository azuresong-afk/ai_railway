package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/rag"
)

// ragRecords — записи аудита двух загрузок манифеста коллекции kb-hr в
// хранилище в памяти: первая версия и вторая с изменённым, новым и
// пропавшим документом.
func ragRecords(t *testing.T) []audit.Entry {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	m := rag.NewMemory()
	svc, err := rag.New(rag.Options{Store: m, Provider: p, Clock: func() time.Time { return time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	load := func(docs ...[3]string) {
		var parts []string
		for _, d := range docs {
			parts = append(parts, fmt.Sprintf(`{"id":%q,"sha256":"%s","size":%s}`, d[0], strings.Repeat(d[1], 64), d[2]))
		}
		ds, err := rag.ParseManifest([]byte(`{"documents":[` + strings.Join(parts, ",") + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.LoadManifest(context.Background(), rag.By{Actor: tUser}, "kb-hr", ds); err != nil {
			t.Fatal(err)
		}
	}
	load([3]string{"hr/otpusk.md", "a", "100"}, [3]string{"hr/bonus.md", "b", "200"}, [3]string{"hr/old.md", "c", "300"})
	load([3]string{"hr/otpusk.md", "a", "100"}, [3]string{"hr/bonus.md", "e", "200"}, [3]string{"hr/new.md", "d", "50"})
	return m.Records
}

// canonDetails — подробности записи, как их хранит журнал: каноническая
// форма JSON.
func canonDetails(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestDM30_RAGDocumentChanged — новая версия манифеста коллекции RAG с
// изменённым, новым и пропавшим документом даёт оповещение встроенного
// правила «новое» rag.document_changed: коллекция и число документов
// каждого вида в заголовке, ID документов в подробностях, без хешей;
// первая версия оповещения не даёт, повтор той же коллекции дополняет
// открытое оповещение; правило можно отключить, поле rag_collection — только
// у встроенного правила.
// Покрывает: DM-30
func TestDM30_RAGDocumentChanged(t *testing.T) {
	e := newEnv(t)
	recs := ragRecords(t)
	changed := 0
	for _, r := range recs {
		e.audit(t, e.rec(t, r.Actor, "", r.Action, r.Object, r.Result, canonDetails(t, r.Details)))
		if r.Action == "rag.document_changed" {
			changed++
		}
		if r.Action == "rag.manifest_loaded" && changed == 0 {
			if n := len(e.alerts(t, BuiltinRAGDocumentChanged)); n != 0 {
				t.Fatalf("первая версия дала оповещение: %d", n)
			}
		}
	}
	if changed != 1 {
		t.Fatalf("записей rag.document_changed: %d", changed)
	}
	got := e.alerts(t, BuiltinRAGDocumentChanged)
	if len(got) != 1 {
		t.Fatalf("оповещений %d: %+v", len(got), got)
	}
	a := got[0]
	if a.Kind != KindNew || a.Severity != "medium" || !strings.Contains(a.Title, "kb-hr") ||
		!strings.Contains(a.Title, "новых: 1, изменённых: 1, пропавших: 1") {
		t.Fatalf("оповещение: %+v", a)
	}
	text := detailsText(t, a.Details)
	for _, want := range []string{"hr/bonus.md", "hr/new.md", "hr/old.md"} {
		if !strings.Contains(text, want) {
			t.Fatalf("в подробностях нет %q: %s", want, text)
		}
	}
	if strings.Contains(text, strings.Repeat("e", 64)) || strings.Contains(text, "hr/otpusk.md") {
		t.Fatalf("в подробностях хеш или неизменённый документ: %s", text)
	}
	// Ещё одно изменение той же коллекции дополняет открытое оповещение.
	for _, r := range recs {
		if r.Action == "rag.document_changed" {
			e.audit(t, e.rec(t, r.Actor, "", r.Action, r.Object, r.Result, canonDetails(t, r.Details)))
		}
	}
	if n := len(e.alerts(t, BuiltinRAGDocumentChanged)); n != 1 {
		t.Fatalf("повтор по коллекции дал второе оповещение: %d", n)
	}
	// Неуспешная запись и запись без изменений оповещения не дают.
	e.audit(t, e.rec(t, tUser, "", "rag.document_changed", audit.Object{Type: "rag_collection", ID: "kb-it"}, audit.ResultFailure,
		map[string]any{"collection": "kb-it", "changed": 3}))
	e.audit(t, e.rec(t, tUser, "", "rag.document_changed", audit.Object{Type: "rag_collection", ID: "kb-fin"}, audit.ResultSuccess,
		map[string]any{"collection": "kb-fin"}))
	if n := len(e.alerts(t, BuiltinRAGDocumentChanged)); n != 1 {
		t.Fatalf("лишние оповещения: %d", n)
	}
	r := e.rule(t, BuiltinRAGDocumentChanged)
	if Locked(r.Kind) || r.Condition.Field != RAGCollectionField {
		t.Fatalf("правило: %+v", r)
	}
	var ie *InputError
	if _, err := e.svc.CreateRule(context.Background(), e.admin, RuleInput{Kind: KindNew, Name: "Свои коллекции",
		Condition: Condition{Field: RAGCollectionField}}); !errors.As(err, &ie) {
		t.Fatalf("создание по rag_collection: %v", err)
	}
	off := false
	in := RuleInput{Name: r.Name, Description: r.Description, Enabled: &off, Severity: r.Severity, Condition: r.Condition,
		SuppressMinutes: &r.SuppressMinutes, Recipients: r.Recipients, Version: r.Version}
	if _, err := e.svc.UpdateRule(context.Background(), e.admin, r.ID, in); err != nil {
		t.Fatalf("отключение правила: %v", err)
	}
}
