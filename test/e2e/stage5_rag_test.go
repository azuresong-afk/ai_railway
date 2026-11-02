//go:build e2e

package e2e

// RAG этапа 5 (задачи 5.24, 5.25; ADR-0029, п. 5): индексатор заказчика
// проверяет документы коллекции через шлюз до индексации (пакетный Check API,
// DM-07 «RAG — 5»), отправляет манифест коллекции на сервер токеном API, и
// изменение документов между версиями манифеста даёт оповещение
// rag.document_changed (DM-30). Живые сервер, шлюз и PostgreSQL.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// s5RAGBatch — ответ пакетной проверки до индексации.
type s5RAGBatch struct {
	Excluded int `json:"excluded"`
	Results  []struct {
		ID       string `json:"id"`
		EventID  string `json:"event_id"`
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
		Text     *string
	} `json:"results"`
}

func TestE2EStage5_RAGPreindexAndManifest(t *testing.T) {
	st := s3NewStack(t, s3Opts{})
	st.policy("support")
	app := st.app("rag-indexer", "support")
	st.startGateway()

	// Проверка до индексации: документ со скрытой инструкцией исключается,
	// чистый индексируется; модель не вызывается.
	st.mockReset()
	batch, err := json.Marshal(map[string]any{"source": "rag", "stage": "pre_index", "documents": []map[string]string{
		{"id": "kb/report-q3.md", "text": "Квартальный отчёт: выручка выросла на 4 %. Итоги подробно — в приложении."},
		{"id": "kb/report-q3-full.md", "text": s4RAGDoc},
	}})
	if err != nil {
		t.Fatal(err)
	}
	code, body := s4PostGateway(t, st, app.key, "/guard/v1/check/batch", nil, string(batch))
	if code != http.StatusOK {
		t.Fatalf("пакетная проверка: %d %s", code, body)
	}
	var res s5RAGBatch
	if err := json.Unmarshal([]byte(body), &res); err != nil || len(res.Results) != 2 {
		t.Fatalf("пакетная проверка: %v: %s", err, body)
	}
	if res.Excluded != 1 || res.Results[0].Decision != "allow" || res.Results[1].Decision != "exclude" || res.Results[1].Reason != "policy" {
		t.Fatalf("решения: %s", body)
	}
	if strings.Contains(body, "admin password") {
		t.Fatalf("в ответе фрагмент документа: %s", body)
	}
	if st.mockLast().Received {
		t.Fatal("пакетная проверка обратилась к провайдеру")
	}
	ev := s3LastEvent(t, st.admin, `type = "check" and source = "rag" and action = "block"`, map[string]bool{})
	if ev.ID != res.Results[1].EventID {
		t.Fatalf("событие документа %s, в ответе %s", ev.ID, res.Results[1].EventID)
	}
	card := st.admin.do("GET", "/api/v1/events/"+ev.ID, nil)
	if card.code != http.StatusOK || strings.Contains(string(card.body), "admin password") || !strings.Contains(string(card.body), `"DM-07"`) {
		t.Fatalf("карточка события: %s", card)
	}

	// Манифест — токеном API индексатора с правом rag.manage.
	r := st.admin.do("POST", "/api/v1/api-tokens", map[string]any{"name": "indexer", "password": s2AdminPass,
		"permissions": []map[string]string{{"permission": "rag.manage"}}})
	if r.code != http.StatusCreated {
		t.Fatalf("выпуск токена API: %s", r)
	}
	var tok struct{ Token string }
	r.json(t, &tok)
	indexer := st.s.client("198.51.100.71")
	indexer.bearer = tok.Token
	h := func(c string) string { return strings.Repeat(c, 64) }
	put := func(docs ...map[string]any) s2Resp {
		return indexer.doOpt("PUT", "/api/v1/rag/collections/kb-finance/manifest", map[string]any{"documents": docs}, false)
	}
	if r := put(map[string]any{"id": "kb/report-q3.md", "sha256": h("a"), "size": 75},
		map[string]any{"id": "kb/report-q3-full.md", "sha256": h("b"), "size": 120, "excluded": true}); r.code != http.StatusCreated {
		t.Fatalf("первая версия манифеста: %s", r)
	}
	if st.waitAlertOnce("rag.document_changed").ID != "" {
		t.Fatal("первая версия манифеста дала оповещение")
	}
	// Подмена документа в источнике: новая версия манифеста с изменённым
	// хешем и новым документом.
	if r := put(map[string]any{"id": "kb/report-q3.md", "sha256": h("c"), "size": 80},
		map[string]any{"id": "kb/report-q3-full.md", "sha256": h("b"), "size": 120, "excluded": true},
		map[string]any{"id": "kb/report-q4.md", "sha256": h("d"), "size": 60}); r.code != http.StatusOK {
		t.Fatalf("вторая версия манифеста: %s", r)
	}
	a := st.waitAlert("rag.document_changed", 30*time.Second)
	if !strings.Contains(a.Title, "kb-finance") || !strings.Contains(a.Title, "новых: 1, изменённых: 1, пропавших: 0") {
		t.Fatalf("оповещение: %+v", a)
	}
	// Токену с rag.manage чтение коллекций недоступно, снятие исключения —
	// только сессией консоли.
	if r := indexer.do("GET", "/api/v1/rag/collections", nil); r.code != http.StatusForbidden {
		t.Fatalf("чтение токеном без rag.read: %s", r)
	}
	r = st.admin.do("GET", "/api/v1/rag/collections/kb-finance", nil)
	var col struct {
		Version   int `json:"version"`
		Documents int `json:"documents"`
		Diff      struct {
			Changed int `json:"changed"`
			Added   int `json:"added"`
		} `json:"diff"`
	}
	r.json(t, &col)
	if r.code != http.StatusOK || col.Version != 2 || col.Documents != 3 || col.Diff.Changed != 1 || col.Diff.Added != 1 {
		t.Fatalf("карточка коллекции: %s", r)
	}
}
