package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

const batchPath = "/guard/v1/check/batch"

// batchBody — тело пакета из пар «ID — текст».
func batchBody(t testing.TB, docs ...[2]string) string {
	t.Helper()
	parts := make([]string, 0, len(docs))
	for _, d := range docs {
		parts = append(parts, `{"id":`+jsonString(t, d[0])+`,"text":`+jsonString(t, d[1])+`}`)
	}
	return `{"source":"rag","stage":"pre_index","documents":[` + strings.Join(parts, ",") + `]}`
}

func decodeBatch(t *testing.T, resp *httptest.ResponseRecorder) batchResponse {
	t.Helper()
	if resp.Code != http.StatusOK {
		t.Fatalf("пакет: %d %s", resp.Code, resp.Body.String())
	}
	var r batchResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &r); err != nil {
		t.Fatalf("ответ не JSON: %q", resp.Body.String())
	}
	return r
}

// TestDM07_RAGPreindexBatch — индексатор проверяет документы коллекции до
// индексации одним вызовом: документ с косвенной инъекцией получает
// «исключить» с находками, документ с ПДн — «индексировать» с текстом после
// маскирования, чистый — «индексировать» без текста; по каждому документу —
// своё событие check с source rag, ID события — в ответе, содержимое — только
// по режиму хранения приложения; провайдер LLM не вызывается.
// Покрывает: DM-07 (RAG)
func TestDM07_RAGPreindexBatch(t *testing.T) {
	for _, storage := range []string{"", events.StorageMasked} {
		t.Run("storage="+storage, func(t *testing.T) {
			up, rec := newUpstream(t, nil)
			var log *eventLog
			g := newGateway(t, up.URL, func(o *gwOpts) {
				o.app = func(a *config.Application) { enforce(a); a.Storage = storage }
				log = o.events
			})
			resp := postJSON(t, g, batchPath, batchBody(t,
				[2]string{"kb/clean.md", "Отпуск оформляется заявлением за две недели."},
				[2]string{"kb/poison.md#2", "Раздел 2. " + injectionText},
				[2]string{"kb/contacts.md", "Почта " + piiEmail + " в справочнике"},
			), nil)
			r := decodeBatch(t, resp)
			if r.Stage != StagePreIndex || r.Excluded != 1 || r.Unchecked || len(r.Results) != 3 {
				t.Fatalf("ответ: %+v", r)
			}
			clean, poison, contacts := r.Results[0], r.Results[1], r.Results[2]
			if clean.ID != "kb/clean.md" || clean.Decision != DecisionAllow || clean.Text != nil || clean.Reason != "" || len(clean.Findings) != 0 {
				t.Fatalf("чистый документ: %+v", clean)
			}
			if poison.ID != "kb/poison.md#2" || poison.Decision != DecisionExclude || poison.Reason != ReasonPolicy ||
				poison.Action != "block" || poison.Text != nil || len(poison.Findings) == 0 {
				t.Fatalf("документ с инъекцией: %+v", poison)
			}
			if contacts.Decision != DecisionAllow || contacts.Text == nil || *contacts.Text != "Почта "+emailMask+" в справочнике" {
				t.Fatalf("документ с ПДн: %+v", contacts)
			}
			// Найденное значение в ответ не попадает — только место и категория.
			if strings.Contains(resp.Body.String(), "password") || strings.Contains(resp.Body.String(), piiEmail) {
				t.Fatalf("в ответе фрагмент текста: %s", resp.Body.String())
			}
			if _, _, _, calls := rec.get(); calls != 0 {
				t.Fatal("пакетная проверка обратилась к провайдеру")
			}
			if resp.Header().Get(HeaderEventID) != "" {
				t.Fatalf("X-AISec-Event-Id у пакета: %q", resp.Header().Get(HeaderEventID))
			}
			evs := log.all()
			if len(evs) != 3 {
				t.Fatalf("событий %d, ожидалось по одному на документ", len(evs))
			}
			for i, e := range evs {
				if e.Type != events.TypeCheck || e.Source != "rag" || e.App != "app" || e.ID != r.Results[i].EventID {
					t.Fatalf("событие %d: %+v", i, e)
				}
				switch {
				case storage == "" && e.Content != nil:
					t.Fatalf("содержимое при хранении без содержимого: %+v", e.Content)
				case storage == events.StorageMasked && (e.Content == nil || strings.Contains(e.Content.Request, piiEmail)):
					t.Fatalf("содержимое при хранении masked: %+v", e.Content)
				}
			}
			if !slices.Contains(evs[1].Threats, "DM-07") || evs[1].Decision.Action != "block" {
				t.Fatalf("событие документа с инъекцией: %+v", evs[1])
			}
		})
	}
}

// В режиме monitor документ с инъекцией не исключается: decision allow,
// action block — как у Check API.
func TestRAGBatchMonitorReportsButDoesNotExclude(t *testing.T) {
	up, _ := newUpstream(t, nil)
	g := newGateway(t, up.URL, nil)
	r := decodeBatch(t, postJSON(t, g, batchPath, batchBody(t, [2]string{"a", injectionText}), nil))
	if r.Excluded != 0 || r.Results[0].Decision != DecisionAllow || r.Results[0].Action != "block" || len(r.Results[0].Findings) == 0 {
		t.Fatalf("monitor: %+v", r)
	}
}

// Сбой детекторов: fail_closed — документ исключается с причиной
// check_unavailable (индексатор повторит позже), fail_open — индексируется с
// пометкой incomplete.
func TestRAGBatchFailClosedAndFailOpen(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { a.FailMode = "fail_closed" }
		o.setup, o.detTimeout, log = withDetector(t, slow), 10*time.Millisecond, o.events
	})
	r := decodeBatch(t, postJSON(t, g, batchPath, batchBody(t, [2]string{"a", "Привет"}, [2]string{"b", "Пока"}), nil))
	if r.Excluded != 2 {
		t.Fatalf("fail_closed: %+v", r)
	}
	for _, x := range r.Results {
		if x.Decision != DecisionExclude || x.Reason != ReasonUnavailable || !x.Incomplete {
			t.Fatalf("fail_closed: %+v", x)
		}
	}
	for _, e := range log.all() {
		if e.Decision.Rule != ruleFailClosed {
			t.Fatalf("событие: %+v", e.Decision)
		}
	}
	g = newGateway(t, up.URL, func(o *gwOpts) {
		o.app = func(a *config.Application) { a.FailMode = "fail_open" }
		o.setup, o.detTimeout = withDetector(t, slow), 10*time.Millisecond
	})
	r = decodeBatch(t, postJSON(t, g, batchPath, batchBody(t, [2]string{"a", "Привет"}), nil))
	if r.Excluded != 0 || r.Results[0].Decision != DecisionAllow || !r.Results[0].Incomplete {
		t.Fatalf("fail_open: %+v", r)
	}
}

// Пределы и разбор пакета: отказ — без событий и без вызова провайдера.
func TestRAGBatchLimits(t *testing.T) {
	up, rec := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { log = o.events })
	many := make([][2]string, MaxBatchDocuments+1)
	for i := range many {
		many[i] = [2]string{fmt.Sprintf("d%d", i), "x"}
	}
	doc := `{"id":"a","text":"x"}`
	cases := []struct {
		name, body string
		status     int
		code       string
	}{
		{"больше 100 документов", batchBody(t, many...), http.StatusBadRequest, "too_many_documents"},
		{"нет документов", `{"source":"rag","stage":"pre_index","documents":[]}`, http.StatusBadRequest, "invalid_request"},
		{"нет source", `{"stage":"pre_index","documents":[` + doc + `]}`, http.StatusBadRequest, "invalid_request"},
		{"source user", `{"source":"user","stage":"pre_index","documents":[` + doc + `]}`, http.StatusBadRequest, "invalid_request"},
		{"нет stage", `{"source":"rag","documents":[` + doc + `]}`, http.StatusBadRequest, "invalid_request"},
		{"другой stage", `{"source":"rag","stage":"post_index","documents":[` + doc + `]}`, http.StatusBadRequest, "invalid_request"},
		{"повтор ID", batchBody(t, [2]string{"a", "x"}, [2]string{"a", "y"}), http.StatusBadRequest, "invalid_request"},
		{"пустой ID", batchBody(t, [2]string{"", "x"}), http.StatusBadRequest, "invalid_request"},
		{"длинный ID", batchBody(t, [2]string{strings.Repeat("a", maxBatchDocumentID+1), "x"}), http.StatusBadRequest, "invalid_request"},
		{"смена направления в ID", batchBody(t, [2]string{"a\u202eb", "x"}), http.StatusBadRequest, "invalid_request"},
		{"пробел в начале ID", batchBody(t, [2]string{" a", "x"}), http.StatusBadRequest, "invalid_request"},
		{"пустой текст", batchBody(t, [2]string{"a", ""}), http.StatusBadRequest, "invalid_request"},
		{"текст больше предела", batchBody(t, [2]string{"a", strings.Repeat("я", 1<<9+1)}), http.StatusRequestEntityTooLarge, "document_too_large"},
		{"неизвестное поле", `{"source":"rag","stage":"pre_index","documents":[` + doc + `],"x":1}`, http.StatusBadRequest, "invalid_request"},
		{"поле документа", `{"source":"rag","stage":"pre_index","documents":[{"id":"a","text":"x","sha256":"0"}]}`, http.StatusBadRequest, "invalid_request"},
		{"данные после объекта", batchBody(t, [2]string{"a", "x"}) + `{}`, http.StatusBadRequest, "invalid_request"},
		{"тело — не объект", `[]`, http.StatusBadRequest, "invalid_request"},
		{"длинный user", `{"source":"rag","stage":"pre_index","user":"` + strings.Repeat("u", 300) + `","documents":[` + doc + `]}`, http.StatusBadRequest, "invalid_request"},
	}
	for _, c := range cases {
		resp := postJSON(t, g, batchPath, c.body, nil)
		if resp.Code != c.status || errCode(t, resp) != c.code {
			t.Errorf("%s: %d %s", c.name, resp.Code, resp.Body.String())
		}
		if strings.Contains(resp.Body.String(), "a\u202eb") {
			t.Errorf("%s: значение в тексте ошибки: %s", c.name, resp.Body.String())
		}
	}
	// Ровно 100 документов принимаются; текст ровно в предел — тоже.
	if r := decodeBatch(t, postJSON(t, g, batchPath, batchBody(t, many[:MaxBatchDocuments]...), nil)); len(r.Results) != MaxBatchDocuments {
		t.Fatalf("100 документов: %d", len(r.Results))
	}
	if r := decodeBatch(t, postJSON(t, g, batchPath, batchBody(t, [2]string{"a", strings.Repeat("я", 1<<9)}), nil)); len(r.Results) != 1 {
		t.Fatalf("текст в предел: %+v", r)
	}
	if n := len(log.all()); n != MaxBatchDocuments+1 {
		t.Errorf("событий %d: ошибки разбора не должны создавать событий", n)
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("пакетная проверка обратилась к провайдеру")
	}
	// Тип содержимого и общий предел тела пакета.
	if resp := postJSON(t, g, batchPath, `{}`, map[string]string{"Content-Type": "text/plain"}); resp.Code != http.StatusUnsupportedMediaType {
		t.Errorf("Content-Type: %d", resp.Code)
	}
	big := `{"source":"rag","stage":"pre_index","documents":[{"id":"a","text":"` + strings.Repeat("a", MinBatchBody) + `"}]}`
	if resp := postJSON(t, g, batchPath, big, nil); resp.Code != http.StatusRequestEntityTooLarge || errCode(t, resp) != "request_too_large" {
		t.Errorf("большое тело: %d %s", resp.Code, resp.Body.String())
	}
}

// Квоты: пакет учитывается в частоте по числу документов (ревью 5.r2,
// 5Н16), отказ — до проверки документов, 429 и одно событие; предел размера
// входа — к каждому тексту.
func TestRAGBatchQuotas(t *testing.T) {
	up, _ := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { o.quotas.RequestsPerMinute = 3; log = o.events })
	if r := decodeBatch(t, postJSON(t, g, batchPath, batchBody(t, [2]string{"a", "раз"}, [2]string{"b", "два"}), nil)); len(r.Results) != 2 {
		t.Fatalf("первый пакет: %+v", r)
	}
	resp := postJSON(t, g, batchPath, batchBody(t, [2]string{"c", "три"}, [2]string{"d", "четыре"}), nil)
	if resp.Code != http.StatusTooManyRequests || errCode(t, resp) != "quota_exceeded" || resp.Header().Get("Retry-After") == "" {
		t.Fatalf("второй пакет сверх квоты: %d %s", resp.Code, resp.Body.String())
	}
	evs := log.all()
	if len(evs) != 3 || evs[2].Source != "rag" || evs[2].Decision.Action != "block" {
		t.Fatalf("события: %+v", evs)
	}
	// Пакет больше квоты частоты не пройдёт никогда.
	four := batchBody(t, [2]string{"e", "1"}, [2]string{"f", "2"}, [2]string{"g", "3"}, [2]string{"h", "4"})
	g2 := newGateway(t, up.URL, func(o *gwOpts) { o.quotas.RequestsPerMinute = 3 })
	if resp := postJSON(t, g2, batchPath, four, nil); resp.Code != http.StatusTooManyRequests {
		t.Fatalf("пакет больше квоты: %d %s", resp.Code, resp.Body.String())
	}
	if r := decodeBatch(t, postJSON(t, g2, batchPath, batchBody(t, [2]string{"e", "1"}, [2]string{"f", "2"}, [2]string{"g", "3"}), nil)); len(r.Results) != 3 {
		t.Fatalf("пакет в квоте: %+v", r)
	}
	g = newGateway(t, up.URL, func(o *gwOpts) { o.quotas.MaxInputBytes = 20 })
	docs := make([][2]string, 5)
	for i := range docs {
		docs[i] = [2]string{fmt.Sprintf("d%d", i), strings.Repeat("a", 20)}
	}
	if r := decodeBatch(t, postJSON(t, g, batchPath, batchBody(t, docs...), nil)); len(r.Results) != 5 {
		t.Fatalf("тексты в пределе: %+v", r)
	}
	if resp := postJSON(t, g, batchPath, batchBody(t, [2]string{"a", strings.Repeat("a", 21)}), nil); resp.Code != http.StatusTooManyRequests {
		t.Fatalf("текст сверх предела: %d", resp.Code)
	}
}

// Маршрут требует действующий ключ приложения; до конфигурации — 503.
func TestRAGBatchDeniesWithoutValidKey(t *testing.T) {
	up, rec := newUpstream(t, nil)
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { o.noKey = true; log = o.events })
	for name, hdr := range map[string]map[string]string{
		"без ключа":  nil,
		"чужой ключ": {"Authorization": "Bearer aisec_wrong"},
		"не Bearer":  {"Authorization": "Basic abc"},
	} {
		resp := postJSON(t, g, batchPath, batchBody(t, [2]string{"a", "x"}), hdr)
		if resp.Code != http.StatusUnauthorized || errCode(t, resp) != "invalid_api_key" {
			t.Errorf("%s: %d %s", name, resp.Code, resp.Body.String())
		}
	}
	if len(log.all()) != 0 {
		t.Error("отказ в доступе создал событие")
	}
	if _, _, _, calls := rec.get(); calls != 0 {
		t.Fatal("запрос без ключа дошёл до провайдера")
	}
	if resp := do(t, newGateway(t, up.URL, nil), http.MethodGet, batchPath); resp.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", resp.Code)
	}
	w := httptest.NewRecorder()
	NewUnavailable(quiet()).ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodPost, batchPath, nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "config_unavailable") {
		t.Fatalf("до конфигурации: %d %s", w.Code, w.Body.String())
	}
}

// FuzzParseBatch — разбор пакета: отказ — код и текст без результата;
// принятый пакет — source rag, stage pre_index, от 1 до 100 документов с
// допустимыми ID без повторов и непустыми текстами UTF-8 в пределе.
func FuzzParseBatch(f *testing.F) {
	for _, s := range []string{
		`{"source":"rag","stage":"pre_index","documents":[{"id":"a","text":"x"}]}`,
		`{"source":"rag","stage":"pre_index","user":"u","documents":[{"id":"a","text":"x"},{"id":"b","text":"y"}]}`,
		`{"source":"rag","stage":"pre_index","documents":[{"id":"a","text":"x"},{"id":"a","text":"y"}]}`,
		`{"source":"rag","stage":"pre_index","documents":[{"id":"\u202e","text":"x"}]}`,
		`{"source":"rag","stage":"pre_index","documents":[]}`, `{}`, `[]`, `null`,
		"{\"source\":\"rag\",\"stage\":\"pre_index\",\"documents\":[{\"id\":\"a\",\"text\":\"\xff\"}]}",
	} {
		f.Add([]byte(s), int64(16))
	}
	f.Fuzz(func(t *testing.T, body []byte, maxText int64) {
		req, err := parseBatch(body, maxText)
		if err != nil {
			if req != nil || err.code == "" || err.msg == "" {
				t.Fatalf("ошибка с результатом: %+v", err)
			}
			return
		}
		if req.Source != "rag" || req.Stage != StagePreIndex || len(req.Documents) == 0 || len(req.Documents) > MaxBatchDocuments ||
			len(req.User) > maxUserIDLength {
			t.Fatalf("пакет: %+v", req)
		}
		seen := map[string]bool{}
		for _, d := range req.Documents {
			if !validBatchID(d.ID) || seen[d.ID] || d.Text == "" || int64(len(d.Text)) > maxText {
				t.Fatalf("документ: %q", d.ID)
			}
			seen[d.ID] = true
		}
	})
}
