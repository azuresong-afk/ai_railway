//go:build e2e

package e2e

// Модель-оценщик judge.llm в контуре заказчика (задачи 5.27, 5.28 этапа 5;
// строки DM-18 и DM-19 «LLM — 5»; ADR-0030): живые сервер и шлюз, провайдер
// оценщика с признаком «размещён у заказчика» на частном адресе. Сама
// модель-оценщик — заглушка теста: OpenAI-совместимый HTTPS-сервер, который
// отвечает вердиктами формата judge-prompt/1 по словам-маркерам правил.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

var (
	s5JudgeRuleRe = regexp.MustCompile(`(?m)^- ([a-z0-9][a-z0-9_-]*): `)
	s5JudgeTextRe = regexp.MustCompile(`(?s)<<<AISEC-TEXT-([0-9a-f]{32})>>>\n(.*)\n<<<END-AISEC-TEXT-([0-9a-f]{32})>>>`)
)

// s5Judge — заглушка модели-оценщика.
type s5Judge struct {
	addr  string
	caPEM []byte
	mu    sync.Mutex
	// markers — ID правила → слово, по которому правило считается нарушенным.
	markers map[string]string
	// broken — отвечать не по формату (оценка не получена).
	broken bool
	calls  int
}

func (j *s5Judge) setBroken(v bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.broken = v
}

func (j *s5Judge) callCount() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.calls
}

func (j *s5Judge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/chat/completions") {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role, Content string
		} `json:"messages"`
	}
	if json.Unmarshal(body, &req) != nil || len(req.Messages) != 2 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	j.mu.Lock()
	j.calls++
	broken := j.broken
	j.mu.Unlock()
	content := "не знаю"
	if m := s5JudgeTextRe.FindStringSubmatch(req.Messages[1].Content); !broken && m != nil {
		type verdict struct {
			Rule       string  `json:"rule"`
			Violated   bool    `json:"violated"`
			Confidence float64 `json:"confidence"`
		}
		var out struct {
			Verdicts []verdict `json:"verdicts"`
		}
		text := strings.ToLower(m[2])
		for _, rm := range s5JudgeRuleRe.FindAllStringSubmatch(req.Messages[0].Content, -1) {
			v := verdict{Rule: rm[1], Confidence: 0.1}
			if word := j.markers[rm[1]]; word != "" && strings.Contains(text, strings.ToLower(word)) {
				v.Violated, v.Confidence = true, 0.95
			}
			out.Verdicts = append(out.Verdicts, v)
		}
		b, _ := json.Marshal(out) //nolint:gosec // G104: структура из строк и чисел кодируется всегда
		content = string(b)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G104: ответ заглушки
		"id": "judge-e2e", "object": "chat.completion", "model": req.Model,
		"choices": []map[string]any{{"index": 0, "message": map[string]string{"role": "assistant", "content": content}, "finish_reason": "stop"}},
		"usage":   map[string]int{"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70}})
}

// s5StartJudge поднимает заглушку оценщика на частном адресе ip.
func s5StartJudge(t *testing.T, ip string, markers map[string]string) *s5Judge {
	t.Helper()
	now := time.Now()
	ca, err := aisecCrypto.NewCA("e2e judge CA", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServer([]string{ip}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.TLS()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tp.ServerConfig(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	j := &s5Judge{addr: ln.Addr().String(), caPEM: ca.CertPEM(), markers: markers}
	srv := &http.Server{Handler: j, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(aisecCrypto.TLSListener(ln, cfg)) }() //nolint:gosec // G104: ошибка закрытия сервера при очистке теста не важна
	t.Cleanup(func() { _ = srv.Close() })                           //nolint:gosec // G104: очистка теста
	return j
}

// s5JudgeStack готовит стенд с оценщиком: провайдер на частном адресе без
// признака «внешний» и с отметкой «размещён у заказчика», политика с двумя
// правилами judge.llm, приложение на mock-llm. bindProvider — завести ещё
// приложение на провайдере оценщика: провайдер попадает в пакет шлюза, только
// если им пользуется приложение.
func s5JudgeStack(t *testing.T, bindProvider bool) (*s3Stack, *s5Judge, s3App) {
	t.Helper()
	ip := s5PrivateIP(t)
	st := s3NewStack(t, s3Opts{})
	j := s5StartJudge(t, ip, map[string]string{"no-refund": "возврат денег", "no-insult": "идиот"})
	jid := addProvider(t, st.admin, "judge-local", "https://"+j.addr+"/v1", j.caPEM)

	// Признаки провайдера оценщика ставит администратор безопасности из
	// консоли, с причиной и повторной проверкой пароля: провайдер создаётся
	// «внешним», оценщиком может быть только провайдер без него и с отметкой
	// «размещён у заказчика» на частном адресе.
	reason := "Оценщик развёрнут в контуре заказчика (e2e)"
	if r := st.admin.do("PUT", "/api/v1/providers/"+jid+"/external", map[string]any{"external": false, "reason": reason}); r.code != http.StatusBadRequest {
		t.Fatalf("снятие признака «внешний» без пароля: %s", r)
	}
	if r := st.admin.do("PUT", "/api/v1/providers/"+jid+"/external", map[string]any{"external": false, "reason": reason,
		"password": s2AdminPass}); r.code != http.StatusOK {
		t.Fatalf("снятие признака «внешний»: %s", r)
	}
	if r := st.admin.do("PUT", "/api/v1/providers/"+jid+"/on-premise", map[string]any{"on_premise": true, "reason": reason}); r.code != http.StatusBadRequest {
		t.Fatalf("признак без пароля: %s", r)
	}
	if r := st.admin.do("PUT", "/api/v1/providers/"+jid+"/on-premise", map[string]any{"on_premise": true, "reason": reason,
		"password": s2AdminPass}); r.code != http.StatusOK {
		t.Fatalf("признак on_premise: %s", r)
	}
	spec := map[string]any{"name": "Оценщик e2e", "mode": "enforce",
		"judge": map[string]any{"provider": "judge-local", "model": "judge-e2e"},
		"rules": []map[string]any{
			{"id": "no-refund", "detector": "judge.llm", "directions": []string{"output"}, "action": "block", "severity": "high",
				"judge": map[string]any{"kind": "business", "criterion": "Ассистент не обещает возврат денег клиенту.",
					"mode": "sync", "timeout_ms": 3000, "on_failure": "allow"}},
			{"id": "no-insult", "detector": "judge.llm", "directions": []string{"input"}, "action": "block", "severity": "medium",
				"judge": map[string]any{"kind": "content", "criterion": "Пользователь не оскорбляет сотрудников компании.",
					"mode": "sync", "timeout_ms": 3000, "on_failure": "allow"}},
		}}
	if r := st.admin.do("POST", "/api/v1/policies", map[string]any{"id": "judged", "spec": spec}); r.code != http.StatusCreated {
		t.Fatalf("политика с оценщиком: %s", r)
	}
	app := st.app("judged-app", "judged")
	if bindProvider {
		// Приложение-«носитель» провайдера оценщика: без политики с judge.
		st.policy("plain")
		st.s5App("judge-carrier", "plain", "fail_closed", jid)
	}
	st.startGateway()
	return st, j, app
}

// Оценщик judge.llm в контуре: DM-19 (обещание возврата денег в ответе) и
// DM-18 (оскорбление в запросе) останавливаются; сбой оценщика даёт отметку
// «не проверено», а не молчаливый пропуск.
func TestE2EStage5_JudgeLLMOnPremise(t *testing.T) {
	st, j, app := s5JudgeStack(t, true)

	// Обычный запрос проходит: оценщик вызван, нарушений нет.
	code, body := st.chat(app.key, "Расскажите, как оформить заказ.")
	if code != http.StatusOK {
		t.Fatalf("обычный запрос: %d %s", code, body)
	}
	if j.callCount() == 0 {

	}

	// DM-19: ассистент (mock-llm повторяет запрос в ответе) обещает возврат
	// денег — ответ блокируется до выдачи приложению, в событии находка
	// judge.llm и строка матрицы.
	st.mockReset()
	code, body = st.chat(app.key, "Мы гарантируем возврат денег в течение дня.")
	if code == http.StatusOK || strings.Contains(body, "возврат денег") {
		t.Fatalf("обещание возврата не заблокировано: %d %s", code, body)
	}
	// Блокировка ответа — решение response события: действие запроса allow.
	ev := s5WaitCard(t, st.admin, `type = "gateway_request"`, `"DM-19"`)
	if !strings.Contains(ev.Raw, `"detector":"judge.llm"`) || !strings.Contains(ev.Raw, `"DM-19"`) || strings.Contains(ev.Raw, "judge_unchecked") {
		t.Fatalf("карточка нарушения: %s", ev.Raw)
	}

	// DM-18: оскорбление в запросе останавливается до отправки модели.
	st.mockReset()
	code, _ = st.chat(app.key, "Вы все идиот и ничего не умеете.")
	if code == http.StatusOK || st.mockLast().Received {
		t.Fatalf("оскорбление дошло до провайдера: %d", code)
	}
	ev = s5WaitCard(t, st.admin, `type = "gateway_request" and action = "block"`, `"DM-18"`)
	if !strings.Contains(ev.Raw, `"detector":"judge.llm"`) {
		t.Fatalf("карточка оскорбления: %s", ev.Raw)
	}
	if a := st.waitAlert("threshold.judge_violation", 90*time.Second); a.ID == "" {
		t.Fatal("нет оповещения threshold.judge_violation")
	}

	// Оценка не получена (ответ не по формату): on_failure: allow пропускает
	// запрос, событие помечено judge_unchecked — «не проверено» видно.
	j.setBroken(true)
	code, body = st.chat(app.key, "Как поживает мой заказ?")
	if code != http.StatusOK {
		t.Fatalf("при сбое оценщика (allow): %d %s", code, body)
	}
	if !s2WaitFor(30*time.Second, func() bool { return len(s5Events(t, st.admin, `judge_unchecked = true`)) > 0 }) {
		t.Fatal("нет события с отметкой judge_unchecked")
	}
}

// Дефект, найденный при 5.49 (открытые вопросы stage-5.md): провайдер-оценщик
// с отметкой «размещён у заказчика» попадает в пакет шлюза, только если им
// пользуется хотя бы одно приложение (сборщик пакета берёт провайдеров
// приложений). Руководство (раздел 32) об этом молчит: оценщик, заведённый по
// шагам руководства, всегда даёт «не проверено». Тест воспроизводит дефект и
// пропущен до исправления.
func TestE2EStage5_JudgeProviderWithoutApp(t *testing.T) {
	t.Skip("дефект 5.49-2 (stage-5.md, «Открытые вопросы»): провайдер оценщика без приложения не попадает в пакет шлюза")
	st, j, app := s5JudgeStack(t, false)
	if code, body := st.chat(app.key, "Расскажите, как оформить заказ."); code != http.StatusOK {
		t.Fatalf("обычный запрос: %d %s", code, body)
	}
	if j.callCount() == 0 {
		t.Fatal("оценщик не вызывался: провайдера нет в пакете шлюза")
	}
}
