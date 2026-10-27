package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/exfil"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/providers"
	"github.com/azuresong-afk/ai_railway/internal/pseudonym"
	"github.com/azuresong-afk/ai_railway/internal/sse"
)

// Проверка ответа модели (ТЗ, 4.3, шаг 7; 5.1; задача 1.23): выходные
// детекторы политики проверяют текст ответа, refusal и аргументы tool_calls
// (DM-13); решение политики применяется к ответу; псевдонимы запроса
// заменяются исходными значениями.
//
// Режимы (параметр политики response_check, ТЗ, 5.1):
//   - ответ без потока и buffered — ответ собирается целиком, проверяется и
//     только потом отдаётся; блокировка — ошибка policy_violation, как у
//     запроса;
//   - incremental — текст проверяется окнами по мере поступления; клиенту
//     уходит только проверенный текст, последние streamHoldBack байт и
//     недописанное слово ждут следующей проверки; при блокировке поток
//     обрывается событием с ошибкой policy_violation;
//   - monitor — части уходят без задержки, ответ проверяется после
//     передачи, решение только журналируется.
//
// В режиме политики monitor к ответу не применяется ничего (ТЗ, 5.3), а
// если в политике нет выходных правил, применять нечего: поток тогда
// передаётся как в monitor при любом response_check. Обратная подстановка
// выполняется всегда, в том числе в monitor.

// Параметры режима incremental. Задержка — до streamCheckStep +
// streamHoldBack байт текста (около сотни токенов); работа детекторов на
// ответ — около (streamOverlap + streamCheckStep) / streamCheckStep его
// длин, а когда окно начинается раньше с начала абзаца, пункта списка или
// строки кода (exfil.Window) — до (exfil.MaxWindowBack + streamOverlap +
// streamCheckStep) / streamCheckStep, около 25 длин
// (TestIncrementalWorkBounded).
const (
	// streamCheckStep — новый текст, после которого проверяется окно.
	streamCheckStep = 512
	// streamHoldBack — хвост, который не уходит клиенту до следующей
	// проверки: находка, которая ещё дописывается (телефон, канарейка,
	// ссылка), должна целиком остаться в непереданном тексте, чтобы её можно
	// было замаскировать.
	streamHoldBack = 256
	// streamOverlap — переданный текст, который входит в следующее окно:
	// контекст для детекторов на стыке окон.
	streamOverlap = 4 << 10
	// streamMaxHold — «слово» без пробельных символов длиннее этого
	// отдаётся, не дожидаясь конца: иначе одно слово задерживало бы весь
	// ответ, а окно проверки росло бы вместе с ним. Находка, разрезанная
	// выпуском, обрывает поток.
	streamMaxHold = 4 << 10
	// streamMaxPending — предел непереданного текста: находка для
	// маскирования, которая всё ещё дописывается (незакрытый блок ключа),
	// держит текст, и окно проверки растёт. Сверх предела поток обрывается:
	// проверять дальше пришлось бы квадратично.
	streamMaxPending = 64 << 10
)

// Места текстов ответа в событии.
const (
	locContent = "choices[0].message.content"
	locRefusal = "choices[0].message.refusal"
)

// threatToolArgs — строка матрицы находок в аргументах вызовов функций в
// ответе: утечка через вызов функции, какой бы детектор её ни нашёл.
const threatToolArgs = "DM-13"

func locToolArgs(i int) string {
	return fmt.Sprintf("choices[0].message.tool_calls[%d].function.arguments", i)
}

// Служебные правила решения по ответу.
const (
	// ruleToolArgsJSON — маскирование сломало JSON аргументов вызова
	// (значение стояло числом): такой вызов приложению не отдаётся.
	ruleToolArgsJSON = "tool_args_json"
	// ruleStreamCut — маскируемый фрагмент начался в уже переданном тексте
	// (incremental): замаскировать его нельзя, поток обрывается.
	ruleStreamCut = "stream_cut"
	// ruleStreamHold — непереданного текста больше streamMaxPending.
	ruleStreamHold = "stream_hold_limit"
	// ruleStreamLate — находка для блокировки или маскирования целиком в
	// уже переданном тексте: её нашла проверка с большим контекстом
	// (следующее окно, весь ответ). Применить её поздно, поток обрывается,
	// а событие не выглядит как исполненная блокировка.
	ruleStreamLate = "stream_late"
)

// restoreContext — сколько переданного текста до и непереданного после
// восстановленного фрагмента видит повторная проверка output.exfil в потоке.
const restoreContext = 4 << 10

// respRef — куда вернуть текст ответа.
type respRef struct {
	choice  int
	refusal bool
	tool    int // номер вызова; -1 — не вызов
}

// responseTexts — тексты ответа для выходных детекторов: content, refusal
// и аргументы каждого вызова инструмента (DM-13). Вариант ответа один
// (chat.MaxResponseChoices).
func responseTexts(resp *chat.Response) ([]inspectText, []respRef) {
	var texts []inspectText
	var refs []respRef
	for ci := range resp.Choices {
		m := &resp.Choices[ci].Message
		if m.Content != nil {
			texts = append(texts, inspectText{Text: *m.Content, Source: detect.SourceOutput, Location: locContent})
			refs = append(refs, respRef{choice: ci, tool: -1})
		}
		if m.Refusal != nil {
			texts = append(texts, inspectText{Text: *m.Refusal, Source: detect.SourceOutput, Location: locRefusal})
			refs = append(refs, respRef{choice: ci, refusal: true, tool: -1})
		}
		for j := range m.ToolCalls {
			texts = append(texts, inspectText{Text: m.ToolCalls[j].Function.Arguments, Source: detect.SourceOutput, Location: locToolArgs(j), Threat: threatToolArgs})
			refs = append(refs, respRef{choice: ci, tool: j})
		}
	}
	return texts, refs
}

func (r respRef) set(resp *chat.Response, text string) {
	m := &resp.Choices[r.choice].Message
	switch {
	case r.tool >= 0:
		m.ToolCalls[r.tool].Function.Arguments = text
	case r.refusal:
		m.Refusal = &text
	default:
		m.Content = &text
	}
}

// jsonResponseFormat — запрошен ответ в формате JSON: в content значение
// подставляется только в значение строки (ADR-0005, п. 5).
func jsonResponseFormat(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var rf struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(raw, &rf) == nil && (rf.Type == "json_object" || rf.Type == "json_schema")
}

// streamResponseMode — как проверяется потоковый ответ приложения.
func streamResponseMode(app *App) policy.ResponseCheck {
	if effectiveMode(app) != policy.Enforce || len(app.Policy.Detectors(detect.Output)) == 0 {
		return policy.ResponseMonitor
	}
	switch app.Policy.ResponseCheck {
	case policy.ResponseBuffered, policy.ResponseMonitor:
		return app.Policy.ResponseCheck
	}
	return policy.ResponseIncremental
}

// outputCheck — проверка текстов ответа по политике приложения.
// Окна потока проверяются без детекторов маскирования для хранения
// (forEvent = false): содержимое события берётся из итоговой проверки.
func (h *ChatHandler) outputCheck(ctx context.Context, app *App, user string, texts []inspectText, mode policy.Mode, detectOnly, forEvent bool) (*inspection, error) {
	return app.inspect(ctx, inspectRequest{
		Endpoint: policy.EndpointChat, Direction: detect.Output, Mode: mode, External: app.Provider.External(), Texts: texts, User: user,
		Mask: forEvent && app.Storage == events.StorageMasked, Timeout: h.cfg.DetectorTimeout, DetectOnly: detectOnly,
	})
}

// checkFull проверяет собранный ответ (ответ без потока, buffered),
// применяет решение и обратную подстановку. false — ответ не отдаётся,
// ошибка уже записана (или клиент ушёл).
func (h *ChatHandler) checkFull(w http.ResponseWriter, r *http.Request, app *App, rec *record, resp *chat.Response) bool {
	rec.respMode = events.ResponseBuffered
	texts, refs := responseTexts(resp)
	start := h.cfg.Now()
	in, err := h.outputCheck(r.Context(), app, rec.ev.User, texts, "", false, true)
	rec.ev.LatencyMS["output_check"] = h.cfg.Now().Sub(start).Milliseconds()
	switch {
	case err != nil && r.Context().Err() != nil:
		h.logger.Info("клиент прервал запрос во время проверки ответа", "path", r.URL.Path)
		return false
	case err != nil:
		h.logger.Error("проверка ответа не выполнена", "app", app.ID, "event_id", rec.ev.ID, "error", err)
		rec.respFailClosed()
		w.Header().Set(HeaderDecision, string(policy.Block))
		WriteError(w, http.StatusInternalServerError, "внутренняя ошибка шлюза", "server_error", "internal_error")
		return false
	}
	rec.resp, rec.respTexts = in, texts
	if len(in.Failures) > 0 {
		h.logger.Warn("сбой детекторов при проверке ответа", "app", app.ID, "event_id", rec.ev.ID,
			"failures", len(in.Failures), "fail_open", app.FailOpen)
	}
	if !in.Blocked() {
		for i, changed := range in.Changed {
			if !changed {
				continue
			}
			// Маска на месте числа ломает JSON аргументов: вызов с такими
			// аргументами приложение не разберёт, а «починить» его значит
			// подменить данные модели. Ответ блокируется.
			if refs[i].tool >= 0 && json.Valid([]byte(texts[i].Text)) && !json.Valid([]byte(in.Texts[i])) {
				in.blockResponse(app, ruleToolArgsJSON)
				break
			}
			refs[i].set(resp, in.Texts[i])
		}
	}
	switch {
	case in.FailBlock:
		w.Header().Set(HeaderDecision, string(policy.Block))
		WriteError(w, http.StatusServiceUnavailable, "ответ модели не удалось проверить, повторите позже", "service_unavailable", "check_unavailable")
		return false
	case in.Decision.Block:
		// Какие детекторы сработали, приложению не сообщается (ТЗ, 5.1).
		w.Header().Set(HeaderDecision, string(policy.Block))
		WriteError(w, http.StatusBadRequest, in.Decision.Message, "invalid_request_error", "policy_violation")
		return false
	}
	h.restoreFull(r.Context(), app, rec, resp)
	// Политика вызовов — по аргументам, которые получит приложение: их же
	// видит дежурный при подтверждении (задача 4.10). Ответ без потока
	// удерживается целиком, keep-alive нет.
	if toolsCheck(app, resp) {
		if b := h.decideTools(r.Context(), app, rec, resp.Choices[0].Message.ToolCalls, nil); b != nil {
			if r.Context().Err() != nil {
				return false
			}
			in.blockTools(app, b)
			w.Header().Set(HeaderDecision, string(policy.Block))
			WriteError(w, http.StatusBadRequest, in.Decision.Message, "invalid_request_error", "policy_violation")
			return false
		}
	}
	w.Header().Set(HeaderDecision, rec.headerDecision())
	return true
}

// blockTools — блокировка ответа политикой вызовов: решение в событие
// (правило вызова) и сообщение для приложения.
func (in *inspection) blockTools(app *App, b *toolBlock) {
	in.Decision.Block, in.Decision.Action, in.Decision.Rule = true, policy.Block, b.rule
	in.Decision.Message = b.message
	if in.Decision.Message == "" {
		in.Decision.Message = app.Policy.BlockMessage
	}
}

// blockResponse блокирует ответ служебным правилом (только enforce: в
// monitor ответу ничего не применяется).
func (in *inspection) blockResponse(app *App, rule string) {
	if in.Decision.Mode != policy.Enforce {
		return
	}
	in.Decision.Block, in.Decision.Action, in.Decision.Rule = true, policy.Block, rule
	in.Decision.Message = app.Policy.BlockMessage
}

// restoreFull — обратная подстановка в собранный ответ. Подстановка, после
// которой output.exfil находит в тексте больше ссылок, чем до неё,
// отменяется (ADR-0005, «Последствия»): значение остаётся замаскированным.
func (h *ChatHandler) restoreFull(ctx context.Context, app *App, rec *record, resp *chat.Response) {
	v := rec.vault
	if v == nil || v.Len() == 0 {
		return
	}
	jsonContent := rec.jsonMode
	for ci := range resp.Choices {
		m := &resp.Choices[ci].Message
		if m.Content != nil {
			restore := v.Restore
			if jsonContent {
				restore = v.RestoreJSON
			}
			m.Content = h.restoreChecked(ctx, app, rec, *m.Content, restore)
		}
		if m.Refusal != nil {
			m.Refusal = h.restoreChecked(ctx, app, rec, *m.Refusal, v.Restore)
		}
		args := make([]string, len(m.ToolCalls))
		for j := range m.ToolCalls {
			args[j] = m.ToolCalls[j].Function.Arguments
		}
		out, ok := restoreToolCalls(v, args)
		if ok && app.exfilAfterRestore(ctx, strings.Join(args, "\n"), strings.Join(out, "\n"), h.cfg.DetectorTimeout) {
			rec.withheld += len(args)
			ok = false
		}
		if ok {
			for j := range m.ToolCalls {
				m.ToolCalls[j].Function.Arguments = out[j]
			}
		}
	}
}

// restoreChecked — подстановка в текст с проверкой output.exfil после неё.
func (h *ChatHandler) restoreChecked(ctx context.Context, app *App, rec *record, text string, restore func(string) string) *string {
	out := restore(text)
	if out != text && app.exfilAfterRestore(ctx, text, out, h.cfg.DetectorTimeout) {
		rec.withheld++
		out = text
	}
	return &out
}

// exfilAfterRestore — после подстановки output.exfil нашёл то, чего не было
// в тексте с псевдонимами: значение попало в ссылку, хотя пакет pseudonym не
// восстанавливает его там, где оно может стать адресом. Это вторая линия
// защиты (ADR-0005). Сбой детектора — тоже «да»: подстановку безопаснее
// отменить.
func (a *App) exfilAfterRestore(ctx context.Context, before, after string, timeout time.Duration) bool {
	if _, ok := a.Detectors.Get(exfil.ID); !ok || before == after {
		return false
	}
	if timeout <= 0 {
		timeout = DefaultDetectorTimeout
	}
	// Находка — категория и найденный текст: ссылка, в которую попало
	// значение, — новый текст, даже если такая же ссылка с псевдонимом уже
	// была находкой (изображение вне allowlist находится и без данных).
	type key struct{ cat, text string }
	found := func(s string) (map[key]bool, bool) {
		fs, rerrs, err := a.Detectors.Run(ctx, []string{exfil.ID},
			detect.Text{Text: s, Direction: detect.Output, Source: detect.SourceOutput}, detectorTimeout(timeout, len(s)))
		out := map[key]bool{}
		for _, f := range fs {
			out[key{f.Category, s[f.Start:f.End]}] = true
		}
		return out, err == nil && len(rerrs) == 0
	}
	fb, okb := found(before)
	fa, oka := found(after)
	if !okb || !oka {
		return true
	}
	for k := range fa {
		if !fb[k] {
			return true
		}
	}
	return false
}

// restoreToolCalls — обратная подстановка в аргументы вызовов одного
// ответа (Vault.RestoreToolCalls): признак адреса в любом вызове запрещает
// подстановку во всех (внедрённая инструкция может разнести адрес и значение
// по параллельным вызовам — ревью 1.17–1.21, п. 9). Аргументы не JSON —
// подстановки нет, false.
func restoreToolCalls(v *pseudonym.Vault, args []string) ([]string, bool) {
	var parts []string
	for _, a := range args {
		switch {
		case a == "":
		case !json.Valid([]byte(a)):
			return args, false
		default:
			parts = append(parts, a)
		}
	}
	if len(parts) == 0 {
		return args, false
	}
	restored := v.RestoreToolCalls(parts)
	out := make([]string, len(args))
	k := 0
	for i, a := range args {
		if a == "" {
			continue
		}
		out[i] = restored[k]
		k++
	}
	return out, true
}

// streamBuffered — потоковый ответ в режиме buffered: собрать целиком,
// проверить, отдать. До проверки приложение ничего не получает, поэтому
// блокировка и сбой — обычные ответы с ошибкой, а не обрыв потока.
func (h *ChatHandler) streamBuffered(w http.ResponseWriter, r *http.Request, app *App, st providers.Stream, requested string, rec *record) {
	asm := chat.NewAssembler()
	rec.outBytes = func() int { return responseBytes(asm.Response()) }
	for {
		c, err := st.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err == nil {
			err = asm.Add(c)
		}
		if err != nil {
			if r.Context().Err() != nil {
				h.logger.Info("клиент прервал поток", "path", r.URL.Path)
				return
			}
			h.logger.Warn("поток провайдера прерван", "provider", app.Provider.ID(), "error", errorKind(err))
			var pe *providers.Error
			switch {
			case errors.As(err, &pe):
				WriteError(w, http.StatusBadGateway, pe.Message, "upstream_error", pe.Code)
			case errors.Is(err, chat.ErrResponseTooLarge):
				WriteError(w, http.StatusBadGateway, "ответ провайдера модели больше предела", "upstream_error", "upstream_bad_response")
			default:
				WriteError(w, http.StatusBadGateway, "поток провайдера модели прерван", "upstream_error", "upstream_stream_error")
			}
			return
		}
		rec.usage(c.Usage)
	}
	resp := asm.Response()
	resp.Model = requested
	if !h.checkFull(w, r, app, rec, resp) {
		return
	}
	rec.issue(resp)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	for _, c := range replayChunks(resp) {
		data, err := json.Marshal(c)
		if err != nil || sse.Write(w, sse.Event{Data: string(data)}) != nil {
			return
		}
	}
	if sse.Write(w, sse.Event{Data: chat.Done}) == nil {
		_ = rc.Flush() //nolint:gosec // G104: клиент ушёл — писать больше некуда
	}
}

// replayChunks — проверенный ответ частями потока: одна часть с сообщением
// целиком и причиной завершения, отдельная часть с расходом токенов.
func replayChunks(resp *chat.Response) []chat.Chunk {
	head := chat.Chunk{ID: resp.ID, Object: "chat.completion.chunk", Created: resp.Created, Model: resp.Model,
		SystemFingerprint: resp.SystemFingerprint, Choices: []chat.ChunkChoice{}}
	var out []chat.Chunk
	for _, ch := range resp.Choices {
		c := head
		d := chat.Delta{Role: ch.Message.Role, Content: ch.Message.Content, Refusal: ch.Message.Refusal}
		for i, tc := range ch.Message.ToolCalls {
			d.ToolCalls = append(d.ToolCalls, toolDelta(i, tc))
		}
		var fin *string
		if ch.FinishReason != "" {
			s := ch.FinishReason
			fin = &s
		}
		c.Choices = []chat.ChunkChoice{{Index: ch.Index, Delta: d, FinishReason: fin}}
		out = append(out, c)
	}
	if resp.Usage != nil {
		c := head
		c.Usage = resp.Usage
		out = append(out, c)
	}
	return out
}

func toolDelta(i int, tc chat.ToolCall) chat.ToolCallDelta {
	d := chat.ToolCallDelta{Index: i, ID: tc.ID, Type: tc.Type}
	d.Function.Name, d.Function.Arguments = tc.Function.Name, tc.Function.Arguments
	return d
}

// streamText — текст ответа (content или refusal), который приходит частями.
// Позиции — в байтах исходного текста провайдера.
type streamText struct {
	acc strings.Builder
	// released — сколько байт отдано клиенту; checked — сколько покрыто
	// последней проверкой.
	released, checked int
	// pending — что замаскировать в непереданном тексте (start ≥ released).
	pending []protectSpan
	// mask — словарь только для масок [[ТИП]]: в ответе псевдонимы не
	// выдаются, а счётчики словаря запроса не смешиваются с ответом.
	mask *pseudonym.Vault
	// code — начало окна с учётом блоков кода, списков и абзацев markdown
	// (exfil.Window): окно с середины блока кода прочитало бы код не так,
	// как весь ответ (ревью 1.22–1.24, п. 1).
	code exfil.Window
	// done — фрагменты, отданные замаскированными: находка, которую новое
	// окно видит в переданном тексте на их месте, уже применена.
	done []protectSpan
	// restore — обратная подстановка; nil — без подстановки.
	restore *pseudonym.Stream
	// restIn — текст, поданный в restore, но ещё задержанный им; ctxIn,
	// ctxOut — конец отданного текста до и после подстановки (контекст
	// повторной проверки).
	restIn        string
	ctxIn, ctxOut []byte
	// exfilGrew — повторная проверка output.exfil после подстановки
	// (exfilAfterRestore): true — подстановка отменяется; nil — без проверки.
	exfilGrew func(before, after string) bool
	masked    bool // хотя бы один фрагмент отдан замаскированным
}

func newStreamText(restore *pseudonym.Stream, exfilGrew func(before, after string) bool) *streamText {
	return &streamText{mask: pseudonym.NewVault(pseudonym.Limits{}), restore: restore, exfilGrew: exfilGrew}
}

// unchecked — новый текст после последней проверки.
func (w *streamText) unchecked() int { return w.acc.Len() - w.checked }

// start — начало окна проверки: streamOverlap байт уже переданного текста
// для контекста, от начала слова.
func (w *streamText) start() int {
	ws := w.released - streamOverlap
	if ws <= 0 {
		return 0
	}
	text := w.acc.String()
	if i := strings.IndexFunc(text[ws:w.released], unicode.IsSpace); i >= 0 {
		_, size := utf8.DecodeRuneInString(text[ws+i:])
		return ws + i + size
	}
	for ws < w.released && !utf8.RuneStart(text[ws]) {
		ws++
	}
	return ws
}

// absorb принимает находки проверки окна (номер текста k, начало окна ws,
// служебный префикс окна shift байт, strict — окно без учёта кода). late —
// находка, из-за которой поток обрывается правилом ruleStreamLate.
// Находки в уже переданном тексте ничего не меняют: замаскировать их
// поздно, а в событие они попадут из итоговой проверки. false — находка,
// которую надо заблокировать или замаскировать, задевает переданный текст:
// поток обрывается.
func (w *streamText) absorb(in *inspection, k, ws, shift int, strict bool) (cut bool, rule string, late *detect.Finding) {
	var pend []protectSpan
	for _, m := range in.Decision.Matches {
		f := in.Findings[m.Hit]
		if f.Text != k || f.End <= shift {
			continue
		}
		s, e := ws+max(f.Start-shift, 0), ws+f.End-shift
		block := in.Decision.Block && m.Action == policy.Block
		mask := m.Apply == policy.Redact || m.Apply == policy.Pseudonymize
		if e <= w.released {
			// Находка целиком в переданном тексте. Блокирующую прежние
			// окна не видели (иначе поток уже оборван), маскируемую — если
			// её место не закрыто отданными масками целиком: её нашёл
			// только больший контекст (ревью 1.22–1.24, п. 1). Молча
			// пропустить её нельзя. Строгое окно (код не учитывается)
			// строже всего текста: его находки в переданном тексте решает
			// итоговая проверка всего ответа, иначе обычный ответ с кодом
			// обрывался бы ложно.
			if !strict && (block || mask && !w.maskedAll(s, e)) {
				return true, ruleStreamLate, &f.Finding
			}
			continue
		}
		if block {
			return true, m.Rule, nil
		}
		if !mask {
			continue
		}
		if s < w.released {
			return true, ruleStreamCut, nil
		}
		pend = append(pend, protectSpan{s, e, f.Category, policy.Redact, cutOut(f.Finding)})
	}
	// Найденное прежними окнами остаётся под маской, даже если это окно его
	// не нашло (сбой детектора при fail_open, другой контекст на стыке окон):
	// маскировать найденное безопаснее, чем отдать.
	for _, sp := range w.pending {
		if !slices.Contains(pend, sp) {
			pend = append(pend, sp)
		}
	}
	w.pending = pend
	w.checked = w.acc.Len()
	return false, "", nil
}

// maskedAll — фрагмент [s, e) целиком закрыт отданными масками: находка,
// которая шире маски, применена не вся.
func (w *streamText) maskedAll(s, e int) bool {
	var cover []protectSpan
	for _, sp := range w.done {
		if sp.start < e && s < sp.end {
			cover = append(cover, sp)
		}
	}
	slices.SortFunc(cover, func(a, b protectSpan) int { return a.start - b.start })
	for _, sp := range cover {
		if sp.start > s {
			return false
		}
		s = max(s, sp.end)
	}
	return s >= e
}

// releasePoint — докуда можно отдать текст после проверки: без хвоста
// streamHoldBack, по границу слова, не разрезая маскируемый фрагмент.
func (w *streamText) releasePoint() int {
	limit := w.checked - streamHoldBack
	if limit <= w.released {
		return w.released
	}
	text := w.acc.String()
	p := limit
	if i := strings.LastIndexFunc(text[w.released:limit], unicode.IsSpace); i >= 0 {
		_, size := utf8.DecodeRuneInString(text[w.released+i:])
		p = w.released + i + size
	} else if w.acc.Len()-w.released < streamMaxHold {
		return w.released
	}
	for p > w.released && !utf8.RuneStart(text[p]) {
		p--
	}
	for moved := true; moved; {
		moved = false
		for _, sp := range w.pending {
			if sp.start < p && p < sp.end {
				p, moved = sp.start, true
			}
		}
	}
	return p
}

// release отдаёт текст до p с масками и обратной подстановкой; final —
// конец текста: сбросить задержанный хвост подстановки.
func (w *streamText) release(p int, final bool) (string, error) {
	var piece string
	if p > w.released {
		var spans, rest []protectSpan
		for _, sp := range w.pending {
			if sp.end <= p {
				spans = append(spans, protectSpan{sp.start - w.released, sp.end - w.released, sp.category, sp.action, sp.cut})
				w.done = append(w.done, sp)
			} else {
				rest = append(rest, sp)
			}
		}
		var err error
		piece, err = applySpans(w.acc.String()[w.released:p], spans, w.mask)
		if err != nil {
			return "", err
		}
		w.masked = w.masked || len(spans) > 0
		w.pending, w.released = rest, p
	}
	return w.restorePiece(piece, final), nil
}

// restorePiece — обратная подстановка в отдаваемый текст; final — конец
// текста: сбросить задержанный хвост. Подстановка, после которой
// output.exfil находит новое (значение стало частью ссылки), отменяется,
// как в ответе без потока (restoreChecked): фрагмент уходит с псевдонимом.
// Проверка видит restoreContext байт отданного текста до фрагмента и
// непереданного после него (в incremental — то, что ждёт следующей
// проверки; в monitor после фрагмента ничего нет).
func (w *streamText) restorePiece(piece string, final bool) string {
	if w.restore == nil {
		return piece
	}
	in := w.restIn + piece
	out := w.restore.Write(piece)
	if final {
		out += w.restore.Flush()
	}
	raw := in[:len(in)-w.restore.Pending()]
	w.restIn = in[len(raw):]
	if out != raw && w.exfilGrew != nil {
		ahead := w.restIn + w.acc.String()[w.released:]
		ahead = ahead[:prefixLen(ahead, restoreContext)]
		before, after := suffix(string(w.ctxIn), restoreContext), suffix(string(w.ctxOut), restoreContext)
		if w.exfilGrew(before+raw+ahead, after+out+ahead) {
			out = raw
		}
	}
	w.ctxIn, w.ctxOut = keepTail(w.ctxIn, raw), keepTail(w.ctxOut, out)
	return out
}

// keepTail дописывает s в буфер контекста и держит в нём не больше
// 2·restoreContext байт: обрезка — раз на restoreContext байт, без копии
// контекста на каждую часть потока.
func keepTail(b []byte, s string) []byte {
	b = append(b, s...)
	if len(b) > 2*restoreContext {
		b = append(b[:0], b[len(b)-restoreContext:]...)
	}
	return b
}

// prefixLen — длина начала s не больше n байт, не разрезая символ.
func prefixLen(s string, n int) int {
	if n >= len(s) {
		return len(s)
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return n
}

// suffix — конец s не длиннее n байт, не разрезая символ.
func suffix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
}

// streamProc — передача потока с проверкой окнами (incremental) или без
// задержки с проверкой после передачи (monitor).
type streamProc struct {
	h           *ChatHandler
	app         *App
	rec         *record
	r           *http.Request
	send        func([]byte) bool
	requested   string
	incremental bool
	asm         *chat.Assembler
	content     *streamText
	refusal     *streamText
	// holdTools — вызовы инструментов отдаются целиком в конце: их надо
	// проверить (incremental) или восстановить (RestoreToolArgs работает
	// только с собранными аргументами).
	holdTools bool
	head      chat.Chunk
	finished  bool
	// failures — сбои детекторов на окнах (в событие).
	failures []events.DetectorFailure
	// reply — хеш content, отданного приложению (history.integrity); nil —
	// без сессии.
	reply *reply
	// comment — комментарий SSE (keep-alive ожидания подтверждения); nil —
	// не пишется.
	comment func(text string) bool
}

func (h *ChatHandler) newStreamProc(r *http.Request, app *App, rec *record, requested string, incremental bool, send func([]byte) bool) *streamProc {
	sp := &streamProc{h: h, app: app, rec: rec, r: r, send: send, requested: requested, incremental: incremental, asm: chat.NewAssembler()}
	rec.outBytes = func() int { return responseBytes(sp.asm.Response()) }
	var cr, rr *pseudonym.Stream
	if v := rec.vault; v != nil && v.Len() > 0 {
		cr, rr = v.NewStream(), v.NewStream()
		if rec.jsonMode {
			cr = v.NewJSONStream()
		}
		sp.holdTools = true
	}
	// Повторная проверка после подстановки — с контекстом клиента: ушёл
	// клиент — проверка падает, подстановка отменяется, а текст уже некому
	// отдавать.
	grew := func(before, after string) bool {
		if app.exfilAfterRestore(r.Context(), before, after, h.cfg.DetectorTimeout) {
			rec.withheld++
			return true
		}
		return false
	}
	sp.content, sp.refusal = newStreamText(cr, grew), newStreamText(rr, grew)
	// Политика вызовов решает по вызову целиком (задача 4.10): с разделом
	// tools вызовы отдаются только в конце, после решения.
	sp.holdTools = sp.holdTools || incremental || app.Policy.ToolsDeclared()
	if rec.sess.replies() {
		sp.reply = rec.sess.tracker.newReply()
	}
	return sp
}

// sent учитывает content, отданный приложению, в хеше выданного ответа.
func (sp *streamProc) sent(piece string) {
	if sp.reply != nil {
		sp.reply.WriteString(piece)
	}
}

// issue — хеш выданного ответа в событие: то, что приложение получило,
// даже если поток оборван (приложение могло сохранить начало ответа).
func (sp *streamProc) issue() {
	if sp.reply == nil {
		return
	}
	if h := sp.reply.Sum(); h != "" {
		sp.rec.sess.ev.Issued = append(sp.rec.sess.ev.Issued, h)
	}
}

// streamOut — исход обработки части.
type streamOut int

const (
	streamGo   streamOut = iota // продолжать
	streamStop                  // поток завершён: оборван или клиент ушёл
)

// chunk обрабатывает часть потока провайдера.
func (sp *streamProc) chunk(c *chat.Chunk) streamOut {
	if err := sp.asm.Add(c); err != nil {
		return sp.upstreamFailed(err)
	}
	sp.rec.usage(c.Usage)
	if sp.head.ID == "" {
		sp.head = chat.Chunk{ID: c.ID, Object: "chat.completion.chunk", Created: c.Created, SystemFingerprint: c.SystemFingerprint}
	}
	out := sp.head
	out.Model, out.Usage, out.Choices = sp.requested, c.Usage, []chat.ChunkChoice{}
	final := false
	for _, ch := range c.Choices {
		d := ch.Delta
		if sp.finished && (d.Content != nil || d.Refusal != nil || len(d.ToolCalls) > 0) {
			// Текст после причины завершения проверить уже нечем.
			return sp.upstreamFailed(providers.ErrBadResponse)
		}
		if d.Content != nil {
			sp.content.acc.WriteString(*d.Content)
		}
		if d.Refusal != nil {
			sp.refusal.acc.WriteString(*d.Refusal)
		}
		od := chat.Delta{Role: d.Role}
		if !sp.holdTools {
			od.ToolCalls = d.ToolCalls
		}
		fr := ch.FinishReason
		if sp.finished {
			// Повторная причина завершения без содержимого (её повторяют
			// некоторые прокси в части с usage) не завершает ответ ещё раз:
			// вызовы инструментов не уходят дважды, а весь ответ не
			// проверяется заново (ревью 1.22–1.24, п. 2).
			fr = nil
		}
		final = final || fr != nil
		out.Choices = append(out.Choices, chat.ChunkChoice{Index: ch.Index, Delta: od, FinishReason: fr})
	}
	if final {
		return sp.finish(&out)
	}
	checked := false
	if sp.incremental && max(sp.content.unchecked(), sp.refusal.unchecked()) >= streamCheckStep {
		if res := sp.checkWindows(); res != streamGo {
			return res
		}
		checked = true
	}
	if res := sp.releaseInto(&out, false, checked); res != streamGo {
		return res
	}
	return sp.emit(&out)
}

// checkWindows проверяет окна текстов с новым текстом (incremental).
func (sp *streamProc) checkWindows() streamOut {
	type item struct {
		w         *streamText
		ws, shift int
		strict    bool
	}
	var items []item
	var texts []inspectText
	for _, x := range []struct {
		w   *streamText
		loc string
	}{{sp.content, locContent}, {sp.refusal, locRefusal}} {
		if x.w.unchecked() == 0 {
			continue
		}
		if x.w.acc.Len()-x.w.released > streamMaxPending {
			return sp.cut(true, ruleStreamHold, "")
		}
		win, ws, shift, strict := x.w.code.Next(x.w.acc.String(), x.w.start())
		items = append(items, item{x.w, ws, shift, strict})
		texts = append(texts, inspectText{Text: win, Source: detect.SourceOutput, Location: x.loc, NoCode: strict})
	}
	if len(texts) == 0 {
		return streamGo
	}
	start := sp.h.cfg.Now()
	in, err := sp.h.outputCheck(sp.r.Context(), sp.app, sp.rec.ev.User, texts, "", true, false)
	sp.rec.ev.LatencyMS["output_check"] += sp.h.cfg.Now().Sub(start).Milliseconds()
	if err != nil {
		return sp.checkError(err)
	}
	// Сбои на окнах повторяются от окна к окну: в событие — без повторов.
	for _, f := range in.Failures {
		if !slices.Contains(sp.failures, f) {
			sp.failures = append(sp.failures, f)
		}
	}
	if in.FailBlock {
		return sp.cut(false, "", "")
	}
	for k, it := range items {
		if cut, rule, late := it.w.absorb(in, k, it.ws, it.shift, it.strict); cut {
			sp.rec.respCutFinding = late
			return sp.cut(true, rule, in.Decision.Message)
		}
	}
	return streamGo
}

// checkError — проверка окна не состоялась: клиент ушёл или конвейер
// собран неверно (поток обрывается как при сбое fail_closed).
func (sp *streamProc) checkError(err error) streamOut {
	if sp.r.Context().Err() != nil {
		return streamStop
	}
	sp.h.logger.Error("проверка ответа не выполнена", "app", sp.app.ID, "event_id", sp.rec.ev.ID, "error", err)
	sp.rec.respFailClosed()
	return sp.cut(false, "", "")
}

// releaseInto добавляет в часть out текст, который можно отдать. В
// incremental до конца ответа точка выпуска пересчитывается только после
// проверки окна (checked): между проверками она не меняется.
func (sp *streamProc) releaseInto(out *chat.Chunk, final, checked bool) streamOut {
	for _, x := range []struct {
		w       *streamText
		refusal bool
	}{{sp.content, false}, {sp.refusal, true}} {
		p := x.w.acc.Len()
		if sp.incremental && !final {
			if !checked {
				continue
			}
			p = x.w.releasePoint()
		}
		piece, err := x.w.release(p, final)
		if err != nil {
			return sp.checkError(err)
		}
		if piece == "" {
			continue
		}
		if len(out.Choices) == 0 {
			out.Choices = []chat.ChunkChoice{{Index: 0}}
		}
		d := &out.Choices[0].Delta
		if x.refusal {
			d.Refusal = &piece
		} else {
			d.Content = &piece
			sp.sent(piece)
		}
	}
	return streamGo
}

// finish — конец ответа (причина завершения или конец потока): итоговая
// проверка всего ответа, выпуск хвоста, вызовы инструментов.
func (sp *streamProc) finish(out *chat.Chunk) streamOut {
	sp.finished = true
	if sp.incremental {
		resp := sp.asm.Response()
		texts, refs := responseTexts(resp)
		start := sp.h.cfg.Now()
		in, err := sp.h.outputCheck(sp.r.Context(), sp.app, sp.rec.ev.User, texts, "", true, true)
		sp.rec.ev.LatencyMS["output_check"] += sp.h.cfg.Now().Sub(start).Milliseconds()
		if err != nil {
			return sp.checkError(err)
		}
		sp.rec.resp, sp.rec.respTexts = in, texts
		if in.FailBlock {
			return sp.cut(false, "", "")
		}
		for k, ref := range refs {
			w := sp.content
			switch {
			case ref.tool >= 0:
				continue
			case ref.refusal:
				w = sp.refusal
			}
			if cut, rule, late := w.absorb(in, k, 0, 0, false); cut {
				sp.rec.respCutFinding = late
				return sp.cut(true, rule, in.Decision.Message)
			}
		}
		if res := sp.finishTools(in, texts, refs, resp, out); res != streamGo {
			return res
		}
	} else if sp.holdTools {
		resp := sp.asm.Response()
		_, refs := responseTexts(resp)
		if res := sp.finishTools(nil, nil, refs, resp, out); res != streamGo {
			return res
		}
	}
	if res := sp.releaseInto(out, true, true); res != streamGo {
		return res
	}
	return sp.emit(out)
}

// finishTools — проверенные (incremental) и восстановленные вызовы
// инструментов в итоговую часть.
func (sp *streamProc) finishTools(in *inspection, texts []inspectText, refs []respRef, resp *chat.Response, out *chat.Chunk) streamOut {
	if len(resp.Choices) == 0 || len(resp.Choices[0].Message.ToolCalls) == 0 {
		return streamGo
	}
	calls := resp.Choices[0].Message.ToolCalls
	if in != nil {
		// Блокировку по content и refusal уже решил absorb: находка в
		// переданном тексте поток не обрывает.
		for _, m := range in.Decision.Matches {
			if f := in.Findings[m.Hit]; in.Decision.Block && m.Action == policy.Block && refs[f.Text].tool >= 0 {
				return sp.cut(true, m.Rule, in.Decision.Message)
			}
		}
		if err := in.protect(texts, pseudonym.NewVault(pseudonym.Limits{})); err != nil {
			return sp.checkError(err)
		}
		for i, ref := range refs {
			if ref.tool < 0 || i >= len(in.Changed) || !in.Changed[i] {
				continue
			}
			if json.Valid([]byte(texts[i].Text)) && !json.Valid([]byte(in.Texts[i])) {
				return sp.cut(true, ruleToolArgsJSON, "")
			}
			calls[ref.tool].Function.Arguments = in.Texts[i]
			sp.content.masked = true
		}
	}
	if v := sp.rec.vault; v != nil && v.Len() > 0 {
		args := make([]string, len(calls))
		for j := range calls {
			args[j] = calls[j].Function.Arguments
		}
		restored, ok := restoreToolCalls(v, args)
		if ok && sp.app.exfilAfterRestore(sp.r.Context(), strings.Join(args, "\n"), strings.Join(restored, "\n"), sp.h.cfg.DetectorTimeout) {
			sp.rec.withheld += len(args)
			ok = false
		}
		if ok {
			for j := range calls {
				calls[j].Function.Arguments = restored[j]
			}
		}
	}
	if toolsCheck(sp.app, resp) {
		keepAlive := func() {
			if sp.comment != nil {
				sp.comment(ApprovalPendingComment)
			}
		}
		if b := sp.h.decideTools(sp.r.Context(), sp.app, sp.rec, calls, keepAlive); b != nil {
			if sp.r.Context().Err() != nil {
				return streamStop
			}
			return sp.cut(true, b.rule, b.message)
		}
	}
	if len(out.Choices) == 0 {
		out.Choices = []chat.ChunkChoice{{Index: 0}}
	}
	for i, tc := range calls {
		out.Choices[0].Delta.ToolCalls = append(out.Choices[0].Delta.ToolCalls, toolDelta(i, tc))
	}
	return streamGo
}

// emit отправляет часть, если в ней есть что отправлять.
func (sp *streamProc) emit(out *chat.Chunk) streamOut {
	if len(out.Choices) == 0 && out.Usage == nil {
		return streamGo
	}
	for _, ch := range out.Choices {
		d := ch.Delta
		if ch.FinishReason == nil && d.Role == "" && d.Content == nil && d.Refusal == nil && len(d.ToolCalls) == 0 && out.Usage == nil {
			return streamGo
		}
	}
	data, err := json.Marshal(out)
	if err != nil || !sp.send(data) {
		return streamStop
	}
	return streamGo
}

// end — поток провайдера закончился (EOF): итоговая обработка, если её не
// было, и [DONE].
func (sp *streamProc) end() {
	if !sp.finished {
		out := sp.head
		out.Model, out.Choices = sp.requested, []chat.ChunkChoice{}
		if sp.finish(&out) != streamGo {
			return
		}
	}
	sp.send([]byte(chat.Done))
}

// upstreamFailed — поток провайдера прерван или ответ вне пределов: отдать
// проверенный текст и сообщить об ошибке без [DONE].
func (sp *streamProc) upstreamFailed(err error) streamOut {
	if sp.r.Context().Err() != nil {
		sp.h.logger.Info("клиент прервал поток", "path", sp.r.URL.Path)
		return streamStop
	}
	sp.h.logger.Warn("поток провайдера прерван", "provider", sp.app.Provider.ID(), "error", errorKind(err))
	if !sp.finished {
		out := sp.head
		out.Model, out.Choices = sp.requested, []chat.ChunkChoice{}
		if sp.finish(&out) != streamGo {
			return streamStop
		}
	}
	body := streamErrorBody(err)
	if errors.Is(err, chat.ErrResponseTooLarge) || errors.Is(err, providers.ErrBadResponse) {
		body = errorBody("ответ провайдера модели не разобран или больше предела", "upstream_error", "upstream_bad_response")
	}
	sp.send(body)
	return streamStop
}

// cut обрывает поток (incremental): отдаёт задержанный хвост обратной
// подстановки уже переданного текста и событие с ошибкой без [DONE].
// byPolicy — блокировка политикой (policy_violation, msg — сообщение
// решения, пусто — политики), иначе — проверка не состоялась
// (check_unavailable).
func (sp *streamProc) cut(byPolicy bool, rule, msg string) streamOut {
	sp.finished = true
	sp.rec.respCut, sp.rec.respCutRule = true, rule
	sp.rec.respCheckFailed = !byPolicy
	if msg == "" {
		msg = sp.app.Policy.BlockMessage
	}
	out := sp.head
	out.Model, out.Choices = sp.requested, []chat.ChunkChoice{}
	for _, x := range []struct {
		w       *streamText
		refusal bool
	}{{sp.content, false}, {sp.refusal, true}} {
		if piece := x.w.restorePiece("", true); piece != "" {
			if len(out.Choices) == 0 {
				out.Choices = []chat.ChunkChoice{{Index: 0}}
			}
			if x.refusal {
				out.Choices[0].Delta.Refusal = &piece
			} else {
				out.Choices[0].Delta.Content = &piece
				sp.sent(piece)
			}
		}
	}
	if sp.emit(&out) != streamGo {
		return streamStop
	}
	if byPolicy {
		sp.send(errorBody(msg, "invalid_request_error", "policy_violation"))
	} else {
		sp.send(errorBody("ответ модели не удалось проверить", "service_unavailable", "check_unavailable"))
	}
	return streamStop
}

// afterStream — проверка ответа для события после передачи (monitor) и
// для оборванного потока (incremental): клиент уже получил всё, что
// получит, поэтому проверка идёт без контекста клиента.
func (sp *streamProc) afterStream() {
	if sp.rec.resp != nil {
		return
	}
	resp := sp.asm.Response()
	texts, _ := responseTexts(resp)
	if len(texts) == 0 {
		return
	}
	mode := policy.Mode("")
	if !sp.incremental {
		mode = policy.Monitor
	}
	start := sp.h.cfg.Now()
	in, err := sp.h.outputCheck(context.WithoutCancel(sp.r.Context()), sp.app, sp.rec.ev.User, texts, mode, true, true)
	sp.rec.ev.LatencyMS["output_check"] += sp.h.cfg.Now().Sub(start).Milliseconds()
	if err != nil {
		sp.h.logger.Error("проверка ответа после передачи не выполнена", "app", sp.app.ID, "event_id", sp.rec.ev.ID, "error", err)
		return
	}
	sp.rec.resp, sp.rec.respTexts = in, texts
}

func errorBody(msg, typ, code string) []byte {
	b, err := json.Marshal(map[string]any{"error": map[string]any{"message": msg, "type": typ, "code": code}})
	if err != nil {
		return []byte(`{"error":{"message":"поток прерван","type":"server_error","code":"internal_error"}}`)
	}
	return b
}
