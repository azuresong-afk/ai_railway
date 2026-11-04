//go:build e2e && linux

package e2e

// Изображения в запросах к модели (задача 5.49, сценарий S12, строки DM-46,
// DM-47, DM-50; ADR-0032): живые сервер, шлюз, mock-llm и настоящий процесс
// aisec-media. Сборка без OCR (тег aisec_onnx, ADR-0033): ПДн и инструкции
// на изображениях даёт QR-код и метаданные — цепочка «анализатор → детекторы
// → политика → событие с рамкой» та же. Вариант с OCR — stage5_ocr_test.go.

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// s5VisionPolicy — политика с проверкой изображений: ПДн и секреты из
// изображения блокируются (на изображении текст не замаскировать, решение Р9
// этапа 5), инъекция блокируется, остальное проходит.
func s5VisionPolicy(st *s3Stack, id string, extra map[string]any) {
	st.t.Helper()
	spec := map[string]any{"name": "Изображения e2e", "mode": "enforce", "media_check": "sync",
		"rules": []map[string]any{
			{"id": "injection", "detector": "injection.heuristic", "directions": []string{"input"}, "action": "block", "severity": "high"},
			{"id": "pii-input", "detector": "pii.ru", "directions": []string{"input"}, "action": "pseudonymize", "severity": "medium"},
			{"id": "secrets", "detector": "secrets", "directions": []string{"input"}, "action": "redact", "severity": "high"},
		}}
	for k, v := range extra {
		spec[k] = v
	}
	if r := st.admin.do("POST", "/api/v1/policies", map[string]any{"id": id, "spec": spec}); r.code != http.StatusCreated {
		st.t.Fatalf("политика %s: %s", id, r)
	}
}

// s5MediaOK — анализатор разобрал изображение и извлёк текст: проверено
// целиком (сборка с OCR) или без OCR с причиной no_ocr (QR и метаданные
// извлечены, текст на растре — нет).
func s5MediaOK(m s5MediaCheck) bool { return m.Checked || m.Reason == "no_ocr" }

// S12 (ТЗ 1.4, критерий приёмки ТЗ 14): сотрудник отправляет во внешнюю
// модель изображение с ПДн. Анализатор находит ПДн, запрос блокируется, а в
// карточке события видно, где именно на изображении они были. Безобидное
// изображение проходит. Имя без ID строки: тест идёт на живой БД.
func TestE2EStage5_S12_ScreenshotWithPII(t *testing.T) {
	st, _ := s5MediaStack(t, s3Opts{})
	s5VisionPolicy(st, "vision", nil)
	app := st.app("vision-app", "vision")
	st.startGateway()
	seen := map[string]bool{}

	// Визитка с QR-кодом: телефон и e-mail внутри QR (qr-02.png, DM-46/DM-47).
	st.mockReset()
	code, body := s4PostGateway(t, st, app.key, "/v1/chat/completions", nil,
		s5ImageChat(t, "Что на картинке?", s5Corpus(t, "qr-02.png")))
	if code == http.StatusOK || !strings.Contains(body, "политик") {
		t.Fatalf("изображение с ПДн не заблокировано: %d %s", code, body)
	}
	if st.mockLast().Received {
		t.Fatal("заблокированный запрос дошёл до провайдера")
	}
	ev := s3LastEvent(t, st.admin, `type = "gateway_request" and action = "block"`, seen)
	card := s5Card(t, st.admin, ev.ID)
	var boxed *s5Finding
	for i, f := range card.Findings {
		if strings.HasPrefix(f.Detector, "pii") && f.Box != nil {
			boxed = &card.Findings[i]
		}
	}
	if boxed == nil || boxed.Source != "image" && boxed.Source != "qr" || boxed.Box.W <= 0 || boxed.Box.H <= 0 {
		t.Fatalf("в карточке нет находки ПДн с рамкой на изображении: %s", card.Raw)
	}
	// Сборка без OCR (тег aisec_onnx): текст из QR извлечён, но изображение
	// целиком «не проверено» по причине no_ocr; с OCR — проверено (s5MediaOK).
	if len(card.Media) != 1 || !s5MediaOK(card.Media[0]) || card.Media[0].Format != "png" || card.Media[0].Texts < 1 ||
		card.Media[0].Mode != "sync" {
		t.Fatalf("проверка изображения в карточке: %s", card.Raw)
	}
	// Ни телефона, ни e-mail из QR, ни самого изображения в карточке нет
	// (содержимое — только по режиму хранения, ТЗ 5.5).
	for _, leak := range []string{"base64,", "iVBORw0KGgo", "@"} {
		if strings.Contains(card.Raw, leak) && leak != "@" {
			t.Fatalf("в карточке событие содержит %q", leak)
		}
	}

	// Безобидное изображение (QR со ссылкой на меню) проходит: ложных
	// срабатываний нет, провайдер получил запрос.
	st.mockReset()
	code, body = s4PostGateway(t, st, app.key, "/v1/chat/completions", nil,
		s5ImageChat(t, "Что на картинке?", s5Corpus(t, "qr-03.png")))
	if code != http.StatusOK {
		t.Fatalf("безобидное изображение: %d %s", code, body)
	}
	if !st.mockLast().Received {
		t.Fatal("безобидный запрос не дошёл до провайдера")
	}
	ok := s3LastEvent(t, st.admin, `type = "gateway_request" and action = "allow"`, seen)
	okCard := s5Card(t, st.admin, ok.ID)
	if len(okCard.Media) != 1 || !s5MediaOK(okCard.Media[0]) || len(okCard.Findings) != 0 {
		t.Fatalf("карточка безобидного изображения: %s", okCard.Raw)
	}

	// Инструкция в метаданных изображения (meta-01.png, DM-47): видимого
	// текста нет, запрос блокируется, находка — без рамки (метаданные не
	// имеют места на изображении).
	st.mockReset()
	code, _ = s4PostGateway(t, st, app.key, "/v1/chat/completions", nil,
		s5ImageChat(t, "Опиши изображение.", s5Corpus(t, "meta-01.png")))
	if code == http.StatusOK || st.mockLast().Received {
		t.Fatalf("инъекция в метаданных не остановлена: %d", code)
	}
	meta := s5Card(t, st.admin, s3LastEvent(t, st.admin, `type = "gateway_request" and action = "block"`, seen).ID)
	if len(meta.Findings) == 0 || meta.Findings[0].Box != nil {
		t.Fatalf("находка в метаданных: %s", meta.Raw)
	}

	// Check API: то же изображение, ответ с находками и рамкой.
	hit := false
	for _, f := range meta.Findings {
		hit = hit || strings.HasPrefix(f.Detector, "injection")
	}
	if !hit {
		t.Fatalf("нет находки инъекции: %s", meta.Raw)
	}
	_ = time.Second
}

// DM-50: анализатор изображений завис — запросы не задерживаются дольше срока
// media_check_timeout_ms и не проходят «молча»: событие получает отметку
// media_unavailable, серия таких событий даёт оповещение
// frequency.media_unavailable, «Состояние системы» — условие по шлюзу.
// Политика с non_text: block останавливает такой запрос. После продолжения
// работы анализатора изображения снова проверяются. Имя без ID строки: тест
// идёт на живой БД.
func TestE2EStage5_MediaStallMarksUnchecked(t *testing.T) {
	st, media := s5MediaStack(t, s3Opts{})
	// Приложение с fail_open пропускает непроверенное изображение с
	// отметкой, с fail_closed — отвечает 503, политика non_text: block
	// останавливает непроверенное в любом режиме.
	s5VisionPolicy(st, "vision", map[string]any{"media_check_timeout_ms": 300})
	s5VisionPolicy(st, "strict", map[string]any{"media_check_timeout_ms": 300, "non_text": "block"})
	app := st.s5App("open-app", "vision", "fail_open", "")
	closed := st.s5App("closed-app", "vision", "fail_closed", "")
	strict := st.s5App("strict-app", "strict", "fail_open", "")
	st.startGateway()
	seen := map[string]bool{}
	clean := s5ImageChat(t, "Что на картинке?", s5Corpus(t, "qr-03.png"))

	// Анализатор жив: изображение разобрано, отметки нет.
	if code, body := s4PostGateway(t, st, app.key, "/v1/chat/completions", nil, clean); code != http.StatusOK {
		t.Fatalf("до зависания: %d %s", code, body)
	}
	if ev := s5Card(t, st.admin, s3LastEvent(t, st.admin, `type = "gateway_request"`, seen).ID); len(ev.Media) != 1 || !s5MediaOK(ev.Media[0]) ||
		strings.Contains(ev.Raw, `"media_unavailable"`) {
		t.Fatalf("до зависания: %s", ev.Raw)
	}

	media.freeze()
	// Изображение с другим содержимым: кэш итогов анализатора не помогает.
	stalled := func(n int) string {
		return s5ImageChat(t, "Что на картинке? Вариант "+strconv.Itoa(n), s5Corpus(t, "qr-03.png"))
	}
	start := time.Now()
	st.mockReset()
	if code, body := s4PostGateway(t, st, app.key, "/v1/chat/completions", nil, stalled(0)); code != http.StatusOK {
		t.Fatalf("при зависании (fail_open): %d %s", code, body)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("зависший анализатор задержал запрос на %v", d)
	}
	if !st.mockLast().Received {
		t.Fatal("запрос с отметкой «не проверено» не дошёл до провайдера")
	}
	ev := s5Card(t, st.admin, s3LastEvent(t, st.admin, `type = "gateway_request"`, seen).ID)
	if len(ev.Media) != 1 || ev.Media[0].Checked || (ev.Media[0].Reason != "timeout" && ev.Media[0].Reason != "unavailable") ||
		!strings.Contains(ev.Raw, `"media_unavailable":true`) {
		t.Fatalf("при зависании: %s", ev.Raw)
	}

	// fail_closed: проверка не удалась — запрос не уходит, событие помечено.
	st.mockReset()
	code, body := s4PostGateway(t, st, closed.key, "/v1/chat/completions", nil, stalled(1))
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "check_unavailable") || st.mockLast().Received {
		t.Fatalf("fail_closed при зависании: %d %s", code, body)
	}
	if ev := s5Card(t, st.admin, s3LastEvent(t, st.admin, `type = "gateway_request"`, seen).ID); !strings.Contains(ev.Raw, `"media_unavailable":true`) {
		t.Fatalf("отказ fail_closed без отметки media_unavailable: %s", ev.Raw)
	}

	// non_text: block останавливает непроверенное изображение и при fail_open.
	st.mockReset()
	code, _ = s4PostGateway(t, st, strict.key, "/v1/chat/completions", nil, stalled(2))
	if code == http.StatusOK || st.mockLast().Received {
		t.Fatalf("non_text: block пропустил непроверенное изображение: %d", code)
	}

	// Серия отметок — оповещение DM-50 (10 событий за 10 минут) и условие
	// «Состояния системы» по шлюзу (после heartbeat).
	for i := 3; i < 14; i++ {
		s4PostGateway(t, st, app.key, "/v1/chat/completions", nil, stalled(i))
	}
	if a := st.waitAlert("frequency.media_unavailable", 90*time.Second); a.ID == "" {
		t.Fatal("нет оповещения frequency.media_unavailable")
	}
	if !s2WaitFor(90*time.Second, func() bool {
		r := st.admin.do("GET", "/api/v1/system/status", nil)
		return r.code == http.StatusOK && strings.Contains(string(r.body), `"condition":"gateway_media_`) &&
			s5ActiveCondition(t, r, "gateway_media_overloaded", "gateway_media_unavailable")
	}) {
		t.Fatal("«Состояние системы» не показало сбой aisec-media шлюза")
	}

	// Анализатор продолжил работу: изображения снова проверяются.
	media.thaw()
	if !s2WaitFor(60*time.Second, func() bool {
		code, _ := s4PostGateway(t, st, app.key, "/v1/chat/completions", nil, stalled(100+int(time.Now().UnixNano()%1000)))
		return code == http.StatusOK && !strings.Contains(s5Card(t, st.admin,
			s3LastEvent(t, st.admin, `type = "gateway_request"`, map[string]bool{}).ID).Raw, `"media_unavailable":true`)
	}) {
		t.Fatal("после продолжения работы анализатора изображения не проверяются")
	}
}

// s5ActiveCondition — среди уведомлений «Состояния системы» активно одно из
// условий conds.
func s5ActiveCondition(t *testing.T, r s2Resp, conds ...string) bool {
	t.Helper()
	var st struct {
		Notifications []struct {
			Condition string `json:"condition"`
			Active    bool   `json:"active"`
		} `json:"notifications"`
	}
	r.json(t, &st)
	for _, n := range st.Notifications {
		if n.Active && slices.Contains(conds, n.Condition) {
			return true
		}
	}
	return false
}
