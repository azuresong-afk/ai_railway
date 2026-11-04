//go:build e2e && linux && aisec_onnx

package e2e

// S12 со снимком экрана без QR-кода: ПДн и инструкции читает OCR (задача
// 5.49; DM-45, DM-46; ADR-0033). Тест нужен aisec-media, собранный с тегом
// aisec_onnx, библиотека ONNX Runtime и модели OCR, поэтому идёт отдельной
// целью make e2e-ocr, а не в make e2e и CI (там библиотеки нет). Без
// переменных окружения пропускается.

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

// s5OCRStack — стенд с aisec-media с OCR: AISEC_E2E_MEDIA_BIN — бинарник,
// AISEC_ORT_LIB — библиотека ORT, AISEC_MEDIA_MODELS_DIR — модели.
func s5OCRStack(t *testing.T) *s3Stack {
	t.Helper()
	bin, lib, models := os.Getenv("AISEC_E2E_MEDIA_BIN"), os.Getenv("AISEC_ORT_LIB"), os.Getenv("AISEC_MEDIA_MODELS_DIR")
	if bin == "" || lib == "" || models == "" {
		t.Skip("нужны AISEC_E2E_MEDIA_BIN, AISEC_ORT_LIB и AISEC_MEDIA_MODELS_DIR (make e2e-ocr)")
	}
	s5MediaBinary = bin
	t.Cleanup(func() { s5MediaBinary = "" })
	st, _ := s5MediaStack(t, s3Opts{}, "-ort-lib", lib, "-models", models, "-workers", "1")
	return st
}

func TestE2EStage5_OCR_ScreenshotWithPII(t *testing.T) {
	st := s5OCRStack(t)
	s5VisionPolicy(st, "vision", map[string]any{"media_check_timeout_ms": 10000})
	app := st.app("vision-app", "vision")
	st.startGateway()
	seen := map[string]bool{}

	// Скриншот карточки клиента в CRM (card-01.png): ИНН, паспорт, телефон,
	// e-mail, дата рождения. Запрос блокируется, в карточке события — рамки
	// находок на изображении.
	st.mockReset()
	code, body := s4PostGateway(t, st, app.key, "/v1/chat/completions", nil,
		s5ImageChat(t, "Что на скриншоте?", s5Corpus(t, "card-01.png")))
	if code == http.StatusOK || st.mockLast().Received {
		t.Fatalf("скриншот с ПДн не заблокирован: %d %s", code, body)
	}
	card := s5Card(t, st.admin, s3LastEvent(t, st.admin, `type = "gateway_request" and action = "block"`, seen).ID)
	boxes := 0
	for _, f := range card.Findings {
		if strings.HasPrefix(f.Detector, "pii") && f.Source == "image" && f.Box != nil && f.Box.W > 0 && f.Box.H > 0 {
			boxes++
		}
	}
	if boxes < 3 || len(card.Media) != 1 || !card.Media[0].Checked {
		t.Fatalf("в карточке нет рамок ПДн (%d) или изображение не проверено целиком: %s", boxes, card.Raw)
	}

	// Инструкция для ассистента на слайде (inject-01.png, DM-45).
	st.mockReset()
	code, _ = s4PostGateway(t, st, app.key, "/v1/chat/completions", nil, s5ImageChat(t, "Перескажи слайд.", s5Corpus(t, "inject-01.png")))
	if code == http.StatusOK || st.mockLast().Received {
		t.Fatalf("инструкция на изображении не остановлена: %d", code)
	}

	// Диаграмма выручки (clean-03.jpg) проходит: изображение проверено, находок нет.
	st.mockReset()
	code, body = s4PostGateway(t, st, app.key, "/v1/chat/completions", nil, s5ImageChat(t, "Опиши диаграмму.", s5Corpus(t, "clean-03.jpg")))
	if code != http.StatusOK || !st.mockLast().Received {
		t.Fatalf("диаграмма заблокирована: %d %s", code, body)
	}
	ok := s5Card(t, st.admin, s3LastEvent(t, st.admin, `type = "gateway_request" and action = "allow"`, seen).ID)
	if len(ok.Findings) != 0 || len(ok.Media) != 1 || !ok.Media[0].Checked {
		t.Fatalf("карточка диаграммы: %s", ok.Raw)
	}
}
