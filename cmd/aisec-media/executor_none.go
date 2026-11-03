//go:build !aisec_onnx || !cgo

package main

import (
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/media"
)

// ocrBuilt — сборка без тега aisec_onnx: исполнителя OCR нет (ADR-0032,
// раздел 9; ADR-0033). aisec-media декодирует изображения, читает
// метаданные и QR и отвечает без ocr в checks — шлюз ставит отметку «не
// проверено» (no_ocr).
const ocrBuilt = false

func newOCREngine(*config, aisecCrypto.Provider) (media.OCREngine, error) {
	return nil, nil //nolint:nilnil // без OCR: исполнителя нет, и это не ошибка
}
