//go:build !aisec_onnx

package main

import (
	"errors"

	"github.com/azuresong-afk/ai_railway/internal/ml"
)

// newExecutor — сборка без тега aisec_onnx: исполнителя ONNX Runtime нет,
// aisec-ml с моделями не запускается (ADR-0024, раздел 1).
func newExecutor() (ml.Executor, error) {
	return nil, errors.New("aisec-ml собран без ONNX Runtime (тег aisec_onnx, ADR-0024): исполнителя моделей нет")
}
