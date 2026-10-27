//go:build !aisec_onnx

package main

import (
	"context"
	"strings"
	"testing"
)

func TestRunWithoutONNXExecutor(t *testing.T) {
	f := newFixture(t)
	f.d.newExecutor = newExecutor
	if err := run(context.Background(), f.cfg, f.d); err == nil || !strings.Contains(err.Error(), "aisec_onnx") {
		t.Fatalf("сборка без ONNX запустилась: %v", err)
	}
}
