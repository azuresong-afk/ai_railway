package bad

import ort "github.com/yalue/onnxruntime_go" // want:depguard

// UseONNX — обвязка ONNX Runtime вне cmd/aisec-ml запрещена (ADR-0024).
func UseONNX() string { return ort.GetVersion() }
