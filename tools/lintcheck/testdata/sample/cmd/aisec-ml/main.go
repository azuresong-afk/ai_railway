// Команда aisec-ml в образце: обвязка ONNX Runtime здесь разрешена.
package main

import ort "github.com/yalue/onnxruntime_go" // clean:depguard

func main() { _ = ort.GetVersion() }
