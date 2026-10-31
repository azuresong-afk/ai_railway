// Пакет modelscan образца — сканер файлов моделей (ADR-0029, п. 4).
package modelscan

// Formats — поддерживаемые форматы.
func Formats() []string { return []string{"safetensors"} }
