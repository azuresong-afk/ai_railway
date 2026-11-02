package bad

import "github.com/azuresong-afk/ai_railway/internal/modelscan" // want:depguard

// UseModelScan — сканер файлов моделей вне aisec-cli и тестов запрещён (ADR-0029, п. 4).
func UseModelScan() []string { return modelscan.Formats() }
