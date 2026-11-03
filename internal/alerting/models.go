package alerting

import (
	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Встроенные правила сканера моделей (ТЗ 5.12, 5.16; задачи 5.21 и 5.22
// этапа 5, ADR-0029, дополнение 1). Срабатывают по записям аудита, которые
// сервер пишет той же транзакцией, что принимает отчёт aisec-cli models scan
// или verify и запрещает модель. Решение (дополнение 1 к ADR-0029): два
// правила — подмена файлов (DM-29) и запрет по проверке форматов и шаблона
// чата (DM-27, DM-28) — разные реакции: подмена весов — инцидент на узле
// заказчика, находка сканера — замена модели или формата. Оба правила —
// безопасности: не отключаются.
const (
	// BuiltinModelsHashMismatch — файлы весов или адаптеров модели не
	// совпали с эталонными хешами реестра (DM-29).
	BuiltinModelsHashMismatch = "models.hash_mismatch"
	// BuiltinModelsScanBlocked — отчёт сканера запретил модель: находка с
	// запретом (pickle, нарушенная структура, предел, DM-27) или внедрённые
	// инструкции в шаблоне чата (DM-28).
	BuiltinModelsScanBlocked = "models.scan_blocked"
	// ModelField — поле группировки правил сканера: модель реестра
	// («провайдер/имя»).
	ModelField = "model"
)

// modelRules — встроенные правила задач 5.21 и 5.22.
func modelRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinModelsHashMismatch, Kind: KindSecurity, Name: "Подмена файлов модели",
			Description: "DM-29: файлы весов или адаптеров модели на узле не совпали с эталонными хешами реестра ИИ " +
				"(изменён, пропал или появился лишний файл). Модель запрещена и исключена из пакета шлюзов до снятия запрета.",
			Enabled: true, Severity: "critical", GroupBy: []string{ModelField}, Recipients: none},
		{BuiltinKey: BuiltinModelsScanBlocked, Kind: KindSecurity, Name: "Модель запрещена по отчёту сканера",
			Description: "DM-27, DM-28: сканер нашёл в файлах модели pickle, нарушенную структуру или непроверенный остаток, " +
				"либо в шаблоне чата — внедрённые инструкции. Модель запрещена и исключена из пакета шлюзов до снятия запрета.",
			Enabled: true, Severity: "high", GroupBy: []string{ModelField}, Recipients: none},
	}
}

// modelLabel — модель в оповещении: «провайдер/имя» или имя модели
// заказчика без провайдера.
func modelLabel(r *audit.Record, d map[string]any) string {
	name := str(d["name"], r.Object.ID)
	if p := str(d["provider"], ""); p != "" {
		return p + "/" + name
	}
	return name
}

// modelHashMismatchRaise — срабатывание по записи models.hash_mismatch: в
// подробностях — узел, число расхождений по видам и до 20 путей, без хешей.
func modelHashMismatchRaise(r *audit.Record, d map[string]any) (Raise, bool) {
	if r.Result != audit.ResultSuccess || r.Object.ID == "" {
		return Raise{}, false
	}
	label := modelLabel(r, d)
	extra := map[string]any{"model": label, "model_id": r.Object.ID, "host": d["host"], "report": d["report"], "kind": d["kind"],
		"changed": d["changed"], "missing": d["missing"], "extra": d["extra"], "not_hashed": d["not_hashed"], "total": d["total"],
		"paths": d["paths"]}
	return raiseOf(BuiltinModelsHashMismatch, map[string]string{ModelField: r.Object.ID}, map[string]string{ModelField: label}, 1,
		map[string]any{"items": []any{item(r, extra)}}), true
}

// modelScanBlockedRaise — срабатывание по записи models.scan_reported с
// запретом по находкам сканера или шаблону чата. Подмена файлов поднимает
// своё правило (models.hash_mismatch).
func modelScanBlockedRaise(r *audit.Record, d map[string]any) (Raise, bool) {
	if r.Result != audit.ResultSuccess || r.Object.ID == "" {
		return Raise{}, false
	}
	reasons, _ := d["block_reasons"].([]any)
	var own []any
	for _, x := range reasons {
		if s, _ := x.(string); s == "scan" || s == "chat_template" {
			own = append(own, s)
		}
	}
	if len(own) == 0 {
		return Raise{}, false
	}
	label := modelLabel(r, d)
	extra := map[string]any{"model": label, "model_id": r.Object.ID, "host": d["host"], "report": d["report"], "kind": d["kind"],
		"reasons": own, "templates": d["templates"], "findings": d["findings"]}
	return raiseOf(BuiltinModelsScanBlocked, map[string]string{ModelField: r.Object.ID}, map[string]string{ModelField: label}, 1,
		map[string]any{"items": []any{item(r, extra)}}), true
}
