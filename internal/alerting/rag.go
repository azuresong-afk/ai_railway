package alerting

import (
	"strconv"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Встроенное правило манифеста RAG (ТЗ 5.12, 5.16, DM-30; задача 5.24 этапа
// 5, ADR-0029, п. 5). Срабатывает по записи аудита rag.document_changed,
// которую сервер пишет в транзакции загрузки манифеста, когда в новой
// версии есть документы вне прошлой версии, изменённые или пропавшие. Ключ
// дедупликации — коллекция: пока оповещение открыто, следующие изменения
// той же коллекции дополняют его.
const (
	// BuiltinRAGDocumentChanged — документы коллекции RAG изменились. Вид
	// «новое»: обновление базы знаний — обычное дело, правило можно
	// отключить и сменить получателей.
	BuiltinRAGDocumentChanged = "rag.document_changed"
	// RAGCollectionField — поле правила «новое» для
	// BuiltinRAGDocumentChanged: коллекция. В событиях шлюза такого поля нет.
	RAGCollectionField = "rag_collection"
)

// ragRules — встроенное правило задачи 5.24.
func ragRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinRAGDocumentChanged, Kind: KindNew, Name: "Изменились документы коллекции RAG",
			Description: "DM-30: в новой версии манифеста коллекции RAG есть документы, которых не было в прошлой версии, " +
				"изменённые (другой хеш или размер) или пропавшие. В оповещении — коллекция, число документов каждого вида и " +
				"до 20 их ID, без содержимого. Неожиданное изменение — повод проверить источник документов: подмена или " +
				"отравление базы знаний.",
			Enabled: true, Severity: "medium", Condition: Condition{Field: RAGCollectionField}, GroupBy: []string{RAGCollectionField},
			SuppressMinutes: DefaultSuppressMinutes, Recipients: none},
	}
}

// ragDocumentChangedRaise — срабатывание по записи rag.document_changed. В
// подробностях — версии, число документов каждого вида и ID из записи
// (сервис ограничил их число и объём).
func ragDocumentChangedRaise(r *audit.Record, d map[string]any) (Raise, bool) {
	if r.Result != audit.ResultSuccess {
		return Raise{}, false
	}
	slug := str(d["collection"], r.Object.ID)
	if slug == "" {
		return Raise{}, false
	}
	num := func(k string) int {
		v, _ := d[k].(float64)
		return int(max(v, 0))
	}
	added, changed, removed := num("added"), num("changed"), num("removed")
	if added+changed+removed == 0 {
		return Raise{}, false
	}
	value := slug + " (новых: " + strconv.Itoa(added) + ", изменённых: " + strconv.Itoa(changed) + ", пропавших: " +
		strconv.Itoa(removed) + ")"
	extra := map[string]any{"collection": slug, "version": d["version"], "prev_version": d["prev_version"],
		"added": added, "changed": changed, "removed": removed, "ids": d["ids"], "ids_truncated": d["ids_truncated"]}
	return raiseOf(BuiltinRAGDocumentChanged, map[string]string{RAGCollectionField: slug},
		map[string]string{RAGCollectionField: value}, 1,
		map[string]any{"items": []any{item(r, extra)}}), true
}
